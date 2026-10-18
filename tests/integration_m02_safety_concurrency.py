#!/usr/bin/env python3
"""Manual, explicitly authorized S06 two-session PostgreSQL race harness.

This module does not connect to a database during import, tests, or compilation.
Run manually only with explicit authorization and PADDOCK_DB_URL set to the
intended disposable ``paddock_test`` database. All psql output is captured;
raw output and the DSN are never printed.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
import hashlib
import unittest
from dataclasses import dataclass
from typing import IO
from urllib.parse import parse_qsl, unquote, urlsplit

DB_URL_ENV = "PADDOCK_DB_URL"
DB_NAME = "paddock_test"
STATEMENT_TIMEOUT_MS = 15_000
LOCK_TIMEOUT_MS = 10_000
PREFLIGHT_TIMEOUT = 20
SESSION_TIMEOUT = 35
CLEANUP_TIMEOUT = 20
POLL_INTERVAL = 0.1

@dataclass(frozen=True)
class FixtureIds:
    token: str
    bundle: str
    scope: str
    root: str
    rollout: str
    app_a: str
    app_b: str
    advisory_key: int


def new_fixture_ids() -> FixtureIds:
    token = uuid.uuid4().hex
    return FixtureIds(token, hashlib.sha256(token.encode()).hexdigest(),
                      f"fixture-s06-{token}-scope", f"fixture-s06-{token}-root",
                      f"fixture-s06-{token}-rollout", f"paddock_s06_{token}_a",
                      f"paddock_s06_{token}_b", int(token[:16], 16) & ((1 << 63) - 1))


class HarnessError(RuntimeError):
    """Safe-to-report harness failure; contains no subprocess output."""


def _sql_literal(value: str) -> str:
    """Quote a literal assembled from fixed harness constants."""
    return "'" + value.replace("'", "''") + "'"


def preflight_sql(ids: FixtureIds) -> str:
    """Read-only identity/schema/fixture guard. Emits only a compact sentinel."""
    return f"""\
BEGIN READ ONLY;
DO $$
BEGIN
  IF current_database() <> '{DB_NAME}' THEN
    RAISE EXCEPTION 'wrong database';
  END IF;
  IF current_setting('server_version_num')::integer < 180000
     OR current_setting('server_version_num')::integer >= 190000 THEN
    RAISE EXCEPTION 'wrong PostgreSQL major';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_trigger
      WHERE tgrelid = 'raw.policy_scopes'::regclass AND NOT tgisinternal
        AND tgname = 'policy_scopes_frozen_rollback_ct')
     OR NOT EXISTS (SELECT 1 FROM pg_trigger
      WHERE tgrelid = 'raw.policy_rollouts'::regclass AND NOT tgisinternal
        AND tgname = 'policy_rollouts_frozen_rollback_ct') THEN
    RAISE EXCEPTION 'S06 triggers missing';
  END IF;
  IF EXISTS (SELECT 1 FROM raw.policy_bundles
                WHERE bundle_digest = '{ids.bundle}')
      OR EXISTS (SELECT 1 FROM raw.policy_scopes WHERE scope_id = '{ids.scope}')
      OR EXISTS (SELECT 1 FROM raw.roots WHERE root_id = '{ids.root}')
      OR EXISTS (SELECT 1 FROM raw.policy_rollouts WHERE rollout_id = '{ids.rollout}')
      OR EXISTS (SELECT 1 FROM pg_stat_activity WHERE application_name IN ('{ids.app_a}', '{ids.app_b}')) THEN
    RAISE EXCEPTION 'fixture identifier already exists';
  END IF;
END $$;
SELECT 'PADDOCK_S06_PREFLIGHT_OK';
COMMIT;
"""


def seed_sql(ids: FixtureIds) -> str:
    """Seed only uniquely named fixture entities, then commit them."""
    return f"""\
BEGIN;
INSERT INTO raw.policy_bundles
  (bundle_digest, canonical_bytes, schema_version, signer_key_id, signature)
VALUES ('{ids.bundle}', decode('01','hex'), 'v1', 'fixture-s06-{ids.token}-signer', decode('01','hex'));
INSERT INTO raw.policy_scopes (scope_id, baseline_bundle_digest, mode)
VALUES ('{ids.scope}', '{ids.bundle}', 'ACTIVE');
INSERT INTO raw.roots (root_id, scope_id, effective_bundle_digest)
VALUES ('{ids.root}', '{ids.scope}', '{ids.bundle}');
INSERT INTO raw.policy_rollouts
  (rollout_id, scope_id, state, target_root_id, base_activation_epoch,
   last_activation_epoch, base_security_epoch, rollback_from)
VALUES ('{ids.rollout}', '{ids.scope}', 'ROLLING_BACK', '{ids.root}', 0, 0, 0, 'MONITORING');
UPDATE raw.policy_scopes SET live_rollout_id = '{ids.rollout}' WHERE scope_id = '{ids.scope}';
COMMIT;
"""


def worker_sql(ids: FixtureIds, application_name: str, operation: str) -> str:
    if application_name not in (ids.app_a, ids.app_b) or operation not in ("freeze", "complete"):
        raise ValueError("unknown worker operation")
    statement = (
        f"UPDATE raw.policy_scopes SET mode = 'FROZEN' WHERE scope_id = '{ids.scope}';"
        if operation == "freeze"
        else f"UPDATE raw.policy_rollouts SET state = 'COMPLETED', rollback_from = NULL WHERE rollout_id = '{ids.rollout}' AND state = 'ROLLING_BACK';"
    )
    return f"""\
SET application_name = '{application_name}';
\\set VERBOSITY verbose
SET statement_timeout = '{STATEMENT_TIMEOUT_MS}ms';
SET lock_timeout = '{LOCK_TIMEOUT_MS}ms';
BEGIN;
DO $$ DECLARE affected bigint; BEGIN
  {statement[:-1]};
  GET DIAGNOSTICS affected = ROW_COUNT;
  IF affected <> 1 THEN RAISE EXCEPTION 'expected exactly one updated row'; END IF;
END $$;
\\echo PADDOCK_S06_WORKER_{application_name}_UPDATED
SELECT pg_advisory_xact_lock({ids.advisory_key});
COMMIT;
\\echo PADDOCK_S06_WORKER_{application_name}_COMMITTED
"""


def cleanup_sql(ids: FixtureIds) -> str:
    """Remove only fixture rows, in reverse dependency order."""
    return f"""\
BEGIN;
UPDATE raw.policy_scopes SET mode = 'ACTIVE', live_rollout_id = NULL
 WHERE scope_id = '{ids.scope}';
DELETE FROM raw.policy_rollouts WHERE rollout_id = '{ids.rollout}';
DELETE FROM raw.roots WHERE root_id = '{ids.root}';
DELETE FROM raw.policy_scopes WHERE scope_id = '{ids.scope}';
DELETE FROM raw.policy_bundles WHERE bundle_digest = '{ids.bundle}';
COMMIT;
"""


def final_state_sql(ids: FixtureIds) -> str:
    return f"""\
SELECT coalesce((SELECT mode FROM raw.policy_scopes WHERE scope_id = '{ids.scope}'), '<absent>')
       || '|' || coalesce((SELECT state FROM raw.policy_rollouts WHERE rollout_id = '{ids.rollout}'), '<absent>');
"""


def _redact(text: str, dsn: str) -> str:
    """Redact connection strings, URI credentials, and libpq key/value DSNs."""
    if dsn:
        text = text.replace(dsn, "<redacted-dsn>")
    text = re.sub(r"(?i)(postgres(?:ql)?://)[^\s'\"]+", r"\1<redacted>", text)
    text = re.sub(r"(?i)\b(password|passfile|host|user|dbname)=('[^']*'|\"[^\"]*\"|[^\s]+)", r"\1=<redacted>", text)
    return text


@dataclass
class PsqlSession:
    process: subprocess.Popen[str]
    output_thread: threading.Thread
    output: list[str]

    @classmethod
    def start(cls, command: list[str], env: dict[str, str]) -> "PsqlSession":
        proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, text=True, bufsize=1, env=env)
        output: list[str] = []

        def drain() -> None:
            assert proc.stdout is not None
            output.extend(proc.stdout)

        thread = threading.Thread(target=drain, daemon=True)
        thread.start()
        return cls(proc, thread, output)

    def send(self, sql: str) -> None:
        if self.process.stdin is None or self.process.poll() is not None:
            raise HarnessError("psql session exited before command delivery")
        self.process.stdin.write(sql)
        self.process.stdin.flush()

    def close_input(self) -> None:
        if self.process.stdin and not self.process.stdin.closed:
            self.process.stdin.close()

    def wait(self, timeout: float) -> int:
        try:
            code = self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            self.terminate()
            raise HarnessError("psql session timed out") from exc
        self.output_thread.join(timeout=2)
        if self.output_thread.is_alive():
            self.terminate()
            raise HarnessError("psql output reader did not stop")
        return code

    def terminate(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)
        self.close_input()
        self.output_thread.join(timeout=2)


def _libpq_environment(dsn: str, base: dict[str, str] | None = None) -> dict[str, str]:
    """Translate an operator PostgreSQL URI into libpq environment settings.

    PGPASSWORD is inherited only by this trusted local child process. It is not
    printed or persisted; process-environment visibility remains a host risk.
    """
    try:
        parsed = urlsplit(dsn)
        parsed_port = parsed.port
    except ValueError as exc:
        raise HarnessError("PADDOCK_DB_URL is not a valid PostgreSQL URI") from exc
    if parsed.scheme not in ("postgres", "postgresql") or not parsed.hostname:
        raise HarnessError("PADDOCK_DB_URL must be a PostgreSQL URI with a host")
    database = unquote(parsed.path.lstrip("/"))
    username = unquote(parsed.username or "")
    if not database or not username or parsed.fragment:
        raise HarnessError("PADDOCK_DB_URL is missing required connection fields")

    option_map = {
        "sslmode": "PGSSLMODE",
        "sslrootcert": "PGSSLROOTCERT",
        "sslcert": "PGSSLCERT",
        "sslkey": "PGSSLKEY",
        "target_session_attrs": "PGTARGETSESSIONATTRS",
        "connect_timeout": "PGCONNECT_TIMEOUT",
        "channel_binding": "PGCHANNELBINDING",
        "application_name": "PGAPPNAME",
        "gssencmode": "PGGSSENCMODE",
    }
    options = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
    if len({key for key, _ in options}) != len(options) or any(key not in option_map for key, _ in options):
        raise HarnessError("PADDOCK_DB_URL contains duplicate or unsupported connection options")

    env = dict(os.environ if base is None else base)
    for key in tuple(env):
        if key.startswith("PG") or key == DB_URL_ENV:
            env.pop(key, None)
    env.update({"PGHOST": parsed.hostname, "PGDATABASE": database, "PGUSER": username})
    if parsed_port is not None:
        env["PGPORT"] = str(parsed_port)
    if parsed.password is not None:
        env["PGPASSWORD"] = unquote(parsed.password)
    for key, value in options:
        env[option_map[key]] = unquote(value)
    return env


def _psql_command(psql: str) -> list[str]:
    """Return psql flags without connection strings or credentials in argv."""
    return [psql, "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1"]


def _run_one_shot(psql: str, sql: str, timeout: float, env: dict[str, str]) -> tuple[int, str]:
    try:
        result = subprocess.run(_psql_command(psql), input=sql, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=timeout, check=False, env=env)
    except subprocess.TimeoutExpired as exc:
        raise HarnessError("psql command timed out") from exc
    # Output remains private in-process and is never surfaced, even on failure.
    return result.returncode, result.stdout or ""


def _marker_seen(session: PsqlSession, marker: str) -> bool:
    return any(marker in line for line in session.output)


_SQLSTATE_ERROR = re.compile(r"^ERROR:\s+([A-Z0-9]{5}):")


def parse_sqlstate_error_lines(output: str) -> list[str | None]:
    """Return SQLSTATEs from exact verbose PostgreSQL ERROR lines; None marks malformed errors."""
    errors = [line.rstrip("\r\n") for line in output.splitlines()
              if line.startswith("ERROR:")]
    return [match.group(1) if (match := _SQLSTATE_ERROR.match(line)) else None
            for line in errors]


def _wait_for_workers(psql: str, env: dict[str, str], deadline: float, ids: FixtureIds,
                      workers: list[PsqlSession]) -> bool:
    sql = f"""\
SELECT count(*) FROM pg_stat_activity
 WHERE application_name IN ('{ids.app_a}', '{ids.app_b}')
   AND wait_event_type = 'Lock' AND wait_event = 'advisory';
"""
    while time.monotonic() < deadline:
        if not all(_marker_seen(s, f"PADDOCK_S06_WORKER_{app}_UPDATED")
                   for s, app in zip(workers, (ids.app_a, ids.app_b))):
            time.sleep(POLL_INTERVAL)
            continue
        code, output = _run_one_shot(psql, sql, min(5, max(1, deadline-time.monotonic())), env)
        if code == 0 and output.strip().splitlines()[-1:] == ["2"]:
            return True
        time.sleep(POLL_INTERVAL)
    return False


def _check_fixture_absent(psql: str, env: dict[str, str], ids: FixtureIds) -> None:
    sql = f"""\
SELECT count(*) FROM raw.policy_rollouts WHERE rollout_id = '{ids.rollout}';
SELECT count(*) FROM raw.roots WHERE root_id = '{ids.root}';
SELECT count(*) FROM raw.policy_scopes WHERE scope_id = '{ids.scope}';
SELECT count(*) FROM raw.policy_bundles WHERE bundle_digest = '{ids.bundle}';
"""
    code, output = _run_one_shot(psql, sql, CLEANUP_TIMEOUT, env)
    numbers = [line.strip() for line in output.splitlines() if line.strip() in ("0", "1")]
    if code != 0 or numbers[-4:] != ["0", "0", "0", "0"]:
        raise HarnessError("read-only fixture absence verification failed")


def run_race() -> None:
    ids = new_fixture_ids()
    dsn = os.environ.get(DB_URL_ENV, "")
    if not dsn:
        raise HarnessError(f"{DB_URL_ENV} is required")
    psql = shutil.which("psql")
    if not psql:
        raise HarnessError("psql executable not found")
    env = _libpq_environment(dsn)
    # Avoid inherited psql startup/config behavior; -X also disables .psqlrc.
    code, output = _run_one_shot(psql, preflight_sql(ids), PREFLIGHT_TIMEOUT, env)
    if code != 0 or "PADDOCK_S06_PREFLIGHT_OK" not in output:
        raise HarnessError("read-only safety preflight failed; no fixture rows were seeded")

    # The committed fixture is cleaned in finally even if process coordination fails.
    code, _ = _run_one_shot(psql, seed_sql(ids), PREFLIGHT_TIMEOUT, env)
    if code != 0:
        raise HarnessError("fixture seed transaction failed")

    controller: PsqlSession | None = None
    workers: list[PsqlSession] = []
    worker_codes: list[int | None] = []
    primary_error: BaseException | None = None
    try:
        controller = PsqlSession.start(_psql_command(psql), env)
        controller.send(f"SET statement_timeout = '{STATEMENT_TIMEOUT_MS}ms';\nSELECT pg_advisory_lock({ids.advisory_key});\n\\echo PADDOCK_S06_CONTROLLER_HELD\n")
        deadline = time.monotonic() + 5
        while not _marker_seen(controller, "PADDOCK_S06_CONTROLLER_HELD") and time.monotonic() < deadline:
            if controller.process.poll() is not None:
                raise HarnessError("controller session failed before barrier acquisition")
            time.sleep(POLL_INTERVAL)
        if not _marker_seen(controller, "PADDOCK_S06_CONTROLLER_HELD"):
            raise HarnessError("controller could not acquire barrier")

        workers.append(PsqlSession.start(_psql_command(psql), env))
        workers.append(PsqlSession.start(_psql_command(psql), env))
        workers[0].send(worker_sql(ids, ids.app_a, "freeze"))
        workers[1].send(worker_sql(ids, ids.app_b, "complete"))
        if not _wait_for_workers(psql, env, time.monotonic() + SESSION_TIMEOUT, ids, workers):
            raise HarnessError("both workers were not observed waiting on the advisory barrier")
        controller.send(f"SELECT pg_advisory_unlock({ids.advisory_key});\n\\echo PADDOCK_S06_CONTROLLER_RELEASED\n\\q\n")
        controller.close_input()
        for worker in workers:
            worker.close_input()
        for worker in workers:
            worker_codes.append(worker.wait(SESSION_TIMEOUT))
        controller_code = controller.wait(SESSION_TIMEOUT)
        if controller_code != 0 or not _marker_seen(controller, "PADDOCK_S06_CONTROLLER_RELEASED"):
            raise HarnessError("controller did not release barrier successfully")

        # Each transaction's only success marker follows COMMIT; failed sessions
        # are accepted only as SQL-level aborted worker transactions (not transport failures).
        commits = [_marker_seen(s, f"PADDOCK_S06_WORKER_{app}_COMMITTED")
                   for s, app in zip(workers, (ids.app_a, ids.app_b))]
        if commits not in ([True, False], [False, True]) or [code == 0 for code in worker_codes] != commits:
            raise HarnessError("worker exit codes and exact commit markers disagree")
        aborted_index = commits.index(False)
        abort_output = "".join(workers[aborted_index].output)
        allowed_sqlstates = ("40P01", "40001", "23514")
        sqlstates = parse_sqlstate_error_lines(abort_output)
        if len(sqlstates) != 1 or sqlstates[0] not in allowed_sqlstates:
            raise HarnessError("losing worker did not abort with an accepted transaction conflict")

        code, state_output = _run_one_shot(psql, final_state_sql(ids), PREFLIGHT_TIMEOUT, env)
        states = [line.strip() for line in state_output.splitlines() if "|" in line]
        expected_state = adjudicated_state(commits)
        if code != 0 or len(states) != 1 or states[0] != expected_state:
            raise HarnessError("final fixture state was mixed or invalid")
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        if controller is not None:
            controller.terminate()
        for session in workers:
            session.terminate()
        for session in workers:
            if session.process.poll() is None:
                raise HarnessError("worker remained alive before cleanup")
        if controller is not None and controller.process.poll() is None:
            raise HarnessError("controller remained alive before cleanup")
        cleanup_code, _ = _run_one_shot(psql, cleanup_sql(ids), CLEANUP_TIMEOUT, env)
        absence_error: BaseException | None = None
        try:
            _check_fixture_absent(psql, env, ids)
        except BaseException as exc:
            absence_error = exc
        if cleanup_code != 0:
            raise HarnessError("transactional fixture cleanup failed") from primary_error
        if absence_error is not None:
            raise HarnessError("fixture absence verification failed after cleanup") from absence_error


def _dry_test() -> None:
    """Pure offline assertions; never invokes psql or accesses the environment."""
    first, second = new_fixture_ids(), new_fixture_ids()
    assert len({first.bundle, first.scope, first.root, first.rollout, first.app_a, first.app_b,
                second.bundle, second.scope, second.root, second.rollout, second.app_a, second.app_b}) == 12
    assert "BEGIN READ ONLY" in preflight_sql(first)
    assert "current_database()" in preflight_sql(first)
    assert "server_version_num" in preflight_sql(first)
    assert "policy_scopes_frozen_rollback_ct" in preflight_sql(first)
    assert "policy_rollouts_frozen_rollback_ct" in preflight_sql(first)
    wa = worker_sql(first, first.app_a, "freeze")
    wb = worker_sql(first, first.app_b, "complete")
    assert "GET DIAGNOSTICS affected = ROW_COUNT" in wa and "affected <> 1" in wa
    assert "GET DIAGNOSTICS affected = ROW_COUNT" in wb and "affected <> 1" in wb
    assert f"PADDOCK_S06_WORKER_{first.app_a}_UPDATED" in wa
    assert f"PADDOCK_S06_WORKER_{first.app_b}_UPDATED" in wb
    assert "pg_advisory_xact_lock" in wa
    assert "ROLLING_BACK" in wb and "rollback_from = NULL" in wb
    assert "DELETE FROM raw.policy_bundles" in cleanup_sql(first)
    assert adjudicated_state([True, False]) == "FROZEN|ROLLING_BACK"
    assert adjudicated_state([False, True]) == "ACTIVE|COMPLETED"
    assert "PADDOCK_S06_CONTROLLER_RELEASED" in "\\echo PADDOCK_S06_CONTROLLER_RELEASED"
    assert [parse_sqlstate_error_lines(f"ERROR:  {state}: deadlock detected\n")
            for state in ("40P01", "40001", "23514")] == [["40P01"], ["40001"], ["23514"]]
    for rejected in ("DETAIL: ERROR: 40P01: not an error line\n",
                     "ERROR:  40P01: deadlock\nERROR:  23514: violation\n",
                     "ERROR: deadlock detected\n", "ERROR:  40P01; malformed\n"):
        assert parse_sqlstate_error_lines(rejected) != ["40P01"]
    for invalid in ([True, True], [False, False]):
        try:
            adjudicated_state(invalid)
        except HarnessError:
            pass
        else:
            raise AssertionError("invalid commit combination accepted")
    assert "<redacted-dsn>" in _redact("dsn-value", "dsn-value")
    synthetic_url = "postgresql://unit_user:unit_password@db.example.test:5433/unit_db?sslmode=require&connect_timeout=7"
    child_env = _libpq_environment(synthetic_url, {
        "PATH": "/usr/bin", DB_URL_ENV: synthetic_url, "PGHOST": "inherited-host", "PGOPTIONS": "unsafe"
    })
    assert DB_URL_ENV not in child_env and "PGOPTIONS" not in child_env
    assert child_env["PGHOST"] == "db.example.test" and child_env["PGPORT"] == "5433"
    assert child_env["PGDATABASE"] == "unit_db" and child_env["PGUSER"] == "unit_user"
    assert child_env["PGPASSWORD"] == "unit_password"
    assert child_env["PGSSLMODE"] == "require" and child_env["PGCONNECT_TIMEOUT"] == "7"
    command = _psql_command("psql")
    assert "-A" in command and "-t" in command
    assert synthetic_url not in command
    for invalid_url in ("not-a-uri", "postgresql:///no-host", "postgresql://u:p@h/db?bad_option=x"):
        try:
            _libpq_environment(invalid_url, {"PATH": "/usr/bin"})
        except HarnessError:
            pass
        else:
            raise AssertionError("invalid/unapproved PostgreSQL URI accepted")
    try:
        worker_sql(first, "unexpected", "freeze")
    except ValueError:
        pass
    else:
        raise AssertionError("invalid worker name accepted")


class HarnessUnitTests(unittest.TestCase):
    def test_sql_contracts_and_redaction(self) -> None:
        _dry_test()


def adjudicated_state(commits: list[bool]) -> str:
    if commits == [True, False]:
        return "FROZEN|ROLLING_BACK"
    if commits == [False, True]:
        return "ACTIVE|COMPLETED"
    raise HarnessError("expected exactly one committed worker")


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--dry-test":
        unittest.main(argv=[sys.argv[0]], exit=False)
    elif len(sys.argv) == 2 and sys.argv[1] == "--apply":
        try:
            run_race()
        except HarnessError as exc:
            print(f"S06 race harness failed: {exc}", file=sys.stderr)
            raise SystemExit(1)
        print("S06 two-session race completed; fixture cleanup verified.")
    else:
        print("Manual authorized invocation only: set PADDOCK_DB_URL and pass --apply; --dry-test is offline.", file=sys.stderr)
        raise SystemExit(2)

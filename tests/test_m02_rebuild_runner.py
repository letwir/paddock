from __future__ import annotations

from pathlib import Path
import re
import stat
import unittest


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "m02_s04_rebuild_test.sh"


class M02RebuildRunnerStaticTests(unittest.TestCase):
    """Offline source contracts: this suite reads runner text and never executes it."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.source = RUNNER.read_text(encoding="utf-8")
        cls.issue = (ROOT / "Issues.md").read_text(encoding="utf-8")

    def test_opt_in_and_preflight_gates(self) -> None:
        text = self.source
        dispatch = text.index('case "${1-}" in')
        run_gate = text.index('--run)', dispatch)
        effects = text.index('unset PADDOCK_DB_URL')
        self.assertLess(dispatch, effects)
        self.assertLess(run_gate, effects)
        self.assertIn('--help)', text)
        self.assertRegex(text, r"(?m)^  \'\'\) usage; exit 0 ;;$")
        self.assertIn('[[ $(id -u) -eq 0 ]]', text)
        self.assertIn('command -v "$tool"', text)
        for tool in ("initdb", "pg_ctl", "psql"):
            self.assertIn(tool, text)

    def test_runner_mode_is_owner_only_executable(self) -> None:
        mode = stat.S_IMODE(RUNNER.stat().st_mode)
        self.assertEqual(mode, 0o700, "runner must have mode 0700")

    def test_private_temp_cluster_and_fail_safe_cleanup(self) -> None:
        text = self.source
        self.assertIn('build_dir="$repo_root/.build"', text)
        self.assertIn('[[ ! -L "$build_dir" ]]', text)
        self.assertIn('"$repo_root/.build"', text)
        self.assertIn('mktemp -d "$build_dir/m02-s04.', text)
        self.assertIn('case "$work_dir" in "$build_dir"/m02-s04.*)', text)
        self.assertIn('case "$work_real" in "$build_real"/m02-s04.*)', text)
        cleanup = text[text.index('cleanup() {'):text.index('\n}\ntrap cleanup EXIT')]
        self.assertIn('pg_ctl -D "$pgdata" status', cleanup)
        self.assertIn('pg_ctl -D "$pgdata" -m fast -w stop', cleanup)
        self.assertIn('confirm_rc != 3', cleanup)
        self.assertIn('safe_to_remove=0', cleanup)
        self.assertRegex(cleanup, r'rm -rf -- "\$work_dir"')
        self.assertIn('"$work_dir" == "$build_dir"/m02-s04.*', cleanup)
        self.assertIn('"$(CDPATH= cd -- "$work_dir" && pwd -P)" == "$work_real"', cleanup)
        self.assertNotRegex(cleanup, r'rm\s+-rf\s+--\s+"\$pgdata"')

    def test_environment_scrub_local_only_connection_parameters(self) -> None:
        text = self.source
        unset = text[text.index('unset PADDOCK_DB_URL'):text.index('\n\nif [[ $(id -u)', text.index('unset PADDOCK_DB_URL'))]
        for name in (
            "PADDOCK_DB_URL", "PADDOCK_APP_DB_URL", "PADDOCK_ADMIN_DSN", "PGHOST",
            "PGHOSTADDR", "PGPORT", "PGUSER", "PGDATABASE", "PGPASSWORD", "PGPASSFILE",
            "PGOPTIONS", "PGAPPNAME", "PGCONNECT_TIMEOUT", "PGSSLMODE", "PGSSLROOTCERT",
            "PGSSLCERT", "PGSSLKEY", "PGCHANNELBINDING", "PGSERVICE", "PGSERVICEFILE",
        ):
            self.assertIn(name, unset)
        self.assertIn('--auth-local=trust --auth-host=reject', text)
        self.assertIn('"-F -h \'\' -k \'$socket_dir\' -p $port"', text)
        psql_lines = [line for line in text.splitlines() if re.search(r"(?:^|\s)psql(?:\s|$)", line) and "command -v" not in line and not line.lstrip().startswith("#")]
        self.assertGreaterEqual(len(psql_lines), 4)
        for line in psql_lines:
            self.assertIn('-h ', line)
            self.assertIn('-p ', line)
            self.assertIn('-U ', line)
            self.assertIn('-d ', line)
        self.assertIn('"$socket_dir"', text)
        self.assertIn('port=55439', text)

    def test_roles_database_and_alias_are_fixed_and_non_elevated(self) -> None:
        text = self.source
        self.assertIn("CREATE DATABASE paddock_test", text)
        self.assertIn("CREATE ROLE paddock_app LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS", text)
        self.assertIn("CREATE ROLE paddock_migrator LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS", text)
        self.assertIn('bootstrap-admin) dbrole=$bootstrap_user ;;', text)
        self.assertIn('*) fail "unsupported database role for $label" ;;', text)
        self.assertIn('bootstrap_user=$(id -un)', text)
        self.assertNotIn('PADDOCK_DB_URL"$', text)
        self.assertNotRegex(text, r'(?i)DROP\s+(DATABASE|SCHEMA)|CASCADE|reset')

    def test_m02_only_ordered_rebuild_and_down_assertions(self) -> None:
        text = self.source
        for migration in ("init.sql", "governance_constraints.sql", "governance_roles.sql", "governance_safety_constraints.sql", "governance_safety_constraints_down.sql", "down.sql"):
            self.assertIn(migration, text)
        self.assertNotRegex(text, r'(?i)M08|M09|governance_(?:budget|checkpoint)|budget_(?:up|down)')
        sequence = (
            "apply_sql up-init", "apply_sql up-governance-constraints",
            "apply_sql up-governance-roles", "apply_sql up-safety-constraints",
            "assert_rebuild_state first-up-assertions", "apply_sql down-safety",
            "apply_sql down-base", 'assert_sql down-assertions',
            "apply_sql reup-init", "apply_sql reup-governance-constraints",
            "apply_sql reup-governance-roles", "apply_sql reup-safety-constraints",
            "assert_rebuild_state reup-assertions",
        )
        offsets = [text.index(item) for item in sequence]
        self.assertEqual(offsets, sorted(offsets))
        down = text[text.index('assert_sql down-assertions'):text.index('apply_sql reup-init')]
        self.assertRegex(down, r"(?s)count\(\*\).*?<> 0")
        self.assertIn("to_regclass('raw.policy_rollouts_one_active_per_scope_uidx') IS NOT NULL", down)
        self.assertIn("policy_scopes_frozen_requires_live_rollout_ck", down)
        self.assertIn("policy_scopes_frozen_rollback_ct", down)
        self.assertIn("policy_rollouts_frozen_rollback_ct", down)
        self.assertIn("raw.enforce_frozen_scope_rollback()", down)
        self.assertIn("raw.prevent_frozen_rollout_leaving_rollback()", down)
        self.assertIn("nspname='raw'", down)
        self.assertIn("paddock_app", down)
        self.assertIn("paddock_migrator", down)

    def test_reup_bootstrap_and_migrator_roles_are_explicit(self) -> None:
        text = self.source
        self.assertIn("apply_sql reup-init bootstrap-admin init.sql", text)
        self.assertIn(
            "apply_sql reup-governance-constraints bootstrap-admin governance_constraints.sql",
            text,
        )
        self.assertIn(
            "apply_sql reup-governance-roles bootstrap-admin governance_roles.sql",
            text,
        )
        self.assertIn(
            "apply_sql reup-safety-constraints paddock_migrator governance_safety_constraints.sql",
            text,
        )
        self.assertIn(
            "apply_sql down-safety paddock_migrator governance_safety_constraints_down.sql",
            text,
        )

    def test_first_and_second_up_assert_expected_catalog_and_acl_contract(self) -> None:
        text = self.source
        state = text[text.index('assert_rebuild_state()'):text.index('\nassert_rebuild_state first-up-assertions')]
        for item in (
            "<> 11", "relowner=mig_oid", "policy_rollouts_one_active_per_scope_uidx",
            "policy_scopes_frozen_requires_live_rollout_ck", "policy_scopes_frozen_rollback_ct",
            "policy_rollouts_frozen_rollback_ct", "rolcanlogin", "rolsuper", "rolcreaterole",
            "rolcreatedb", "rolreplication", "rolbypassrls", "pg_auth_members",
            "has_schema_privilege(mig_oid,'raw','CREATE')",
            "has_schema_privilege(app_oid,'raw','USAGE')", "has_schema_privilege(app_oid,'raw','CREATE')",
            "has_table_privilege(app_oid,'raw.policy_bundles','SELECT')",
            "has_table_privilege(app_oid,'raw.policy_bundles','INSERT')",
            "has_table_privilege(app_oid,'raw.domain_events','SELECT')",
            "has_table_privilege(app_oid,'raw.domain_events','INSERT')",
            "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER",
            "a.grantee IN (0,app_oid)", "col.attacl",
        ):
            self.assertIn(item, state)
        self.assertIn('assert_rebuild_state first-up-assertions', text)
        self.assertIn('assert_rebuild_state reup-assertions', text)

    def test_output_exit_codes_and_no_secret_rendering(self) -> None:
        text = self.source
        self.assertIn('"$@" >"$output" 2>&1 || rc=$?', text)
        self.assertIn('cat -- "$output"', text)
        self.assertIn("printf '%s Exit Code: %s\\n'", text)
        self.assertIn('VERBOSITY=verbose', text)
        self.assertNotRegex(text, r'(?i)printf[^\n]*(?:PADDOCK_DB_URL|PGPASSWORD|password|dsn)')
        self.assertNotIn('echo "$PADDOCK_DB_URL"', text)
        self.assertIn('--file="$repo_root/sql/$file"', text)

    def test_issue_scope_explicitly_excludes_runtime_and_m08_m09(self) -> None:
        start = re.search(r"(?m)^- \[(?: |-|~|\*|x)\] `PDK-M02-S04`", self.issue)
        self.assertIsNotNone(start, "S04 Issue anchor with a valid state marker must exist")
        selected = self.issue[start.start():self.issue.index('- [x] `PDK-M02-S05`')]
        self.assertIn('temporary local PostgreSQL cluster', selected)
        self.assertIn('M08/M09 migrations and fixtures are OUT OF SCOPE', selected)
        self.assertIn('without separately recorded approval', selected)
        self.assertIn('runner_attempt_receipt', selected)
        self.assertIn('failed before role DDL/down', selected)
        self.assertIn('After fixing psql `\\\\error`, the user explicitly approved exactly one corrected run', selected)
        self.assertIn('runner_runtime_receipt', selected)
        self.assertIn('receipts/PDK-M02-S04/2026-10-17-runtime-verification.json', selected)
        self.assertIn('Existing populated `paddock_test` and retained M09 data were not targeted', selected)
        self.assertIn('No additional runner invocation is authorized', selected)
        self.assertIn('The current populated `paddock_test` must not be used for `down.sql`', selected)


if __name__ == "__main__":
    unittest.main()

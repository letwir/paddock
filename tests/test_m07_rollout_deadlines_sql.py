"""Offline source contracts only. Never imports a DB driver or executes SQL."""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
COLUMNS = (
    "monitoring_started_at", "monitoring_last_observed_at", "observation_deadline",
    "hold_since", "hold_deadline", "hold_used", "hold_budget", "extension_used",
    "extension_command_id", "extension_nonce", "monitoring_decision", "decision_at",
    "evidence_digest", "decision_revision",
)
LEGACY_SIGNATURE = "raw.safety_cas_rollout(text,text,bigint,text,text,text,text,bigint,bigint,bigint,text,text)"
BASE = (
    "rollout_id", "scope_id", "state", "target_root_id", "base_activation_epoch",
    "last_activation_epoch", "base_security_epoch", "rollback_from",
)
SIGNATURES = (
    "raw.safety_rollout_monitoring(text,text)",
    "raw.safety_cas_rollout(jsonb,jsonb)",
    "raw.safety_list_rollout_deadlines(integer)",
)


def body(sql, tag):
    marker = "$" + tag + "$"
    return sql.split(marker, 2)[1]


def assert_cas_fields(case, sql):
    cas = body(sql, "safety_cas_rollout_full")
    expected = re.search(r"is distinct from row\((.*?)\) then", cas, re.S).group(1)
    actual = re.search(r"if not found or row\((.*?)\)\s*is distinct", cas, re.S).group(1)
    case.assertEqual(re.findall(r"e\.(\w+)", expected), list(BASE + COLUMNS))
    case.assertEqual(re.findall(r"r\.(\w+)", actual), list(BASE + COLUMNS))
    update = cas.split("update raw.policy_rollouts set", 1)[1].split("where", 1)[0]
    case.assertEqual(set(re.findall(r"(\w+)\s*= n\.\w+", update)), set(BASE[2:] + COLUMNS))


class RolloutDeadlinesSQLTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.up = (ROOT / "sql/governance_rollout_deadlines.sql").read_text().lower()
        cls.down = (ROOT / "sql/governance_rollout_deadlines_down.sql").read_text().lower()
        cls.legacy = (ROOT / "sql/governance_rollout_api.sql").read_text().lower()
        cls.adapter = (ROOT / "internal/storage/postgres/rollout_governance_tx.go").read_text()
        cls.store = (ROOT / "internal/storage/postgres/rollout_deadline_store.go").read_text()

    def test_parentheses_and_dollar_body_delimiters(self):
        # Lexical sanity only, explicitly not a PostgreSQL parser/runtime claim.
        for source in (self.up, self.down):
            code = re.sub(r"--[^\n]*|'(?:[^']|'')*'", "", source)
            depth = 0
            for token in code:
                if token == "(":
                    depth += 1
                elif token == ")":
                    depth -= 1
                    self.assertGreaterEqual(depth, 0)
            self.assertEqual(depth, 0)
            tags = re.findall(r"\$[a-z_]+\$", code)
            for tag in set(tags):
                self.assertEqual(tags.count(tag), 2, tag)

    def test_guards_precede_ddl_and_no_effectful_runner(self):
        for source, ddl in ((self.up, "alter table"), (self.down, "drop function")):
            with self.subTest(ddl=ddl):
                self.assertIn("\\set on_error_stop on", source)
                for token in ("begin;", "current_database() <> 'paddock_test'", "current_user <> 'paddock_migrator'",
                              "session_user <> 'paddock_migrator'", "not rolsuper", "not rolcreaterole",
                              "not rolcreatedb", "not rolreplication", "not rolbypassrls", "pg_auth_members",
                              "r.rolname = 'paddock_migrator'", "has_any_column_privilege", "has_schema_privilege"):
                    self.assertIn(token, source)
                    self.assertLess(source.index(token), source.index(ddl))
                self.assertTrue(source.rstrip().endswith("commit;"))
                self.assertNotRegex(source, r"\b(?:cascade|drop database|drop schema|truncate)\s+(?:raw\.|paddock)")
                self.assertNotRegex(source, r"grant\s+(?:select|insert|update|delete|all)\s+on\s+(?:table|raw\.)")

    def test_additive_exact_schema_interval_and_revision(self):
        self.assertEqual(re.findall(r"add column (\w+)", self.up), list(COLUMNS))
        for col in ("hold_used", "hold_budget"):
            self.assertIn(f"add column {col} interval not null default interval '0'", self.up)
            for unit in ("year", "month", "day"):
                self.assertIn(f"extract({unit} from {col}) = 0", self.up)
        self.assertIn("add column decision_revision bigint not null default 0", self.up)
        self.assertIn("decision_revision >= 0", self.up)
        self.assertIn("check (coalesce((", self.up)
        self.assertIn("), false))", self.up)

    def test_no_fabrication_and_down_no_data_loss(self):
        legacy = body(self.up, "legacy_guard")
        self.assertIn("state in ('monitoring','completed') or rollback_from = 'monitoring'", legacy)
        self.assertIn("raise exception", legacy)
        self.assertLess(self.up.index("lock table raw.policy_rollouts in access exclusive mode"), self.up.index("do $legacy_guard$"))
        self.assertLess(self.up.index("do $legacy_guard$"), self.up.index("add column"))
        self.assertNotRegex(self.up[:self.up.index("create or replace function")], r"\b(?:update|insert into) raw\.policy_rollouts")
        down_guard = body(self.down, "down_data_guard")
        self.assertIn("where monitoring_started_at is not null", down_guard)
        self.assertIn("raise exception", down_guard)
        for sig in SIGNATURES:
            self.assertIn(f"drop function {sig};", self.down)
        self.assertEqual(re.findall(r"drop column (\w+)", self.down), list(reversed(COLUMNS)))
        self.assertNotIn("drop table", self.down)
        self.assertNotIn("safety_create_rollout", self.down)

    def test_invariants_include_complete_window_and_fresh_pass(self):
        for token in (
            "monitoring_started_at is null", "decision_revision = 0", "hold_used = interval '0'",
            "monitoring_last_observed_at >= monitoring_started_at", "hold_used <= hold_budget",
            "observation_deadline = monitoring_started_at + interval '168 hours' + hold_used",
            "hold_budget = interval '24 hours'", "hold_budget = interval '48 hours'",
            "extension_command_id = btrim(extension_command_id)", "extension_nonce = btrim(extension_nonce)",
            "decision_at >= monitoring_started_at", "decision_at <= monitoring_last_observed_at",
            "hold_deadline = hold_since + (hold_budget - hold_used)", "monitoring_last_observed_at < hold_deadline",
            "monitoring_decision = 'pass' and decision_at >= observation_deadline",
            "evidence_digest ~ '^[0-9a-f]{64}$'", "monitoring_decision = 'abort' and evidence_digest = ''",
        ):
            self.assertIn(token, self.up)
        for col in (COLUMNS[0:5] + ("decision_at",)):
            self.assertIn(f"{col} < timestamptz '10000-01-01 00:00:00+00'", self.up)

    def test_decision_revision_zero_only_without_decision(self):
        check = self.up.split("add constraint policy_rollouts_monitoring_window_ck", 1)[1].split("), false));", 1)[0]

        def assert_revision_branches(source):
            self.assertRegex(source, r"monitoring_decision = '' and decision_at is null and evidence_digest = '' and decision_revision = 0\)")
            self.assertRegex(source, r"monitoring_decision in \('pass','hold','fail','abort'\) and decision_revision >= 1 and decision_at is not null")

        assert_revision_branches(check)
        # Negative oracle: the former nonnegative-only constraint must fail.
        for replacement in ("", "and decision_revision >= 0 "):
            with self.subTest(replacement=replacement):
                with self.assertRaises(AssertionError):
                    assert_revision_branches(check.replace("and decision_revision >= 1 ", replacement, 1))

    def test_all_expected_fields_compared_and_all_mutable_fields_written(self):
        assert_cas_fields(self, self.up)
        comparison = re.search(r"is distinct from row\((.*?)\) then", self.up, re.S).group()
        # Negative oracle: dropping any single monitoring comparison/update fails.
        for col in COLUMNS:
            with self.subTest(column=col):
                with self.assertRaises(AssertionError):
                    changed = comparison.replace(f"e.{col}", "e.created_at", 1)
                    assert_cas_fields(self, self.up.replace(comparison, changed, 1))
                with self.assertRaises(AssertionError):
                    assert_cas_fields(self, self.up.replace(f"{col} = n.{col}", "updated_at = n.updated_at", 1))

    def test_full_target_snapshot_and_scope_rollout_lock_order(self):
        cas = body(self.up, "safety_cas_rollout_full")
        self.assertIn("actual_targets is distinct from $1->'targets'", cas)
        for col in ("root_id", "baseline_bundle_digest", "candidate_bundle_digest", "base_root_epoch"):
            self.assertIn(f"'{col}', t.{col}", cas)
        for tag in ("safety_cas_rollout_full", "safety_rollout_monitoring"):
            code = body(self.up, tag)
            self.assertLess(code.index("from raw.policy_scopes"), code.index("from raw.policy_rollouts"))
            self.assertIn("for update", code)
        self.assertIn("jsonb_populate_record(null::raw.policy_rollouts, $1)", cas)
        self.assertIn("jsonb_populate_record(null::raw.policy_rollouts, $2)", cas)
        self.assertIn("complete typed rollout snapshots required", cas)

    def test_listing_bounded_db_clock_deterministic_hints_without_locks(self):
        code = re.sub(r"--[^\n]*", "", body(self.up, "safety_list_rollout_deadlines"))
        for token in ("$1 is null or $1 < 1 or $1 > 1000", "db_now := clock_timestamp()", "r.state = 'monitoring'",
                      "r.monitoring_decision in ('fail','abort')", "r.monitoring_decision = 'hold' then r.hold_deadline",
                      "else r.observation_deadline end) <= db_now", "r.scope_id collate \"c\", r.rollout_id collate \"c\"", "limit $1"):
            self.assertIn(token, code)
        self.assertNotRegex(code, r"for\s+(?:update|share|no key update|key share)|skip locked|pg_advisory")
        self.assertIn("policy_rollouts_due_deadline_idx", self.up)
        self.assertIn("Scheduling hints only", (ROOT / "sql/governance_rollout_deadlines.sql").read_text())

    def test_definer_signatures_owner_session_path_and_exact_acls(self):
        for tag in ("safety_rollout_monitoring", "safety_cas_rollout_full", "safety_list_rollout_deadlines"):
            code = body(self.up, tag)
            self.assertIn("session_user <> 'paddock_app'", code)
        self.assertEqual(self.up.count("security definer set search_path = pg_catalog"), 4)
        for sig in SIGNATURES + (LEGACY_SIGNATURE,):
            self.assertIn(f"alter function {sig} owner to paddock_migrator;", self.up)
            self.assertIn(f"to_regprocedure('{sig}')", self.up)
        self.assertIn("acl.grantee <> p.proowner and acl.grantee <> 0", self.up)
        self.assertIn("revoke all on function %s from %i", self.up)
        compact = re.sub(r"\s+", " ", self.up)
        for verb, suffix in (("revoke all", "from public, paddock_app;"), ("grant execute", "to paddock_app;")):
            self.assertIn(f"{verb} on function {', '.join(SIGNATURES + (LEGACY_SIGNATURE,))} {suffix}", compact)
        for legacy in (body(self.legacy, "safety_cas_rollout"), body(self.up, "safety_cas_rollout_legacy")):
            self.assertIn("to_jsonb(r)->>'monitoring_started_at' is not null", legacy)
            self.assertLess(legacy.index("return false;"), legacy.index("update raw.policy_rollouts"))

    def test_adapter_and_port_transactor_source_contracts(self):
        self.assertIn("func (g *rolloutGovernanceTx) LockRollout", self.adapter)
        self.assertIn("delete(g.lockedRollouts, key)", self.adapter)
        self.assertIn("SELECT * FROM raw.safety_rollout_monitoring", self.adapter)
        self.assertIn("SELECT raw.safety_cas_rollout($1::jsonb, $2::jsonb)", self.adapter)
        for col in COLUMNS:
            self.assertIn('"' + col + '"', self.store)
        for token in ("i.Months != 0", "i.Days != 0", "math.MaxInt64/int64(time.Microsecond)", "d%time.Microsecond != 0", "Nanosecond()%1000 != 0", "port.ValidateRolloutDeadlineBatch(limit)", "defer rows.Close()", "rows.Err()", "ctx.Err()"):
            self.assertIn(token, self.store)
        transactor = (ROOT / "internal/storage/postgres/rollout_transactor.go").read_text()
        self.assertIn("WithinTransaction(ctx context.Context, fn func(port.GovernanceTx)", transactor)
        self.assertIn("return t.WithinRolloutTransaction(ctx", transactor)

    def test_integration_is_compile_only_opt_in_source(self):
        source = (ROOT / "internal/storage/postgres/rollout_deadline_integration_test.go").read_text()
        self.assertTrue(source.startswith("//go:build integration && paddock_test\n"))
        for token in ("MonitoringRoundtrip", "FullFieldStaleCAS", "DeadlineOrderingAndBounds", "ConcurrentReaperCleanup",
                      "context.WithTimeout", "t.Cleanup", "NewRolloutTransactor", "NewRolloutDeadlineStore", "NewRolloutDeadlineReaper", "reflect.TypeOf", "DecisionRevision"):
            self.assertIn(token, source)
        self.assertNotIn("func init(", source)
        self.assertNotIn("func TestMain(", source)


if __name__ == "__main__":
    unittest.main()

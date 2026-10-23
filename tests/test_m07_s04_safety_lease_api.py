"""Offline source contracts only: no driver, DB connection, or migration execution."""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SIGNATURE = "raw.safety_validate_current_lease(text,text,text,text,text,text,bigint)"


class SafetyLeaseAPITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.up = (ROOT / "sql/governance_safety_lease_api.sql").read_text().lower()
        cls.down = (ROOT / "sql/governance_safety_lease_api_down.sql").read_text().lower()
        cls.body = cls.up.split("$safety_validate_current_lease$")[1]
        cls.adapter = (ROOT / "internal/storage/postgres/safety_gate_lease.go").read_text()
        cls.gate = (ROOT / "internal/governance/application/safety_gate.go").read_text()
        cls.m06 = (ROOT / "internal/storage/postgres/integration_test.go").read_text()
        cls.shared = (ROOT / "internal/storage/postgres/rollout_application_integration_test.go").read_text()

    def test_guarded_additive_function_and_restricted_down(self):
        for source, ddl in ((self.up, "create function"), (self.down, "drop function")):
            with self.subTest(ddl=ddl):
                self.assertIn("\\set on_error_stop on", source)
                for guard in ("current_database() <> 'paddock_test'", "current_user <> 'paddock_migrator'",
                              "session_user <> 'paddock_migrator'", "not rolsuper", "not rolcreaterole",
                              "not rolcreatedb", "not rolreplication", "not rolbypassrls", "pg_auth_members"):
                    self.assertLess(source.index(guard), source.index(ddl))
                self.assertIn("begin;", source)
                self.assertTrue(source.rstrip().endswith("commit;"))
                self.assertNotRegex(source, r"\b(?:create|alter|drop)\s+(?:table|schema|role|index|trigger)\b")
                self.assertNotIn("cascade", source)
        self.assertEqual(len(re.findall(r"\bcreate function\b", self.up)), 1)
        self.assertIn(f"drop function {SIGNATURE} restrict;", self.down)
        self.assertIn("p.prosecdef", self.down)
        self.assertIn("r.rolname='paddock_migrator'", self.down)
        self.assertIn("existing safety and m08 lease apis required", self.up)

    def test_fixed_path_owner_and_app_execute_only(self):
        self.assertIn("language plpgsql security definer set search_path=pg_catalog", self.up)
        self.assertIn("if session_user <> 'paddock_app' then", self.body)
        self.assertIn("using errcode='42501'", self.body)
        self.assertIn(f"alter function {SIGNATURE} owner to paddock_migrator;", self.up)
        self.assertIn(f"revoke all on function {SIGNATURE} from public,paddock_app;", self.up)
        self.assertIn(f"grant execute on function {SIGNATURE} to paddock_app;", self.up)
        self.assertIn("a.grantee not in (p.proowner", self.up)
        self.assertIn("has_table_privilege", self.up)
        self.assertIn("has_any_column_privilege", self.up)
        grants = re.findall(r"\bgrant\s+[^;]+;", self.up)
        self.assertEqual(grants, [f"grant execute on function {SIGNATURE} to paddock_app;"])

    def test_work_order_then_lease_share_locks_then_fresh_clock(self):
        work = self.body.index("select w.* into work from raw.work_orders w")
        lease = self.body.index("select l.* into lease from raw.work_order_leases l")
        clock = self.body.index("return lease.expires_at > clock_timestamp()")
        self.assertLess(work, lease)
        self.assertLess(lease, clock)
        self.assertIn("for share;", self.body[work:lease])
        self.assertIn("for share;", self.body[lease:clock])
        self.assertEqual(self.body.count("for share;"), 2)
        self.assertNotIn("for update", self.body)
        self.assertNotRegex(self.body, r"\b(?:now|transaction_timestamp|statement_timestamp)\s*\(")

    def test_exact_tuple_scope_state_and_fail_closed(self):
        for check in ("work.root_id is distinct from p_root_id", "work.pull_state is distinct from 'running'",
                      "work.lease_epoch is distinct from p_lease_epoch", "s.scope_id=r.scope_id",
                      "r.root_id=p_root_id and s.scope_id=p_scope_id",
                      "row(lease.work_order_id,lease.attempt_id,lease.worker_id,lease.session_id,lease.lease_epoch)",
                      "is distinct from row(p_work_order_id,p_attempt_id,p_worker_id,p_session_id,p_lease_epoch)",
                      "a.work_order_id=p_work_order_id and a.attempt_id=p_attempt_id"):
            self.assertIn(check, self.body)
        self.assertEqual(self.body.count("if not found or"), 2)
        for parameter in ("scope_id", "root_id", "work_order_id", "attempt_id", "worker_id", "session_id", "lease_epoch"):
            self.assertIn(f"p_{parameter} is null", self.body)
        self.assertNotIn("return true", self.body)
        self.assertNotIn("exception when", self.body)
        self.assertNotRegex(self.body, r"\b(?:insert|update|delete|execute|perform)\b")
        self.assertNotIn("domain_events", self.body)
        self.assertNotIn("event_outbox", self.body)

    def test_adapter_and_gate_compose_one_typed_transaction(self):
        self.assertIn("SELECT raw.safety_validate_current_lease($1,$2,$3,$4,$5,$6,$7)", self.adapter)
        self.assertIn('fmt.Errorf("validate SafetyGate current lease: %w", err)', self.adapter)
        self.assertIn("return domain.ErrInvalidLease", self.adapter)
        self.assertIn("port.SafetyGateTransactor", self.gate)
        self.assertIn("WithinSafetyGateTransaction", self.gate)
        self.assertLess(self.gate.index("domain.Authorize(state, authorization.Grant)"),
                        self.gate.index("tx.ValidateCurrentLease(ctx, scopeID, authorization.Grant.Root, authorization.Lease)"))
        self.assertNotIn("port.Transactor", self.gate)

    def test_m06_preseed_app_api_and_rollback_cleanup_boundary(self):
        section = self.m06.split('t.Run("SafetyService receipts in rollback-only transaction"', 1)[1]
        section = section.split('\n\tt.Run(', 1)[0]
        self.assertLess(section.index("INSERT INTO raw.work_orders"), section.index("appPool.Begin(caseCtx)"))
        self.assertIn("pool.Exec(caseCtx, `INSERT INTO raw.work_orders", section)
        for api in ("configure_work_order_capabilities", "mark_work_order_pull_ready", "issue_work_order_lease"):
            self.assertIn(f"raw.{api}", section)
        self.assertIn("tx.QueryRow(caseCtx", section)
        self.assertIn("authorization(releasedGrant)", section)
        self.assertIn("authorization(preStopGrant)", section)
        self.assertIn("rollback left safety lease fixture rows", section)
        self.assertIn("DELETE FROM raw.work_orders WHERE work_order_id=$1 AND root_id=$2", section)
        self.assertNotRegex(section, r"INSERT INTO raw.work_order_(?:leases|attempts|pull_slots)")
        self.assertNotIn("appPool.Exec(caseCtx, `INSERT", section)

    def test_shared_fixture_real_leases_and_exact_cleanup(self):
        for api in ("configure_work_order_capabilities", "mark_work_order_pull_ready", "issue_work_order_lease"):
            self.assertIn(f"raw.{api}", self.shared)
        cleanup = self.shared.split("t.Cleanup(func() {", 1)[1]
        positions = []
        for relation in ("work_order_leases", "work_order_pull_slots", "work_order_attempts", "work_orders"):
            token = f"DELETE FROM raw.{relation} WHERE work_order_id=ANY($1::text[])"
            positions.append(cleanup.index(token))
        positions.append(cleanup.index("DELETE FROM raw.roots"))
        self.assertEqual(positions, sorted(positions))
        for assertion in ("pre-Rollback grant accepted", "current baseline/v1 grant", "expired lease",
                          "wrong attempt", "wrong worker", "wrong session", "stale lease epoch",
                          "other Root WorkOrder", "denials altered current lease"):
            self.assertIn(assertion, self.shared)
        self.assertNotRegex(self.shared, r"INSERT INTO raw.work_order_(?:leases|attempts|pull_slots)")

    def test_lexical_delimiters_only_not_a_postgres_parser(self):
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
                self.assertEqual(tags.count(tag), 2)


if __name__ == "__main__":
    unittest.main()

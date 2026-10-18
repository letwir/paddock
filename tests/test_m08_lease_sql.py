import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class LeaseSQLContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = (ROOT / "sql/governance_lease.sql").read_text()
        cls.down = (ROOT / "sql/governance_lease_down.sql").read_text()

    def test_guards_roles_and_owners(self):
        for fragment in (
            "current_database()<>'paddock_test'", "current_user<>'paddock_migrator'",
            "NOT rolsuper", "NOT rolcreaterole", "NOT rolcreatedb", "NOT rolreplication",
            "NOT rolbypassrls", "pg_catalog.pg_auth_members", "paddock_migrator must own S02 tables",
            "n.nspname='raw' AND r.rolname='paddock_migrator'",
            "pull_state='RUNNING'", "S02 RUNNING work or pull slots prevent lease migration",
            "OWNER TO paddock_migrator",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.sql)

    def test_schema_composite_attempt_reference_and_privileges(self):
        for fragment in (
            "lease_epoch bigint NOT NULL DEFAULT 0 CHECK (lease_epoch>=0)",
            "CREATE TABLE raw.work_order_leases", "work_order_id text PRIMARY KEY REFERENCES raw.work_orders",
            "FOREIGN KEY(attempt_id,work_order_id) REFERENCES raw.work_order_attempts(attempt_id,work_order_id)",
            "UNIQUE (attempt_id,work_order_id)", "issued_at timestamptz NOT NULL",
            "heartbeat_at timestamptz NOT NULL", "expires_at timestamptz NOT NULL",
            "REVOKE ALL ON TABLE raw.work_order_leases FROM PUBLIC,paddock_app",
            "REVOKE ALL (lease_epoch) ON TABLE raw.work_orders FROM PUBLIC,paddock_app",
            "REVOKE ALL ON FUNCTION", "FROM PUBLIC,paddock_app", "TO paddock_app",
            "raw.reserve_work_order_pull(text,text,text,text,jsonb,jsonb)",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.sql)
        for signature in (
            "raw.issue_work_order_lease(text,text,text,text,text,jsonb,jsonb,interval)",
            "raw.heartbeat_work_order_lease(text,text,text,text,bigint,interval)",
            "raw.reap_work_order_leases(integer)",
            "raw.complete_work_order_lease(text,text,text,text,bigint)",
        ):
            self.assertIn(signature, self.sql)
        self.assertEqual(self.sql.count("SECURITY DEFINER SET search_path=pg_catalog"), 4)

    def test_atomic_issue_validation_and_single_clock_sample(self):
        issue = self.sql.split("CREATE FUNCTION raw.issue_work_order_lease", 1)[1].split("CREATE FUNCTION raw.heartbeat", 1)[0]
        for fragment in ("FOR UPDATE", "st<>'READY'", "NOT isfinite(p_ttl)", "p_ttl<=interval '0'", "jsonb_array_elements(p_requirements)",
                         "jsonb_array_elements(p_evidence)", "raw.work_order_dependencies", "p.pull_state<>'DONE'",
                         "INSERT INTO raw.work_order_attempts", "INSERT INTO raw.work_order_pull_slots",
                          "INSERT INTO raw.work_order_leases", "lease_epoch=new_epoch", "w.lease_epoch+1"):
            self.assertIn(fragment, issue)
        self.assertEqual(issue.count("clock_timestamp()"), 1)
        self.assertIn("op_time+p_ttl", issue)

    def test_heartbeat_and_completion_fence_identity_expiry(self):
        heartbeat = self.sql.split("CREATE FUNCTION raw.heartbeat_work_order_lease", 1)[1].split("CREATE FUNCTION raw.reap", 1)[0]
        complete = self.sql.split("CREATE FUNCTION raw.complete_work_order_lease", 1)[1].split("ALTER FUNCTION", 1)[0]
        for block in (heartbeat, complete):
            for value in ("attempt_id=p_attempt_id", "worker_id=p_worker_id", "session_id=p_session_id", "lease_epoch=p_epoch", "expires_at>op_time"):
                self.assertIn(value, block)
            self.assertIn("FOR UPDATE", block)
            self.assertEqual(block.count("clock_timestamp()"), 1)
        self.assertIn("pull_state='DONE'", complete)
        self.assertIn("NOT isfinite(p_ttl)", heartbeat)
        self.assertIn("DELETE FROM raw.work_order_pull_slots", complete)
        self.assertIn("RETURN false", complete)

    def test_reaper_is_bounded_db_clocked_and_workorder_first(self):
        reap = self.sql.split("CREATE FUNCTION raw.reap_work_order_leases", 1)[1].split("CREATE FUNCTION raw.complete", 1)[0]
        self.assertIn("LIMIT p_batch_size FOR UPDATE OF w SKIP LOCKED", reap)
        self.assertIn("JOIN raw.work_order_leases l ON l.work_order_id=w.work_order_id", reap)
        self.assertIn("l.expires_at<=op_time", reap)
        self.assertIn("DELETE FROM raw.work_order_leases", reap)
        self.assertIn("DELETE FROM raw.work_order_pull_slots", reap)
        self.assertIn("pull_state='READY'", reap)
        self.assertEqual(reap.count("clock_timestamp()"), 1)

    def test_down_is_guarded_narrow_and_refuses_active_leases(self):
        for fragment in ("current_database()<>'paddock_test'", "current_user<>'paddock_migrator'",
                         "pg_catalog.pg_auth_members", "expected lease tables must be ordinary tables owned by paddock_migrator",
                         "IF EXISTS(SELECT 1 FROM raw.work_order_leases)", "DROP TABLE raw.work_order_leases",
                         "DROP COLUMN lease_epoch", "DROP CONSTRAINT work_order_attempts_attempt_order_uq"):
            self.assertIn(fragment, self.down)
        self.assertNotRegex(self.down, re.compile(r"\bCASCADE\b", re.IGNORECASE))
        self.assertNotIn("GRANT EXECUTE ON FUNCTION raw.reserve_work_order_pull", self.down)
        self.assertIn("lease_epoch<>0", self.down)
        self.assertIn("has_function_privilege('paddock_app','raw.reserve_work_order_pull(text,text,text,text,jsonb,jsonb)','EXECUTE')", self.down)
        self.assertIn("legacy lease-free reserve must remain non-executable by paddock_app", self.down)


if __name__ == "__main__":
    unittest.main()

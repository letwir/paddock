"""Offline M10-S01 SQL source checks; never connect to or migrate a database."""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SQL = (ROOT / "sql/governance_worker_enrollment.sql").read_text()
DOWN = (ROOT / "sql/governance_worker_enrollment_down.sql").read_text()
APIS = {
    "issue_worker_enrollment_challenge": "text,text,text,text,text",
    "read_worker_enrollment_challenge": "text",
    "consume_worker_enrollment": "text,text,text,text,text,bytea,text",
}


def body(name):
    match = re.search(r"CREATE FUNCTION raw\." + name + r"\(.*?\$\$(.*?)\$\$;", SQL, re.S)
    if not match:
        raise AssertionError("missing function " + name)
    return match.group(1)


class WorkerEnrollmentSQLTests(unittest.TestCase):
    def test_exact_app_only_fixed_path_capabilities(self):
        functions = re.findall(r"CREATE FUNCTION raw\.(\w+)\(.*?\$\$", SQL, re.S)
        self.assertEqual(set(functions), set(APIS))
        self.assertEqual(len(functions), 3)
        for name, args in APIS.items():
            header = re.search(r"CREATE FUNCTION raw\." + name + r"\(.*?\$\$", SQL, re.S).group()
            self.assertIn("SECURITY DEFINER SET search_path=pg_catalog", header)
            self.assertRegex(body(name), r"session_user(?:<>|=)'paddock_app'")
            signature = "raw." + name + "(" + args + ")"
            self.assertRegex(SQL, r"REVOKE ALL ON FUNCTION [^;]*" + re.escape(signature) + r"[^;]* FROM PUBLIC,paddock_app;")
            self.assertRegex(SQL, r"GRANT EXECUTE ON FUNCTION [^;]*" + re.escape(signature) + r"[^;]* TO paddock_app;")
        grants = re.findall(r"GRANT\s+.*?;", SQL, re.S | re.I)
        self.assertEqual(len(grants), 1)
        self.assertTrue(grants[0].startswith("GRANT EXECUTE ON FUNCTION "))
        self.assertNotRegex(grants[0], r"TO\s+PUBLIC")
        self.assertIn("REVOKE ALL ON TABLE raw.worker_enrollment_challenges,raw.worker_enrollment_workers FROM PUBLIC,paddock_app;", SQL)
        self.assertNotRegex(SQL, r"(?i)GRANT\s+(SELECT|INSERT|UPDATE|DELETE|ALL|TRUNCATE)")
        self.assertNotRegex(SQL, r"(?i)(EXECUTE\s+format|EXECUTE\s+'|CREATE EXTENSION)")
        self.assertIn("acl.grantee NOT IN (p.proowner,(SELECT oid FROM pg_catalog.pg_roles WHERE rolname='paddock_app'))", SQL)
        self.assertIn("RAISE EXCEPTION 'unexpected enrollment API grantee'", SQL)

    def test_single_locked_atomic_consume_and_key_uniqueness(self):
        consume = body("consume_worker_enrollment")
        lock = consume.index("FOR UPDATE")
        insert = consume.index("INSERT INTO raw.worker_enrollment_workers")
        update = consume.index("UPDATE raw.worker_enrollment_challenges")
        result = consume.index("RETURN QUERY")
        self.assertLess(lock, insert)
        self.assertLess(insert, update)
        self.assertLess(update, result)
        self.assertIn("ticket.consumed_worker_id IS NOT NULL", consume[:insert])
        for field, arg in (("nonce", "p_nonce"), ("fingerprint", "p_fingerprint"),
                           ("schema_version", "p_schema"), ("audience", "p_audience")):
            self.assertIn("ticket." + field + " IS DISTINCT FROM " + arg, consume[:insert])
        self.assertIn("c.challenge_id=p_id", consume[:lock])
        self.assertIn("encode(pg_catalog.sha256(p_key),'hex') IS DISTINCT FROM ticket.fingerprint", consume[:insert])
        self.assertIn("CONSTRAINT worker_enrollment_workers_fingerprint_key UNIQUE", SQL)
        self.assertIn("ON CONFLICT ON CONSTRAINT worker_enrollment_workers_fingerprint_key DO NOTHING", consume)
        self.assertIn("IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P1002'", consume[insert:update])
        self.assertNotIn("EXCEPTION WHEN", consume)
        self.assertNotRegex(consume, r"\b(COMMIT|ROLLBACK)\b")
        self.assertIn("c.consumed_worker_id IS NULL", body("read_worker_enrollment_challenge"))

    def test_q0_only_no_scope_trust_or_authority_writes(self):
        tables = re.findall(r"CREATE TABLE raw\.(\w+)", SQL)
        self.assertEqual(tables, ["worker_enrollment_workers", "worker_enrollment_challenges"])
        targets = set(re.findall(r"(?:INSERT INTO|UPDATE|DELETE FROM) raw\.(\w+)", SQL))
        self.assertEqual(targets, set(tables))
        self.assertIn("CHECK(quarantine_tier='Q0')", SQL)
        self.assertIn("CHECK(state='QUARANTINED')", SQL)
        self.assertIn("VALUES(p_worker,p_fingerprint,p_key,'Q0','QUARANTINED')", SQL)
        self.assertIn("worker_id ~ '^worker_[0-9a-f]{64}$'", SQL)
        self.assertIn("CHECK(fingerprint=encode(pg_catalog.sha256(public_key),'hex'))", SQL)
        self.assertIn("consumed_worker_id text COLLATE \"C\" UNIQUE REFERENCES raw.worker_enrollment_workers(worker_id)", SQL)
        self.assertIn("schema_version='paddock.worker-enrollment/1'", SQL)
        self.assertIn("audience='paddock.coordinator'", SQL)
        self.assertNotRegex(SQL, r"(?i)\b(expires_at|ttl_seconds|rate_limit|max_challenges|scope_id|authority_id|trust_level)\b")

    def test_guarded_migration_and_exact_non_cascading_down(self):
        for source in (SQL, DOWN):
            self.assertIn("\\set ON_ERROR_STOP on", source)
            self.assertIn("BEGIN;", source)
            self.assertTrue(source.rstrip().endswith("COMMIT;"))
            self.assertIn("current_database()<>'paddock_test'", source)
            self.assertIn("current_user<>'paddock_migrator'", source)
        self.assertIn("NOT rolbypassrls", SQL)
        self.assertIn("pg_catalog.pg_auth_members", SQL)
        self.assertIn("n.nspname='raw' AND r.rolname='paddock_migrator'", SQL)
        self.assertNotRegex(SQL, r"\bDROP\s")
        self.assertNotRegex(DOWN, r"(?im)^DROP .*CASCADE")
        self.assertEqual(re.findall(r"DROP TABLE raw\.(\w+);", DOWN), ["worker_enrollment_challenges", "worker_enrollment_workers"])
        for name, args in APIS.items():
            self.assertIn("DROP FUNCTION raw." + name + "(" + args + ");", DOWN)
        self.assertEqual(len(re.findall(r"(?m)^DROP ", DOWN)), 5)


if __name__ == "__main__":
    unittest.main()

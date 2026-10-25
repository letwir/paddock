"""Offline M04-S05 source contracts. Never connects to PostgreSQL or reads credentials."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ReceiptRetentionStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = (ROOT / "sql/governance_safety_api.sql").read_text()
        cls.port = (ROOT / "internal/governance/port/transaction.go").read_text()
        cls.adapter = (ROOT / "internal/storage/postgres/governance_tx.go").read_text()
        cls.response = (ROOT / "internal/governance/application/receipt_response.go").read_text()

    def body(self, name):
        match = re.search(rf"CREATE OR REPLACE FUNCTION raw\.{name}\(.*?\${name}\$;", self.sql, re.S)
        self.assertIsNotNone(match, name)
        return re.sub(r"--[^\n]*", "", match.group())

    def test_existing_fixed_path_app_only_api_without_schema_or_grant_expansion(self):
        for name in ("safety_lookup_command_receipt", "safety_insert_command_receipt"):
            body = self.body(name)
            self.assertIn("SECURITY DEFINER SET search_path = pg_catalog", body)
            self.assertIn("IF session_user <> 'paddock_app' THEN", body)
            self.assertRegex(self.sql, rf"ALTER FUNCTION raw\.{name}\([^;]*OWNER TO paddock_migrator;")
            self.assertRegex(self.sql, rf"REVOKE ALL ON FUNCTION[^;]*raw\.{name}\([^;]*FROM PUBLIC, paddock_app;")
            self.assertRegex(self.sql, rf"GRANT EXECUTE ON FUNCTION[^;]*raw\.{name}\([^;]*TO paddock_app;")
            self.assertIn("pg_advisory_xact_lock(pg_catalog.hashtextextended($1, 0))", body)
        self.assertIn("pg_catalog.aclexplode", self.sql)
        self.assertNotRegex(self.sql.lower(), r"\b(create|alter)\s+(table|schema)\b")
        self.assertNotRegex(self.sql.lower(), r"\bgrant\s+(select|insert|update|delete|all)\b")
        self.assertIn("FROM raw.safety_lookup_command_receipt($1)", self.adapter)
        rollout = (ROOT / "internal/storage/postgres/rollout_governance_tx.go").read_text()
        self.assertIn("type rolloutGovernanceTx struct{ *safetyGovernanceTx }", rollout)

    def test_requested_row_first_then_at_most_999_oldest_due_terminal_rows(self):
        body = self.body("safety_lookup_command_receipt")
        requested = body.index("UPDATE raw.command_receipts r")
        sweep = body.index("WITH due AS")
        returned = body.index("RETURN QUERY")
        self.assertLess(requested, sweep)
        self.assertLess(sweep, returned)
        first = body[requested:sweep]
        self.assertIn("r.command_id = $1", first)
        self.assertIn("r.status IN ('SUCCEEDED', 'REJECTED')", first)
        other = body[sweep:returned]
        self.assertIn("r.command_id <> $1", other)
        self.assertIn("r.status IN ('SUCCEEDED', 'REJECTED')", other)
        self.assertIn("ORDER BY r.completed_at, r.command_id", other)
        self.assertRegex(other, r"LIMIT 999\s+FOR UPDATE OF r SKIP LOCKED")
        self.assertEqual(len(re.findall(r"\bUPDATE raw\.command_receipts", body)), 2)
        self.assertEqual(len(re.findall(r"\bSET response_bytes = v_tombstone", body)), 2)
        self.assertNotRegex(body, r"\bSET\s+(status|request_digest|completed_at|command_id)\b")
        self.assertNotRegex(body, r"\bDELETE\b")
        self.assertEqual(1 + 999, 1000)

    def test_exact_half_open_365_day_db_wall_clock_boundary(self):
        body = self.body("safety_lookup_command_receipt")
        predicate = "pg_catalog.clock_timestamp() >= r.completed_at + interval '365 days'"
        self.assertEqual(body.count(predicate), 2)
        self.assertNotRegex(body.lower(), r"\b(now|transaction_timestamp|statement_timestamp)\s*\(")
        # Boundary fixture accompanies the source predicate check, not a claim
        # that Python executes PostgreSQL or verifies database locking behavior.
        completed = datetime(2024, 2, 29, tzinfo=timezone.utc)
        deadline = completed + timedelta(days=365)
        for offset, expired in ((-1, False), (0, True), (1, True)):
            with self.subTest(microseconds=offset):
                observed = deadline + timedelta(microseconds=offset)
                self.assertEqual(observed >= deadline, expired)
        self.assertEqual(deadline, datetime(2025, 2, 28, tzinfo=timezone.utc))

    def test_permanent_tombstone_has_identical_go_sql_bytes_and_safe_vocabulary(self):
        tombstone = re.search(r"const ReceiptTombstoneResponse = `([^`]+)`", self.port).group(1)
        self.assertIn(f"pg_catalog.convert_to('{tombstone}', 'UTF8')", self.sql)
        response = json.loads(tombstone)
        self.assertEqual(response["schema_version"], "paddock.command-response/1")
        self.assertEqual((response["kind"], response["code"]), ("EXPIRED", "RECEIPT_EXPIRED"))
        self.assertEqual(set(response), {"schema_version", "kind", "code", "detail"})
        lookup = self.body("safety_lookup_command_receipt")
        self.assertEqual(lookup.count("r.response_bytes <> v_tombstone"), 2)
        insert = self.body("safety_insert_command_receipt")
        self.assertIn("$3 NOT IN ('SUCCEEDED', 'REJECTED')", insert)
        self.assertIn("cannot insert a retention tombstone", insert)
        self.assertNotIn("ON CONFLICT", insert)
        self.assertIn("pg_catalog.clock_timestamp()", insert)
        self.assertIn("r.Expired = bytes.Equal(r.Response, []byte(port.ReceiptTombstoneResponse))", self.adapter)

    def test_shared_replay_checks_digest_before_expiry_and_commits_maintenance(self):
        replay = self.response[self.response.index("func commandReplay"):self.response.index("func withinReceiptCommand")]
        self.assertLess(replay.index("r.RequestDigest != d"), replay.index("if r.Expired"))
        self.assertIn("port.ErrReceiptExpired", replay)
        self.assertIn('r.Status == "REJECTED"', replay)
        for path in ("rollout_service.go", "safety.go"):
            app = (ROOT / "internal/governance/application" / path).read_text()
            self.assertIn("withinReceiptCommand(", app)
            self.assertNotIn("tx.LookupCommandReceipt(", app)
            self.assertIn("marshalCommandResult(result)", app)
        self.assertNotIn("Cause.Error()", self.response)
        self.assertNotIn("err.Error()", self.response)
        self.assertIn('case "TRANSIENT":', self.response)
        self.assertIn('case "UNKNOWN_COMMIT":', self.response)
        self.assertIn('Status: "REJECTED"', self.response)
        self.assertIn("if err != nil {\n\t\treturn err\n\t}\n\treturn outcome", self.response)

    def test_integration_source_is_explicitly_opted_in_and_never_applies_sql(self):
        source = (ROOT / "internal/storage/postgres/receipt_retention_integration_test.go").read_text()
        self.assertTrue(source.startswith("//go:build integration && paddock_test && receipt_retention"))
        self.assertIn('os.Getenv("PADDOCK_RECEIPT_RETENTION_INTEGRATION") != "1"', source)
        self.assertIn('db != "paddock_test"', source)
        self.assertNotRegex(source.lower(), r"\b(drop|truncate|create|alter)\s+(table|schema|database|function)\b")

    def test_integration_fixture_collision_and_cleanup_are_exact_prefix_only(self):
        source = (ROOT / "internal/storage/postgres/receipt_retention_integration_test.go").read_text()
        prefix = 'left(command_id,char_length($1))=$1'
        self.assertRegex(source, r'prefix := fmt\.Sprintf\("m04_s05_it_%d_", time\.Now\(\)\.UnixNano\(\)\)')
        migrator_close = source.index("t.Cleanup(migrator.Close)")
        app_close = source.index("t.Cleanup(app.Close)")
        preflight = source.index("var prefixCollisions int")
        cleanup_start = source.index("t.Cleanup(func()", preflight)
        first_insert = source.index('insert(beforeID, "SUCCEEDED", full)')
        cleanup_error = source.index("receipt retention fixture cleanup failed")
        cleanup_end = source.index("\n\t})", cleanup_start)
        cleanup = source[cleanup_start:cleanup_end]
        self.assertLess(migrator_close, app_close)
        self.assertLess(app_close, preflight)
        self.assertLess(preflight, cleanup_start)
        self.assertLess(cleanup_start, first_insert)
        self.assertEqual(source[preflight:cleanup_start].count(prefix), 1)
        self.assertIn("prefixCollisions != 0", source[preflight:cleanup_start])
        deletes = re.findall(r"`DELETE\s+FROM\s+raw\.[^`]+`", cleanup, re.I)
        self.assertEqual(deletes, [f"`DELETE FROM raw.command_receipts WHERE {prefix}`"])
        self.assertIn(f"SELECT count(*) FROM raw.command_receipts WHERE {prefix}", cleanup)
        self.assertIn("remaining != 0", cleanup)
        self.assertIn('t.Error("receipt retention fixture cleanup failed")', cleanup)
        self.assertIn("t.Errorf(\"receipt retention fixture cleanup readback", cleanup)
        self.assertLess(cleanup_error, first_insert)
        self.assertNotIn("DELETE FROM raw.command_receipts WHERE command_id LIKE", source)


if __name__ == "__main__":
    unittest.main()

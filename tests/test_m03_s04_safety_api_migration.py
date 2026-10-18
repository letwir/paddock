"""Offline contracts for the M03-S04 app-only Safety persistence API.

These checks inspect SQL/Go source only. They do not parse or execute SQL and
never connect to PostgreSQL.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "sql" / "governance_safety_api.sql"
ADAPTER = ROOT / "internal" / "storage" / "postgres" / "governance_tx.go"
DIRECT_ADAPTER = ROOT / "internal" / "storage" / "postgres" / "governance_tx_direct.go"
TRANSACTOR = ROOT / "internal" / "storage" / "postgres" / "transactor.go"
SAFETY_ADAPTER = ROOT / "internal" / "storage" / "postgres" / "safety_tx.go"

FUNCTIONS = (
    "safety_lock_scope",
    "safety_lock_rollout",
    "safety_lock_scope_roots",
    "safety_cas_scope",
    "safety_cas_root",
    "safety_cas_security_epoch",
    "safety_lookup_command_receipt",
    "safety_insert_command_receipt",
)


def go_function(source, name, receiver="safetyGovernanceTx"):
    match = re.search(rf"^func \(g \*{receiver}\) {name}\b.*?(?=^func |\Z)", source, re.M | re.S)
    if not match:
        raise AssertionError(f"Go adapter method {name} was not found")
    return match.group(0)


class SafetyAPIMigrationStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = MIGRATION.read_text(encoding="utf-8").lower()
        cls.go = ADAPTER.read_text(encoding="utf-8")
        cls.direct_go = DIRECT_ADAPTER.read_text(encoding="utf-8")
        cls.transactor = TRANSACTOR.read_text(encoding="utf-8")
        cls.safety_adapter = SAFETY_ADAPTER.read_text(encoding="utf-8")

    def test_one_guarded_transaction_and_no_table_privilege_broadening(self):
        self.assertEqual(len(re.findall(r"\bbegin\s*;", self.sql)), 1)
        self.assertEqual(len(re.findall(r"\bcommit\s*;", self.sql)), 1)
        self.assertRegex(self.sql, r"current_database\(\)\s*<>\s*'paddock_test'")
        self.assertRegex(self.sql, r"current_user\s*<>\s*'paddock_migrator'")
        self.assertRegex(self.sql, r"session_user\s*<>\s*'paddock_migrator'")
        self.assertRegex(self.sql, r"pg_catalog\.pg_auth_members")
        self.assertIsNotNone(re.search(r"n\.nspname\s*=\s*'raw'.*?r\.rolname\s*=\s*'paddock_migrator'", self.sql, re.S))
        self.assertNotRegex(self.sql, r"\balter\s+table\b")
        self.assertNotRegex(self.sql, r"\bgrant\b[^;]*\bon\s+(?:table\s+)?raw\.")
        self.assertNotRegex(self.sql, r"\bgrant\b[^;]*\bon\s+table\b")

    def test_all_functions_are_migrator_owned_fixed_path_and_app_session_guarded(self):
        for name in FUNCTIONS:
            with self.subTest(function=name):
                definition = re.search(
                    rf"create\s+or\s+replace\s+function\s+raw\.{name}\s*\(.*?\$[a-z0-9_]+\$;",
                    self.sql,
                    re.S,
                )
                self.assertIsNotNone(definition, f"missing function definition {name}")
                body = definition.group(0)
                self.assertRegex(body, r"security\s+definer")
                self.assertRegex(body, r"set\s+search_path\s*=\s*pg_catalog")
                self.assertRegex(body, r"if\s+session_user\s*<>\s*'paddock_app'")
                self.assertIsNotNone(re.search(rf"alter\s+function\s+raw\.{name}\s*\(.*?owner\s+to\s+paddock_migrator", self.sql, re.S))
                self.assertRegex(self.sql, rf"revoke\s+all\s+on\s+function[^;]*raw\.{name}\s*\(")
                self.assertRegex(self.sql, rf"grant\s+execute\s+on\s+function[^;]*raw\.{name}\s*\(")
        self.assertRegex(self.sql, r"from\s+public,\s*paddock_app")
        self.assertRegex(self.sql, r"to\s+paddock_app\s*;")

    def test_api_covers_only_required_scope_root_receipt_operations(self):
        for relation in ("policy_scopes", "roots", "policy_rollouts", "rollout_targets", "security_generation", "command_receipts"):
            with self.subTest(relation=relation):
                self.assertIn(f"raw.{relation}", self.sql)
        for required in (
            "for update",
            "for key share",
            "update raw.policy_scopes",
            "update raw.roots",
            "update raw.security_generation",
            "insert into raw.command_receipts",
            "return found",
        ):
            self.assertIn(required, self.sql)
        self.assertNotIn("raw.event_outbox", self.sql)
        self.assertNotIn("insert into raw.domain_events", self.sql)

    def test_go_adapter_routes_safety_db_access_through_functions(self):
        required_calls = {
            "LockScope": (("raw.safety_lock_scope($1)",), ("FROM raw.policy_scopes", "FROM raw.roots")),
            "LockRollout": (("raw.safety_lock_rollout($1, $2)",), ("FROM raw.policy_rollouts", "FROM raw.rollout_targets")),
            "ValidateTargets": (("raw.safety_lock_scope_roots($1)",), ("FROM raw.roots",)),
            "CompareAndSwapScope": (("raw.safety_cas_scope(", "raw.safety_cas_root("), ("UPDATE raw.",)),
            "CompareAndSwapSecurityEpoch": (("raw.safety_cas_security_epoch(",), ("UPDATE raw.security_generation",)),
            "LookupCommandReceipt": (("raw.safety_lookup_command_receipt($1)",), ("FROM raw.command_receipts",)),
            "InsertCommandReceipt": (("raw.safety_insert_command_receipt($1, $2, $3, $4)",), ("INSERT INTO raw.command_receipts",)),
        }
        for method, (functions, forbidden_sql) in required_calls.items():
            with self.subTest(method=method):
                body = go_function(self.go, method)
                for function_call in functions:
                    self.assertIn(function_call, body)
                for direct_sql in forbidden_sql:
                    self.assertNotIn(direct_sql, body)

    def test_event_append_stays_on_existing_atomic_function(self):
        adapter = (ROOT / "internal" / "storage" / "postgres" / "governance_tx.go").read_text(encoding="utf-8")
        body = re.search(r"^func \(g \*governanceTx\) AppendEvent\b.*?(?=^func |\Z)", adapter, re.M | re.S).group(0)
        self.assertIn("raw.append_domain_event_and_outbox($1, $2, $3, $4, $5, $6, $7)", body)
        self.assertNotIn("INSERT INTO raw.domain_events", body)
        self.assertNotIn("INSERT INTO raw.event_outbox", body)

    def test_function_only_adapter_is_selected_only_for_safety(self):
        self.assertIn("safetyAPI = true", self.safety_adapter)
        self.assertIn("if t.safetyAPI", self.transactor)
        self.assertIn("newSafetyGovernanceTx(tx)", self.transactor)
        for method, relation in (
            ("LockScope", "raw.policy_scopes"),
            ("LockRollout", "raw.policy_rollouts"),
            ("CompareAndSwapScope", "UPDATE raw.policy_scopes"),
            ("CompareAndSwapSecurityEpoch", "UPDATE raw.security_generation"),
        ):
            body = go_function(self.direct_go, method, receiver="governanceTx")
            self.assertIn(relation, body, f"generic adapter lost its existing {method} path")


if __name__ == "__main__":
    unittest.main()

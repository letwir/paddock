import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class BudgetStorageBytesMigrationTests(unittest.TestCase):
    def test_additive_guarded_constraint_migration(self):
        sql = (ROOT / "sql/governance_budget_storage_bytes.sql").read_text()
        normalized = " ".join(sql.split())
        self.assertIn("current_database()<>'paddock_test'", normalized)
        self.assertIn("current_user<>'paddock_migrator'", normalized)
        self.assertIn("rolname='paddock_migrator' AND NOT rolsuper", normalized)
        self.assertIn("rolname='paddock_app' AND NOT rolsuper", normalized)
        self.assertIn("n.nspname='raw' AND r.rolname='paddock_migrator'", normalized)
        self.assertIn("c.relname='budget_accounts' AND c.relkind='r' AND r.rolname='paddock_migrator'", normalized)
        self.assertIn("DROP CONSTRAINT budget_accounts_resource_kind_check", normalized)
        self.assertIn("ADD CONSTRAINT budget_accounts_resource_kind_check", normalized)
        self.assertIn("CHECK(resource_kind IN ('CURRENCY','TOKENS','COMPUTE','STORAGE_BYTES'))", normalized)
        self.assertIn("budget_accounts_storage_bytes_unit_check CHECK(resource_kind<>'STORAGE_BYTES' OR unit_code='byte')", normalized)
        self.assertIn("Apply only after sql/governance_budget.sql", sql)
        self.assertNotRegex(normalized, r"\bDROP\s+(TABLE|FUNCTION|SCHEMA|DATABASE)\b")
        self.assertNotRegex(normalized, r"\bCREATE\s+EXTENSION\b")
        self.assertNotIn("CASCADE", normalized.upper())
        self.assertNotIn("TRUNCATE", normalized.upper())


if __name__ == "__main__":
    unittest.main()

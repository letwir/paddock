import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
UP = ROOT / "sql" / "governance_work_orders.sql"
DOWN = ROOT / "sql" / "governance_work_orders_down.sql"


class WorkOrderSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.up = UP.read_text(encoding="utf-8")
        cls.down = DOWN.read_text(encoding="utf-8")

    def test_additive_migration_is_guarded_and_creates_all_history_tables(self):
        self.assertIn("BEGIN;", self.up)
        self.assertIn("COMMIT;", self.up)
        self.assertRegex(self.up, r"current_database\(\)\s*<>\s*'paddock_test'")
        self.assertIn("pg_catalog.pg_class", self.up)
        self.assertNotIn("to_regclass('raw.roots')", self.up)
        for table in ("work_orders", "work_order_dependencies", "work_order_attempts"):
            self.assertRegex(self.up, rf"CREATE TABLE raw\.{table}\s*\(")

    def test_ownership_and_dependency_edges_are_root_scoped(self):
        self.assertIn("UNIQUE (work_order_id, root_id)", self.up)
        for constraint in ("parent_id", "work_order_id", "depends_on_id"):
            self.assertIsNotNone(re.search(
                rf"FOREIGN KEY \({constraint}, root_id\).*?REFERENCES raw\.work_orders\(work_order_id, root_id\)",
                self.up, re.S,
            ))
        self.assertIn("work_orders_one_tree_root_per_root_uidx", self.up)

    def test_database_rejects_dependency_and_ownership_cycles(self):
        self.assertEqual(self.up.count("current_setting('transaction_isolation') <> 'read committed'"), 2)
        self.assertEqual(self.up.count("USING ERRCODE = 'serialization_failure'"), 2)
        self.assertIn("pg_advisory_xact_lock(hashtextextended(NEW.root_id, 0))", self.up)
        self.assertIn("WITH RECURSIVE reachable", self.up)
        self.assertIn("WITH RECURSIVE ancestors", self.up)
        self.assertIn("BEFORE UPDATE ON raw.work_order_dependencies", self.up)
        self.assertIn("work order dependencies are immutable", self.up)
        self.assertIn("work order identity and ownership are immutable", self.up)

    def test_attempt_history_has_positive_unique_sequence(self):
        self.assertIn("attempt_number bigint NOT NULL CHECK (attempt_number > 0)", self.up)
        self.assertIn("UNIQUE (work_order_id, attempt_number)", self.up)
        self.assertIn("BEFORE UPDATE ON raw.work_order_attempts", self.up)
        self.assertIn("work order attempts are immutable history", self.up)

    def test_down_migration_is_scoped_and_never_drops_database_or_schema(self):
        self.assertRegex(self.down, r"current_database\(\)\s*<>\s*'paddock_test'")
        self.assertNotRegex(self.down, r"DROP\s+(DATABASE|SCHEMA)\b|CASCADE")
        for table in ("work_order_attempts", "work_order_dependencies", "work_orders"):
            self.assertIn(f"DROP TABLE raw.{table};", self.down)


if __name__ == "__main__":
    unittest.main()

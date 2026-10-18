"""Offline structural checks for the additive M02 governance constraints."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
INIT_SQL = (ROOT / "sql" / "init.sql").read_text(encoding="utf-8")
MIGRATION = (ROOT / "sql" / "governance_constraints.sql").read_text(encoding="utf-8")


class GovernanceConstraintMigrationTests(unittest.TestCase):
    def test_guarded_transactional_additive_migration(self):
        sql = MIGRATION.lower()
        self.assertRegex(sql, r"\bbegin\s*;")
        self.assertRegex(sql, r"\bcommit\s*;")
        self.assertRegex(sql, r"current_database\(\)\s*<>\s*'paddock_test'")
        self.assertIn("to_regclass('raw.policy_rollouts')", sql)
        self.assertIn("create unique index if not exists", sql)
        self.assertNotRegex(sql, r"\bdrop\s+(database|schema|table)\b")
        self.assertNotRegex(sql, r"\bcreate\s+(database|schema|table)\b")

    def test_active_unique_index_predicate_is_exact(self):
        match = re.search(
            r"create\s+unique\s+index\s+if\s+not\s+exists\s+"
            r"policy_rollouts_one_active_per_scope_uidx\s+on\s+"
            r"raw\.policy_rollouts\s*\(\s*scope_id\s*\)\s*"
            r"where\s+state\s+in\s*\(([^)]*)\)",
            MIGRATION,
            re.IGNORECASE | re.DOTALL,
        )
        self.assertIsNotNone(match, "missing scope partial unique index")
        states = re.findall(r"'([^']+)'", match.group(1))
        self.assertEqual(set(states), {"CANARY", "MONITORING", "ROLLING_BACK"})
        self.assertEqual(len(states), 3, "active state list must contain no duplicates")

        # Positive/negative membership assertions express the intended index behavior:
        # active states conflict per scope; shadow and terminal states are outside it.
        indexed = set(states)
        for state in ("CANARY", "MONITORING", "ROLLING_BACK"):
            self.assertIn(state, indexed)
        for state in ("SHADOW", "COMPLETED", "ROLLED_BACK", "SAFE_STOPPED"):
            self.assertNotIn(state, indexed)
        # HOLD is a monitoring decision, not a persisted state; the rollout
        # remains MONITORING and thus keeps its active slot.
        self.assertNotIn("HOLD", indexed)
        self.assertNotRegex(INIT_SQL, r"\bstate\s+[^,;]*\bHOLD\b")
        self.assertIn("MONITORING", indexed)

    def test_base_schema_has_required_scope_composite_foreign_keys(self):
        sql = re.sub(r"--[^\n]*", " ", INIT_SQL)
        compact = re.sub(r"\s+", " ", sql).lower()
        required = (
            r"foreign key\s*\(\s*rollout_id\s*,\s*scope_id\s*\)\s*"
            r"references\s+raw\.policy_rollouts\s*\(\s*rollout_id\s*,\s*scope_id\s*\)",
            r"foreign key\s*\(\s*root_id\s*,\s*scope_id\s*\)\s*"
            r"references\s+raw\.roots\s*\(\s*root_id\s*,\s*scope_id\s*\)",
        )
        for fk in required:
            with self.subTest(fk=fk):
                self.assertRegex(compact, fk)


if __name__ == "__main__":
    unittest.main()

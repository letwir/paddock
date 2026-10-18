"""Offline structural checks for the S06 safety-mode migration.

These tests inspect migration text only; they never connect to a DB.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
UP_PATH = ROOT / "sql" / "governance_safety_constraints.sql"
DOWN_PATH = ROOT / "sql" / "governance_safety_constraints_down.sql"
INIT_PATH = ROOT / "sql" / "init.sql"


def uncomment(sql):
    return re.sub(r"--[^\n]*|/\*.*?\*/", " ", sql, flags=re.S)


class SafetyConstraintMigrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.up_raw = UP_PATH.read_text(encoding="utf-8")
        cls.down_raw = DOWN_PATH.read_text(encoding="utf-8")
        cls.init_raw = INIT_PATH.read_text(encoding="utf-8")
        cls.up = uncomment(cls.up_raw).lower()
        cls.down = uncomment(cls.down_raw).lower()
        cls.init = uncomment(cls.init_raw).lower()

    def test_up_and_down_are_guarded_transactional_and_non_destructive(self):
        for label, sql in (("up", self.up), ("down", self.down)):
            with self.subTest(migration=label):
                self.assertRegex(sql, r"\bbegin\s*;")
                self.assertRegex(sql, r"\bcommit\s*;")
                self.assertIn("current_database()", sql)
                self.assertRegex(sql, r"current_database\s*\(\s*\)\s*<>\s*'paddock_test'")
                self.assertNotRegex(sql, r"\bdrop\s+(?:database|schema)\b")
                self.assertNotRegex(sql, r"\bdrop\s+table\b")
                self.assertNotRegex(sql, r"\bcreate\s+(?:database|schema|table)\b")
                self.assertNotRegex(sql, r"\bcascade\b")
        self.assertRegex(self.up, r"to_regclass\s*\(\s*'raw\.policy_scopes'\s*\)")
        self.assertRegex(self.up, r"to_regclass\s*\(\s*'raw\.policy_rollouts'\s*\)")

    def test_frozen_requires_immediate_live_id_and_deferred_same_scope_rollback(self):
        self.assertRegex(self.up, r"check\s*\(\s*mode\s*<>\s*'frozen'\s+or\s+live_rollout_id\s+is\s+not\s+null\s*\)")
        self.assertRegex(self.up, r"create\s+constraint\s+trigger\s+policy_scopes_frozen_rollback_ct")
        self.assertRegex(self.up, r"create\s+constraint\s+trigger\s+policy_rollouts_frozen_rollback_ct")
        self.assertEqual(len(re.findall(r"create\s+constraint\s+trigger", self.up)), 2)
        self.assertRegex(self.up, r"deferrable\s+initially\s+deferred")
        self.assertIn("rolling_back", self.up)
        self.assertRegex(self.up, r"rollout\.scope_id\s*=\s*new\.scope_id")
        self.assertRegex(self.up, r"rollout\.rollout_id\s*=\s*current_rollout_id")

    def test_both_deferred_triggers_lock_scope_and_rollout_rows_for_same_scope(self):
        """Deferred checks serialize cross-row reads against concurrent writers."""
        functions = {
            name: body
            for name, body in re.findall(
                r"create\s+(?:or\s+replace\s+)?function\s+"
                r"([a-z_][a-z0-9_.]*)\s*\([^)]*\).*?\bas\s+\$\$(.*?)\$\$",
                self.up,
                flags=re.S,
            )
        }
        expected = {
            "raw.enforce_frozen_scope_rollback": r"new\.scope_id",
            "raw.prevent_frozen_rollout_leaving_rollback": r"old\.scope_id",
        }
        for name, scope_key in expected.items():
            with self.subTest(trigger_function=name):
                self.assertIn(name, functions)
                body = functions[name]
                for relation in ("raw.policy_scopes", "raw.policy_rollouts"):
                    lock_query = re.search(
                        rf"(?:select|perform)\b(?:(?!;).)*?\bfrom\s+{re.escape(relation)}\b"
                        rf"(?:(?!;).)*?\bwhere\b(?:(?!;).)*?"
                        rf"(?:scope_id\s*=\s*{scope_key}|{scope_key}\s*=\s*scope_id)"
                        rf"(?:(?!;).)*?\bfor\s+update\b",
                        body,
                        flags=re.S,
                    )
                    self.assertIsNotNone(
                        lock_query,
                        f"{name} must FOR UPDATE-lock {relation} using {scope_key}",
                    )

    def test_lock_abort_is_fail_closed_and_requires_whole_transaction_retry(self):
        # Deadlocks/serialization failures are transaction aborts, never evidence
        # that the invariant passed. Retry must rerun the complete transaction.
        comments = " ".join(re.findall(r"--([^\n]*)", self.up_raw)).lower()
        self.assertRegex(comments, r"40p01.{0,40}deadlock")
        self.assertRegex(comments, r"40001.{0,40}serialization failure")
        self.assertRegex(comments, r"abort the transaction")
        self.assertRegex(comments, r"whole transaction")
        self.assertRegex(comments, r"retry")
        self.assertRegex(comments, r"no automatic retry")
        self.assertRegex(comments, r"neither error means commit succeeded|no automatic retry or commit success")

    def test_safe_stopped_semantics_are_defined_by_init_schema(self):
        # D-017 represents SAFE_STOPPED by the embedded deny-all baseline; it
        # is not a new migration token/column. init.sql permits NULL baseline
        # only in SAFE_STOPPED via its existing mode and nullable-baseline checks.
        self.assertRegex(self.init, r"check\s*\(\s*mode\s+in\s*\([^)]*'safe_stopped'[^)]*\)\s*\)")
        self.assertRegex(self.init, r"check\s*\(\s*\(\s*mode\s*=\s*'safe_stopped'\s*\)\s+or\s+baseline_bundle_digest\s+is\s+not\s+null\s*\)")
        self.assertNotRegex(self.up, r"add\s+(?:column\s+)?safe_baseline\b")
        self.assertNotRegex(self.up, r"safe_stopped")

    def test_down_removes_exact_objects_without_cascade(self):
        constraints = re.findall(r"add\s+constraint\s+([a-z_][a-z0-9_]*)", self.up)
        triggers = re.findall(r"create\s+constraint\s+trigger\s+([a-z_][a-z0-9_]*)", self.up)
        functions = re.findall(r"create\s+(?:or\s+replace\s+)?function\s+([a-z_][a-z0-9_.]*)", self.up)
        self.assertTrue(constraints, "up migration must install named check constraint(s)")
        self.assertEqual(set(triggers), {"policy_scopes_frozen_rollback_ct", "policy_rollouts_frozen_rollback_ct"})
        self.assertTrue(functions, "up migration must install named trigger function(s)")
        for name in constraints:
            self.assertRegex(self.down, rf"drop\s+constraint\s+(?:if\s+exists\s+)?{re.escape(name)}\b")
        for name in triggers:
            self.assertRegex(self.down, rf"drop\s+trigger\s+(?:if\s+exists\s+)?{re.escape(name)}\b")
        for name in functions:
            self.assertRegex(self.down, rf"drop\s+function\s+(?:if\s+exists\s+)?{re.escape(name)}\b")


if __name__ == "__main__":
    unittest.main()

"""Offline contract tests for the initial raw-schema migration."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
INIT_SQL = ROOT / "sql" / "init.sql"
DOWN_SQL = ROOT / "sql" / "down.sql"
EXPECTED_TABLES = (
    "policy_bundles",
    "policy_scopes",
    "roots",
    "policy_rollouts",
    "rollout_targets",
    "governance_approvals",
    "command_receipts",
    "domain_events",
    "event_outbox",
    "event_inbox",
    "security_generation",
)


def sql_without_comments(sql: str) -> str:
    """Remove SQL comments while preserving quoted text and statement structure."""
    # Comments within string/dollar-quoted bodies are data, not comments. The
    # migration currently uses a DO $$ block, so support dollar quotes too.
    token = re.compile(
        r"'(?:''|\\.|[^'])*'"
        r'|"(?:""|\\.|[^"])*"'
        r"|\$[A-Za-z_][A-Za-z_0-9]*\$[\s\S]*?\$[A-Za-z_][A-Za-z_0-9]*\$"
        r"|\$\$[\s\S]*?\$\$"
        r"|--[^\r\n]*"
        r"|/\*[\s\S]*?\*/"
    )

    def replace(match: re.Match[str]) -> str:
        text = match.group(0)
        return text if text.startswith(("'", '"', "$")) else " "

    return token.sub(replace, sql)


def table_statements(sql: str, verb: str) -> list[str]:
    clean = sql_without_comments(sql)
    pattern = re.compile(
        rf"\b{verb}\s+TABLE\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?"
        r"(?:raw\s*\.\s*)?([a-z_][a-z_0-9]*)\b",
        re.IGNORECASE,
    )
    return [match.group(1).lower() for match in pattern.finditer(clean)]


class InitialMigrationContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.up = INIT_SQL.read_text(encoding="utf-8")
        cls.down = DOWN_SQL.read_text(encoding="utf-8")
        cls.clean_up = sql_without_comments(cls.up)
        cls.clean_down = sql_without_comments(cls.down)

    def test_up_creates_exact_expected_raw_tables(self) -> None:
        creates = table_statements(self.up, "CREATE")
        self.assertCountEqual(creates, EXPECTED_TABLES)
        self.assertEqual(len(creates), len(EXPECTED_TABLES), "each table should be created once")
        self.assertRegex(self.clean_up, r"(?is)\bCREATE\s+TABLE\s+raw\s*\.\s*\w+")

    def test_down_drops_exact_expected_raw_tables(self) -> None:
        drops = table_statements(self.down, "DROP")
        self.assertCountEqual(drops, EXPECTED_TABLES)
        self.assertEqual(len(drops), len(EXPECTED_TABLES), "each table should be dropped once")

    def test_down_order_is_reverse_safe_for_foreign_keys(self) -> None:
        drops = table_statements(self.down, "DROP")
        positions = {name: drops.index(name) for name in drops}
        # Child must be dropped before its referenced parent.
        dependencies = (
            ("event_outbox", "domain_events"),
            ("rollout_targets", "policy_bundles"),
            ("rollout_targets", "policy_rollouts"),
            ("rollout_targets", "roots"),
            ("policy_rollouts", "roots"),
            ("policy_rollouts", "policy_scopes"),
            ("roots", "policy_scopes"),
            ("roots", "policy_bundles"),
            ("governance_approvals", "policy_scopes"),
            ("policy_scopes", "policy_bundles"),
        )
        for child, parent in dependencies:
            with self.subTest(child=child, parent=parent):
                self.assertLess(positions[child], positions[parent])

        live_fk = re.search(
            r"(?is)\bALTER\s+TABLE\s+raw\s*\.\s*policy_scopes\b"
            r"[\s\S]{0,500}?\bFOREIGN\s+KEY\s*\(\s*live_rollout_id\s*,\s*scope_id\s*\)",
            self.clean_up,
        )
        if live_fk:
            # Either explicitly remove that FK first, or drop rollouts before
            # scopes so the referenced relation is gone before the FK owner.
            drops = table_statements(self.down, "DROP")
            self.assertLess(drops.index("policy_rollouts"), drops.index("policy_scopes"))
            self.assertRegex(
                self.clean_down,
                r"(?is)\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?raw\s*\.\s*policy_scopes"
                r"[\s\S]{0,300}?\bDROP\s+CONSTRAINT\b[^;]*live_rollout",
            ) if "live_rollout" in self.clean_down.lower() else self.assertLess(
                drops.index("policy_rollouts"), drops.index("policy_scopes")
            )

    def test_down_is_narrow_and_non_cascading(self) -> None:
        self.assertNotRegex(self.clean_down, r"(?i)\bCASCADE\b")
        self.assertNotRegex(self.clean_down, r"(?i)\bDROP\s+(?:SCHEMA|DATABASE)\b")
        self.assertRegex(self.clean_down, r"(?im)^\s*\\set\s+ON_ERROR_STOP\s+on\s*$")
        self.assertRegex(self.clean_down, r"(?i)\bBEGIN\s*;")
        self.assertRegex(self.clean_down, r"(?i)\bCOMMIT\s*;")

        drop_matches = list(
            re.finditer(
                r"(?i)\bDROP\s+TABLE\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?"
                r"([^;]+);",
                self.clean_down,
            )
        )
        self.assertTrue(drop_matches, "down migration must contain table drops")
        for match in drop_matches:
            with self.subTest(drop=match.group(0)):
                self.assertRegex(match.group(1), r"(?i)^\s*raw\s*\.\s*[a-z_][a-z_0-9]*\s*$")

        guard = re.search(
            r"(?is)\bIF\s+current_database\s*\(\s*\)\s*<>\s*'paddock_test'",
            self.clean_down,
        )
        self.assertIsNotNone(guard, "down migration must guard the target database")
        assert guard is not None
        destructive = re.search(r"(?i)\b(?:ALTER|DROP)\b", self.clean_down)
        self.assertIsNotNone(destructive, "down migration must contain destructive DDL")
        assert destructive is not None
        self.assertLess(guard.start(), destructive.start(), "target guard must precede destructive DDL")

        alters = re.findall(r"(?is)\bALTER\s+TABLE\b[^;]*;", self.clean_down)
        self.assertEqual(
            [re.sub(r"\s+", " ", alter).strip().lower() for alter in alters],
            ["alter table if exists raw.policy_scopes drop constraint if exists policy_scopes_live_rollout_scope_fk;"],
            "only the expected circular-FK constraint removal is allowed",
        )

    def test_up_has_database_guard_transaction_and_all_tables(self) -> None:
        self.assertRegex(
            self.clean_up,
            r"(?is)\bIF\s+current_database\s*\(\s*\)\s*<>\s*'paddock_test'",
        )
        self.assertRegex(self.clean_up, r"(?i)\bBEGIN\s*;")
        self.assertRegex(self.clean_up, r"(?i)\bCOMMIT\s*;")
        for table in EXPECTED_TABLES:
            with self.subTest(table=table):
                self.assertRegex(
                    self.clean_up,
                    rf"(?i)\bCREATE\s+TABLE\s+raw\s*\.\s*{re.escape(table)}\b",
                )

    def test_domain_events_store_schema_version_as_envelope_column(self) -> None:
        match = re.search(
            r"(?is)\bCREATE\s+TABLE\s+raw\s*\.\s*domain_events\s*\(([^;]+)\)",
            self.clean_up,
        )
        self.assertIsNotNone(match)
        assert match is not None
        self.assertRegex(match.group(1), r"(?i)\bschema_version\s+text\s+NOT\s+NULL")


if __name__ == "__main__":
    unittest.main()

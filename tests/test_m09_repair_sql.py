"""Static contract tests for the guarded, combined M09 S02/S03 repair."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
REPAIR_PATH = ROOT / "sql/governance_m09_s02_s03_repair.sql"
S02_PATH = ROOT / "sql/governance_spawn_policy.sql"
S03_PATH = ROOT / "sql/governance_checkpoints.sql"

# D_worker=EASY: inspected this test and repair SQL guard; the change is an
# isolated single-file assertion using the existing normalized SQL, not SQL or DB work.


def _read_required(path: Path) -> str:
    if not path.is_file():
        raise AssertionError(f"required SQL source is missing: {path.relative_to(ROOT)}")
    return path.read_text(encoding="utf-8")


def _function_declaration(sql: str, signature: str) -> tuple[str, str]:
    """Return declaration header and dollar-quoted body for one exact signature."""
    declaration = re.compile(
        rf"CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+{re.escape(signature)}"
        r"(?=\s)",
        re.IGNORECASE,
    )
    matches = list(declaration.finditer(sql))
    if len(matches) != 1:
        raise AssertionError(
            f"expected exactly one CREATE [OR REPLACE] FUNCTION for {signature}; found {len(matches)}"
        )

    # Preserve the complete declaration metadata separately from the body.
    header = re.compile(
        r"\s+RETURNS\b[\s\S]*?\bAS\s+\$([A-Za-z_][A-Za-z_0-9]*)?\$",
        re.IGNORECASE,
    ).match(sql, matches[0].end())
    if header is None:
        raise AssertionError(f"expected dollar-quoted body for {signature}")
    delimiter = header.group(1) or ""
    body = re.compile(rf"([\s\S]*?)\${re.escape(delimiter)}\$\s*;").match(
        sql, header.end()
    )
    if body is None:
        raise AssertionError(f"expected dollar-quoted body for {signature}")
    return sql[matches[0].start():header.end()], body.group(1)


def _function_body(sql: str, signature: str) -> str:
    """Return a dollar-quoted function body, requiring one exact declaration."""
    return _function_declaration(sql, signature)[1]


class M09RepairSQLTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repair = _read_required(REPAIR_PATH)
        cls.s02 = _read_required(S02_PATH)
        cls.s03 = _read_required(S03_PATH)
        cls.normalized = " ".join(cls.repair.split())

    def test_single_guarded_transaction_and_exact_isolated_roles(self):
        sql = self.normalized
        self.assertRegex(sql, r"(?is)^.*\bBEGIN\s*;.*\bCOMMIT\s*;\s*$")
        self.assertEqual(len(re.findall(r"\bBEGIN\s*;", sql, re.I)), 1)
        self.assertEqual(len(re.findall(r"\bCOMMIT\s*;", sql, re.I)), 1)
        self.assertIn("current_database()<>'paddock_test'", sql)
        self.assertIn("current_user<>'paddock_migrator'", sql)
        self.assertIn("rolname='paddock_app' AND NOT rolsuper", sql)
        self.assertIn("rolname='paddock_migrator' AND NOT rolsuper", sql)
        for elevated in ("rolcreatedb", "rolcreaterole", "rolreplication", "rolbypassrls"):
            self.assertRegex(sql, rf"rolname='paddock_(?:app|migrator)' AND NOT [^)]*\b{elevated}\b")
        self.assertIn("pg_catalog.pg_auth_members", sql)
        self.assertIn("r.rolname IN('paddock_app','paddock_migrator')", sql)
        self.assertIn("u.rolname IN('paddock_app','paddock_migrator')", sql)

    def test_requires_applied_s02_s03_and_budget_jcs_sha_dependencies(self):
        sql = self.normalized
        for relation in (
            "raw.roots", "raw.work_orders", "raw.work_order_dependencies",
            "raw.work_order_attempts", "raw.work_order_pull_slots", "raw.work_order_leases",
            "raw.budget_accounts", "raw.budget_operations",
        ):
            self.assertIn(f"to_regclass('{relation}')", sql, f"missing prerequisite guard for {relation}")
        for procedure in (
            "raw.issue_work_order_lease(text,text,text,text,text,jsonb,jsonb,interval)",
            "raw.configure_checkpoint_policy(text,bigint,bigint,text)",
            "raw.checkpoint_storage_account(text)",
            "raw.restore_work_order_checkpoint(text)",
            "raw.jcs_quote(text)", "raw.jcs_utf16_sort_key(text)",
            "pg_catalog.sha256(bytea)",
        ):
            self.assertIn(f"to_regprocedure('{procedure}')", sql, f"missing prerequisite guard for {procedure}")
        self.assertIn("budget_accounts_storage_bytes_unit_check", sql)
        self.assertIn("getdatabaseencoding()<>'UTF8'", sql)
        self.assertIn("effective_bundle_digest", sql)
        self.assertIn("policy_digest", sql)

    def test_digest_columns_are_live_catalog_prerequisites_before_replacement(self):
        guard = self.normalized.split("create or replace function", 1)[0]
        self.assertIn("pg_catalog.pg_attribute", guard)
        for relation, column in (
            ("raw.roots", "effective_bundle_digest"),
            ("raw.work_orders", "policy_digest"),
        ):
            with self.subTest(relation=relation, column=column):
                self.assertRegex(
                    guard,
                    rf"(?is)pg_catalog\.pg_attribute\s+\w+.*?"
                    rf"attrelid\s*=\s*'{re.escape(relation)}'::regclass.*?"
                    rf"attname\s*=\s*'{re.escape(column)}'.*?"
                    rf"NOT\s+\w+\.attisdropped",
                )

    def test_only_exact_helper_and_checkpoint_store_signatures_are_replaced(self):
        declarations = re.findall(
            r"\bCREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+([^\s(]+\s*\([^)]*\))",
            self.repair,
            re.I,
        )
        self.assertEqual(
            [" ".join(item.split()) for item in declarations],
            [
                "raw.spawn_fingerprint_context(p_root text,p_parent_work_order_id text)",
                "raw.store_work_order_checkpoint(text,text,text,text,bigint,bytea,bytea,bigint)",
            ],
        )
        self.assertEqual(len(re.findall(r"\bCREATE\s+FUNCTION\b", self.repair, re.I)), 0)
        self.assertEqual(len(re.findall(r"\bCREATE\s+OR\s+REPLACE\s+FUNCTION\b", self.repair, re.I)), 2)
        for signature in (
            "raw.spawn_fingerprint_context(p_root text,p_parent_work_order_id text)",
            "raw.store_work_order_checkpoint(text,text,text,text,bigint,bytea,bytea,bigint)",
        ):
            self.assertIn(signature, self.repair)
        self.assertIn("raw.spawn_fingerprint_context", self.s02)
        self.assertIn("raw.store_work_order_checkpoint(text,text,text,text,bigint,bytea,bytea,bigint)", self.s03)

    def test_digest_helper_has_session_fixed_path_owner_and_app_only_execute(self):
        sql = self.normalized
        helper_header, helper = _function_declaration(
            self.repair, "raw.spawn_fingerprint_context(p_root text,p_parent_work_order_id text)"
        )
        self.assertRegex(helper_header, r"(?is)SECURITY\s+DEFINER\s+SET\s+search_path\s*=\s*pg_catalog\b")
        self.assertNotRegex(helper_header, r"(?is)SET\s+search_path\s*=\s*pg_catalog\s*,")
        self.assertIn("session_user<>'paddock_app'", helper)
        self.assertRegex(helper, r"(?is)JOIN\s+raw\.work_orders\s+(?:AS\s+)?\w+\s+ON")
        self.assertRegex(helper, r"(?is)effective_bundle_digest::text\s*,\s*\w+\.policy_digest::text")
        self.assertIn("p_parent_work_order_id", helper)
        self.assertIn("p_root", helper)
        self.assertIn("ALTER FUNCTION raw.spawn_fingerprint_context(text,text) OWNER TO paddock_migrator", sql)
        self.assertRegex(sql, r"(?i)REVOKE\s+ALL\s+ON\s+FUNCTION\s+raw\.spawn_fingerprint_context\(text,text\)\s+FROM\s+PUBLIC(?:\s*,\s*paddock_app)?\s*;")
        grants = re.findall(r"(?i)GRANT\s+EXECUTE\s+ON\s+FUNCTION\s+raw\.spawn_fingerprint_context\(text,text\)\s+TO\s+([^;]+);", sql)
        self.assertEqual(grants, ["paddock_app"])

    def test_digest_helper_assigns_both_output_columns_before_returning_row(self):
        helper = _function_body(
            self.repair, "raw.spawn_fingerprint_context(p_root text,p_parent_work_order_id text)"
        )
        self.assertRegex(
            helper,
            r"(?is)SELECT\s+r\.effective_bundle_digest::text\s*,\s*w\.policy_digest::text"
            r"\s+INTO\s+effective_bundle_digest\s*,\s*policy_digest\s+"
            r"FROM\s+raw\.roots\s+AS\s+r\s+JOIN\s+raw\.work_orders\s+AS\s+w\s+ON",
        )

        missing_or_null = re.search(
            r"(?is)IF\s+NOT\s+FOUND\s+OR\s+effective_bundle_digest\s+IS\s+NULL\s+"
            r"OR\s+policy_digest\s+IS\s+NULL\s+THEN\b",
            helper,
        )
        return_next = re.search(r"(?i)\bRETURN\s+NEXT\s*;", helper)
        self.assertIsNotNone(missing_or_null, "missing/null outputs must be rejected")
        self.assertIsNotNone(return_next, "the assigned OUT row must be emitted with RETURN NEXT")
        self.assertLess(missing_or_null.start(), return_next.start())
        self.assertNotRegex(helper, r"(?i)\bRETURN\s+QUERY\b")

    def test_checkpoint_store_keeps_reservation_aggregate_and_restore_integrity(self):
        store = _function_body(self.repair, "raw.store_work_order_checkpoint(text,text,text,text,bigint,bytea,bytea,bigint)")
        normalized_store = " ".join(store.split())
        insertion = normalized_store.lower().find("insert into raw.work_order_checkpoints")
        self.assertGreaterEqual(insertion, 0, "replacement store function must insert the checkpoint")
        before_insert = normalized_store[:insertion]
        self.assertRegex(before_insert, r"(?:bo\.)?operation_id\s*=\s*op\s*\|\|\s*':reserve'")
        self.assertRegex(before_insert, r"(?:bo\.)?operation_kind\s*=\s*'RESERVE'")
        self.assertRegex(before_insert, r"(?:bo\.)?request\s*->>\s*'account_id'\s*=\s*pol\.storage_account_id")
        self.assertRegex(before_insert, r"(?:bo\.)?request\s*->>\s*'amount'\s*=\s*n\s*::\s*text")
        self.assertRegex(before_insert, r"(?:bo\.)?result\s*=\s*jsonb_build_object\s*\(\s*'account_id'\s*,\s*pol\.storage_account_id\s*,\s*'reserved'\s*,\s*n\s*\)")
        self.assertRegex(store, r"(?is)SELECT\s+COALESCE\s*\(\s*sum\s*\(\s*\w+\.stored_bytes\s*\)\s*,\s*0\s*\)\s+INTO\s+used\s+FROM\s+raw\.work_order_checkpoints\s+(?:AS\s+)?\w+\s+WHERE\s+\w+\.root_id\s*=\s*rid")
        self.assertNotRegex(store, r"(?i)sum\s*\(\s*stored_bytes\s*\)")

        restore = _function_body(self.s03, "raw.restore_work_order_checkpoint(text)")
        self.assertRegex(restore, r"(?is)pg_catalog\.sha256\s*\(\s*c\.payload\s*\)")
        self.assertRegex(restore, r"(?is)c\.payload_sha256\s*=\s*encode\s*\(\s*pg_catalog\.sha256\s*\(\s*c\.payload\s*\)\s*,\s*'hex'\s*\)")
        self.assertIn("CASE WHEN current_state='L2' THEN c.payload ELSE NULL::bytea END", restore)
        self.assertIn("raw.restore_work_order_checkpoint(text)", self.repair)

    def test_helper_does_not_widen_direct_table_privileges_or_mutation_surface(self):
        upper = self.repair.upper()
        self.assertNotRegex(upper, r"\b(?:DROP|TRUNCATE|DELETE)\b")
        self.assertNotRegex(
            self.repair,
            r"(?is)GRANT\s+(?:SELECT|INSERT|UPDATE|DELETE|TRUNCATE|ALL(?:\s+PRIVILEGES)?)\s+ON\s+(?:TABLE\s+)?(?:RAW\.)?\w+\s+TO\s+(?:PUBLIC\s*,\s*)?PADDOCK_APP",
        )
        self.assertNotRegex(self.repair, r"(?i)GRANT\s+[^;]*\b(?:roots|work_orders|work_order_checkpoints|checkpoint_policies)\b[^;]*\bTO\s+(?:PUBLIC|paddock_app)")
        self.assertNotRegex(self.repair, r"(?i)GRANT\s+EXECUTE\s+ON\s+FUNCTION\s+[^;]+\s+TO\s+PUBLIC")
        self.assertIn("REVOKE ALL ON FUNCTION", self.repair)
        self.assertIn("TO paddock_app", self.repair)


if __name__ == "__main__":
    unittest.main()

"""Offline static contract checks for governance role grants."""

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
SQL_PATH = ROOT / "sql" / "governance_roles.sql"
RAW_TABLES = (
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


def strip_comments(sql: str) -> str:
    return re.sub(r"--[^\n]*", " ", sql)


class GovernanceRolesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = SQL_PATH.read_text(encoding="utf-8")
        cls.clean = strip_comments(cls.sql)

    def test_approved_role_identities_are_required(self):
        self.assertIn("app_name <> 'paddock_app'", self.clean)
        self.assertIn("migration_name <> 'paddock_migrator'", self.clean)
        self.assertIn("app_role=paddock_app", self.sql)
        self.assertIn("migration_role=paddock_migrator", self.sql)

    def test_role_attributes_and_memberships_fail_closed_both_directions(self):
        for attribute in ("rolsuper", "rolcreaterole", "rolcreatedb", "rolreplication", "rolbypassrls"):
            with self.subTest(attribute=attribute):
                self.assertIn(attribute, self.clean)
        self.assertIn("granted_role.rolname IN (app_name, migration_name)", self.clean)
        self.assertIn("member_role.rolname IN (app_name, migration_name)", self.clean)

    def test_migration_ownership_is_verified_after_explicit_transfers(self):
        self.assertIn("DO $ownership_check$", self.clean)
        self.assertIn("migration role must own raw schema after transfer", self.clean)
        self.assertIn("count(*)", self.clean)
        self.assertIn("migration role must own all 11 raw base tables after transfer", self.clean)
        self.assertIn("transfers require execution by the authorized current owner or a superuser", self.sql)
        self.assertIn("exact S03 authorization", self.sql)

    def test_requires_explicit_precreated_role_identifiers(self):
        self.assertRegex(self.sql, r"(?m)^\\if :\{\?app_role\}")
        self.assertRegex(self.sql, r"(?m)^\\if :\{\?migration_role\}")
        self.assertRegex(self.clean, r"(?is)pg_roles[\s\S]*rolname")
        self.assertRegex(self.clean, r"(?is)app_name\s*=\s*migration_name")
        self.assertNotRegex(self.clean, r"(?i)\bCREATE\s+ROLE\b")
        self.assertNotRegex(self.sql, r"(?i)\b(password|secret|credential)\b")

    def test_missing_psql_variables_fail_closed_before_ownership_or_acl_changes(self):
        approved_roles = {
            "app_role": "paddock_app",
            "migration_role": "paddock_migrator",
        }
        for variable, approved_role in approved_roles.items():
            with self.subTest(variable=variable):
                branch = re.search(
                    rf"(?ims)^\\if\s+:\{{\?{variable}\}}\s*\\else\s*(.*?)^\\endif\s*$",
                    self.sql,
                )
                self.assertIsNotNone(branch, f"missing-variable branch for {variable}")
                assignment = re.search(
                    rf"(?m)^\s*\\set\s+{variable}\s+(\S+)\s*$", branch.group(1)
                )
                self.assertIsNotNone(
                    assignment, f"{variable} must be assigned with a supported psql \\set"
                )
                self.assertNotEqual(
                    assignment.group(1),
                    approved_role,
                    f"{variable} sentinel must not equal its approved role name",
                )

        self.assertNotRegex(self.sql, r"(?im)^\s*\\error(?:\s|$)")

        guard_start = self.clean.index("DO $guard$")
        guard_end = self.clean.index("$guard$;", guard_start)
        guard = self.clean[guard_start:guard_end]
        self.assertIn("app_name <> 'paddock_app'", guard)
        self.assertIn("migration_name <> 'paddock_migrator'", guard)
        self.assertLess(guard_end, self.clean.index("ALTER SCHEMA raw OWNER"))
        self.assertLess(guard_end, self.clean.index("REVOKE ALL ON SCHEMA raw"))
        self.assertLess(guard_end, self.clean.index("GRANT USAGE ON SCHEMA raw"))

    def test_guarded_transaction_and_no_destructive_database_ddl(self):
        self.assertRegex(self.clean, r"(?i)\bBEGIN\s*;")
        self.assertRegex(self.clean, r"(?i)\bCOMMIT\s*;")
        self.assertRegex(self.clean, r"(?is)current_database\s*\(\s*\)\s*<>\s*'paddock_test'")
        self.assertNotRegex(self.clean, r"(?i)\bDROP\s+(?:DATABASE|SCHEMA)\b")
        self.assertNotRegex(self.clean, r"(?i)\bGRANT\s+ALL\s+.*\bTO\s+PUBLIC\b")

    def test_application_cannot_update_or_delete_immutable_rows(self):
        self.assertRegex(self.clean, r"(?is)REVOKE\s+ALL\s+ON\s+ALL\s+TABLES\s+IN\s+SCHEMA\s+raw\s+FROM\s+:\"app_role\"")
        self.assertRegex(self.clean, r"(?is)GRANT\s+SELECT\s*,\s*INSERT\s+ON\s+TABLE\s+raw\.policy_bundles\s*,\s*raw\.domain_events\s+TO\s+:\"app_role\"")
        self.assertNotRegex(self.clean, r"(?is)GRANT\s+[^;]*\b(?:UPDATE|DELETE)\b[^;]*\bTO\s+:\"app_role\"")

    def test_all_current_raw_table_column_privileges_are_revoked_before_app_grants(self):
        revocation_start = self.clean.index("DO $revoke_column_privileges$")
        revocation_end = self.clean.index("$revoke_column_privileges$;", revocation_start)
        revocation = self.clean[revocation_start:revocation_end]
        grants_start = self.clean.index("GRANT USAGE ON SCHEMA raw TO :\"app_role\"")

        self.assertIn("FROM PUBLIC, %I", revocation)
        self.assertIn("app_name text := current_setting('paddock.app_role')", revocation)
        self.assertRegex(revocation, r"(?is)pg_class\s+c[\s\S]*pg_namespace\s+n[\s\S]*pg_attribute\s+a")
        self.assertIn("n.nspname = 'raw'", revocation)
        self.assertIn("c.relkind IN ('r', 'p')", revocation)
        self.assertIn("a.attnum > 0", revocation)
        self.assertIn("NOT a.attisdropped", revocation)
        self.assertRegex(revocation, r"(?is)format\s*\([\s\S]*REVOKE ALL \(%I\) ON TABLE %I\.%I FROM PUBLIC, %I")
        self.assertLess(revocation_start, grants_start)

    def test_migration_role_is_separate_and_has_controlled_dml_ddl(self):
        self.assertRegex(self.clean, r"(?is)GRANT\s+USAGE\s*,\s*CREATE\s+ON\s+SCHEMA\s+raw\s+TO\s+:\"migration_role\"")
        self.assertRegex(self.clean, r"(?is)GRANT\s+SELECT\s*,\s*INSERT\s*,\s*UPDATE\s*,\s*DELETE\s+ON\s+ALL\s+TABLES\s+IN\s+SCHEMA\s+raw\s+TO\s+:\"migration_role\"")
        self.assertNotRegex(self.clean, r"(?i)\bALTER\s+ROLE\b|\bCREATE\s+ROLE\b")

    def test_migration_role_owns_raw_schema_and_every_existing_base_table(self):
        self.assertRegex(self.clean, r'(?is)ALTER\s+SCHEMA\s+raw\s+OWNER\s+TO\s+:"migration_role"')
        for table in RAW_TABLES:
            with self.subTest(table=table):
                self.assertRegex(
                    self.clean,
                    rf'(?is)ALTER\s+TABLE\s+raw\.{table}\s+OWNER\s+TO\s+:"migration_role"',
                )
        self.assertEqual(len(re.findall(r"(?i)\bALTER\s+TABLE\s+raw\.", self.clean)), 11)

    def test_script_avoids_unsafe_or_unapproved_ownership_operations(self):
        self.assertNotRegex(self.clean, r"(?i)\bCASCADE\b")
        self.assertRegex(self.sql, r"(?i)Do not run against a live database without separate authorization")
        self.assertRegex(self.clean, r"(?is)app_name\s*=\s*migration_name")
        self.assertRegex(self.clean, r"(?is)rolsuper\s+OR\s+rolcreaterole")
        self.assertRegex(self.clean, r"(?is)application role must not own raw schema")


if __name__ == "__main__":
    unittest.main()

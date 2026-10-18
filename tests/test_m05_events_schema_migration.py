"""Offline source-shape checks for the guarded event schema migration.

These regular-expression checks inspect SQL text only. They do not parse SQL,
connect to PostgreSQL, execute statements, or prove runtime behavior.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
MIGRATION_PATH = ROOT / "sql" / "governance_domain_events_schema.sql"
INIT_PATH = ROOT / "sql" / "init.sql"
CONSTRAINT = "domain_events_schema_version_nonempty_ck"


def uncomment(source):
    """Remove ordinary SQL comments for source-only token checks."""
    return re.sub(r"--[^\n]*|/\*.*?\*/", " ", source, flags=re.S)


class EventSchemaMigrationStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.migration_raw = MIGRATION_PATH.read_text(encoding="utf-8")
        cls.init_raw = INIT_PATH.read_text(encoding="utf-8")
        cls.migration = uncomment(cls.migration_raw).lower()
        cls.init = uncomment(cls.init_raw).lower()

    def test_files_exist_and_migration_is_one_transaction(self):
        self.assertTrue(MIGRATION_PATH.is_file())
        self.assertTrue(INIT_PATH.is_file())
        self.assertEqual(len(re.findall(r"\bbegin\s*;", self.migration)), 1)
        self.assertEqual(len(re.findall(r"\bcommit\s*;", self.migration)), 1)
        self.assertLess(self.migration.index("begin;"), self.migration.index("commit;"))

    def test_exact_database_and_role_guards(self):
        sql = self.migration
        self.assertRegex(sql, r"current_database\s*\(\s*\)\s*<>\s*'paddock_test'")
        self.assertRegex(sql, r"current_user\s*<>\s*'paddock_migrator'")
        self.assertRegex(sql, r"session_user\s*<>\s*'paddock_migrator'")
        for role in ("paddock_migrator", "paddock_app"):
            role_check = re.search(
                rf"from\s+pg_catalog\.pg_roles\s+where\s+rolname\s*=\s*'{role}'"
                rf"(?:(?!\)\s*or\s+not\s+exists).)*",
                sql,
                flags=re.S,
            )
            self.assertIsNotNone(role_check, f"missing catalog check for {role}")
            for flag in ("rolsuper", "rolcreaterole", "rolcreatedb", "rolreplication", "rolbypassrls"):
                self.assertRegex(role_check.group(0), rf"not\s+{flag}\b")
        self.assertRegex(sql, r"pg_catalog\.pg_auth_members")
        self.assertRegex(sql, r"granted_role\.rolname\s+in\s*\(\s*'paddock_app'\s*,\s*'paddock_migrator'")
        self.assertRegex(sql, r"member_role\.rolname\s+in\s*\(\s*'paddock_app'\s*,\s*'paddock_migrator'")

    def test_raw_schema_and_table_must_be_migrator_owned(self):
        sql = self.migration
        self.assertIsNotNone(re.search(
            r"pg_catalog\.pg_namespace\s+n\s+join\s+pg_catalog\.pg_roles\s+r\s+on\s+r\.oid\s*=\s*n\.nspowner"
            r"(?:(?!;).)*?n\.nspname\s*=\s*'raw'(?:(?!;).)*?r\.rolname\s*=\s*'paddock_migrator'",
            sql,
            flags=re.S,
        ))
        self.assertRegex(sql, r"n\.nspname\s*=\s*'raw'\s+and\s+c\.relname\s*=\s*'domain_events'")
        self.assertRegex(sql, r"c\.relkind\s*=\s*'r'\s+and\s+r\.rolname\s*=\s*'paddock_migrator'")

    def test_existing_column_is_accepted_only_in_complete_valid_state(self):
        sql = self.migration
        self.assertRegex(sql, r"schema_version_type\s*<>\s*'text'::pg_catalog\.regtype")
        self.assertRegex(sql, r"not\s+schema_version_not_null")
        constraint_guard = re.search(
            rf"c\.conname\s*=\s*'{CONSTRAINT}'.*?c\.contype\s*=\s*'c'.*?c\.convalidated"
            r".*?c\.conkey\s*=\s*array\[schema_version_attnum\]::smallint\[\]",
            sql,
            flags=re.S,
        )
        self.assertIsNotNone(constraint_guard)
        self.assertRegex(sql, r"partial\s+or\s+incompatible\s+state")
        existing_column = re.search(
            r"if\s+schema_version_attnum\s+is\s+not\s+null\s+then"
            r"(?:(?!\$migration_guard\$).)*?return;",
            sql,
            flags=re.S,
        )
        self.assertIsNotNone(existing_column)
        branch = existing_column.group(0)

        # The name/key/validated checks do not establish what a CHECK means.
        # The catalog expression is normalized inline in the NOT EXISTS guard;
        # accept only the two exact PostgreSQL-rendered forms of the required
        # nonempty predicate, and require that guard before the branch RAISE/RETURN.
        expression_guard = re.search(
            r"not\s+exists\s*\(\s*select\s+1\s+from\s+pg_catalog\.pg_constraint\s+c"
            r"(?:(?!\)\s*then).)*?"
            r"pg_catalog\.regexp_replace\s*\(\s*"
            r"pg_catalog\.lower\s*\(\s*pg_catalog\.pg_get_constraintdef\s*\(\s*c\.oid\s*\)\s*\)\s*,\s*"
            r"'\[\[:space:\]\(\)\]'\s*,\s*''\s*,\s*'g'\s*\)\s+in\s*\(\s*"
            r"\$expected_check\$check\(schema_version<>''::text\)\$expected_check\$\s*,\s*"
            r"\$expected_check\$check\(schema_version<>''\)\$expected_check\$\s*\)",
            branch,
            flags=re.S,
        )
        self.assertIsNotNone(expression_guard, "existing CHECK must match one exact normalized expression")
        raise_position = branch.find("raise exception", expression_guard.end())
        return_position = branch.find("return;", expression_guard.end())
        self.assertGreaterEqual(raise_position, 0, "a missing matching CHECK must raise")
        self.assertGreater(return_position, raise_position, "the no-op RETURN must follow the fail-closed RAISE")

    def test_current_domain_events_shape_is_checked(self):
        sql = self.migration
        for column, pgtype in (
            ("event_id", "text"),
            ("aggregate_kind", "text"),
            ("aggregate_id", "text"),
            ("aggregate_version", "bigint"),
            ("event_type", "text"),
            ("payload", "bytea"),
            ("created_at", "timestamp with time zone"),
        ):
            self.assertRegex(
                sql,
                rf"\('{column}',\s*'{re.escape(pgtype)}'::pg_catalog\.regtype,\s*true\)",
            )
        required_columns_guard = re.search(
            r"if\s+expected_columns\s*<>\s*7\s+then.*?raise\s+exception[^;]*expected\s+table\s+shape.*?end\s+if\s*;",
            sql,
            flags=re.S,
        )
        self.assertIsNotNone(required_columns_guard, "the seven required columns must be checked independently")

        expected_count = re.search(
            r"if\s+schema_version_attnum\s+is\s+null\s+then\s*"
            r"expected_physical_columns\s*:=\s*7\s*;\s*"
            r"else\s*expected_physical_columns\s*:=\s*8\s*;\s*end\s+if\s*;",
            sql,
        )
        actual_count = re.search(
            r"select\s+count\s*\(\s*\*\s*\)\s+into\s+actual_columns.*?"
            r"if\s+actual_columns\s*<>\s*expected_physical_columns\s+then",
            sql,
            flags=re.S,
        )
        self.assertIsNotNone(expected_count, "expected live count starts at seven and changes to eight only when schema_version exists")
        self.assertIsNotNone(actual_count, "actual live column count must be compared with the expected count")
        self.assertLess(required_columns_guard.start(), expected_count.start())
        self.assertLess(expected_count.end(), actual_count.start())
        self.assertRegex(sql, r"does\s+not\s+have\s+the\s+expected\s+table\s+shape")

    def test_absent_column_locks_then_rejects_rows_before_adding(self):
        sql = self.migration
        guard = re.search(r"do\s+\$migration_guard\$(.*?)\$migration_guard\$\s*;", sql, flags=re.S)
        self.assertIsNotNone(guard)
        # The append function intentionally contains the two INSERTs below;
        # the no-row policy applies only to the schema migration guard.
        guard_sql = guard.group(1)
        lock = re.search(r"lock\s+table\s+raw\.domain_events\s+in\s+access\s+exclusive\s+mode\s*;", sql)
        rows_check = re.search(r"if\s+exists\s*\(\s*select\s+1\s+from\s+raw\.domain_events\s+limit\s+1\s*\)", guard_sql)
        add = re.search(r"alter\s+table\s+raw\.domain_events\s+add\s+column\s+schema_version", guard_sql)
        self.assertIsNotNone(lock)
        self.assertIsNotNone(rows_check)
        self.assertIsNotNone(add)
        self.assertLess(lock.start(), rows_check.start())
        self.assertLess(rows_check.start(), add.start())
        self.assertIsNotNone(re.search(r"raise\s+exception[^;]*contains\s+rows", guard_sql, flags=re.S))
        self.assertNotRegex(sql, r"\b(?:update|delete)\s+raw\.domain_events\b")
        self.assertNotRegex(guard_sql, r"\binsert\s+into\s+raw\.domain_events\b")

    def test_only_the_selected_additive_column_definition_and_init_parity(self):
        definition = re.compile(
            rf"alter\s+table\s+raw\.domain_events\s+add\s+column\s+schema_version\s+text\s+not\s+null\s+"
            rf"constraint\s+{CONSTRAINT}\s+check\s*\(\s*schema_version\s*<>\s*''\s*\)\s*;"
        )
        self.assertEqual(len(definition.findall(self.migration)), 1)
        self.assertRegex(
            self.init,
            rf"schema_version\s+text\s+not\s+null\s+constraint\s+{CONSTRAINT}\s+check\s*\(\s*schema_version\s*<>\s*''\s*\)",
        )

    def test_app_only_append_function_security_contract(self):
        sql = self.migration
        signature = (
            r"create\s+or\s+replace\s+function\s+"
            r"raw\.append_domain_event_and_outbox\s*\(\s*"
            r"text\s*,\s*text\s*,\s*text\s*,\s*bigint\s*,\s*text\s*,\s*text\s*,\s*bytea\s*\)"
            r"\s*returns\s+void"
        )
        self.assertRegex(sql, signature)
        start = re.search(signature, sql)
        self.assertIsNotNone(start)
        end = sql.find("$append_domain_event_and_outbox$;", start.end())
        self.assertGreater(end, start.end(), "function body must have a clear dollar-quoted end")
        body = sql[start.start():end]
        self.assertRegex(body, r"security\s+definer")
        self.assertRegex(body, r"set\s+search_path\s*=\s*pg_catalog\b")
        self.assertRegex(body, r"if\s+session_user\s*<>\s*'paddock_app'")
        for argument in ("$1", "$2", "$3", "$5", "$6"):
            self.assertRegex(body, rf"{re.escape(argument)}\s+is\s+null")
            self.assertRegex(body, rf"{re.escape(argument)}\s*=\s*''")
            self.assertRegex(body, rf"{re.escape(argument)}\s*<>\s*pg_catalog\.btrim\s*\(\s*{re.escape(argument)}\s*\)")
        self.assertRegex(body, r"\$4\s+is\s+null\s+or\s+\$4\s*<=\s*0")
        self.assertRegex(body, r"\$7\s+is\s+null")
        self.assertRegex(body, r"\bschema_version\b")
        self.assertGreaterEqual(len(re.findall(r"raise\s+exception", body)), 4)
        event_insert = re.search(
            r"insert\s+into\s+raw\.domain_events\s*\((.*?)\)\s*values\s*\((.*?)\)\s*;",
            body, flags=re.S,
        )
        outbox_insert = re.search(
            r"insert\s+into\s+raw\.event_outbox\s*\((.*?)\)\s*values\s*\((.*?)\)\s*;",
            body, flags=re.S,
        )
        self.assertIsNotNone(event_insert)
        self.assertIsNotNone(outbox_insert)
        self.assertLess(event_insert.start(), outbox_insert.start(), "Event insert must precede Outbox")
        event_columns = re.sub(r"\s+", "", event_insert.group(1))
        event_values = re.sub(r"\s+", "", event_insert.group(2))
        outbox_columns = re.sub(r"\s+", "", outbox_insert.group(1))
        outbox_values = re.sub(r"\s+", "", outbox_insert.group(2))
        self.assertEqual(
            event_columns,
            "event_id,aggregate_kind,aggregate_id,aggregate_version,event_type,schema_version,payload",
        )
        self.assertEqual(event_values, "$1,$2,$3,$4,$5,$6,$7")
        self.assertEqual(outbox_columns, "event_id")
        self.assertEqual(outbox_values, "$1")
        self.assertEqual(len(re.findall(r"\binsert\s+into\b", body)), 2)
        self.assertNotRegex(body, r"\b(?:update|delete|truncate)\b")
        self.assertRegex(sql, r"alter\s+function\s+raw\.append_domain_event_and_outbox\s*\(\s*text\s*,\s*text\s*,\s*text\s*,\s*bigint\s*,\s*text\s*,\s*text\s*,\s*bytea\s*\)\s*owner\s+to\s+paddock_migrator")
        revoke = re.search(r"revoke\s+all\s+on\s+function\s+raw\.append_domain_event_and_outbox\s*\(text\s*,\s*text\s*,\s*text\s*,\s*bigint\s*,\s*text\s*,\s*text\s*,\s*bytea\s*\)\s+from\s+public\s*,\s*paddock_app\s*;", sql)
        grant = re.search(r"grant\s+execute\s+on\s+function\s+raw\.append_domain_event_and_outbox\s*\(text\s*,\s*text\s*,\s*text\s*,\s*bigint\s*,\s*text\s*,\s*text\s*,\s*bytea\s*\)\s+to\s+paddock_app\s*;", sql)
        self.assertIsNotNone(revoke)
        self.assertIsNotNone(grant)
        self.assertLess(revoke.start(), grant.start())

    def test_event_outbox_event_id_shape_is_preflighted_before_function_replacement(self):
        sql = self.migration
        replacement = sql.index("create or replace function raw.append_domain_event_and_outbox")
        outbox_lookup = re.search(
            r"from\s+pg_catalog\.pg_attribute\s+a.*?"
            r"a\.attrelid\s*=\s*event_outbox_oid.*?"
            r"a\.attname\s*=\s*'event_id'.*?"
            r"a\.atttypid\s*=\s*'text'::pg_catalog\.regtype.*?"
            r"a\.attnotnull.*?a\.attnum\s*>\s*0.*?not\s+a\.attisdropped",
            sql, flags=re.S,
        )
        self.assertIsNotNone(outbox_lookup, "require a live text NOT NULL event_outbox.event_id attribute")
        self.assertLess(outbox_lookup.start(), replacement)

        primary_key = re.search(
            r"if\s+not\s+exists\s*\(\s*select\s+1\s+from\s+pg_catalog\.pg_constraint\s+c"
            r"\s+where\s+c\.conrelid\s*=\s*event_outbox_oid\s+and\s+c\.contype\s*=\s*'p'"
            r"\s+and\s+c\.conkey\s*=\s*array\[outbox_event_id_attnum\]::smallint\[\]\s*\)",
            sql, flags=re.S,
        )
        foreign_key = re.search(
            r"if\s+not\s+exists\s*\(\s*select\s+1\s+from\s+pg_catalog\.pg_constraint\s+c.*?"
            r"where\s+c\.conrelid\s*=\s*event_outbox_oid\s+and\s+c\.contype\s*=\s*'f'.*?"
            r"c\.conkey\s*=\s*array\[outbox_event_id_attnum\]::smallint\[\].*?"
            r"c\.confrelid\s*=\s*domain_events_oid.*?"
            r"c\.confkey\s*=\s*array\[target\.attnum\]::smallint\[\]\s*\)",
            sql[primary_key.end():], flags=re.S,
        )
        self.assertIsNotNone(primary_key, "require an event_id-only event_outbox primary key")
        self.assertIsNotNone(foreign_key, "require event_outbox.event_id -> domain_events.event_id")
        foreign_key_start = primary_key.end() + foreign_key.start()
        self.assertLess(outbox_lookup.start(), primary_key.start())
        self.assertLess(primary_key.start(), foreign_key_start)
        self.assertLess(foreign_key_start, replacement)

    def test_function_acl_normalization_removes_nonowner_grants_before_app_only_grant(self):
        sql = self.migration
        create_position = sql.index("create or replace function raw.append_domain_event_and_outbox")
        owner = re.search(
            r"alter\s+function\s+raw\.append_domain_event_and_outbox\s*\(text\s*,\s*text\s*,\s*text\s*,\s*bigint\s*,\s*text\s*,\s*text\s*,\s*bytea\)\s*owner\s+to\s+paddock_migrator",
            sql,
        )
        initial_revoke = re.search(
            r"revoke\s+all\s+on\s+function\s+raw\.append_domain_event_and_outbox\s*"
            r"\(text\s*,\s*text\s*,\s*text\s*,\s*bigint\s*,\s*text\s*,\s*text\s*,\s*bytea\)\s*"
            r"from\s+public\s*,\s*paddock_app\s*;",
            sql,
        )
        cleanup = re.search(
            r"do\s+\$revoke_existing_function_execute\$.*?"
            r"\$revoke_existing_function_execute\$\s*;",
            sql, flags=re.S,
        )
        self.assertIsNotNone(owner, "set the function owner before ACL normalization")
        self.assertIsNotNone(initial_revoke, "initially revoke PUBLIC and paddock_app")
        self.assertIsNotNone(cleanup, "isolate the non-owner EXECUTE ACL cleanup block")
        cleanup_sql = cleanup.group(0)
        self.assertRegex(cleanup_sql, r"from\s+pg_catalog\.pg_proc\s+p")
        self.assertRegex(
            cleanup_sql,
            r"pg_catalog\.aclexplode\s*\(\s*coalesce\s*\(\s*p\.proacl\s*,\s*"
            r"pg_catalog\.acldefault\s*\(\s*'f'\s*,\s*p\.proowner\s*\)\s*\)\s*\)",
        )
        self.assertRegex(
            cleanup_sql,
            r"p\.oid\s*=\s*pg_catalog\.to_regprocedure\s*\(\s*"
            r"'raw\.append_domain_event_and_outbox\(text,text,text,bigint,text,text,bytea\)'\s*\)",
        )
        self.assertRegex(cleanup_sql, r"acl\.privilege_type\s*=\s*'execute'")
        self.assertRegex(cleanup_sql, r"acl\.grantee\s*<>\s*p\.proowner")
        self.assertRegex(
            cleanup_sql,
            r"(?s)execute\s+pg_catalog\.format\s*\(\s*'revoke all on function.*?from %i'.*?grantee_name\s*\)",
        )
        public_revoke = re.search(
            r"revoke\s+all\s+on\s+function\s+raw\.append_domain_event_and_outbox"
            r"\(text\s*,\s*text\s*,\s*text\s*,\s*bigint\s*,\s*text\s*,\s*text\s*,\s*bytea\)"
            r"\s+from\s+public\s*;",
            sql,
        )
        app_grant = re.search(
            r"grant\s+execute\s+on\s+function\s+raw\.append_domain_event_and_outbox"
            r"\(text\s*,\s*text\s*,\s*text\s*,\s*bigint\s*,\s*text\s*,\s*text\s*,\s*bytea\)"
            r"\s+to\s+paddock_app\s*;",
            sql,
        )
        self.assertIsNotNone(public_revoke, "explicitly revoke PUBLIC")
        self.assertIsNotNone(app_grant, "grant EXECUTE only to paddock_app")
        self.assertLess(create_position, owner.start())
        self.assertLess(owner.start(), initial_revoke.start())
        self.assertLess(initial_revoke.start(), cleanup.start())
        self.assertLess(cleanup.end(), public_revoke.start())
        self.assertLess(public_revoke.start(), app_grant.start())
        self.assertEqual(len(re.findall(
            r"revoke\s+all\s+on\s+function\s+raw\.append_domain_event_and_outbox"
            r"\(text\s*,\s*text\s*,\s*text\s*,\s*bigint\s*,\s*text\s*,\s*text\s*,\s*bytea\)"
            r"\s+from\s+public\s*;", sql,
        )), 1)
        grants = re.findall(r"grant\s+execute\s+on\s+function\s+raw\.append_domain_event_and_outbox.*?;", sql, re.S)
        self.assertEqual(len(grants), 1)
        self.assertNotRegex(sql, r"grant\s+execute\s+on\s+function\s+raw\.append_domain_event_and_outbox[^;]*\bto\s+(?!paddock_app\b)[\w\"]+", "no other role may receive EXECUTE")

    def test_app_direct_insert_and_outbox_table_privileges_are_revoked(self):
        sql = self.migration
        baseline = re.search(
            r"revoke\s+all\s+on\s+table\s+raw\.domain_events\s+from\s+public\s*,\s*paddock_app\s*;\s*"
            r"grant\s+select\s+on\s+table\s+raw\.domain_events\s+to\s+paddock_app\s*;\s*"
            r"revoke\s+all\s+on\s+table\s+raw\.event_outbox\s+from\s+public\s*,\s*paddock_app\s*;",
            sql,
        )
        self.assertIsNotNone(baseline, "relation ACL cleanup must precede app SELECT-only grant")
        self.assertNotRegex(sql, r"grant\s+\w+\s+on\s+table\s+raw\.event_outbox")
        # Relation-wide revokes do not clear column-level ACLs. Require dynamic
        # cleanup of every column on both tables for both grantees, before grant.
        column_cleanup = re.search(
            r"do\s+\$revoke_event_column_privileges\$.*?"
            r"select\s+c\.relname\s*,\s*a\.attname.*?"
            r"c\.relname\s+in\s*\(\s*'domain_events'\s*,\s*'event_outbox'\s*\).*?"
            r"execute\s+pg_catalog\.format\s*\(\s*'revoke\s+select\s*\(%1\$i\),\s*"
            r"insert\s*\(%1\$i\),\s*update\s*\(%1\$i\),\s*references\s*\(%1\$i\)\s+"
            r"on\s+table\s+raw\.%2\$i\s+from\s+public,\s*paddock_app'.*?"
            r"column_record\.attname\s*,\s*column_record\.relname.*?"
            r"\$revoke_event_column_privileges\$\s*;",
            sql,
            flags=re.S,
        )
        self.assertIsNotNone(column_cleanup, "dynamic per-column ACL cleanup must cover both event tables")
        self.assertLess(baseline.end(), column_cleanup.start())
        self.assertLess(column_cleanup.end(), sql.index("commit;"))

    def test_append_function_ddl_is_inside_guarded_transaction_and_schema_scope_stays_additive(self):
        sql = self.migration
        begin, commit = sql.index("begin;"), sql.index("commit;")
        function = sql.index("create or replace function raw.append_domain_event_and_outbox")
        self.assertLess(begin, function)
        self.assertLess(function, commit)
        for token in (
            "alter function raw.append_domain_event_and_outbox",
            "revoke all on function raw.append_domain_event_and_outbox",
            "grant execute on function raw.append_domain_event_and_outbox",
            "revoke all on table raw.domain_events",
            "grant select on table raw.domain_events",
            "revoke all on table raw.event_outbox",
            "do $revoke_event_column_privileges$",
        ):
            position = sql.find(token)
            self.assertGreaterEqual(position, 0, f"missing transactional function/ACL change: {token}")
            self.assertLess(begin, position)
            self.assertLess(position, commit)
        # Exactly the schema-version ALTER is permitted outside the function.
        self.assertEqual(len(re.findall(r"\bcreate\s+table\b", sql)), 0)
        self.assertEqual(len(re.findall(r"\balter\s+table\b", sql)), 1)
        self.assertEqual(len(re.findall(r"\badd\s+column\b", sql)), 1)
        # The only data writes are the ordered pair in the append function.
        # UPDATE here is also a column privilege name, not data DML.
        function = re.search(
            r"create\s+or\s+replace\s+function\s+raw\.append_domain_event_and_outbox\b.*?"
            r"as\s+\$append_domain_event_and_outbox\$(.*?)\$append_domain_event_and_outbox\$\s*;",
            sql, flags=re.S,
        )
        self.assertIsNotNone(function)
        body = function.group(1)
        self.assertEqual(len(re.findall(r"\binsert\s+into\b", body)), 2)
        outside_function = sql[:function.start()] + sql[function.end():]
        self.assertNotRegex(outside_function, r"\binsert\s+into\b")
        self.assertNotRegex(outside_function, r"\bupdate\s+raw\.")
        self.assertNotRegex(outside_function, r"\bdelete\s+from\s+raw\.")
        self.assertNotRegex(outside_function, r"\btruncate\b")
        self.assertNotRegex(outside_function, r"\bdrop\b")
        self.assertNotRegex(sql, r"\bcreate\s+role\b")
        self.assertNotRegex(sql, r"\bset\s+role\b")


if __name__ == "__main__":
    unittest.main()

from pathlib import Path
import re
import unittest

SQL = Path(__file__).resolve().parents[1].joinpath('sql/governance_spawn_policy.sql').read_text()
LEASE = Path(__file__).resolve().parents[1].joinpath('sql/governance_lease.sql').read_text()
SPAWN_STORE = Path(__file__).resolve().parents[1].joinpath('internal/storage/postgres/spawn_store.go').read_text()

class SpawnPolicySQLTests(unittest.TestCase):
    def test_exact_test_db_and_role_boundary(self):
        self.assertIn("current_database()<>'paddock_test'", SQL)
        self.assertIn("current_user<>'paddock_migrator'", SQL)
        self.assertIn("session_user<>'paddock_app'", SQL)
        self.assertIn('OWNER TO paddock_migrator', SQL)
        self.assertIn("paddock_migrator must own raw schema and required objects", SQL)
        self.assertIn('REVOKE ALL ON raw.roots,raw.work_orders,raw.work_order_dependencies,raw.work_order_attempts,raw.work_order_pull_slots,raw.work_order_leases FROM paddock_app', SQL)
        self.assertNotIn('paddock_owner', SQL)
        self.assertNotIn("rolname='migrator'", SQL)
        self.assertIn('GRANT EXECUTE', SQL)
        self.assertIn('REVOKE ALL ON raw.spawn_policies,raw.spawn_operations,raw.spawn_fingerprints FROM PUBLIC,paddock_app', SQL)
        self.assertNotRegex(SQL, r'GRANT\s+(?:SELECT|INSERT|UPDATE|DELETE|ALL).*ON\s+(?:TABLE\s+)?raw\.(?:work_orders|work_order_dependencies)')

    def test_root_caps_and_db_current_digest_recheck(self):
        for token in ('max_spawn_depth','max_total_descendants','max_live_children','max_attempts_per_work_order','max_repeat_fingerprint','root_deadline'):
            self.assertIn(token, SQL)
        self.assertIn("clock_timestamp()>=policy.root_deadline", SQL)
        self.assertIn("pull_state IN('QUEUED','READY','RUNNING')", SQL)
        self.assertIn('parent_id IS NOT NULL', SQL)
        self.assertIn('current_definition<>p_definition_digest OR current_policy<>p_policy_digest', SQL)
        self.assertIn('pg_advisory_xact_lock(hashtextextended(p_root,0))', SQL)
        self.assertIn('fingerprint occurrence cap', SQL)

    def test_closed_dependencies_and_persisted_mapping(self):
        self.assertIn("p->>'parent_work_order_id'", SQL)
        self.assertIn("p->'tasks'", SQL)
        self.assertIn('dependency outside proposal', SQL)
        self.assertIn("ids:=ids||jsonb_build_object(k,wid)", SQL)
        self.assertIn('INSERT INTO raw.work_orders(work_order_id,root_id,parent_id', SQL)
        self.assertIn('INSERT INTO raw.work_order_dependencies(root_id,work_order_id,depends_on_id)', SQL)
        self.assertIn('INSERT INTO raw.spawn_operations VALUES(p_root,p_operation,stored_request,result)', SQL)
        self.assertIn("'_semantic_fingerprints',p_fingerprints", SQL)
        self.assertIn('INSERT INTO raw.spawn_fingerprints', SQL)
        self.assertIn('fingerprint keys must match proposal tasks', SQL)
        self.assertIn('duplicate dependency edge', SQL)
        self.assertIn('invalid task key/content/fingerprint', SQL)

    def test_replay_conflict_and_atomic_transaction(self):
        self.assertIn('SELECT so.* INTO prior FROM raw.spawn_operations AS so', SQL)
        self.assertIn('prior.request<>stored_request', SQL)
        self.assertIn("'_root_id',p_root", SQL)
        self.assertIn("'_semantic_fingerprints',p_fingerprints", SQL)
        self.assertIn('RETURN prior.result', SQL)
        self.assertRegex(SQL, r'(?s)BEGIN;.*COMMIT;')
        self.assertNotRegex(SQL, r'EXCEPTION\s+WHEN\s+OTHERS')

    def test_policy_set_same_replay_and_conflict(self):
        self.assertIn('SELECT so.* INTO prior FROM raw.spawn_operations AS so', SQL)
        self.assertIn("prior.request<>jsonb_build_object('kind','policy','policy',p)", SQL)
        self.assertIn("'kind','policy','policy',p", SQL)
        self.assertIn('spawn policy immutable', SQL)

    def test_policy_replay_avoids_result_column_ambiguity(self):
        body = SQL.split('CREATE FUNCTION raw.spawn_policy_set',1)[1].split('END $$;',1)[0]
        self.assertRegex(body, r'SELECT\s+so\.\*\s+INTO\s+prior\s+FROM\s+raw\.spawn_operations\s+AS\s+so')
        self.assertRegex(body, r'SELECT\s+so\.result\s+INTO\s+result\s+FROM\s+raw\.spawn_operations\s+AS\s+so')
        self.assertNotRegex(body, r'SELECT\s+result\s+INTO\s+result')

    def test_strict_request_and_db_digest_authority(self):
        for token in ("jsonb_object_keys(p)", "p ? 'parent_work_order_id'", "p ? 'tasks'", "jsonb_object_keys(task)", "task ? 'depends_on'", "k !~", "btrim(task->>'title')", "d.value#>>'{}'=k", 'current_definition IS NULL', 'p_definition_digest IS NULL'):
            self.assertIn(token, SQL)
        self.assertIn('fingerprint keys must match proposal tasks', SQL)
        self.assertIn("fp !~ '^[0-9a-f]{64}$'", SQL)
        self.assertIn("current_definition<>p_definition_digest OR current_policy<>p_policy_digest", SQL)

    def test_spawn_fingerprint_context_is_fixed_path_secdef_and_app_only(self):
        body = SQL.split('CREATE FUNCTION raw.spawn_fingerprint_context', 1)[1].split('END $$;', 1)[0]
        declaration = body.split('BEGIN', 1)[0]
        self.assertRegex(declaration, r'\(p_root text,p_parent_work_order_id text\)')
        self.assertRegex(declaration, r'RETURNS TABLE\s*\(effective_bundle_digest text,policy_digest text\)')
        self.assertIn('SECURITY DEFINER SET search_path=pg_catalog', declaration)
        self.assertNotRegex(declaration, r'SET\s+search_path\s*=\s*pg_catalog\s*,')
        self.assertIn("IF session_user<>'paddock_app'", body)
        self.assertRegex(
            body,
            r'SELECT\s+r\.effective_bundle_digest::text\s*,\s*w\.policy_digest::text\s+'
            r'INTO\s+effective_bundle_digest\s*,\s*policy_digest\s+'
            r'FROM\s+raw\.roots\s+AS\s+r\s+'
            r'JOIN\s+raw\.work_orders\s+AS\s+w\s+ON\s+w\.root_id=r\.root_id\s+'
            r'WHERE\s+r\.root_id=p_root\s+AND\s+w\.work_order_id=p_parent_work_order_id',
        )
        self.assertNotRegex(body, r'RETURN\s+QUERY')
        denial = re.search(
            r'IF\s+NOT\s+FOUND\s+OR\s+effective_bundle_digest\s+IS\s+NULL\s+'
            r'OR\s+policy_digest\s+IS\s+NULL\s+THEN\s+RAISE\s+EXCEPTION',
            body,
            re.IGNORECASE,
        )
        self.assertIsNotNone(denial)
        self.assertRegex(body[denial.end():], r'\bRETURN\s+NEXT\s*;')
        self.assertIn('ALTER FUNCTION raw.spawn_fingerprint_context(text,text) OWNER TO paddock_migrator', SQL)
        self.assertIn('REVOKE ALL ON FUNCTION raw.spawn_fingerprint_context(text,text) FROM PUBLIC', SQL)
        grants = re.findall(r'GRANT\s+\w+\s+ON\s+FUNCTION\s+raw\.spawn_fingerprint_context\(text,text\)\s+TO\s+([^;]+);', SQL, re.IGNORECASE)
        self.assertEqual(grants, ['paddock_app'])

    def test_spawn_store_uses_context_helper_not_direct_table_selects(self):
        self.assertIn('raw.spawn_fingerprint_context($1,$2)', SPAWN_STORE)
        self.assertNotRegex(SPAWN_STORE, r'(?is)\bSELECT\b[^;]*\bFROM\s+raw\.(?:roots|work_orders)\b')

    def test_task_key_must_be_json_string_before_text_coercion(self):
        body = SQL.split("FOR task IN SELECT value FROM jsonb_array_elements(p->'tasks') LOOP", 1)[1].split("END LOOP;", 1)[0]
        self.assertLess(body.index("jsonb_typeof(task->'key')<>'string'"), body.index("k:=task->>'key'"))

    def test_lease_cap_inside_function_before_attempt_insert(self):
        body = SQL.split('CREATE OR REPLACE FUNCTION raw.issue_work_order_lease',1)[1].split('END $$;',1)[0]
        original = LEASE.split('CREATE FUNCTION raw.issue_work_order_lease',1)[1].split('END $$;',1)[0]
        for arg in ('text,text,text,text,text,jsonb,jsonb,interval','attempt_id text,slot_id text,lease_epoch bigint,expires_at timestamptz'):
            self.assertIn(arg, SQL)
        self.assertIn('max_attempts_per_work_order', body)
        self.assertIn('attempt_cap IS NULL AND attempts>0', body)
        self.assertIn('attempts>=attempt_cap', body)
        self.assertLess(body.index('attempts>=attempt_cap'), body.index('INSERT INTO raw.work_order_attempts'))
        self.assertIn('INSERT INTO raw.work_order_attempts', original)
        for preserved in ('capability_requirements_configured','work_order_capability_requirements','work_order_dependencies','clock_timestamp()','work_order_pull_slots','work_order_leases','UPDATE raw.work_orders SET pull_state=\'RUNNING\''):
            self.assertIn(preserved, body)
        self.assertIn('SET search_path=pg_catalog', body)
        self.assertIn('GRANT EXECUTE ON FUNCTION raw.issue_work_order_lease', SQL)

    def test_no_placeholder_or_destructive_ddl(self):
        self.assertNotIn('must use configured work-order schema adapter', SQL)
        upper=SQL.upper()
        for forbidden in ('DROP ','TRUNCATE ','CREATE EXTENSION','ALTER SYSTEM'):
            self.assertNotIn(forbidden, upper)

if __name__ == '__main__':
    unittest.main()

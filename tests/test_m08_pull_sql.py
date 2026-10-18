import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

def normalized_sql(path):
    return ' '.join((ROOT/path).read_text().split()).lower()

class PullSQLContract(unittest.TestCase):
    def test_capability_repair_is_guarded_and_narrow(self):
        sql = normalized_sql('sql/governance_pull_capability_repair.sql')
        self.assertIn("current_database() <> 'paddock_test'", sql)
        self.assertIn("current_user <> 'paddock_migrator'", sql)
        self.assertIn('paddock_migrator must own all five pull relations', sql)
        self.assertIn('position(\'jsonb_object_length\' in existing_definition)', sql)
        self.assertIn('create or replace function raw.configure_work_order_capabilities', sql)
        self.assertIn('jsonb_object_keys(item)', sql)
        self.assertNotIn('jsonb_object_length(item)', sql)
        self.assertNotRegex(sql, r'\b(drop|alter role|grant|revoke)\b')

    def test_up_queued_dependency_gated_and_unique_slot(self):
        sql=normalized_sql('sql/governance_pull.sql')
        self.assertIn("current_database()<>'paddock_test'", sql)
        self.assertIn("pull_state text not null default 'queued'", sql)
        self.assertIn("predecessor.pull_state<>'done'", sql)
        self.assertIn('capability_requirements_configured boolean not null default false', sql)
        self.assertIn('create table raw.work_order_capability_requirements', sql)
        self.assertIn('create function raw.configure_work_order_capabilities', sql)
        self.assertGreaterEqual(sql.count('security definer set search_path=pg_catalog'), 3)
        self.assertIn('from raw.work_orders where work_order_id=p_work_order_id for update', sql)
        self.assertIn('alter function raw.reserve_work_order_pull', sql)
        self.assertIn("rolname='paddock_migrator' and not rolsuper and not rolcreaterole and not rolcreatedb and not rolreplication and not rolbypassrls", sql)
        preflight_end = sql.index('alter table raw.work_orders')
        for guard in ("current_user<>'paddock_migrator'", 'not rolcreaterole', 'not rolcreatedb',
                      'not rolreplication', 'pg_catalog.pg_auth_members',
                      "granted_role.rolname in ('paddock_app','paddock_migrator')",
                      "member_role.rolname in ('paddock_app','paddock_migrator')"):
            self.assertIn(guard, sql[:preflight_end])
        self.assertIn("rolname='paddock_app' and not rolsuper and not rolcreaterole and not rolcreatedb and not rolreplication and not rolbypassrls", sql[:preflight_end])
        self.assertIn('paddock_migrator must own all five pull relations', sql)
        self.assertIn('create function raw.reserve_work_order_pull', sql)
        self.assertIn('for update', sql)
        self.assertIn('from raw.work_order_dependencies', sql)
        self.assertIn("predecessor.pull_state<>'done'", sql)
        self.assertIn('return query select p_attempt_id,p_slot_id', sql)
        self.assertIn('revoke all on table raw.work_orders,raw.work_order_dependencies,raw.work_order_attempts,raw.work_order_pull_slots,raw.work_order_capability_requirements from public,paddock_app', sql)
        self.assertIn('revoke all (%i) on table %i.%i from public,paddock_app', sql)
        self.assertIn('revoke all on table', sql)
        self.assertIn("'select','insert','update','delete','truncate','references','trigger'", (ROOT/'internal/storage/postgres/pull_integration_test.go').read_text().lower())
        self.assertIn("'select','insert','update','references'", (ROOT/'internal/storage/postgres/pull_integration_test.go').read_text().lower())
        self.assertIn('raw.configure_work_order_capabilities(text,jsonb),raw.mark_work_order_pull_ready(text),raw.reserve_work_order_pull(text,text,text,text,jsonb,jsonb) from public', sql)
        self.assertIn('raw.configure_work_order_capabilities(text,jsonb),raw.mark_work_order_pull_ready(text),raw.reserve_work_order_pull(text,text,text,text,jsonb,jsonb) to paddock_app', sql)
        self.assertIn('and w.capability_requirements_configured', sql)
        self.assertIn('duplicate capability requirement name', sql)
        self.assertIn("pull_state='queued' and not capability_requirements_configured", sql)
        self.assertIn('(select count(*) from jsonb_object_keys(item))<>2', sql)
        self.assertNotIn('jsonb_object_length(item)', sql)
        self.assertIn("item->>'name'<>btrim(item->>'name')", sql)
        self.assertIn("item->>'value'<>btrim(item->>'value')", sql)
        self.assertIn('insert into raw.work_order_capability_requirements', sql)
        self.assertLess(sql.index('insert into raw.work_order_capability_requirements'), sql.index('update raw.work_orders set capability_requirements_configured=true'))
        self.assertIn('zero requirement rows is explicitly unconstrained', sql)
        self.assertIn('create function raw.mark_work_order_pull_ready', sql)
        self.assertIn('work_order_id text primary key references raw.work_orders', sql)
        self.assertIn('slot_id text not null unique', sql)
        self.assertIn("'queued','ready','running','done'", sql)
        self.assertIn('lease/completion apis are not implemented here', sql)
        self.assertNotRegex(sql, r'(?i)\b(CASCADE|DROP DATABASE|DROP SCHEMA)\b')

    def test_migration_order_ownership_and_app_boundary(self):
        sql=normalized_sql('sql/governance_pull.sql')
        functions = ('configure_work_order_capabilities', 'mark_work_order_pull_ready', 'reserve_work_order_pull')
        creates = [sql.index(f'create function raw.{name}') for name in functions]
        owner_change = sql.index('alter function raw.configure_work_order_capabilities')
        revoke = sql.index('revoke all on function raw.configure_work_order_capabilities')
        grant = sql.index('grant execute on function raw.configure_work_order_capabilities')
        self.assertTrue(all(pos < owner_change < revoke < grant for pos in creates))
        self.assertLess(max(creates), owner_change)
        table_creates = [sql.index('create table raw.work_order_capability_requirements'), sql.index('create table raw.work_order_pull_slots')]
        owner_check = sql.index('paddock_migrator must own all five pull relations')
        self.assertTrue(all(pos < owner_check for pos in table_creates))
        self.assertLess(owner_check, min(creates))
        self.assertIn("current_user<>'paddock_migrator'", sql[:sql.index('alter table raw.work_orders')])
        self.assertIn("c.relname in ('work_orders','work_order_dependencies','work_order_attempts')", sql)
        self.assertIn("rolname='paddock_migrator' and not rolsuper and not rolcreaterole and not rolcreatedb and not rolreplication and not rolbypassrls", sql)
        self.assertIn("rolname='paddock_app'", sql)
        self.assertIn('revoke all on table raw.work_orders,raw.work_order_dependencies,raw.work_order_attempts,raw.work_order_pull_slots,raw.work_order_capability_requirements from public,paddock_app', sql)
        self.assertIn('revoke all (%i) on table %i.%i from public,paddock_app', sql)
        self.assertNotRegex(sql, r'(?i)GRANT\s+(SELECT|INSERT|UPDATE|DELETE|ALL)(?:\s*\([^)]*\))?\s+ON\s+(?:TABLE\s+)?raw\.(?:work_orders|work_order_dependencies|work_order_attempts|work_order_pull_slots|work_order_capability_requirements)')
        self.assertNotIn('grant select on raw.work_order_capability_requirements', sql)
        self.assertNotRegex(sql, r'(?i)GRANT\s+\w+\s+ON\s+(?:TABLE\s+)?raw\.(?:work_orders|work_order_dependencies|work_order_attempts|work_order_pull_slots|work_order_capability_requirements)\s+TO\s+(?:PUBLIC|paddock_app)')
        self.assertNotRegex(sql, r'(?i)COMMENT[^;]*\bSELECT\b[^;]*paddock_app')
        self.assertEqual(sql.count('alter function '), 3)
        self.assertEqual(sql.count('grant execute on function'), 1)

    def test_reservation_uses_persisted_canonical_requirements(self):
        store=(ROOT/'internal/storage/postgres/pull_store.go').read_text()
        self.assertIn('raw.issue_work_order_lease', store)
        self.assertNotIn('raw.reserve_work_order_pull', store)
        self.assertIn('canonicalRequirements = []scheduler.CapabilityRequirement{}', store)
        self.assertIn('canonicalEvidence = []scheduler.Evidence{}', store)
        self.assertIn('json.Marshal(canonicalRequirements)', store)
        self.assertIn('json.Marshal(canonicalEvidence)', store)
        scheduler=(ROOT/'internal/governance/scheduler/pull.go').read_text()
        self.assertIn('json:"name"', scheduler)
        self.assertIn('json:"value"', scheduler)
        pull = scheduler[scheduler.index('func (p *Puller) Pull('):]
        request_guard = pull.index('w.SessionID == "" || p.LeaseTTL <= 0')
        gates = pull.index('for _, gate := range')
        self.assertLess(request_guard, gates)
        self.assertIn('w.SessionID == ""', pull[:gates])
        self.assertIn('p.LeaseTTL <= 0', pull[:gates])
        self.assertNotIn('raw.work_orders', store)
        self.assertNotIn('raw.work_order_attempts', store)
        self.assertNotIn('raw.work_order_pull_slots', store)
        self.assertIn('sameRequirements', store)
        integration=(ROOT/'internal/storage/postgres/pull_integration_test.go').read_text()
        integration_lower = integration.lower()
        for fragment in ('has_table_privilege(\'paddock_app\'', 'prosecdef', 'search_path=pg_catalog',
                         'has_any_column_privilege', "'truncate','references','trigger'",
                         "p.prorettype <> 'trigger'::regtype",
                         'paddock_app', 'canonical DB requirements were accepted',
                         'reservation accepted mismatched evidence', 'empty policy accepted non-empty evidence',
                         'reservation winners=%d, want exactly 1'):
            self.assertIn(fragment.lower(), integration_lower)

    def test_down_is_scoped_and_targeted(self):
        sql=(ROOT/'sql/governance_pull_down.sql').read_text()
        self.assertIn("current_database()<>'paddock_test'", sql)
        self.assertIn("current_user<>'paddock_migrator'", sql)
        self.assertIn('pg_catalog.pg_class', sql)
        self.assertIn('pg_catalog.pg_proc', sql)
        self.assertIn("rolname='paddock_migrator'", sql)
        for name in ('work_orders', 'work_order_dependencies', 'work_order_attempts',
                     'work_order_pull_slots', 'work_order_capability_requirements'):
            self.assertIn(f"raw.{name}", sql)
        self.assertIn('DROP FUNCTION raw.mark_work_order_pull_ready(text)', sql)
        self.assertIn('DROP FUNCTION raw.configure_work_order_capabilities(text,jsonb)', sql)
        self.assertIn('DROP FUNCTION raw.reserve_work_order_pull(text,text,text,text,jsonb,jsonb)', sql)
        self.assertIn('DROP TABLE raw.work_order_pull_slots', sql)
        self.assertIn('DROP TABLE raw.work_order_capability_requirements', sql)
        self.assertIn('DROP COLUMN capability_requirements_configured', sql)
        self.assertIn('DROP COLUMN pull_state', sql)
        self.assertNotRegex(sql, r'(?i)\b(CASCADE|DROP DATABASE|DROP SCHEMA)\b')

if __name__=='__main__': unittest.main()

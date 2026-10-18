-- Additive follow-up migration. Apply only after sql/governance_budget.sql.
-- Never reapply the initial migration to a deployed database.
BEGIN;
DO $$ BEGIN
 IF current_database()<>'paddock_test' THEN RAISE EXCEPTION 'refusing storage-bytes migration outside paddock_test'; END IF;
 IF current_user<>'paddock_migrator' THEN RAISE EXCEPTION 'storage-bytes migration must run as paddock_migrator'; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='paddock_migrator' AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls)
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='paddock_app' AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid=m.roleid JOIN pg_catalog.pg_roles u ON u.oid=m.member WHERE r.rolname IN ('paddock_app','paddock_migrator') OR u.rolname IN ('paddock_app','paddock_migrator')) THEN RAISE EXCEPTION 'isolated non-elevated roles required'; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n JOIN pg_catalog.pg_roles r ON r.oid=n.nspowner WHERE n.nspname='raw' AND r.rolname='paddock_migrator') THEN RAISE EXCEPTION 'paddock_migrator must own raw schema'; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace JOIN pg_catalog.pg_roles r ON r.oid=c.relowner WHERE n.nspname='raw' AND c.relname='budget_accounts' AND c.relkind='r' AND r.rolname='paddock_migrator') THEN RAISE EXCEPTION 'paddock_migrator must own raw.budget_accounts'; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_constraint WHERE conrelid='raw.budget_accounts'::regclass AND conname='budget_accounts_resource_kind_check' AND contype='c') THEN RAISE EXCEPTION 'expected budget_accounts_resource_kind_check constraint is missing'; END IF;
END $$;
ALTER TABLE raw.budget_accounts DROP CONSTRAINT budget_accounts_resource_kind_check;
ALTER TABLE raw.budget_accounts ADD CONSTRAINT budget_accounts_resource_kind_check
 CHECK(resource_kind IN ('CURRENCY','TOKENS','COMPUTE','STORAGE_BYTES'));
ALTER TABLE raw.budget_accounts ADD CONSTRAINT budget_accounts_storage_bytes_unit_check
 CHECK(resource_kind<>'STORAGE_BYTES' OR unit_code='byte');
COMMIT;

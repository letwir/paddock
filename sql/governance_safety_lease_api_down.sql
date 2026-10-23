-- Source only: remove only the M07-S04 validator, with dependency protection.
\set ON_ERROR_STOP on
BEGIN;
DO $migration_guard$
BEGIN
    IF current_database() <> 'paddock_test' THEN
        RAISE EXCEPTION 'safety lease API down requires paddock_test';
    END IF;
    IF current_user <> 'paddock_migrator' OR session_user <> 'paddock_migrator' THEN
        RAISE EXCEPTION 'safety lease API down requires paddock_migrator';
    END IF;
    IF (SELECT count(*) FROM pg_catalog.pg_roles
        WHERE rolname IN ('paddock_app','paddock_migrator')
          AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb
          AND NOT rolreplication AND NOT rolbypassrls) <> 2
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m
          JOIN pg_catalog.pg_roles r ON r.oid=m.roleid
          JOIN pg_catalog.pg_roles u ON u.oid=m.member
          WHERE r.rolname IN ('paddock_app','paddock_migrator')
             OR u.rolname IN ('paddock_app','paddock_migrator')) THEN
        RAISE EXCEPTION 'isolated non-elevated roles without memberships required';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_proc p
        JOIN pg_catalog.pg_roles r ON r.oid=p.proowner
        WHERE p.oid=pg_catalog.to_regprocedure('raw.safety_validate_current_lease(text,text,text,text,text,text,bigint)')
          AND r.rolname='paddock_migrator' AND p.prosecdef
          AND p.proconfig @> ARRAY['search_path=pg_catalog']::text[]
          AND p.prorettype='boolean'::pg_catalog.regtype) THEN
        RAISE EXCEPTION 'expected migrator-owned safety lease validator required';
    END IF;
END
$migration_guard$;
DROP FUNCTION raw.safety_validate_current_lease(text,text,text,text,text,text,bigint) RESTRICT;
COMMIT;

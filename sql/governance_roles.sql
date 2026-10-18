-- Least-privilege grants for pre-provisioned PADDOCK roles.
-- Uses the pre-provisioned paddock_app and paddock_migrator roles.
-- Roles must already exist; this script never creates roles or handles passwords.
-- Example invocation: psql -v ON_ERROR_STOP=1 -v app_role=paddock_app -v migration_role=paddock_migrator -f sql/governance_roles.sql
-- Ownership transfers require execution by the authorized current owner or a superuser,
-- and exact S03 authorization for the target database and these ownership changes.
-- Apply only to paddock_test. This changes ownership and grants, not lifecycle.
-- Do not run against a live database without separate authorization.
\set ON_ERROR_STOP on
\if :{?app_role}
\else
  \set app_role __PADDOCK_REQUIRED_APP_ROLE_MISSING__
\endif
\if :{?migration_role}
\else
  \set migration_role __PADDOCK_REQUIRED_MIGRATION_ROLE_MISSING__
\endif

BEGIN;
SELECT set_config('paddock.app_role', :'app_role', true);
SELECT set_config('paddock.migration_role', :'migration_role', true);
DO $guard$
DECLARE
    app_name text := current_setting('paddock.app_role');
    migration_name text := current_setting('paddock.migration_role');
BEGIN
    IF current_database() <> 'paddock_test' THEN
        RAISE EXCEPTION 'refusing unexpected database %, expected paddock_test', current_database();
    END IF;
    IF app_name <> 'paddock_app' OR migration_name <> 'paddock_migrator' THEN
        RAISE EXCEPTION 'role variables must identify paddock_app and paddock_migrator';
    END IF;
    IF app_name !~ '^[a-zA-Z_][a-zA-Z_0-9$]{0,62}$'
       OR migration_name !~ '^[a-zA-Z_][a-zA-Z_0-9$]{0,62}$'
       OR app_name = migration_name THEN
        RAISE EXCEPTION 'role variables must be distinct valid PostgreSQL role identifiers';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = app_name)
       OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = migration_name) THEN
        RAISE EXCEPTION 'both roles must be provisioned by an authorized operator';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_roles
        WHERE rolname IN (app_name, migration_name)
          AND (rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls)
    ) THEN
        RAISE EXCEPTION 'PADDOCK roles must not have elevated role attributes';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_auth_members m
        JOIN pg_roles granted_role ON granted_role.oid = m.roleid
        JOIN pg_roles member_role ON member_role.oid = m.member
        WHERE granted_role.rolname IN (app_name, migration_name)
           OR member_role.rolname IN (app_name, migration_name)
    ) THEN
        RAISE EXCEPTION 'PADDOCK roles must have no role memberships in either direction';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'raw' AND r.rolname = app_name
    ) THEN
        RAISE EXCEPTION 'application role must not own raw relations';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_namespace n JOIN pg_roles r ON r.oid = n.nspowner
        WHERE n.nspname = 'raw' AND r.rolname = app_name
    ) THEN
        RAISE EXCEPTION 'application role must not own raw schema';
    END IF;
END
$guard$;

-- Make the pre-provisioned migration role the owner, so it can perform DDL.
-- psql's :'var' quoting is for values; :"var" safely quotes role identifiers.
ALTER SCHEMA raw OWNER TO :"migration_role";
ALTER TABLE raw.policy_bundles OWNER TO :"migration_role";
ALTER TABLE raw.policy_scopes OWNER TO :"migration_role";
ALTER TABLE raw.roots OWNER TO :"migration_role";
ALTER TABLE raw.policy_rollouts OWNER TO :"migration_role";
ALTER TABLE raw.rollout_targets OWNER TO :"migration_role";
ALTER TABLE raw.governance_approvals OWNER TO :"migration_role";
ALTER TABLE raw.command_receipts OWNER TO :"migration_role";
ALTER TABLE raw.domain_events OWNER TO :"migration_role";
ALTER TABLE raw.event_outbox OWNER TO :"migration_role";
ALTER TABLE raw.event_inbox OWNER TO :"migration_role";
ALTER TABLE raw.security_generation OWNER TO :"migration_role";

DO $ownership_check$
DECLARE
    migration_name text := current_setting('paddock.migration_role');
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_namespace n JOIN pg_roles r ON r.oid = n.nspowner
        WHERE n.nspname = 'raw' AND r.rolname = migration_name
    ) THEN
        RAISE EXCEPTION 'migration role must own raw schema after transfer';
    END IF;
    IF (SELECT count(*) FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_roles r ON r.oid = c.relowner
        WHERE n.nspname = 'raw' AND c.relkind IN ('r', 'p')
          AND c.relname IN ('policy_bundles', 'policy_scopes', 'roots', 'policy_rollouts',
              'rollout_targets', 'governance_approvals', 'command_receipts', 'domain_events',
              'event_outbox', 'event_inbox', 'security_generation')
          AND r.rolname = migration_name) <> 11 THEN
        RAISE EXCEPTION 'migration role must own all 11 raw base tables after transfer';
    END IF;
END
$ownership_check$;

-- Table-level revokes do not remove explicit column grants. Revoke every
-- column privilege on each current raw table column before granting app access.
DO $revoke_column_privileges$
DECLARE
    app_name text := current_setting('paddock.app_role');
    column_record record;
BEGIN
    FOR column_record IN
        SELECT n.nspname, c.relname, a.attname
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_attribute a ON a.attrelid = c.oid
        WHERE n.nspname = 'raw'
          AND c.relkind IN ('r', 'p')
          AND a.attnum > 0
          AND NOT a.attisdropped
        ORDER BY c.oid, a.attnum
    LOOP
        EXECUTE format(
            'REVOKE ALL (%I) ON TABLE %I.%I FROM PUBLIC, %I',
            column_record.attname,
            column_record.nspname,
            column_record.relname,
            app_name
        );
    END LOOP;
END
$revoke_column_privileges$;

-- Revoke inherited/default broad access first; grant only the application
-- operations needed for immutable bundle/event records. No PUBLIC grants.
REVOKE ALL ON SCHEMA raw FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA raw FROM PUBLIC;
REVOKE ALL ON SCHEMA raw FROM :"app_role";
REVOKE ALL ON ALL TABLES IN SCHEMA raw FROM :"app_role";
GRANT USAGE ON SCHEMA raw TO :"app_role";
GRANT SELECT, INSERT ON TABLE raw.policy_bundles, raw.domain_events TO :"app_role";

-- Migration authority is separate and explicitly broader, but limited to the
-- existing raw schema objects. Pre-created role membership/ownership remains
-- the operator's responsibility; these grants do not grant role membership.
GRANT USAGE, CREATE ON SCHEMA raw TO :"migration_role";
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA raw TO :"migration_role";
COMMIT;

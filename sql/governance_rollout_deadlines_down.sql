-- Source only. Refuse to discard any persisted monitoring evidence or window.
\set ON_ERROR_STOP on
BEGIN;
DO $migration_guard$
DECLARE
    relation_name text;
BEGIN
    IF current_database() <> 'paddock_test' THEN
        RAISE EXCEPTION 'rollout API requires paddock_test';
    END IF;
    IF current_user <> 'paddock_migrator' OR session_user <> 'paddock_migrator' THEN
        RAISE EXCEPTION 'rollout API requires paddock_migrator';
    END IF;
    IF (SELECT count(*) FROM pg_catalog.pg_roles
        WHERE rolname IN ('paddock_app', 'paddock_migrator')
          AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb
          AND NOT rolreplication AND NOT rolbypassrls) <> 2 THEN
        RAISE EXCEPTION 'isolated non-elevated app and migrator roles required';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_auth_members m
        JOIN pg_catalog.pg_roles granted_role ON granted_role.oid = m.roleid
        JOIN pg_catalog.pg_roles member_role ON member_role.oid = m.member
        WHERE granted_role.rolname IN ('paddock_app', 'paddock_migrator')
           OR member_role.rolname IN ('paddock_app', 'paddock_migrator')
    ) THEN
        RAISE EXCEPTION 'app and migrator must have no role memberships';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_namespace n
        JOIN pg_catalog.pg_roles r ON r.oid = n.nspowner
        WHERE n.nspname = 'raw' AND r.rolname = 'paddock_migrator'
    ) THEN
        RAISE EXCEPTION 'paddock_migrator must own raw';
    END IF;
    FOREACH relation_name IN ARRAY ARRAY[
        'policy_scopes', 'roots', 'policy_rollouts', 'rollout_targets', 'security_generation'
    ] LOOP
        IF NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_class c
            JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
            JOIN pg_catalog.pg_roles r ON r.oid = c.relowner
            WHERE n.nspname = 'raw' AND c.relname = relation_name
              AND c.relkind = 'r' AND r.rolname = 'paddock_migrator'
        ) THEN
            RAISE EXCEPTION 'raw.% must be a migrator-owned table', relation_name;
        END IF;
    END LOOP;
END
$migration_guard$;
DO $permission_guard$
BEGIN
    IF pg_catalog.has_schema_privilege('paddock_app', 'raw', 'CREATE') OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'raw' AND c.relname IN ('policy_rollouts','rollout_targets')
          AND (pg_catalog.has_table_privilege('paddock_app', c.oid, 'INSERT,UPDATE,DELETE,TRUNCATE')
            OR pg_catalog.has_any_column_privilege('paddock_app', c.oid, 'INSERT,UPDATE'))
    ) THEN
        RAISE EXCEPTION 'app must use only definer APIs for rollout writes';
    END IF;
END
$permission_guard$;

LOCK TABLE raw.policy_rollouts IN ACCESS EXCLUSIVE MODE;
DO $down_data_guard$
BEGIN
    IF EXISTS (SELECT 1 FROM raw.policy_rollouts WHERE monitoring_started_at IS NOT NULL) THEN
        RAISE EXCEPTION 'cannot remove persisted monitoring data';
    END IF;
END
$down_data_guard$;
DROP FUNCTION raw.safety_list_rollout_deadlines(integer);
DROP FUNCTION raw.safety_cas_rollout(jsonb,jsonb);
DROP FUNCTION raw.safety_rollout_monitoring(text,text);
DROP INDEX raw.policy_rollouts_due_deadline_idx;
ALTER TABLE raw.policy_rollouts DROP CONSTRAINT policy_rollouts_monitoring_window_ck;
ALTER TABLE raw.policy_rollouts
    DROP COLUMN decision_revision,
    DROP COLUMN evidence_digest,
    DROP COLUMN decision_at,
    DROP COLUMN monitoring_decision,
    DROP COLUMN extension_nonce,
    DROP COLUMN extension_command_id,
    DROP COLUMN extension_used,
    DROP COLUMN hold_budget,
    DROP COLUMN hold_used,
    DROP COLUMN hold_deadline,
    DROP COLUMN hold_since,
    DROP COLUMN observation_deadline,
    DROP COLUMN monitoring_last_observed_at,
    DROP COLUMN monitoring_started_at;
COMMIT;

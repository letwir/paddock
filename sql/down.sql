-- PADDOCK initial Governance schema down migration (PostgreSQL).
-- This script removes only the 11 named raw tables; it does not drop a schema,
-- database, role, or unrelated object. Review the target before running.
--
-- SAFETY: refuses to run unless current_database() is exactly 'paddock_test'.
-- This name guard does not prove that the database is disposable. The existing
-- PADDOCK_DB_URL target is populated; do not run this script against it without
-- explicit authorization for that exact task and target.
--
-- Operator usage (only on an explicitly authorized disposable paddock_test DB):
--   psql "$PADDOCK_DB_URL" -X -v ON_ERROR_STOP=1 -f sql/down.sql
-- PADDOCK_DB_URL must be injected by the operator; never store or print its value.
-- psql ON_ERROR_STOP makes SQL errors stop the script; because all DDL is inside
-- one transaction, an error followed by connection close rolls the transaction back.

\set ON_ERROR_STOP on
BEGIN;

DO $$
BEGIN
    IF current_database() <> 'paddock_test' THEN
        RAISE EXCEPTION 'refusing to remove PADDOCK tables from unexpected database %, expected paddock_test', current_database();
    END IF;
END
$$;

-- Break the deferred circular dependency before dropping either table.
ALTER TABLE IF EXISTS raw.policy_scopes
    DROP CONSTRAINT IF EXISTS policy_scopes_live_rollout_scope_fk;

-- Reverse dependency order for tables created by sql/init.sql.
DROP TABLE IF EXISTS raw.rollout_targets;
DROP TABLE IF EXISTS raw.governance_approvals;
DROP TABLE IF EXISTS raw.policy_rollouts;
DROP TABLE IF EXISTS raw.roots;
DROP TABLE IF EXISTS raw.policy_scopes;
DROP TABLE IF EXISTS raw.policy_bundles;
DROP TABLE IF EXISTS raw.event_outbox;
DROP TABLE IF EXISTS raw.domain_events;
DROP TABLE IF EXISTS raw.command_receipts;
DROP TABLE IF EXISTS raw.event_inbox;
DROP TABLE IF EXISTS raw.security_generation;

COMMIT;

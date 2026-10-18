-- Additive Governance constraints for the dedicated PADDOCK test database.
-- This migration never creates/drops a database, schema, or table.
-- Apply only to paddock_test after the base schema in sql/init.sql exists.

BEGIN;

DO $$
BEGIN
    IF current_database() <> 'paddock_test' THEN
        RAISE EXCEPTION 'refusing governance constraints migration on %, expected paddock_test', current_database();
    END IF;

    IF to_regclass('raw.policy_rollouts') IS NULL THEN
        RAISE EXCEPTION 'required base table raw.policy_rollouts is missing';
    END IF;
END
$$;

-- D-011: exactly one active rollout per scope. SHADOW candidates may coexist;
-- HOLD is a monitoring decision, not a persisted state: a held rollout remains
-- MONITORING and therefore retains its active slot.
CREATE UNIQUE INDEX IF NOT EXISTS policy_rollouts_one_active_per_scope_uidx
    ON raw.policy_rollouts (scope_id)
    WHERE state IN ('CANARY', 'MONITORING', 'ROLLING_BACK');

COMMIT;

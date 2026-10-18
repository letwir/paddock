-- Reverse only sql/governance_safety_constraints.sql objects.
-- This migration creates/drops no database, schema, or table.
-- Do not run against a live database; the guard only identifies paddock_test.

BEGIN;

DO $$
BEGIN
    IF current_database() <> 'paddock_test' THEN
        RAISE EXCEPTION 'refusing governance safety rollback on %, expected paddock_test', current_database();
    END IF;

    IF to_regclass('raw.policy_scopes') IS NULL
       OR to_regclass('raw.policy_rollouts') IS NULL THEN
        RAISE EXCEPTION 'required base tables raw.policy_scopes and raw.policy_rollouts must exist';
    END IF;
END
$$;

DROP TRIGGER IF EXISTS policy_scopes_frozen_rollback_ct ON raw.policy_scopes;
DROP TRIGGER IF EXISTS policy_rollouts_frozen_rollback_ct ON raw.policy_rollouts;

DROP FUNCTION IF EXISTS raw.enforce_frozen_scope_rollback();
DROP FUNCTION IF EXISTS raw.prevent_frozen_rollout_leaving_rollback();

ALTER TABLE raw.policy_scopes
    DROP CONSTRAINT IF EXISTS policy_scopes_frozen_requires_live_rollout_ck;

COMMIT;

-- Enforce the D-017 rollback-only meaning of policy_scopes.mode = 'FROZEN'.
-- SAFE_STOPPED continues to use the embedded deny-all baseline; no column is added.
-- Apply only after sql/init.sql on the dedicated paddock_test database.
-- This migration creates no database, schema, or table and must not be run live.

BEGIN;

DO $$
BEGIN
    IF current_database() <> 'paddock_test' THEN
        RAISE EXCEPTION 'refusing governance safety migration on %, expected paddock_test', current_database();
    END IF;

    IF to_regclass('raw.policy_scopes') IS NULL
       OR to_regclass('raw.policy_rollouts') IS NULL THEN
        RAISE EXCEPTION 'required base tables raw.policy_scopes and raw.policy_rollouts must exist';
    END IF;
END
$$;

-- This row-local invariant is immediate, independent of the deferred cross-table checks.
ALTER TABLE raw.policy_scopes
    ADD CONSTRAINT policy_scopes_frozen_requires_live_rollout_ck
    CHECK (mode <> 'FROZEN' OR live_rollout_id IS NOT NULL);

CREATE FUNCTION raw.enforce_frozen_scope_rollback()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
    current_mode text;
    current_rollout_id text;
    rollout_state text;
BEGIN
    -- Serialize this deferred cross-table check against concurrent state changes.
    -- Keep the global lock order scope -> rollout. Existing UPDATE locks can still
    -- form a deadlock; SQLSTATE 40P01 (deadlock) and 40001 (serialization failure)
    -- abort the transaction. The caller must retry the whole transaction; there is
    -- no automatic retry and neither error means commit succeeded.
    SELECT scope.mode, scope.live_rollout_id
      INTO current_mode, current_rollout_id
      FROM raw.policy_scopes AS scope
     WHERE scope.scope_id = NEW.scope_id
     FOR UPDATE;

    IF NOT FOUND OR current_mode <> 'FROZEN' THEN
        RETURN NULL;
    END IF;

    SELECT rollout.state
      INTO rollout_state
      FROM raw.policy_rollouts AS rollout
     WHERE rollout.rollout_id = current_rollout_id
       AND rollout.scope_id = NEW.scope_id
     FOR UPDATE;

    IF NOT FOUND OR rollout_state <> 'ROLLING_BACK' THEN
        RAISE EXCEPTION 'FROZEN scope % must reference a same-scope ROLLING_BACK rollout', NEW.scope_id
            USING ERRCODE = 'check_violation';
    END IF;

    RETURN NULL;
END
$$;

CREATE FUNCTION raw.prevent_frozen_rollout_leaving_rollback()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
    current_state text;
BEGIN
    -- Lock scope first, then rollout, matching the companion deferred trigger.
    -- Concurrent UPDATE locks may nevertheless deadlock; SQLSTATE 40P01 (deadlock)
    -- and 40001 (serialization failure) abort the transaction. The caller must
    -- retry the whole transaction; there is no automatic retry or commit success.
    IF OLD.state = 'ROLLING_BACK' THEN
        PERFORM 1
          FROM raw.policy_scopes AS scope
         WHERE scope.scope_id = OLD.scope_id
         FOR UPDATE;

        SELECT rollout.state
          INTO current_state
          FROM raw.policy_rollouts AS rollout
         WHERE rollout.rollout_id = OLD.rollout_id
           AND rollout.scope_id = OLD.scope_id
         FOR UPDATE;

        IF FOUND AND current_state <> 'ROLLING_BACK' AND EXISTS (
            SELECT 1
              FROM raw.policy_scopes AS scope
             WHERE scope.mode = 'FROZEN'
               AND scope.live_rollout_id = OLD.rollout_id
               AND scope.scope_id = OLD.scope_id
        ) THEN
            RAISE EXCEPTION 'rollout % cannot leave ROLLING_BACK while its scope remains FROZEN', OLD.rollout_id
                USING ERRCODE = 'check_violation';
        END IF;
    END IF;

    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER policy_scopes_frozen_rollback_ct
AFTER INSERT OR UPDATE ON raw.policy_scopes
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION raw.enforce_frozen_scope_rollback();

CREATE CONSTRAINT TRIGGER policy_rollouts_frozen_rollback_ct
AFTER UPDATE ON raw.policy_rollouts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION raw.prevent_frozen_rollout_leaving_rollback();

COMMIT;

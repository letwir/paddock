-- S06 safety-mode positive/negative fixture. Do not run as part of offline tests.
-- Requires sql/init.sql, sql/governance_constraints.sql, and
-- sql/governance_safety_constraints.sql. All rows are transaction-local.
\set ON_ERROR_STOP on
BEGIN;

DO $$
BEGIN
    IF current_database() <> 'paddock_test' THEN
        RAISE EXCEPTION 'expected paddock_test, connected to %', current_database();
    END IF;
    IF to_regclass('raw.policy_scopes') IS NULL
       OR to_regclass('raw.policy_rollouts') IS NULL THEN
        RAISE EXCEPTION 'required safety fixture tables are missing';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = 'raw.policy_scopes'::regclass
                   AND NOT tgisinternal AND tgname = 'policy_scopes_frozen_rollback_ct')
       OR NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = 'raw.policy_rollouts'::regclass
                      AND NOT tgisinternal AND tgname = 'policy_rollouts_frozen_rollback_ct') THEN
        RAISE EXCEPTION 'S06 deferred constraint triggers are missing';
    END IF;
END
$$;

INSERT INTO raw.policy_bundles
    (bundle_digest, canonical_bytes, schema_version, signer_key_id, signature)
VALUES ('caaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', '\x01', 'v1', 'fixture-s06-signer', '\x01');

INSERT INTO raw.policy_scopes (scope_id, baseline_bundle_digest, mode)
VALUES ('fixture-s06-scope-a', 'caaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'ACTIVE'),
       ('fixture-s06-scope-b', 'caaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'ACTIVE');
INSERT INTO raw.roots (root_id, scope_id, effective_bundle_digest)
VALUES ('fixture-s06-root-a', 'fixture-s06-scope-a', 'caaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
       ('fixture-s06-root-b', 'fixture-s06-scope-b', 'caaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');

-- Immediate CHECK: no savepoint/constraint forcing is needed for a missing id.
DO $$
BEGIN
    BEGIN
        UPDATE raw.policy_scopes SET mode = 'FROZEN', live_rollout_id = NULL
        WHERE scope_id = 'fixture-s06-scope-b';
        RAISE EXCEPTION 'expected immediate CHECK to reject FROZEN without live id';
    EXCEPTION WHEN check_violation OR raise_exception THEN
        IF SQLSTATE = 'P0001' AND SQLERRM LIKE 'expected immediate CHECK%' THEN RAISE; END IF;
    END;
END
$$;

-- Valid same-scope rollback: the FK is deferred, allowing the paired rows to be
-- built first; forcing both named deferred triggers validates the final state.
INSERT INTO raw.policy_rollouts
    (rollout_id, scope_id, state, target_root_id, base_activation_epoch,
     last_activation_epoch, base_security_epoch, rollback_from)
VALUES ('fixture-s06-rollback-a', 'fixture-s06-scope-a', 'ROLLING_BACK',
        'fixture-s06-root-a', 0, 0, 0, 'MONITORING');
UPDATE raw.policy_scopes SET mode = 'FROZEN', live_rollout_id = 'fixture-s06-rollback-a'
WHERE scope_id = 'fixture-s06-scope-a';
SET CONSTRAINTS ALL IMMEDIATE;
SET CONSTRAINTS ALL DEFERRED;

-- Wrong-scope and wrong-state cases are forced inside exception subtransactions,
-- so the expected deferred violation rolls back only that case.
DO $$
BEGIN
    BEGIN
        UPDATE raw.policy_scopes SET mode = 'FROZEN', live_rollout_id = 'fixture-s06-rollback-a'
        WHERE scope_id = 'fixture-s06-scope-b';
        SET CONSTRAINTS ALL IMMEDIATE;
        RAISE EXCEPTION 'expected wrong-scope live rollout to be rejected';
    EXCEPTION WHEN check_violation OR foreign_key_violation OR raise_exception THEN
        IF SQLSTATE = 'P0001' AND SQLERRM LIKE 'expected wrong-scope%' THEN RAISE; END IF;
    END;
    SET CONSTRAINTS ALL DEFERRED;

    INSERT INTO raw.policy_rollouts
        (rollout_id, scope_id, state, target_root_id, base_activation_epoch,
         last_activation_epoch, base_security_epoch)
    VALUES ('fixture-s06-shadow-b', 'fixture-s06-scope-b', 'SHADOW',
            'fixture-s06-root-b', 0, 0, 0);
    BEGIN
        UPDATE raw.policy_scopes SET mode = 'FROZEN', live_rollout_id = 'fixture-s06-shadow-b'
        WHERE scope_id = 'fixture-s06-scope-b';
        SET CONSTRAINTS ALL IMMEDIATE;
        RAISE EXCEPTION 'expected wrong-state live rollout to be rejected';
    EXCEPTION WHEN check_violation OR raise_exception THEN
        IF SQLSTATE = 'P0001' AND SQLERRM LIKE 'expected wrong-state%' THEN RAISE; END IF;
    END;
    SET CONSTRAINTS ALL DEFERRED;
END
$$;

-- Existing init.sql mode CHECK and nullable-baseline CHECK define SAFE_STOPPED;
-- this fixture asserts acceptance of NULL baseline, without migration-only token.
UPDATE raw.policy_scopes SET mode = 'SAFE_STOPPED', baseline_bundle_digest = NULL, live_rollout_id = NULL
WHERE scope_id = 'fixture-s06-scope-b';
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM raw.policy_scopes WHERE scope_id = 'fixture-s06-scope-b'
                   AND mode = 'SAFE_STOPPED' AND baseline_bundle_digest IS NULL) THEN
        RAISE EXCEPTION 'SAFE_STOPPED with NULL baseline was not retained';
    END IF;
END
$$;

ROLLBACK;

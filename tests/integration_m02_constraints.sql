-- S02 acceptance fixture for scope-consistent rollout constraints.
-- Run against the dedicated test database after sql/init.sql and
-- sql/governance_constraints.sql have been applied:
--   psql "$PADDOCK_DB_URL" -X -v ON_ERROR_STOP=1 -f tests/integration_m02_constraints.sql
-- The script performs no committed mutations; all fixture rows are rolled back.

\set ON_ERROR_STOP on

BEGIN;

DO $$
BEGIN
    IF current_database() <> 'paddock_test' THEN
        RAISE EXCEPTION 'expected paddock_test, connected to %', current_database();
    END IF;

    IF to_regclass('raw.policy_rollouts_one_active_per_scope_uidx') IS NULL THEN
        RAISE EXCEPTION 'required active-rollout index is missing';
    END IF;

    IF (
        SELECT count(*)
        FROM pg_constraint
        WHERE connamespace = 'raw'::regnamespace
          AND contype = 'f'
          AND conrelid IN ('raw.policy_scopes'::regclass,
                           'raw.policy_rollouts'::regclass,
                           'raw.rollout_targets'::regclass)
          AND (
              (conrelid = 'raw.policy_scopes'::regclass
               AND conname = 'policy_scopes_live_rollout_scope_fk')
              OR (conrelid = 'raw.policy_rollouts'::regclass
                  AND conname = 'policy_rollouts_target_root_id_scope_id_fkey')
              OR (conrelid = 'raw.rollout_targets'::regclass
                  AND conname IN ('rollout_targets_rollout_id_scope_id_fkey',
                                  'rollout_targets_root_id_scope_id_fkey'))
          )
          AND cardinality(conkey) = 2
          AND cardinality(confkey) = 2
    ) <> 4 THEN
        RAISE EXCEPTION 'one or more required composite scope foreign keys are missing';
    END IF;
END
$$;

INSERT INTO raw.policy_bundles
    (bundle_digest, canonical_bytes, schema_version, signer_key_id, signature)
VALUES
    ('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', '\x01', 'v1', 'fixture-signer', '\x01'),
    ('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', '\x02', 'v1', 'fixture-signer', '\x02');

INSERT INTO raw.policy_scopes (scope_id, baseline_bundle_digest)
VALUES
    ('fixture-s02-scope-a', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
    ('fixture-s02-scope-b', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');

INSERT INTO raw.roots (root_id, scope_id, effective_bundle_digest)
VALUES
    ('fixture-s02-root-a', 'fixture-s02-scope-a', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
    ('fixture-s02-root-b', 'fixture-s02-scope-b', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');

-- Multiple SHADOW candidates do not consume the active slot.
INSERT INTO raw.policy_rollouts
    (rollout_id, scope_id, state, target_root_id, base_activation_epoch,
     last_activation_epoch, base_security_epoch)
VALUES
    ('fixture-s02-shadow-a1', 'fixture-s02-scope-a', 'SHADOW', 'fixture-s02-root-a', 0, 0, 0),
    ('fixture-s02-shadow-a2', 'fixture-s02-scope-a', 'SHADOW', 'fixture-s02-root-a', 0, 0, 0);

-- CANARY and ROLLED_BACK may coexist in one scope; only active states are unique.
INSERT INTO raw.policy_rollouts
    (rollout_id, scope_id, state, target_root_id, base_activation_epoch,
     last_activation_epoch, base_security_epoch)
VALUES
    ('fixture-s02-canary-a', 'fixture-s02-scope-a', 'CANARY', 'fixture-s02-root-a', 0, 0, 0),
    ('fixture-s02-rolledback-a', 'fixture-s02-scope-a', 'ROLLED_BACK', 'fixture-s02-root-a', 0, 0, 0);

-- The second active rollout in scope A must fail specifically on the partial unique index.
DO $$
BEGIN
    BEGIN
        INSERT INTO raw.policy_rollouts
            (rollout_id, scope_id, state, target_root_id, base_activation_epoch,
             last_activation_epoch, base_security_epoch)
        VALUES
            ('fixture-s02-canary-a2', 'fixture-s02-scope-a', 'CANARY', 'fixture-s02-root-a', 0, 0, 0);
        RAISE EXCEPTION 'expected unique_violation for a second active rollout';
    EXCEPTION
        WHEN unique_violation THEN
            NULL;
    END;
END
$$;

-- A target cannot pair scope A's rollout with scope B's root.
INSERT INTO raw.policy_rollouts
    (rollout_id, scope_id, state, target_root_id, base_activation_epoch,
     last_activation_epoch, base_security_epoch)
VALUES
    ('fixture-s02-shadow-b', 'fixture-s02-scope-b', 'SHADOW', 'fixture-s02-root-b', 0, 0, 0);

DO $$
BEGIN
    BEGIN
        INSERT INTO raw.rollout_targets
            (rollout_id, scope_id, root_id, baseline_bundle_digest,
             candidate_bundle_digest, base_root_epoch)
        VALUES
            ('fixture-s02-shadow-b', 'fixture-s02-scope-b', 'fixture-s02-root-a',
             'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
             'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 0);
        RAISE EXCEPTION 'expected foreign_key_violation for a cross-scope rollout target';
    EXCEPTION
        WHEN foreign_key_violation THEN
            NULL;
    END;
END
$$;

ROLLBACK;

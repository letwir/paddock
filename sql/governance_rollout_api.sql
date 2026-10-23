-- M04-S01 app-only creation and expected-value Rollout/Target CAS.
-- Source only until separately approved; apply after governance_safety_api.sql
-- as paddock_migrator on the isolated paddock_test database.
-- No direct app table or column privileges are granted.
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

-- The scalar epochs are the locked pre-Canary epochs. State and last epoch
-- are derived, not arbitrary caller-selected insert values. Each target object
-- has exactly root_id,target,baseline_digest,candidate_digest,base_root_epoch.
CREATE OR REPLACE FUNCTION raw.safety_create_rollout(text, text, bigint, bigint, json)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $safety_create_rollout$
DECLARE
    v_scope raw.policy_scopes%ROWTYPE;
    v_security_epoch bigint;
    v_target json;
    v_target_root text;
    v_root_id text;
    v_root_ids text[] := ARRAY[]::text[];
    v_root raw.roots%ROWTYPE;
    v_key_count bigint;
    v_unknown_key boolean;
BEGIN
    IF session_user <> 'paddock_app' THEN
        RAISE EXCEPTION 'safety_create_rollout requires session_user paddock_app';
    END IF;
    IF $1 IS NULL OR $1 = '' OR $1 <> pg_catalog.btrim($1)
       OR $2 IS NULL OR $2 = '' OR $2 <> pg_catalog.btrim($2)
       OR $3 IS NULL OR $3 < 0 OR $4 IS NULL OR $4 < 0 THEN
        RAISE EXCEPTION 'invalid rollout identity or epochs';
    END IF;
    -- json preserves duplicates; validate them BEFORE json_array_elements or
    -- json object extraction. Never cast to jsonb (which would erase duplicates).
    IF $5 IS NULL OR NOT ($5 IS JSON ARRAY WITH UNIQUE KEYS) THEN
        RAISE EXCEPTION 'targets must be a JSON array with unique object keys';
    END IF;
    IF pg_catalog.json_array_length($5) = 0 THEN
        RAISE EXCEPTION 'targets must not be empty';
    END IF;
    FOR v_target IN SELECT value FROM pg_catalog.json_array_elements($5) LOOP
        IF pg_catalog.json_typeof(v_target) <> 'object' THEN
            RAISE EXCEPTION 'target must be an object';
        END IF;
        SELECT count(*), COALESCE(bool_or(k NOT IN
            ('root_id', 'target', 'baseline_digest', 'candidate_digest', 'base_root_epoch')), false)
          INTO v_key_count, v_unknown_key
          FROM pg_catalog.json_object_keys(v_target) AS keys(k);
        IF v_key_count <> 5 OR v_unknown_key THEN
            RAISE EXCEPTION 'target requires exactly the five named keys';
        END IF;
        IF pg_catalog.json_typeof(v_target->'root_id') <> 'string'
           OR pg_catalog.json_typeof(v_target->'target') <> 'boolean'
           OR pg_catalog.json_typeof(v_target->'baseline_digest') NOT IN ('string', 'null')
           OR pg_catalog.json_typeof(v_target->'candidate_digest') <> 'string'
           OR pg_catalog.json_typeof(v_target->'base_root_epoch') <> 'number' THEN
            RAISE EXCEPTION 'invalid target field types';
        END IF;
        v_root_id := v_target->>'root_id';
        IF v_root_id = '' OR v_root_id <> pg_catalog.btrim(v_root_id)
           OR v_root_id = ANY(v_root_ids)
           OR (v_target->>'baseline_digest' IS NOT NULL AND
               v_target->>'baseline_digest' !~ '^[0-9a-f]{64}$')
           OR v_target->>'candidate_digest' !~ '^[0-9a-f]{64}$'
           OR v_target->>'base_root_epoch' !~ '^(0|[1-9][0-9]*)$' THEN
            RAISE EXCEPTION 'invalid or duplicate target Root';
        END IF;
        -- Casting also rejects values outside PostgreSQL bigint range.
        PERFORM (v_target->>'base_root_epoch')::bigint;
        v_root_ids := pg_catalog.array_append(v_root_ids, v_root_id);
        IF (v_target->>'target')::boolean THEN
            IF v_target_root IS NOT NULL THEN
                RAISE EXCEPTION 'exactly one Canary Root is required';
            END IF;
            v_target_root := v_root_id;
        END IF;
    END LOOP;
    IF v_target_root IS NULL THEN
        RAISE EXCEPTION 'exactly one Canary Root is required';
    END IF;

    SELECT s.* INTO v_scope FROM raw.policy_scopes s WHERE s.scope_id = $2 FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'missing Scope';
    END IF;
    -- SHARE conflicts with the non-key UPDATE in safety_cas_security_epoch,
    -- keeping this expected generation stable until the caller transaction ends.
    SELECT sg.security_epoch INTO v_security_epoch FROM raw.security_generation sg
     WHERE sg.singleton_id = true FOR SHARE;
    IF NOT FOUND OR v_security_epoch <> $4 OR v_scope.activation_epoch <> $3
       OR v_scope.mode <> 'ACTIVE' OR v_scope.live_rollout_id IS NOT NULL THEN
        RAISE EXCEPTION 'stale Scope or Security Epoch';
    END IF;
    -- Same deterministic Root lock order as safety_lock_scope_roots. Recheck
    -- membership, baseline and epochs under these locks before inserting anything.
    PERFORM r.root_id FROM raw.roots r WHERE r.scope_id = $2 ORDER BY r.root_id FOR UPDATE;
    IF (SELECT count(*) FROM raw.roots r WHERE r.scope_id = $2) <> pg_catalog.cardinality(v_root_ids) THEN
        RAISE EXCEPTION 'targets must include every same-Scope Root';
    END IF;
    FOR v_target IN SELECT value FROM pg_catalog.json_array_elements($5) LOOP
        SELECT r.* INTO v_root FROM raw.roots r
         WHERE r.root_id = v_target->>'root_id' AND r.scope_id = $2;
        IF NOT FOUND OR v_root.authorization_epoch <> (v_target->>'base_root_epoch')::bigint
           OR v_root.effective_bundle_digest IS DISTINCT FROM v_target->>'baseline_digest'
           OR v_root.safe_baseline IS DISTINCT FROM (v_target->>'baseline_digest' IS NULL) THEN
            RAISE EXCEPTION 'stale or cross-Scope target Root';
        END IF;
    END LOOP;
    INSERT INTO raw.policy_rollouts
        (rollout_id, scope_id, state, target_root_id, base_activation_epoch, last_activation_epoch, base_security_epoch)
    VALUES ($1, $2, 'CANARY', v_target_root, $3, $3 + 1, $4);
    INSERT INTO raw.rollout_targets
        (rollout_id, scope_id, root_id, baseline_bundle_digest, candidate_bundle_digest, base_root_epoch)
    SELECT $1, $2, t.value->>'root_id', t.value->>'baseline_digest',
           t.value->>'candidate_digest', (t.value->>'base_root_epoch')::bigint
      FROM pg_catalog.json_array_elements($5) AS t(value);
END
$safety_create_rollout$;

-- Exact generic CompareAndSwapRollout row predicates and next-value fields.
-- A false result (including missing row) is port.ErrStaleWrite at the adapter.
CREATE OR REPLACE FUNCTION raw.safety_cas_rollout(
    text, text, bigint, text, text, text, text, bigint, bigint, bigint, text, text)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $safety_cas_rollout$
BEGIN
    IF session_user <> 'paddock_app' THEN
        RAISE EXCEPTION 'safety_cas_rollout requires session_user paddock_app';
    END IF;
    PERFORM 1 FROM raw.policy_scopes WHERE scope_id = $6 FOR UPDATE;
    -- After M07 installation, a base-only expected value cannot fence a new
    -- Decision or HoldExtend. Keep the M04 signature for pre-monitoring rows,
    -- but require the full-snapshot overload for initialized windows. to_jsonb
    -- also permits this source to be installed before the additive migration.
    IF EXISTS (SELECT 1 FROM raw.policy_rollouts r
               WHERE r.rollout_id = $5 AND r.scope_id = $6
                 AND pg_catalog.to_jsonb(r)->>'monitoring_started_at' IS NOT NULL) THEN
        RETURN false;
    END IF;
    UPDATE raw.policy_rollouts
       SET state = $1, target_root_id = $2, last_activation_epoch = $3,
           rollback_from = $4, updated_at = clock_timestamp()
     WHERE rollout_id = $5 AND scope_id = $6 AND state = $7
       AND base_activation_epoch = $8 AND last_activation_epoch = $9
       AND base_security_epoch = $10 AND target_root_id IS NOT DISTINCT FROM $11
       AND rollback_from IS NOT DISTINCT FROM $12;
    RETURN FOUND;
END
$safety_cas_rollout$;

CREATE OR REPLACE FUNCTION raw.safety_cas_rollout_target(
    text, text, bigint, text, text, text, text, text, bigint)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $safety_cas_rollout_target$
BEGIN
    IF session_user <> 'paddock_app' THEN
        RAISE EXCEPTION 'safety_cas_rollout_target requires session_user paddock_app';
    END IF;
    UPDATE raw.rollout_targets
       SET baseline_bundle_digest = $1, candidate_bundle_digest = $2,
           base_root_epoch = $3, updated_at = clock_timestamp()
     WHERE rollout_id = $4 AND scope_id = $5 AND root_id = $6
       AND baseline_bundle_digest IS NOT DISTINCT FROM $7
       AND candidate_bundle_digest = $8 AND base_root_epoch = $9;
    RETURN FOUND;
END
$safety_cas_rollout_target$;

ALTER FUNCTION raw.safety_create_rollout(text, text, bigint, bigint, json) OWNER TO paddock_migrator;
ALTER FUNCTION raw.safety_cas_rollout(text, text, bigint, text, text, text, text, bigint, bigint, bigint, text, text) OWNER TO paddock_migrator;
ALTER FUNCTION raw.safety_cas_rollout_target(text, text, bigint, text, text, text, text, text, bigint) OWNER TO paddock_migrator;

-- CREATE OR REPLACE preserves old ACLs, including any other-role grants.
DO $revoke_existing_rollout_api_execute$
DECLARE
    grant_row record;
BEGIN
    FOR grant_row IN
        SELECT DISTINCT p.oid::pg_catalog.regprocedure AS signature, r.rolname
          FROM pg_catalog.pg_proc p
          CROSS JOIN LATERAL pg_catalog.aclexplode(
              COALESCE(p.proacl, pg_catalog.acldefault('f', p.proowner))) acl
          JOIN pg_catalog.pg_roles r ON r.oid = acl.grantee
         WHERE p.oid IN (
             pg_catalog.to_regprocedure('raw.safety_create_rollout(text,text,bigint,bigint,json)'),
             pg_catalog.to_regprocedure('raw.safety_cas_rollout(text,text,bigint,text,text,text,text,bigint,bigint,bigint,text,text)'),
             pg_catalog.to_regprocedure('raw.safety_cas_rollout_target(text,text,bigint,text,text,text,text,text,bigint)'))
           AND acl.grantee <> p.proowner AND acl.grantee <> 0
           AND acl.privilege_type = 'EXECUTE'
    LOOP
        EXECUTE pg_catalog.format('REVOKE ALL ON FUNCTION %s FROM %I', grant_row.signature, grant_row.rolname);
    END LOOP;
END
$revoke_existing_rollout_api_execute$;

REVOKE ALL ON FUNCTION raw.safety_create_rollout(text, text, bigint, bigint, json),
    raw.safety_cas_rollout(text, text, bigint, text, text, text, text, bigint, bigint, bigint, text, text),
    raw.safety_cas_rollout_target(text, text, bigint, text, text, text, text, text, bigint)
FROM PUBLIC, paddock_app;
GRANT EXECUTE ON FUNCTION raw.safety_create_rollout(text, text, bigint, bigint, json),
    raw.safety_cas_rollout(text, text, bigint, text, text, text, text, bigint, bigint, bigint, text, text),
    raw.safety_cas_rollout_target(text, text, bigint, text, text, text, text, text, bigint)
TO paddock_app;

COMMIT;

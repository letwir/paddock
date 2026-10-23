-- M07-S06 source only. Apply after governance_rollout_api.sql, separately approved.
-- No database operations are performed by the offline acceptance tests.
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

-- Lock before inspecting legacy data so a concurrent writer cannot race the guard.
LOCK TABLE raw.policy_rollouts IN ACCESS EXCLUSIVE MODE;
DO $legacy_guard$
BEGIN
    IF EXISTS (SELECT 1 FROM raw.policy_rollouts
               WHERE state IN ('MONITORING','COMPLETED') OR rollback_from = 'MONITORING') THEN
        RAISE EXCEPTION 'incompatible legacy monitoring data; no state/deadline inference is permitted';
    END IF;
END
$legacy_guard$;

ALTER TABLE raw.policy_rollouts
    ADD COLUMN monitoring_started_at timestamptz,
    ADD COLUMN monitoring_last_observed_at timestamptz,
    ADD COLUMN observation_deadline timestamptz,
    ADD COLUMN hold_since timestamptz,
    ADD COLUMN hold_deadline timestamptz,
    ADD COLUMN hold_used interval NOT NULL DEFAULT INTERVAL '0',
    ADD COLUMN hold_budget interval NOT NULL DEFAULT INTERVAL '0',
    ADD COLUMN extension_used boolean NOT NULL DEFAULT false,
    ADD COLUMN extension_command_id text NOT NULL DEFAULT '',
    ADD COLUMN extension_nonce text NOT NULL DEFAULT '',
    ADD COLUMN monitoring_decision text NOT NULL DEFAULT '',
    ADD COLUMN decision_at timestamptz,
    ADD COLUMN evidence_digest text NOT NULL DEFAULT '',
    ADD COLUMN decision_revision bigint NOT NULL DEFAULT 0;

-- A duration is elapsed microseconds, never calendar months/days (including
-- cancellation combinations). Finite, bounded timestamps exclude infinity.
ALTER TABLE raw.policy_rollouts ADD CONSTRAINT policy_rollouts_monitoring_window_ck
CHECK (COALESCE((
    decision_revision >= 0
    AND EXTRACT(YEAR FROM hold_used) = 0 AND EXTRACT(MONTH FROM hold_used) = 0 AND EXTRACT(DAY FROM hold_used) = 0
    AND EXTRACT(YEAR FROM hold_budget) = 0 AND EXTRACT(MONTH FROM hold_budget) = 0 AND EXTRACT(DAY FROM hold_budget) = 0
    AND ((monitoring_started_at IS NULL
        AND monitoring_last_observed_at IS NULL AND observation_deadline IS NULL
        AND hold_since IS NULL AND hold_deadline IS NULL AND decision_at IS NULL
        AND hold_used = INTERVAL '0' AND hold_budget = INTERVAL '0'
        AND NOT extension_used AND extension_command_id = '' AND extension_nonce = ''
        AND monitoring_decision = '' AND evidence_digest = '' AND decision_revision = 0
        AND state NOT IN ('MONITORING','COMPLETED') AND rollback_from IS DISTINCT FROM 'MONITORING')
    OR (monitoring_started_at IS NOT NULL AND monitoring_last_observed_at IS NOT NULL AND observation_deadline IS NOT NULL
        AND state NOT IN ('SHADOW','CANARY')
        AND monitoring_last_observed_at >= monitoring_started_at
        AND hold_used >= INTERVAL '0' AND hold_used <= hold_budget
        AND observation_deadline = monitoring_started_at + INTERVAL '168 hours' + hold_used
        AND ((NOT extension_used AND hold_budget = INTERVAL '24 hours' AND extension_command_id = '' AND extension_nonce = '')
          OR (extension_used AND hold_budget = INTERVAL '48 hours' AND extension_command_id <> ''
              AND extension_command_id = btrim(extension_command_id) AND extension_nonce <> '' AND extension_nonce = btrim(extension_nonce)))
        AND ((monitoring_decision = '' AND decision_at IS NULL AND evidence_digest = '' AND decision_revision = 0)
          OR (monitoring_decision IN ('PASS','HOLD','FAIL','ABORT') AND decision_revision >= 1 AND decision_at IS NOT NULL
              AND decision_at >= monitoring_started_at AND decision_at <= monitoring_last_observed_at
              AND (evidence_digest ~ '^[0-9a-f]{64}$' OR (monitoring_decision = 'ABORT' AND evidence_digest = ''))))
        AND ((monitoring_decision = 'HOLD' AND hold_since IS NOT NULL AND hold_deadline IS NOT NULL
              AND hold_since >= monitoring_started_at AND hold_since <= decision_at AND hold_since <= monitoring_last_observed_at
              AND hold_used < hold_budget AND hold_deadline = hold_since + (hold_budget - hold_used)
              AND monitoring_last_observed_at < hold_deadline)
          OR (monitoring_decision <> 'HOLD' AND hold_since IS NULL AND hold_deadline IS NULL))
        AND (state <> 'COMPLETED' OR (monitoring_decision = 'PASS' AND decision_at >= observation_deadline
                                    AND monitoring_last_observed_at >= observation_deadline))))
    AND (monitoring_started_at IS NULL OR (monitoring_started_at > TIMESTAMPTZ '0001-01-01 00:00:00+00' AND monitoring_started_at < TIMESTAMPTZ '10000-01-01 00:00:00+00'))
    AND (monitoring_last_observed_at IS NULL OR (monitoring_last_observed_at > TIMESTAMPTZ '0001-01-01 00:00:00+00' AND monitoring_last_observed_at < TIMESTAMPTZ '10000-01-01 00:00:00+00'))
    AND (observation_deadline IS NULL OR (observation_deadline > TIMESTAMPTZ '0001-01-01 00:00:00+00' AND observation_deadline < TIMESTAMPTZ '10000-01-01 00:00:00+00'))
    AND (hold_since IS NULL OR (hold_since > TIMESTAMPTZ '0001-01-01 00:00:00+00' AND hold_since < TIMESTAMPTZ '10000-01-01 00:00:00+00'))
    AND (hold_deadline IS NULL OR (hold_deadline > TIMESTAMPTZ '0001-01-01 00:00:00+00' AND hold_deadline < TIMESTAMPTZ '10000-01-01 00:00:00+00'))
    AND (decision_at IS NULL OR (decision_at > TIMESTAMPTZ '0001-01-01 00:00:00+00' AND decision_at < TIMESTAMPTZ '10000-01-01 00:00:00+00'))
), false));

CREATE INDEX policy_rollouts_due_deadline_idx ON raw.policy_rollouts
    ((CASE WHEN monitoring_decision IN ('FAIL','ABORT') THEN decision_at
           WHEN monitoring_decision = 'HOLD' THEN hold_deadline ELSE observation_deadline END), scope_id COLLATE "C", rollout_id COLLATE "C")
    WHERE state = 'MONITORING';

CREATE OR REPLACE FUNCTION raw.safety_rollout_monitoring(text, text)
RETURNS TABLE (monitoring_started_at timestamptz,
    monitoring_last_observed_at timestamptz,
    observation_deadline timestamptz,
    hold_since timestamptz,
    hold_deadline timestamptz,
    hold_used interval,
    hold_budget interval,
    extension_used boolean,
    extension_command_id text,
    extension_nonce text,
    monitoring_decision text,
    decision_at timestamptz,
    evidence_digest text,
    decision_revision bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $safety_rollout_monitoring$
BEGIN
    IF session_user <> 'paddock_app' THEN
        RAISE EXCEPTION 'safety_rollout_monitoring requires session_user paddock_app';
    END IF;
    PERFORM 1 FROM raw.policy_scopes WHERE scope_id = $1 FOR UPDATE;
    PERFORM 1 FROM raw.policy_rollouts WHERE scope_id = $1 AND rollout_id = $2 FOR UPDATE;
    RETURN QUERY SELECT r.monitoring_started_at, r.monitoring_last_observed_at, r.observation_deadline, r.hold_since, r.hold_deadline, r.hold_used, r.hold_budget, r.extension_used, r.extension_command_id, r.extension_nonce, r.monitoring_decision, r.decision_at, r.evidence_digest, r.decision_revision
        FROM raw.policy_rollouts r WHERE r.scope_id = $1 AND r.rollout_id = $2;
END
$safety_rollout_monitoring$;

-- Upgrade the pre-existing overload as part of this migration too: applying
-- only the additive migration to an already deployed M04 API must not retain a
-- base-only monitoring CAS bypass. This guard is harmless after down removes
-- the columns (to_jsonb then has no monitoring_started_at key).
CREATE OR REPLACE FUNCTION raw.safety_cas_rollout(
    text, text, bigint, text, text, text, text, bigint, bigint, bigint, text, text)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $safety_cas_rollout_legacy$
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
$safety_cas_rollout_legacy$;

-- Full expected snapshot overload. Target updates remain in the same caller
-- transaction through the existing target CAS; every expected target, including
-- cardinality, is checked here before the parent update. No stale partial commit.
CREATE OR REPLACE FUNCTION raw.safety_cas_rollout(jsonb, jsonb)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $safety_cas_rollout_full$
DECLARE
    e raw.policy_rollouts%ROWTYPE;
    n raw.policy_rollouts%ROWTYPE;
    r raw.policy_rollouts%ROWTYPE;
    actual_targets jsonb;
BEGIN
    IF session_user <> 'paddock_app' THEN
        RAISE EXCEPTION 'safety_cas_rollout requires session_user paddock_app';
    END IF;
    IF $1 IS NULL OR $2 IS NULL OR pg_catalog.jsonb_typeof($1) <> 'object' OR pg_catalog.jsonb_typeof($2) <> 'object'
       OR NOT ($1 ?& ARRAY['rollout_id','scope_id','state','target_root_id','base_activation_epoch','last_activation_epoch','base_security_epoch','rollback_from','monitoring_started_at','monitoring_last_observed_at','observation_deadline','hold_since','hold_deadline','hold_used','hold_budget','extension_used','extension_command_id','extension_nonce','monitoring_decision','decision_at','evidence_digest','decision_revision','targets'])
       OR NOT ($2 ?& ARRAY['rollout_id','scope_id','state','target_root_id','base_activation_epoch','last_activation_epoch','base_security_epoch','rollback_from','monitoring_started_at','monitoring_last_observed_at','observation_deadline','hold_since','hold_deadline','hold_used','hold_budget','extension_used','extension_command_id','extension_nonce','monitoring_decision','decision_at','evidence_digest','decision_revision','targets'])
       OR (SELECT count(*) FROM pg_catalog.jsonb_object_keys($1)) <> 23
       OR (SELECT count(*) FROM pg_catalog.jsonb_object_keys($2)) <> 23
       OR pg_catalog.jsonb_typeof($1->'targets') <> 'array' OR pg_catalog.jsonb_typeof($2->'targets') <> 'array' THEN
        RAISE EXCEPTION 'complete typed rollout snapshots required';
    END IF;
    e := pg_catalog.jsonb_populate_record(NULL::raw.policy_rollouts, $1);
    n := pg_catalog.jsonb_populate_record(NULL::raw.policy_rollouts, $2);
    -- PostgreSQL interval equality normalizes calendar components. A Domain
    -- duration must instead have only its elapsed-microseconds component.
    IF EXTRACT(YEAR FROM e.hold_used) <> 0 OR EXTRACT(MONTH FROM e.hold_used) <> 0 OR EXTRACT(DAY FROM e.hold_used) <> 0
       OR EXTRACT(YEAR FROM e.hold_budget) <> 0 OR EXTRACT(MONTH FROM e.hold_budget) <> 0 OR EXTRACT(DAY FROM e.hold_budget) <> 0 THEN
        RETURN false;
    END IF;
    IF e.rollout_id IS DISTINCT FROM n.rollout_id OR e.scope_id IS DISTINCT FROM n.scope_id
       OR e.base_activation_epoch IS DISTINCT FROM n.base_activation_epoch
       OR e.base_security_epoch IS DISTINCT FROM n.base_security_epoch
       OR n.last_activation_epoch < e.last_activation_epoch THEN
        RETURN false;
    END IF;
    PERFORM 1 FROM raw.policy_scopes WHERE scope_id = e.scope_id FOR UPDATE;
    SELECT * INTO r FROM raw.policy_rollouts WHERE scope_id = e.scope_id AND rollout_id = e.rollout_id FOR UPDATE;
    IF NOT FOUND OR ROW(r.rollout_id, r.scope_id, r.state, r.target_root_id, r.base_activation_epoch, r.last_activation_epoch, r.base_security_epoch, r.rollback_from, r.monitoring_started_at, r.monitoring_last_observed_at, r.observation_deadline, r.hold_since, r.hold_deadline, r.hold_used, r.hold_budget, r.extension_used, r.extension_command_id, r.extension_nonce, r.monitoring_decision, r.decision_at, r.evidence_digest, r.decision_revision)
        IS DISTINCT FROM ROW(e.rollout_id, e.scope_id, e.state, e.target_root_id, e.base_activation_epoch, e.last_activation_epoch, e.base_security_epoch, e.rollback_from, e.monitoring_started_at, e.monitoring_last_observed_at, e.observation_deadline, e.hold_since, e.hold_deadline, e.hold_used, e.hold_budget, e.extension_used, e.extension_command_id, e.extension_nonce, e.monitoring_decision, e.decision_at, e.evidence_digest, e.decision_revision) THEN
        RETURN false;
    END IF;
    SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
        'root_id', t.root_id, 'baseline_bundle_digest', t.baseline_bundle_digest,
        'candidate_bundle_digest', t.candidate_bundle_digest, 'base_root_epoch', t.base_root_epoch) ORDER BY t.root_id COLLATE "C")
        INTO actual_targets FROM raw.rollout_targets t WHERE t.scope_id = e.scope_id AND t.rollout_id = e.rollout_id;
    IF actual_targets IS DISTINCT FROM $1->'targets' THEN RETURN false; END IF;
    -- The immutable target set must be identical; the existing target CAS may
    -- subsequently update all target values, never add/delete targets.
    IF (SELECT pg_catalog.jsonb_agg(v->>'root_id' ORDER BY (v->>'root_id') COLLATE "C") FROM pg_catalog.jsonb_array_elements($1->'targets') v)
       IS DISTINCT FROM (SELECT pg_catalog.jsonb_agg(v->>'root_id' ORDER BY (v->>'root_id') COLLATE "C") FROM pg_catalog.jsonb_array_elements($2->'targets') v) THEN
        RETURN false;
    END IF;
    UPDATE raw.policy_rollouts SET
        state = n.state,
        target_root_id = n.target_root_id,
        base_activation_epoch = n.base_activation_epoch,
        last_activation_epoch = n.last_activation_epoch,
        base_security_epoch = n.base_security_epoch,
        rollback_from = n.rollback_from,
        monitoring_started_at = n.monitoring_started_at,
        monitoring_last_observed_at = n.monitoring_last_observed_at,
        observation_deadline = n.observation_deadline,
        hold_since = n.hold_since,
        hold_deadline = n.hold_deadline,
        hold_used = n.hold_used,
        hold_budget = n.hold_budget,
        extension_used = n.extension_used,
        extension_command_id = n.extension_command_id,
        extension_nonce = n.extension_nonce,
        monitoring_decision = n.monitoring_decision,
        decision_at = n.decision_at,
        evidence_digest = n.evidence_digest,
        decision_revision = n.decision_revision,
        updated_at = clock_timestamp()
        WHERE rollout_id = e.rollout_id AND scope_id = e.scope_id;
    RETURN FOUND;
END
$safety_cas_rollout_full$;

CREATE OR REPLACE FUNCTION raw.safety_list_rollout_deadlines(integer)
RETURNS TABLE (scope_id text, rollout_id text, monitoring_started_at timestamptz,
    monitoring_last_observed_at timestamptz,
    observation_deadline timestamptz,
    hold_since timestamptz,
    hold_deadline timestamptz,
    hold_used interval,
    hold_budget interval,
    extension_used boolean,
    extension_command_id text,
    extension_nonce text,
    monitoring_decision text,
    decision_at timestamptz,
    evidence_digest text,
    decision_revision bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $safety_list_rollout_deadlines$
DECLARE
    db_now timestamptz;
BEGIN
    IF session_user <> 'paddock_app' THEN
        RAISE EXCEPTION 'safety_list_rollout_deadlines requires session_user paddock_app';
    END IF;
    IF $1 IS NULL OR $1 < 1 OR $1 > 1000 THEN RAISE EXCEPTION 'invalid rollout deadline batch'; END IF;
    db_now := clock_timestamp();
    -- Scheduling hints only: deliberately no row locks or SKIP LOCKED.
    RETURN QUERY SELECT r.scope_id, r.rollout_id, r.monitoring_started_at, r.monitoring_last_observed_at, r.observation_deadline, r.hold_since, r.hold_deadline, r.hold_used, r.hold_budget, r.extension_used, r.extension_command_id, r.extension_nonce, r.monitoring_decision, r.decision_at, r.evidence_digest, r.decision_revision
      FROM raw.policy_rollouts r
     WHERE r.state = 'MONITORING' AND
       (r.monitoring_decision IN ('FAIL','ABORT') OR
        (CASE WHEN r.monitoring_decision = 'HOLD' THEN r.hold_deadline ELSE r.observation_deadline END) <= db_now)
     ORDER BY (CASE WHEN r.monitoring_decision IN ('FAIL','ABORT') THEN r.decision_at
                    WHEN r.monitoring_decision = 'HOLD' THEN r.hold_deadline ELSE r.observation_deadline END),
              r.scope_id COLLATE "C", r.rollout_id COLLATE "C"
     LIMIT $1;
END
$safety_list_rollout_deadlines$;

ALTER FUNCTION raw.safety_cas_rollout(text,text,bigint,text,text,text,text,bigint,bigint,bigint,text,text) OWNER TO paddock_migrator;
ALTER FUNCTION raw.safety_rollout_monitoring(text,text) OWNER TO paddock_migrator;
ALTER FUNCTION raw.safety_cas_rollout(jsonb,jsonb) OWNER TO paddock_migrator;
ALTER FUNCTION raw.safety_list_rollout_deadlines(integer) OWNER TO paddock_migrator;

-- Replacements preserve ACLs. Remove every non-owner grant, not only PUBLIC.
DO $revoke_existing_deadline_api_execute$
DECLARE grant_row record;
BEGIN
    FOR grant_row IN
        SELECT DISTINCT p.oid::pg_catalog.regprocedure AS signature, r.rolname
          FROM pg_catalog.pg_proc p
          CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(p.proacl, pg_catalog.acldefault('f', p.proowner))) acl
          JOIN pg_catalog.pg_roles r ON r.oid = acl.grantee
         WHERE p.oid IN (
            pg_catalog.to_regprocedure('raw.safety_rollout_monitoring(text,text)'),
            pg_catalog.to_regprocedure('raw.safety_cas_rollout(jsonb,jsonb)'),
            pg_catalog.to_regprocedure('raw.safety_list_rollout_deadlines(integer)'),
            pg_catalog.to_regprocedure('raw.safety_cas_rollout(text,text,bigint,text,text,text,text,bigint,bigint,bigint,text,text)')
         ) AND acl.grantee <> p.proowner AND acl.grantee <> 0 AND acl.privilege_type = 'EXECUTE'
    LOOP
        EXECUTE pg_catalog.format('REVOKE ALL ON FUNCTION %s FROM %I', grant_row.signature, grant_row.rolname);
    END LOOP;
END
$revoke_existing_deadline_api_execute$;
REVOKE ALL ON FUNCTION raw.safety_rollout_monitoring(text,text), raw.safety_cas_rollout(jsonb,jsonb), raw.safety_list_rollout_deadlines(integer), raw.safety_cas_rollout(text,text,bigint,text,text,text,text,bigint,bigint,bigint,text,text) FROM PUBLIC, paddock_app;
GRANT EXECUTE ON FUNCTION raw.safety_rollout_monitoring(text,text), raw.safety_cas_rollout(jsonb,jsonb), raw.safety_list_rollout_deadlines(integer), raw.safety_cas_rollout(text,text,bigint,text,text,text,text,bigint,bigint,bigint,text,text) TO paddock_app;
COMMIT;

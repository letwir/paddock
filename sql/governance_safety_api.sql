-- M03-S04 narrow application API for Scope/Root/Security Epoch/Receipt access.
-- Apply only as paddock_migrator on the isolated paddock_test database.
-- No direct table privileges are granted to paddock_app.
BEGIN;

DO $migration_guard$
DECLARE
    relation_name text;
BEGIN
    IF current_database() <> 'paddock_test' THEN
        RAISE EXCEPTION 'refusing safety API migration on %, expected paddock_test', current_database();
    END IF;
    IF current_user <> 'paddock_migrator' OR session_user <> 'paddock_migrator' THEN
        RAISE EXCEPTION 'safety API migration requires current_user and session_user paddock_migrator';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
        WHERE rolname = 'paddock_migrator'
          AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb
          AND NOT rolreplication AND NOT rolbypassrls
    ) OR NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
        WHERE rolname = 'paddock_app'
          AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb
          AND NOT rolreplication AND NOT rolbypassrls
    ) THEN
        RAISE EXCEPTION 'isolated non-elevated paddock_app and paddock_migrator roles are required';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_auth_members m
        JOIN pg_catalog.pg_roles granted_role ON granted_role.oid = m.roleid
        JOIN pg_catalog.pg_roles member_role ON member_role.oid = m.member
        WHERE granted_role.rolname IN ('paddock_app', 'paddock_migrator')
           OR member_role.rolname IN ('paddock_app', 'paddock_migrator')
    ) THEN
        RAISE EXCEPTION 'paddock_app and paddock_migrator must have no role memberships';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_namespace n
        JOIN pg_catalog.pg_roles r ON r.oid = n.nspowner
        WHERE n.nspname = 'raw' AND r.rolname = 'paddock_migrator'
    ) THEN
        RAISE EXCEPTION 'paddock_migrator must own raw schema';
    END IF;
    FOREACH relation_name IN ARRAY ARRAY[
        'policy_scopes', 'roots', 'policy_rollouts', 'rollout_targets',
        'security_generation', 'command_receipts'
    ] LOOP
        IF NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_class c
            JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
            JOIN pg_catalog.pg_roles r ON r.oid = c.relowner
            WHERE n.nspname = 'raw' AND c.relname = relation_name
              AND c.relkind = 'r' AND r.rolname = 'paddock_migrator'
        ) THEN
            RAISE EXCEPTION 'raw.% must exist as an ordinary table owned by paddock_migrator', relation_name;
        END IF;
    END LOOP;
    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_proc p
        JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
        JOIN pg_catalog.pg_roles owner_role ON owner_role.oid = p.proowner
        WHERE n.nspname = 'raw'
          AND p.oid = pg_catalog.to_regprocedure(
              'raw.append_domain_event_and_outbox(text,text,text,bigint,text,text,bytea)'
          )
          AND owner_role.rolname = 'paddock_migrator'
          AND p.prosecdef
          AND p.proconfig @> ARRAY['search_path=pg_catalog']::text[]
          AND pg_catalog.has_function_privilege(
              'paddock_app', p.oid, 'EXECUTE'
          )
    ) THEN
        RAISE EXCEPTION 'the migrator-owned app-only Event/Outbox function must be installed first';
    END IF;
END
$migration_guard$;

CREATE OR REPLACE FUNCTION raw.safety_lock_scope(text)
RETURNS TABLE(
    scope_id text,
    activation_epoch bigint,
    mode text,
    baseline_bundle_digest character(64),
    live_rollout_id text,
    security_epoch bigint,
    root_id text,
    authorization_epoch bigint,
    effective_bundle_digest character(64),
    safe_baseline boolean
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $safety_lock_scope$
DECLARE
    v_scope_id text;
    v_activation_epoch bigint;
    v_mode text;
    v_baseline character(64);
    v_live_rollout_id text;
    v_security_epoch bigint;
BEGIN
    IF session_user <> 'paddock_app' THEN
        RAISE EXCEPTION 'safety_lock_scope requires session_user paddock_app';
    END IF;
    IF $1 IS NULL OR $1 = '' OR $1 <> pg_catalog.btrim($1) THEN
        RAISE EXCEPTION 'safety_lock_scope requires a nonempty trimmed Scope ID';
    END IF;

    SELECT s.scope_id, s.activation_epoch, s.mode, s.baseline_bundle_digest, s.live_rollout_id
      INTO v_scope_id, v_activation_epoch, v_mode, v_baseline, v_live_rollout_id
      FROM raw.policy_scopes s
     WHERE s.scope_id = $1
     FOR UPDATE;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT sg.security_epoch
      INTO v_security_epoch
      FROM raw.security_generation sg
     WHERE sg.singleton_id = true
     FOR KEY SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'safety_lock_scope requires the singleton Security Epoch row';
    END IF;

    IF EXISTS (SELECT 1 FROM raw.roots r WHERE r.scope_id = v_scope_id) THEN
        RETURN QUERY
        SELECT v_scope_id, v_activation_epoch, v_mode, v_baseline, v_live_rollout_id,
               v_security_epoch, r.root_id, r.authorization_epoch,
               r.effective_bundle_digest, r.safe_baseline
          FROM raw.roots r
         WHERE r.scope_id = v_scope_id
         ORDER BY r.root_id;
    ELSE
        RETURN QUERY
        SELECT v_scope_id, v_activation_epoch, v_mode, v_baseline, v_live_rollout_id,
               v_security_epoch, NULL::text, NULL::bigint, NULL::character(64), NULL::boolean;
    END IF;
END
$safety_lock_scope$;

CREATE OR REPLACE FUNCTION raw.safety_lock_rollout(text, text)
RETURNS TABLE(
    rollout_id text,
    scope_id text,
    state text,
    target_root_id text,
    base_activation_epoch bigint,
    last_activation_epoch bigint,
    base_security_epoch bigint,
    rollback_from text,
    root_id text,
    baseline_bundle_digest character(64),
    candidate_bundle_digest character(64),
    base_root_epoch bigint
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $safety_lock_rollout$
DECLARE
    v_rollout_id text;
    v_scope_id text;
    v_state text;
    v_target_root_id text;
    v_base_activation_epoch bigint;
    v_last_activation_epoch bigint;
    v_base_security_epoch bigint;
    v_rollback_from text;
BEGIN
    IF session_user <> 'paddock_app' THEN
        RAISE EXCEPTION 'safety_lock_rollout requires session_user paddock_app';
    END IF;
    IF $1 IS NULL OR $1 = '' OR $1 <> pg_catalog.btrim($1)
       OR $2 IS NULL OR $2 = '' OR $2 <> pg_catalog.btrim($2) THEN
        RAISE EXCEPTION 'safety_lock_rollout requires nonempty trimmed identifiers';
    END IF;

    SELECT r.rollout_id, r.scope_id, r.state, r.target_root_id,
           r.base_activation_epoch, r.last_activation_epoch,
           r.base_security_epoch, r.rollback_from
      INTO v_rollout_id, v_scope_id, v_state, v_target_root_id,
           v_base_activation_epoch, v_last_activation_epoch,
           v_base_security_epoch, v_rollback_from
      FROM raw.policy_rollouts r
     WHERE r.scope_id = $1 AND r.rollout_id = $2
     FOR UPDATE;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    IF EXISTS (SELECT 1 FROM raw.rollout_targets t
               WHERE t.scope_id = $1 AND t.rollout_id = $2) THEN
        RETURN QUERY
        SELECT v_rollout_id, v_scope_id, v_state, v_target_root_id,
               v_base_activation_epoch, v_last_activation_epoch,
               v_base_security_epoch, v_rollback_from,
               t.root_id, t.baseline_bundle_digest,
               t.candidate_bundle_digest, t.base_root_epoch
          FROM raw.rollout_targets t
         WHERE t.scope_id = $1 AND t.rollout_id = $2
         ORDER BY t.root_id
         FOR UPDATE OF t;
    ELSE
        RETURN QUERY
        SELECT v_rollout_id, v_scope_id, v_state, v_target_root_id,
               v_base_activation_epoch, v_last_activation_epoch,
               v_base_security_epoch, v_rollback_from,
               NULL::text, NULL::character(64), NULL::character(64), NULL::bigint;
    END IF;
END
$safety_lock_rollout$;

CREATE OR REPLACE FUNCTION raw.safety_lock_scope_roots(text)
RETURNS TABLE(root_id text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $safety_lock_scope_roots$
BEGIN
    IF session_user <> 'paddock_app' THEN
        RAISE EXCEPTION 'safety_lock_scope_roots requires session_user paddock_app';
    END IF;
    IF $1 IS NULL OR $1 = '' OR $1 <> pg_catalog.btrim($1) THEN
        RAISE EXCEPTION 'safety_lock_scope_roots requires a nonempty trimmed Scope ID';
    END IF;
    RETURN QUERY
    SELECT r.root_id
      FROM raw.roots r
     WHERE r.scope_id = $1
     ORDER BY r.root_id
     FOR UPDATE OF r;
END
$safety_lock_scope_roots$;

CREATE OR REPLACE FUNCTION raw.safety_cas_scope(
    text, bigint, text, text, text,
    bigint, text, text, text, bigint
)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $safety_cas_scope$
BEGIN
    IF session_user <> 'paddock_app' THEN
        RAISE EXCEPTION 'safety_cas_scope requires session_user paddock_app';
    END IF;
    IF $1 IS NULL OR $1 = '' OR $1 <> pg_catalog.btrim($1)
       OR $2 IS NULL OR $2 < 0 OR $3 IS NULL
       OR $6 IS NULL OR $6 < $2 OR $7 IS NULL OR $10 IS NULL OR $10 < 0 THEN
        RAISE EXCEPTION 'safety_cas_scope received malformed epoch or Scope values';
    END IF;
    IF $3 NOT IN ('ACTIVE', 'FROZEN', 'SAFE_STOPPED')
       OR $7 NOT IN ('ACTIVE', 'FROZEN', 'SAFE_STOPPED') THEN
        RAISE EXCEPTION 'safety_cas_scope received unknown Scope mode';
    END IF;
    IF $5 IS NOT NULL AND ($5 = '' OR $5 <> pg_catalog.btrim($5)) THEN
        RAISE EXCEPTION 'safety_cas_scope live Rollout ID is invalid';
    END IF;
    IF $4 IS NOT NULL AND $4 !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'safety_cas_scope expected bundle digest is invalid';
    END IF;
    IF $9 IS NOT NULL AND ($9 = '' OR $9 <> pg_catalog.btrim($9)) THEN
        RAISE EXCEPTION 'safety_cas_scope next live Rollout ID is invalid';
    END IF;
    IF $8 IS NOT NULL AND $8 !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'safety_cas_scope next bundle digest is invalid';
    END IF;
    IF $7 <> 'SAFE_STOPPED' AND $8 IS NULL THEN
        RAISE EXCEPTION 'safety_cas_scope non-stopped Scope requires a baseline bundle';
    END IF;

    UPDATE raw.policy_scopes s
       SET activation_epoch = $6, mode = $7,
           baseline_bundle_digest = NULLIF($8, '')::character(64), live_rollout_id = $9,
           updated_at = pg_catalog.clock_timestamp()
     WHERE s.scope_id = $1
       AND s.activation_epoch = $2 AND s.mode = $3
       AND s.baseline_bundle_digest IS NOT DISTINCT FROM NULLIF($4, '')::character(64)
       AND s.live_rollout_id IS NOT DISTINCT FROM $5
       AND EXISTS (SELECT 1 FROM raw.security_generation sg
                   WHERE sg.singleton_id = true AND sg.security_epoch = $10);
    RETURN FOUND;
END
$safety_cas_scope$;

CREATE OR REPLACE FUNCTION raw.safety_cas_root(
    text, text, bigint, text, boolean,
    bigint, text, boolean
)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $safety_cas_root$
BEGIN
    IF session_user <> 'paddock_app' THEN
        RAISE EXCEPTION 'safety_cas_root requires session_user paddock_app';
    END IF;
    IF $1 IS NULL OR $1 = '' OR $1 <> pg_catalog.btrim($1)
       OR $2 IS NULL OR $2 = '' OR $2 <> pg_catalog.btrim($2)
       OR $3 IS NULL OR $3 < 0 OR $4 = '' OR $5 IS NULL
       OR $6 IS NULL OR $6 < $3 OR $8 IS NULL THEN
        RAISE EXCEPTION 'safety_cas_root received malformed Root values';
    END IF;
    IF ($4 IS NOT NULL AND $4 !~ '^[0-9a-f]{64}$')
       OR ($7 IS NOT NULL AND $7 !~ '^[0-9a-f]{64}$')
       OR ($5 AND $4 IS NOT NULL) OR (NOT $5 AND $4 IS NULL)
       OR ($8 AND $7 IS NOT NULL) OR (NOT $8 AND $7 IS NULL) THEN
        RAISE EXCEPTION 'safety_cas_root policy binding is invalid';
    END IF;

    UPDATE raw.roots r
       SET authorization_epoch = $6, effective_bundle_digest = NULLIF($7, '')::character(64),
           safe_baseline = $8, updated_at = pg_catalog.clock_timestamp()
     WHERE r.root_id = $1 AND r.scope_id = $2
       AND r.authorization_epoch = $3
       AND r.effective_bundle_digest IS NOT DISTINCT FROM NULLIF($4, '')::character(64)
       AND r.safe_baseline = $5;
    RETURN FOUND;
END
$safety_cas_root$;

CREATE OR REPLACE FUNCTION raw.safety_cas_security_epoch(bigint, bigint)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $safety_cas_security_epoch$
BEGIN
    IF session_user <> 'paddock_app' THEN
        RAISE EXCEPTION 'safety_cas_security_epoch requires session_user paddock_app';
    END IF;
    IF $1 IS NULL OR $1 < 0 OR $2 IS NULL THEN
        RAISE EXCEPTION 'safety_cas_security_epoch requires nonnegative epochs';
    END IF;
    IF $1 = 9223372036854775807 THEN
        RAISE EXCEPTION 'safety_cas_security_epoch exceeds PostgreSQL bigint range';
    END IF;
    IF $2 <> $1 + 1 THEN
        RAISE EXCEPTION 'safety_cas_security_epoch requires one monotone increment';
    END IF;
    UPDATE raw.security_generation sg
       SET security_epoch = $2, updated_at = pg_catalog.clock_timestamp()
     WHERE sg.singleton_id = true AND sg.security_epoch = $1;
    RETURN FOUND;
END
$safety_cas_security_epoch$;

CREATE OR REPLACE FUNCTION raw.safety_lookup_command_receipt(text)
RETURNS TABLE(command_id text, request_digest character(64), status text, response_bytes bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $safety_lookup_command_receipt$
DECLARE
    v_tombstone constant bytea := pg_catalog.convert_to('{"schema_version":"paddock.command-response/1","kind":"EXPIRED","code":"RECEIPT_EXPIRED","detail":"The command response retention period has expired; this command ID cannot be reused."}', 'UTF8');
BEGIN
    IF session_user <> 'paddock_app' THEN
        RAISE EXCEPTION 'safety_lookup_command_receipt requires session_user paddock_app';
    END IF;
    IF $1 IS NULL OR $1 = '' OR $1 <> pg_catalog.btrim($1) THEN
        RAISE EXCEPTION 'safety_lookup_command_receipt requires a nonempty trimmed command ID';
    END IF;
    -- Serialize all operations on this globally unique command ID before
    -- callers lock a Scope. Hash collisions only cause extra serialization.
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1, 0));

    -- Requested row first: a backlog must never hide its expired response.
    -- Keep the original status, digest, and completion anchor forever.
    UPDATE raw.command_receipts r
       SET response_bytes = v_tombstone
     WHERE r.command_id = $1
       AND r.status IN ('SUCCEEDED', 'REJECTED')
       AND pg_catalog.clock_timestamp() >= r.completed_at + interval '365 days'
       AND r.response_bytes <> v_tombstone;

    -- At most 999 additional oldest due terminal rows, plus the requested row.
    -- Skip locked rows rather than waiting for another command's transaction.
    WITH due AS (
        SELECT r.command_id
          FROM raw.command_receipts r
         WHERE r.command_id <> $1
           AND r.status IN ('SUCCEEDED', 'REJECTED')
           AND pg_catalog.clock_timestamp() >= r.completed_at + interval '365 days'
           AND r.response_bytes <> v_tombstone
         ORDER BY r.completed_at, r.command_id
         LIMIT 999
         FOR UPDATE OF r SKIP LOCKED
    )
    UPDATE raw.command_receipts r
       SET response_bytes = v_tombstone
      FROM due
     WHERE r.command_id = due.command_id;

    RETURN QUERY
    SELECT r.command_id, r.request_digest, r.status, r.response_bytes
      FROM raw.command_receipts r
     WHERE r.command_id = $1;
END
$safety_lookup_command_receipt$;

CREATE OR REPLACE FUNCTION raw.safety_insert_command_receipt(text, text, text, bytea)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $safety_insert_command_receipt$
BEGIN
    IF session_user <> 'paddock_app' THEN
        RAISE EXCEPTION 'safety_insert_command_receipt requires session_user paddock_app';
    END IF;
    IF $1 IS NULL OR $1 = '' OR $1 <> pg_catalog.btrim($1)
       OR $2 IS NULL OR $2 !~ '^[0-9a-f]{64}$'
       OR $3 IS NULL OR $3 NOT IN ('SUCCEEDED', 'REJECTED')
       OR $4 IS NULL OR pg_catalog.octet_length($4) = 0 THEN
        RAISE EXCEPTION 'safety_insert_command_receipt requires a completed valid Receipt';
    END IF;
    IF $4 = pg_catalog.convert_to('{"schema_version":"paddock.command-response/1","kind":"EXPIRED","code":"RECEIPT_EXPIRED","detail":"The command response retention period has expired; this command ID cannot be reused."}', 'UTF8') THEN
        RAISE EXCEPTION 'safety_insert_command_receipt cannot insert a retention tombstone';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1, 0));
    INSERT INTO raw.command_receipts(command_id, request_digest, status, response_bytes, completed_at)
    VALUES ($1, $2, $3, $4, pg_catalog.clock_timestamp());
END
$safety_insert_command_receipt$;

ALTER FUNCTION raw.safety_lock_scope(text) OWNER TO paddock_migrator;
ALTER FUNCTION raw.safety_lock_rollout(text, text) OWNER TO paddock_migrator;
ALTER FUNCTION raw.safety_lock_scope_roots(text) OWNER TO paddock_migrator;
ALTER FUNCTION raw.safety_cas_scope(text, bigint, text, text, text, bigint, text, text, text, bigint) OWNER TO paddock_migrator;
ALTER FUNCTION raw.safety_cas_root(text, text, bigint, text, boolean, bigint, text, boolean) OWNER TO paddock_migrator;
ALTER FUNCTION raw.safety_cas_security_epoch(bigint, bigint) OWNER TO paddock_migrator;
ALTER FUNCTION raw.safety_lookup_command_receipt(text) OWNER TO paddock_migrator;
ALTER FUNCTION raw.safety_insert_command_receipt(text, text, text, bytea) OWNER TO paddock_migrator;

DO $revoke_existing_safety_api_execute$
DECLARE
    grantee_name name;
BEGIN
    FOR grantee_name IN
        SELECT DISTINCT r.rolname
        FROM pg_catalog.pg_proc p
        CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(p.proacl, pg_catalog.acldefault('f', p.proowner))
        ) acl
        JOIN pg_catalog.pg_roles r ON r.oid = acl.grantee
        WHERE p.oid IN (
            pg_catalog.to_regprocedure('raw.safety_lock_scope(text)'),
            pg_catalog.to_regprocedure('raw.safety_lock_rollout(text,text)'),
            pg_catalog.to_regprocedure('raw.safety_lock_scope_roots(text)'),
            pg_catalog.to_regprocedure('raw.safety_cas_scope(text,bigint,text,text,text,bigint,text,text,text,bigint)'),
            pg_catalog.to_regprocedure('raw.safety_cas_root(text,text,bigint,text,boolean,bigint,text,boolean)'),
            pg_catalog.to_regprocedure('raw.safety_cas_security_epoch(bigint,bigint)'),
            pg_catalog.to_regprocedure('raw.safety_lookup_command_receipt(text)'),
            pg_catalog.to_regprocedure('raw.safety_insert_command_receipt(text,text,text,bytea)')
        )
          AND acl.grantee <> p.proowner
          AND acl.grantee <> 0
          AND acl.privilege_type = 'EXECUTE'
    LOOP
        EXECUTE pg_catalog.format(
            'REVOKE ALL ON FUNCTION raw.safety_lock_scope(text), raw.safety_lock_rollout(text,text), raw.safety_lock_scope_roots(text), raw.safety_cas_scope(text,bigint,text,text,text,bigint,text,text,text,bigint), raw.safety_cas_root(text,text,bigint,text,boolean,bigint,text,boolean), raw.safety_cas_security_epoch(bigint,bigint), raw.safety_lookup_command_receipt(text), raw.safety_insert_command_receipt(text,text,text,bytea) FROM %I',
            grantee_name
        );
    END LOOP;
END
$revoke_existing_safety_api_execute$;

REVOKE ALL ON FUNCTION raw.safety_lock_scope(text),
    raw.safety_lock_rollout(text, text),
    raw.safety_lock_scope_roots(text),
    raw.safety_cas_scope(text, bigint, text, text, text, bigint, text, text, text, bigint),
    raw.safety_cas_root(text, text, bigint, text, boolean, bigint, text, boolean),
    raw.safety_cas_security_epoch(bigint, bigint),
    raw.safety_lookup_command_receipt(text),
    raw.safety_insert_command_receipt(text, text, text, bytea)
FROM PUBLIC, paddock_app;
GRANT EXECUTE ON FUNCTION raw.safety_lock_scope(text),
    raw.safety_lock_rollout(text, text),
    raw.safety_lock_scope_roots(text),
    raw.safety_cas_scope(text, bigint, text, text, text, bigint, text, text, text, bigint),
    raw.safety_cas_root(text, text, bigint, text, boolean, bigint, text, boolean),
    raw.safety_cas_security_epoch(bigint, bigint),
    raw.safety_lookup_command_receipt(text),
    raw.safety_insert_command_receipt(text, text, text, bytea)
TO paddock_app;

COMMIT;

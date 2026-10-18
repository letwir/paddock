-- M05-S03 app-only Outbox lease/claim/ack/retry/Dead Letter API.
-- Apply only as paddock_migrator on the isolated paddock_test database.
-- This migration never grants direct raw.event_outbox privileges to paddock_app.
BEGIN;

DO $migration_guard$
DECLARE
    app_role_oid oid;
    raw_owner name;
    domain_events_oid oid;
    event_outbox_oid oid;
    outbox_event_id_attnum smallint;
    event_event_id_attnum smallint;
    event_fn oid;
    feature_column_count integer;
    feature_constraint_count integer;
BEGIN
    IF current_database() <> 'paddock_test' THEN
        RAISE EXCEPTION 'refusing Outbox dispatch migration on %, expected paddock_test', current_database();
    END IF;
    IF current_user <> 'paddock_migrator' OR session_user <> 'paddock_migrator' THEN
        RAISE EXCEPTION 'Outbox dispatch migration requires current_user and session_user paddock_migrator';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
        WHERE rolname='paddock_migrator' AND NOT rolsuper AND NOT rolcreaterole
          AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls
    ) OR NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
        WHERE rolname='paddock_app' AND NOT rolsuper AND NOT rolcreaterole
          AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls
    ) THEN
        RAISE EXCEPTION 'isolated non-elevated paddock_app and paddock_migrator roles are required';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_auth_members m
        JOIN pg_catalog.pg_roles granted_role ON granted_role.oid=m.roleid
        JOIN pg_catalog.pg_roles member_role ON member_role.oid=m.member
        WHERE granted_role.rolname IN ('paddock_app','paddock_migrator')
           OR member_role.rolname IN ('paddock_app','paddock_migrator')
    ) THEN
        RAISE EXCEPTION 'paddock_app and paddock_migrator must have no role memberships';
    END IF;

    SELECT r.rolname INTO raw_owner
    FROM pg_catalog.pg_namespace n
    JOIN pg_catalog.pg_roles r ON r.oid=n.nspowner
    WHERE n.nspname='raw';
    IF raw_owner IS DISTINCT FROM 'paddock_migrator' THEN
        RAISE EXCEPTION 'raw schema must be owned by paddock_migrator';
    END IF;
    SELECT oid INTO app_role_oid FROM pg_catalog.pg_roles WHERE rolname='paddock_app';

    SELECT c.oid INTO domain_events_oid
    FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    JOIN pg_catalog.pg_roles r ON r.oid=c.relowner
    WHERE n.nspname='raw' AND c.relname='domain_events' AND c.relkind='r' AND r.rolname='paddock_migrator';
    SELECT c.oid INTO event_outbox_oid
    FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    JOIN pg_catalog.pg_roles r ON r.oid=c.relowner
    WHERE n.nspname='raw' AND c.relname='event_outbox' AND c.relkind='r' AND r.rolname='paddock_migrator';
    IF domain_events_oid IS NULL OR event_outbox_oid IS NULL THEN
        RAISE EXCEPTION 'raw.domain_events and raw.event_outbox must be migrator-owned ordinary tables';
    END IF;
    SELECT a.attnum INTO outbox_event_id_attnum
    FROM pg_catalog.pg_attribute a
    WHERE a.attrelid=event_outbox_oid AND a.attname='event_id'
      AND a.attnum>0 AND NOT a.attisdropped
      AND a.atttypid='text'::pg_catalog.regtype AND a.attnotnull;
    SELECT a.attnum INTO event_event_id_attnum
    FROM pg_catalog.pg_attribute a
    WHERE a.attrelid=domain_events_oid AND a.attname='event_id'
      AND a.attnum>0 AND NOT a.attisdropped
      AND a.atttypid='text'::pg_catalog.regtype AND a.attnotnull;
    IF outbox_event_id_attnum IS NULL OR event_event_id_attnum IS NULL THEN
        RAISE EXCEPTION 'Event and Outbox event_id columns must be text NOT NULL';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint c
        WHERE c.conrelid=event_outbox_oid AND c.contype='p'
          AND c.conkey=ARRAY[outbox_event_id_attnum]::smallint[]
          AND c.convalidated
    ) THEN
        RAISE EXCEPTION 'raw.event_outbox must have a validated primary key exactly on event_id';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint c
        WHERE c.conrelid=event_outbox_oid AND c.contype='f'
          AND c.conkey=ARRAY[outbox_event_id_attnum]::smallint[]
          AND c.confrelid=domain_events_oid
          AND c.confkey=ARRAY[event_event_id_attnum]::smallint[]
          AND c.convalidated
    ) THEN
        RAISE EXCEPTION 'raw.event_outbox.event_id must reference raw.domain_events.event_id';
    END IF;

    event_fn := pg_catalog.to_regprocedure('raw.append_domain_event_and_outbox(text,text,text,bigint,text,text,bytea)');
    IF event_fn IS NULL OR NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_proc p
        JOIN pg_catalog.pg_roles owner_role ON owner_role.oid=p.proowner
        WHERE p.oid=event_fn AND owner_role.rolname='paddock_migrator'
          AND p.prosecdef AND p.proconfig @> ARRAY['search_path=pg_catalog']::text[]
          AND pg_catalog.has_function_privilege('paddock_app',p.oid,'EXECUTE')
    ) THEN
        RAISE EXCEPTION 'existing app-only migrator-owned append_domain_event_and_outbox function is required';
    END IF;
    IF pg_catalog.has_table_privilege(app_role_oid,event_outbox_oid,'SELECT')
       OR pg_catalog.has_table_privilege(app_role_oid,event_outbox_oid,'INSERT')
       OR pg_catalog.has_table_privilege(app_role_oid,event_outbox_oid,'UPDATE')
       OR pg_catalog.has_table_privilege(app_role_oid,event_outbox_oid,'DELETE')
       OR EXISTS (
           SELECT 1
           FROM pg_catalog.pg_attribute a
           WHERE a.attrelid=event_outbox_oid AND a.attnum>0 AND NOT a.attisdropped
             AND (pg_catalog.has_column_privilege(app_role_oid,event_outbox_oid,a.attnum,'SELECT')
               OR pg_catalog.has_column_privilege(app_role_oid,event_outbox_oid,a.attnum,'INSERT')
               OR pg_catalog.has_column_privilege(app_role_oid,event_outbox_oid,a.attnum,'UPDATE')
               OR pg_catalog.has_column_privilege(app_role_oid,event_outbox_oid,a.attnum,'REFERENCES'))
       ) THEN
        RAISE EXCEPTION 'paddock_app must not have direct event_outbox table privileges';
    END IF;

    SELECT count(*) INTO feature_column_count
    FROM pg_catalog.pg_attribute a
    WHERE a.attrelid=event_outbox_oid AND a.attnum>0 AND NOT a.attisdropped
      AND a.attname IN ('claim_token','lease_expires_at','dead_lettered_at','redrive_count');
    IF feature_column_count NOT IN (0,4) THEN
        RAISE EXCEPTION 'raw.event_outbox has a partial Outbox dispatch column set';
    END IF;
    SELECT count(*) INTO feature_constraint_count
    FROM pg_catalog.pg_constraint c
    WHERE c.conrelid=event_outbox_oid AND c.conname IN (
        'event_outbox_claim_pair_ck','event_outbox_dead_letter_unclaimed_ck',
        'event_outbox_published_not_dead_lettered_ck','event_outbox_redrive_count_ck'
    );
    IF feature_column_count=0 AND feature_constraint_count<>0 THEN
        RAISE EXCEPTION 'raw.event_outbox has dispatch constraints without the complete column set';
    END IF;
    IF feature_column_count=4 THEN
        IF feature_constraint_count<>4 OR EXISTS (
            SELECT 1 FROM pg_catalog.pg_constraint c
            WHERE c.conrelid=event_outbox_oid AND c.conname IN (
                'event_outbox_claim_pair_ck','event_outbox_dead_letter_unclaimed_ck',
                'event_outbox_published_not_dead_lettered_ck','event_outbox_redrive_count_ck'
            ) AND (c.contype<>'c' OR NOT c.convalidated)
        ) THEN
            RAISE EXCEPTION 'existing Outbox dispatch constraints are partial or unvalidated';
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a WHERE a.attrelid=event_outbox_oid AND a.attname='claim_token' AND a.atttypid='uuid'::pg_catalog.regtype AND NOT a.attnotnull)
           OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a WHERE a.attrelid=event_outbox_oid AND a.attname='lease_expires_at' AND a.atttypid='timestamp with time zone'::pg_catalog.regtype AND NOT a.attnotnull)
           OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a WHERE a.attrelid=event_outbox_oid AND a.attname='dead_lettered_at' AND a.atttypid='timestamp with time zone'::pg_catalog.regtype AND NOT a.attnotnull)
           OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid=event_outbox_oid AND a.attname='redrive_count' AND a.atttypid='integer'::pg_catalog.regtype AND a.attnotnull AND pg_catalog.pg_get_expr(d.adbin,d.adrelid)='0') THEN
            RAISE EXCEPTION 'existing Outbox dispatch column types/defaults are incompatible';
        END IF;
        IF EXISTS (
            SELECT 1 FROM pg_catalog.pg_constraint c
            WHERE c.conrelid=event_outbox_oid AND c.conname='event_outbox_claim_pair_ck'
              AND pg_catalog.regexp_replace(pg_catalog.lower(pg_catalog.pg_get_constraintdef(c.oid)), '[[:space:]()]', '', 'g') <> 'checkclaim_tokenisnull=lease_expires_atisnull'
        ) OR EXISTS (
            SELECT 1 FROM pg_catalog.pg_constraint c
            WHERE c.conrelid=event_outbox_oid AND c.conname='event_outbox_dead_letter_unclaimed_ck'
              AND pg_catalog.regexp_replace(pg_catalog.lower(pg_catalog.pg_get_constraintdef(c.oid)), '[[:space:]()]', '', 'g') <> 'checkdead_lettered_atisnullorclaim_tokenisnullandlease_expires_atisnull'
        ) OR EXISTS (
            SELECT 1 FROM pg_catalog.pg_constraint c
            WHERE c.conrelid=event_outbox_oid AND c.conname='event_outbox_published_not_dead_lettered_ck'
              AND pg_catalog.regexp_replace(pg_catalog.lower(pg_catalog.pg_get_constraintdef(c.oid)), '[[:space:]()]', '', 'g') <> 'checkpublished_atisnullordead_lettered_atisnull'
        ) OR EXISTS (
            SELECT 1 FROM pg_catalog.pg_constraint c
            WHERE c.conrelid=event_outbox_oid AND c.conname='event_outbox_redrive_count_ck'
              AND pg_catalog.regexp_replace(pg_catalog.lower(pg_catalog.pg_get_constraintdef(c.oid)), '[[:space:]()]', '', 'g') NOT IN ('checkredrive_countbetween0and1','checkredrive_count>=0andredrive_count<=1')
        ) THEN
            RAISE EXCEPTION 'existing Outbox dispatch checks have incompatible definitions';
        END IF;
    END IF;
END
$migration_guard$;

ALTER TABLE raw.event_outbox
    ADD COLUMN IF NOT EXISTS claim_token uuid,
    ADD COLUMN IF NOT EXISTS lease_expires_at timestamptz,
    ADD COLUMN IF NOT EXISTS dead_lettered_at timestamptz,
    ADD COLUMN IF NOT EXISTS redrive_count integer NOT NULL DEFAULT 0;

DO $outbox_constraint_guard$
DECLARE
    outbox_oid oid := pg_catalog.to_regclass('raw.event_outbox');
    constraint_count integer;
BEGIN
    SELECT count(*) INTO constraint_count
    FROM pg_catalog.pg_constraint c
    WHERE c.conrelid=outbox_oid AND c.conname IN (
        'event_outbox_claim_pair_ck','event_outbox_dead_letter_unclaimed_ck',
        'event_outbox_published_not_dead_lettered_ck','event_outbox_redrive_count_ck'
    );
    IF constraint_count=0 THEN
        ALTER TABLE raw.event_outbox
            ADD CONSTRAINT event_outbox_claim_pair_ck
                CHECK ((claim_token IS NULL) = (lease_expires_at IS NULL)),
            ADD CONSTRAINT event_outbox_dead_letter_unclaimed_ck
                CHECK (dead_lettered_at IS NULL OR (claim_token IS NULL AND lease_expires_at IS NULL)),
            ADD CONSTRAINT event_outbox_published_not_dead_lettered_ck
                CHECK (published_at IS NULL OR dead_lettered_at IS NULL),
            ADD CONSTRAINT event_outbox_redrive_count_ck
                CHECK (redrive_count BETWEEN 0 AND 1);
    ELSIF constraint_count<>4 THEN
        RAISE EXCEPTION 'raw.event_outbox has a partial dispatch constraint set';
    END IF;
END
$outbox_constraint_guard$;

CREATE INDEX IF NOT EXISTS event_outbox_claimable_idx
    ON raw.event_outbox (available_at,event_id)
    WHERE published_at IS NULL AND dead_lettered_at IS NULL;
CREATE INDEX IF NOT EXISTS event_outbox_redrive_idx
    ON raw.event_outbox (dead_lettered_at,event_id)
    WHERE published_at IS NULL AND dead_lettered_at IS NOT NULL AND redrive_count=0;

DO $outbox_index_readback$
DECLARE
    outbox_oid oid := pg_catalog.to_regclass('raw.event_outbox');
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_index i
        WHERE i.indexrelid=pg_catalog.to_regclass('raw.event_outbox_claimable_idx')
          AND i.indrelid=outbox_oid AND i.indisvalid AND i.indisready AND NOT i.indisunique
          AND pg_catalog.pg_get_indexdef(i.indexrelid) ILIKE '%(available_at, event_id)%'
          AND pg_catalog.regexp_replace(pg_catalog.lower(pg_catalog.pg_get_expr(i.indpred,i.indrelid)), '[[:space:]()]', '', 'g')='published_atisnullanddead_lettered_atisnull'
    ) OR NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_index i
        WHERE i.indexrelid=pg_catalog.to_regclass('raw.event_outbox_redrive_idx')
          AND i.indrelid=outbox_oid AND i.indisvalid AND i.indisready AND NOT i.indisunique
          AND pg_catalog.pg_get_indexdef(i.indexrelid) ILIKE '%(dead_lettered_at, event_id)%'
          AND pg_catalog.regexp_replace(pg_catalog.lower(pg_catalog.pg_get_expr(i.indpred,i.indrelid)), '[[:space:]()]', '', 'g')='published_atisnullanddead_lettered_atisnotnullandredrive_count=0'
    ) THEN
        RAISE EXCEPTION 'Outbox claim/redrive indexes are missing or incompatible';
    END IF;
END
$outbox_index_readback$;

CREATE OR REPLACE FUNCTION raw.claim_event_outbox(integer)
RETURNS TABLE(
    event_id text, aggregate_kind text, aggregate_id text, aggregate_version bigint,
    event_type text, schema_version text, payload bytea, claim_token text,
    attempt_count integer, lease_expires_at timestamptz
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $claim_event_outbox$
DECLARE
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_remaining integer;
    v_changed integer;
BEGIN
    IF session_user<>'paddock_app' THEN
        RAISE EXCEPTION 'claim_event_outbox requires session_user paddock_app';
    END IF;
    IF $1 IS NULL OR $1<1 OR $1>100 THEN
        RAISE EXCEPTION 'claim_event_outbox batch size must be between 1 and 100';
    END IF;
    v_remaining:=$1;
    IF EXISTS (
        SELECT 1
        FROM raw.event_outbox o
        LEFT JOIN raw.domain_events e ON e.event_id=o.event_id
        WHERE e.event_id IS NULL
        LIMIT 1
    ) THEN
        RAISE EXCEPTION 'claim_event_outbox found an Outbox row without its durable Event';
    END IF;

    WITH exhausted AS (
        SELECT o.event_id
        FROM raw.event_outbox o
        WHERE o.published_at IS NULL AND o.dead_lettered_at IS NULL
          AND (o.claim_token IS NULL OR o.lease_expires_at<=v_now)
          AND o.attempt_count >= 20*(o.redrive_count+1)
        ORDER BY o.lease_expires_at,o.event_id
        LIMIT v_remaining
        FOR UPDATE OF o SKIP LOCKED
    )
    UPDATE raw.event_outbox o
       SET dead_lettered_at=v_now,claim_token=NULL,lease_expires_at=NULL,
           last_error='LEASE_EXPIRED_MAX_ATTEMPTS'
      FROM exhausted x WHERE o.event_id=x.event_id;
    GET DIAGNOSTICS v_changed=ROW_COUNT;
    v_remaining:=v_remaining-v_changed;

    IF v_remaining>0 THEN
      WITH redrive AS (
        SELECT o.event_id
        FROM raw.event_outbox o
        WHERE o.published_at IS NULL AND o.dead_lettered_at IS NOT NULL
          AND o.redrive_count=0 AND o.dead_lettered_at<=v_now-interval '24 hours'
        ORDER BY o.dead_lettered_at,o.event_id
        LIMIT v_remaining
        FOR UPDATE OF o SKIP LOCKED
      )
      UPDATE raw.event_outbox o
         SET dead_lettered_at=NULL,redrive_count=1,available_at=v_now
        FROM redrive r WHERE o.event_id=r.event_id;
      GET DIAGNOSTICS v_changed=ROW_COUNT;
      v_remaining:=v_remaining-v_changed;
    END IF;

    IF v_remaining>0 THEN
     RETURN QUERY
      WITH candidates AS (
        SELECT o.event_id
        FROM raw.event_outbox o
        WHERE o.published_at IS NULL AND o.dead_lettered_at IS NULL
          AND o.available_at<=v_now
          AND (o.lease_expires_at IS NULL OR o.lease_expires_at<=v_now)
          AND o.attempt_count < 20*(o.redrive_count+1)
        ORDER BY o.available_at,o.event_id
        LIMIT v_remaining
        FOR UPDATE OF o SKIP LOCKED
    ), claimed AS (
        UPDATE raw.event_outbox o
           SET claim_token=pg_catalog.gen_random_uuid(),
               lease_expires_at=v_now+interval '5 minutes',
               attempt_count=o.attempt_count+1
          FROM candidates c WHERE o.event_id=c.event_id
        RETURNING o.event_id,o.claim_token,o.attempt_count,o.lease_expires_at
    )
    SELECT e.event_id,e.aggregate_kind,e.aggregate_id,e.aggregate_version,
           e.event_type,e.schema_version,e.payload,c.claim_token::text,
           c.attempt_count,c.lease_expires_at
      FROM claimed c JOIN raw.domain_events e ON e.event_id=c.event_id
      ORDER BY e.created_at,e.event_id;
    END IF;
END
$claim_event_outbox$;

CREATE OR REPLACE FUNCTION raw.ack_event_outbox(text,text)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $ack_event_outbox$
BEGIN
    IF session_user<>'paddock_app' THEN
        RAISE EXCEPTION 'ack_event_outbox requires session_user paddock_app';
    END IF;
    IF $1 IS NULL OR $1='' OR $1<>pg_catalog.btrim($1)
       OR $2 IS NULL OR $2 !~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' THEN
        RAISE EXCEPTION 'ack_event_outbox requires a valid Event ID and claim token';
    END IF;
    UPDATE raw.event_outbox o
       SET published_at=pg_catalog.clock_timestamp(),claim_token=NULL,
           lease_expires_at=NULL,last_error=NULL
     WHERE o.event_id=$1 AND o.claim_token=$2::uuid
       AND o.published_at IS NULL AND o.dead_lettered_at IS NULL
       AND o.lease_expires_at>pg_catalog.clock_timestamp();
    RETURN FOUND;
END
$ack_event_outbox$;

CREATE OR REPLACE FUNCTION raw.retry_event_outbox(text,text,text)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $retry_event_outbox$
DECLARE
    v_attempt_count integer;
    v_redrive_count integer;
    v_cycle_attempt integer;
    v_backoff_seconds integer;
    v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
    IF session_user<>'paddock_app' THEN
        RAISE EXCEPTION 'retry_event_outbox requires session_user paddock_app';
    END IF;
    IF $1 IS NULL OR $1='' OR $1<>pg_catalog.btrim($1)
       OR $2 IS NULL OR $2 !~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
       OR $3 IS NULL OR $3 !~ '^[A-Z0-9_]{1,64}$' THEN
        RAISE EXCEPTION 'retry_event_outbox requires valid Event ID, token, and sanitized error code';
    END IF;
    SELECT o.attempt_count,o.redrive_count
      INTO v_attempt_count,v_redrive_count
      FROM raw.event_outbox o
     WHERE o.event_id=$1 AND o.claim_token=$2::uuid
       AND o.published_at IS NULL AND o.dead_lettered_at IS NULL
       AND o.lease_expires_at>v_now
     FOR UPDATE;
    IF NOT FOUND THEN
        RETURN 'STALE_CLAIM';
    END IF;

    IF v_attempt_count >= 20*(v_redrive_count+1) THEN
        UPDATE raw.event_outbox o
           SET dead_lettered_at=v_now,available_at=v_now,last_error=$3,
               claim_token=NULL,lease_expires_at=NULL
         WHERE o.event_id=$1 AND o.claim_token=$2::uuid;
        RETURN 'DEAD_LETTERED';
    END IF;

    v_cycle_attempt := v_attempt_count-(v_redrive_count*20);
    v_backoff_seconds := LEAST(3600,5*(pg_catalog.power(2,LEAST(v_cycle_attempt-1,10)))::integer);
    UPDATE raw.event_outbox o
       SET available_at=v_now+pg_catalog.make_interval(secs=>v_backoff_seconds),
           last_error=$3,claim_token=NULL,lease_expires_at=NULL
     WHERE o.event_id=$1 AND o.claim_token=$2::uuid;
    RETURN 'RETRY_SCHEDULED';
END
$retry_event_outbox$;

-- Preserve the existing transaction contract and add only a low-latency wake-up hint.
CREATE OR REPLACE FUNCTION raw.append_domain_event_and_outbox(text,text,text,bigint,text,text,bytea)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $append_domain_event_and_outbox$
BEGIN
    IF session_user<>'paddock_app' THEN
        RAISE EXCEPTION 'append_domain_event_and_outbox requires session_user paddock_app';
    END IF;
    IF $1 IS NULL OR $1='' OR $1<>pg_catalog.btrim($1)
       OR $2 IS NULL OR $2='' OR $2<>pg_catalog.btrim($2)
       OR $3 IS NULL OR $3<>pg_catalog.btrim($3)
       OR $5 IS NULL OR $5='' OR $5<>pg_catalog.btrim($5)
       OR $6 IS NULL OR $6='' OR $6<>pg_catalog.btrim($6) THEN
        RAISE EXCEPTION 'event identity/type/schema values must be nonempty trimmed text';
    END IF;
    IF $4 IS NULL OR $4<=0 OR $7 IS NULL THEN
        RAISE EXCEPTION 'event version must be positive and payload non-null';
    END IF;
    INSERT INTO raw.domain_events(event_id,aggregate_kind,aggregate_id,aggregate_version,event_type,schema_version,payload)
    VALUES ($1,$2,$3,$4,$5,$6,$7);
    INSERT INTO raw.event_outbox(event_id) VALUES ($1);
    PERFORM pg_catalog.pg_notify('paddock_event_outbox','');
END
$append_domain_event_and_outbox$;

ALTER FUNCTION raw.claim_event_outbox(integer) OWNER TO paddock_migrator;
ALTER FUNCTION raw.ack_event_outbox(text,text) OWNER TO paddock_migrator;
ALTER FUNCTION raw.retry_event_outbox(text,text,text) OWNER TO paddock_migrator;
ALTER FUNCTION raw.append_domain_event_and_outbox(text,text,text,bigint,text,text,bytea) OWNER TO paddock_migrator;

DO $revoke_outbox_function_grants$
DECLARE
    grantee_name name;
BEGIN
    FOR grantee_name IN
        SELECT DISTINCT r.rolname
        FROM pg_catalog.pg_proc p
        CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
        JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
        WHERE p.oid IN (
            pg_catalog.to_regprocedure('raw.claim_event_outbox(integer)'),
            pg_catalog.to_regprocedure('raw.ack_event_outbox(text,text)'),
            pg_catalog.to_regprocedure('raw.retry_event_outbox(text,text,text)'),
            pg_catalog.to_regprocedure('raw.append_domain_event_and_outbox(text,text,text,bigint,text,text,bytea)')
        ) AND a.grantee<>p.proowner AND a.grantee<>0
          AND a.grantee<>(SELECT oid FROM pg_catalog.pg_roles WHERE rolname='paddock_app')
          AND a.privilege_type='EXECUTE'
    LOOP
        EXECUTE pg_catalog.format(
            'REVOKE ALL ON FUNCTION raw.claim_event_outbox(integer), raw.ack_event_outbox(text,text), raw.retry_event_outbox(text,text,text), raw.append_domain_event_and_outbox(text,text,text,bigint,text,text,bytea) FROM %I',
            grantee_name
        );
    END LOOP;
END
$revoke_outbox_function_grants$;

REVOKE ALL ON FUNCTION raw.claim_event_outbox(integer), raw.ack_event_outbox(text,text), raw.retry_event_outbox(text,text,text), raw.append_domain_event_and_outbox(text,text,text,bigint,text,text,bytea)
    FROM PUBLIC,paddock_app;
GRANT EXECUTE ON FUNCTION raw.claim_event_outbox(integer), raw.ack_event_outbox(text,text), raw.retry_event_outbox(text,text,text), raw.append_domain_event_and_outbox(text,text,text,bigint,text,text,bytea)
    TO paddock_app;

COMMIT;

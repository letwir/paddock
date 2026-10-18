-- Guarded additive repair for raw.domain_events.schema_version.
-- Apply only as the isolated migration role on the exact test database.
BEGIN;

DO $migration_guard$
DECLARE
    domain_events_oid oid;
    event_outbox_oid oid;
    append_function_oid oid;
    schema_version_attnum smallint;
    schema_version_type oid;
    schema_version_not_null boolean;
    expected_columns integer;
    actual_columns integer;
    expected_physical_columns integer;
    outbox_event_id_attnum smallint;
BEGIN
    IF current_database() <> 'paddock_test' THEN
        RAISE EXCEPTION 'refusing domain event schema migration on %, expected paddock_test', current_database();
    END IF;
    IF current_user <> 'paddock_migrator' OR session_user <> 'paddock_migrator' THEN
        RAISE EXCEPTION 'domain event schema migration requires current_user and session_user paddock_migrator';
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

    SELECT c.oid INTO domain_events_oid
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_catalog.pg_roles r ON r.oid = c.relowner
    WHERE n.nspname = 'raw' AND c.relname = 'domain_events'
      AND c.relkind = 'r' AND r.rolname = 'paddock_migrator';
    IF domain_events_oid IS NULL THEN
        RAISE EXCEPTION 'raw.domain_events must exist as an ordinary table owned by paddock_migrator';
    END IF;

    SELECT c.oid INTO event_outbox_oid
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_catalog.pg_roles r ON r.oid = c.relowner
    WHERE n.nspname = 'raw' AND c.relname = 'event_outbox'
      AND c.relkind = 'r' AND r.rolname = 'paddock_migrator';
    IF event_outbox_oid IS NULL THEN
        RAISE EXCEPTION 'raw.event_outbox must exist as an ordinary table owned by paddock_migrator';
    END IF;

    SELECT a.attnum INTO outbox_event_id_attnum
    FROM pg_catalog.pg_attribute a
    WHERE a.attrelid = event_outbox_oid AND a.attname = 'event_id'
      AND a.attnum > 0 AND NOT a.attisdropped
      AND a.atttypid = 'text'::pg_catalog.regtype AND a.attnotnull;
    IF outbox_event_id_attnum IS NULL THEN
        RAISE EXCEPTION 'raw.event_outbox.event_id must exist as text NOT NULL';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint c
        WHERE c.conrelid = event_outbox_oid AND c.contype = 'p'
          AND c.conkey = ARRAY[outbox_event_id_attnum]::smallint[]
    ) THEN
        RAISE EXCEPTION 'raw.event_outbox must have a primary key exactly on event_id';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint c
        JOIN pg_catalog.pg_attribute target
          ON target.attrelid = domain_events_oid AND target.attname = 'event_id'
         AND target.attnum > 0 AND NOT target.attisdropped
        WHERE c.conrelid = event_outbox_oid AND c.contype = 'f'
          AND c.conkey = ARRAY[outbox_event_id_attnum]::smallint[]
          AND c.confrelid = domain_events_oid
          AND c.confkey = ARRAY[target.attnum]::smallint[]
    ) THEN
        RAISE EXCEPTION 'raw.event_outbox.event_id must reference raw.domain_events.event_id';
    END IF;

    append_function_oid := pg_catalog.to_regprocedure(
        'raw.append_domain_event_and_outbox(text,text,text,bigint,text,text,bytea)'
    );
    IF append_function_oid IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_proc p
        JOIN pg_catalog.pg_roles r ON r.oid = p.proowner
        WHERE p.oid = append_function_oid
          AND p.prorettype = 'void'::pg_catalog.regtype
          AND r.rolname = 'paddock_migrator'
    ) THEN
        RAISE EXCEPTION 'existing append function must return void and be owned by paddock_migrator';
    END IF;

    SELECT a.attnum, a.atttypid, a.attnotnull
      INTO schema_version_attnum, schema_version_type, schema_version_not_null
    FROM pg_catalog.pg_attribute a
    WHERE a.attrelid = domain_events_oid AND a.attname = 'schema_version'
      AND a.attnum > 0 AND NOT a.attisdropped;

    -- Match the complete expected row shape, allowing only the target column to be absent.
    SELECT count(*) INTO expected_columns
    FROM pg_catalog.pg_attribute a
    WHERE a.attrelid = domain_events_oid AND a.attnum > 0 AND NOT a.attisdropped
      AND (a.attname, a.atttypid, a.attnotnull) IN (
          ('event_id', 'text'::pg_catalog.regtype, true),
          ('aggregate_kind', 'text'::pg_catalog.regtype, true),
          ('aggregate_id', 'text'::pg_catalog.regtype, true),
          ('aggregate_version', 'bigint'::pg_catalog.regtype, true),
          ('event_type', 'text'::pg_catalog.regtype, true),
          ('payload', 'bytea'::pg_catalog.regtype, true),
          ('created_at', 'timestamp with time zone'::pg_catalog.regtype, true)
      );
    IF expected_columns <> 7 THEN
        RAISE EXCEPTION 'raw.domain_events does not have the expected table shape';
    END IF;

    IF schema_version_attnum IS NULL THEN
        expected_physical_columns := 7;
    ELSE
        expected_physical_columns := 8;
    END IF;
    SELECT count(*) INTO actual_columns
    FROM pg_catalog.pg_attribute a
    WHERE a.attrelid = domain_events_oid AND a.attnum > 0 AND NOT a.attisdropped;
    IF actual_columns <> expected_physical_columns THEN
        RAISE EXCEPTION 'raw.domain_events does not have the expected table shape';
    END IF;

    IF schema_version_attnum IS NOT NULL THEN
        IF schema_version_type <> 'text'::pg_catalog.regtype OR NOT schema_version_not_null
           OR NOT EXISTS (
                SELECT 1 FROM pg_catalog.pg_constraint c
                WHERE c.conrelid = domain_events_oid
                  AND c.conname = 'domain_events_schema_version_nonempty_ck'
                  AND c.contype = 'c' AND c.convalidated
                  AND c.conkey = ARRAY[schema_version_attnum]::smallint[]
                  AND pg_catalog.regexp_replace(
                      pg_catalog.lower(pg_catalog.pg_get_constraintdef(c.oid)),
                      '[[:space:]()]', '', 'g'
                  ) IN (
                      $expected_check$check(schema_version<>''::text)$expected_check$,
                      $expected_check$check(schema_version<>'')$expected_check$
                  )
           ) THEN
            RAISE EXCEPTION 'raw.domain_events.schema_version has partial or incompatible state; refusing migration';
        END IF;
        RETURN;
    END IF;

    -- Serialize absent-column decisions and never infer a legacy version.
    LOCK TABLE raw.domain_events IN ACCESS EXCLUSIVE MODE;
    IF EXISTS (SELECT 1 FROM raw.domain_events LIMIT 1) THEN
        RAISE EXCEPTION 'raw.domain_events contains rows; a legacy event version policy is required before schema_version can be added';
    END IF;

    ALTER TABLE raw.domain_events
        ADD COLUMN schema_version text NOT NULL
        CONSTRAINT domain_events_schema_version_nonempty_ck
        CHECK (schema_version <> '');
END
$migration_guard$;

CREATE OR REPLACE FUNCTION raw.append_domain_event_and_outbox(
    text, text, text, bigint, text, text, bytea
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $append_domain_event_and_outbox$
BEGIN
    IF session_user <> 'paddock_app' THEN
        RAISE EXCEPTION 'append_domain_event_and_outbox requires session_user paddock_app';
    END IF;
    IF $1 IS NULL OR $1 = '' OR $1 <> pg_catalog.btrim($1)
       OR $2 IS NULL OR $2 = '' OR $2 <> pg_catalog.btrim($2)
       OR $3 IS NULL OR $3 = '' OR $3 <> pg_catalog.btrim($3)
       OR $5 IS NULL OR $5 = '' OR $5 <> pg_catalog.btrim($5)
       OR $6 IS NULL OR $6 = '' OR $6 <> pg_catalog.btrim($6) THEN
        RAISE EXCEPTION 'event_id, aggregate_kind, aggregate_id, event_type, and schema_version must be nonempty trimmed text';
    END IF;
    IF $4 IS NULL OR $4 <= 0 THEN
        RAISE EXCEPTION 'aggregate_version must be positive';
    END IF;
    IF $7 IS NULL THEN
        RAISE EXCEPTION 'payload must not be null';
    END IF;

    INSERT INTO raw.domain_events (
        event_id, aggregate_kind, aggregate_id, aggregate_version,
        event_type, schema_version, payload
    ) VALUES ($1, $2, $3, $4, $5, $6, $7);
    INSERT INTO raw.event_outbox (event_id) VALUES ($1);
END
$append_domain_event_and_outbox$;

ALTER FUNCTION raw.append_domain_event_and_outbox(text, text, text, bigint, text, text, bytea)
    OWNER TO paddock_migrator;
REVOKE ALL ON FUNCTION raw.append_domain_event_and_outbox(text, text, text, bigint, text, text, bytea)
    FROM PUBLIC, paddock_app;
DO $revoke_existing_function_execute$
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
        WHERE p.oid = pg_catalog.to_regprocedure(
            'raw.append_domain_event_and_outbox(text,text,text,bigint,text,text,bytea)'
        )
          AND acl.privilege_type = 'EXECUTE'
          AND acl.grantee <> p.proowner
    LOOP
        EXECUTE pg_catalog.format(
            'REVOKE ALL ON FUNCTION raw.append_domain_event_and_outbox(text, text, text, bigint, text, text, bytea) FROM %I',
            grantee_name
        );
    END LOOP;
END
$revoke_existing_function_execute$;
REVOKE ALL ON FUNCTION raw.append_domain_event_and_outbox(text, text, text, bigint, text, text, bytea)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION raw.append_domain_event_and_outbox(text, text, text, bigint, text, text, bytea)
    TO paddock_app;

REVOKE ALL ON TABLE raw.domain_events FROM PUBLIC, paddock_app;
GRANT SELECT ON TABLE raw.domain_events TO paddock_app;
REVOKE ALL ON TABLE raw.event_outbox FROM PUBLIC, paddock_app;

DO $revoke_event_column_privileges$
DECLARE
    column_record record;
BEGIN
    FOR column_record IN
        SELECT c.relname, a.attname
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid
        WHERE n.nspname = 'raw'
          AND c.relname IN ('domain_events', 'event_outbox')
          AND c.relkind = 'r'
          AND a.attnum > 0 AND NOT a.attisdropped
        ORDER BY c.relname, a.attnum
    LOOP
        EXECUTE pg_catalog.format(
            'REVOKE SELECT (%1$I), INSERT (%1$I), UPDATE (%1$I), REFERENCES (%1$I) ON TABLE raw.%2$I FROM PUBLIC, paddock_app',
            column_record.attname,
            column_record.relname
        );
    END LOOP;
END
$revoke_event_column_privileges$;

COMMIT;

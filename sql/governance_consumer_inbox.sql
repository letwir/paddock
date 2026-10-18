-- M05-S04 additive Consumer Inbox/projection privileges.
-- Apply only as paddock_migrator on the isolated paddock_test database.
-- The application receives narrowly scoped DML for Inbox idempotency and the
-- local consumer projection; Outbox remains function-only.
BEGIN;

DO $consumer_inbox_guard$
DECLARE
    app_oid oid;
    event_inbox_oid oid;
    inbox_owner name;
    role_record record;
BEGIN
    IF current_database() <> 'paddock_test' THEN
        RAISE EXCEPTION 'refusing Consumer Inbox migration on %, expected paddock_test', current_database();
    END IF;
    IF current_user <> 'paddock_migrator' OR session_user <> 'paddock_migrator' THEN
        RAISE EXCEPTION 'Consumer Inbox migration requires current_user and session_user paddock_migrator';
    END IF;
    FOR role_record IN
        SELECT rolname FROM pg_catalog.pg_roles
        WHERE rolname IN ('paddock_app','paddock_migrator')
          AND (rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls)
    LOOP
        RAISE EXCEPTION 'Consumer Inbox migration refuses elevated role %', role_record.rolname;
    END LOOP;
    IF (SELECT count(*) FROM pg_catalog.pg_roles WHERE rolname IN ('paddock_app','paddock_migrator')) <> 2 THEN
        RAISE EXCEPTION 'Consumer Inbox migration requires paddock_app and paddock_migrator';
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

    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_namespace n JOIN pg_catalog.pg_roles r ON r.oid=n.nspowner
        WHERE n.nspname='raw' AND r.rolname='paddock_migrator'
    ) THEN
        RAISE EXCEPTION 'raw schema must be owned by paddock_migrator';
    END IF;
    SELECT c.oid,r.rolname INTO event_inbox_oid,inbox_owner
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    JOIN pg_catalog.pg_roles r ON r.oid=c.relowner
    WHERE n.nspname='raw' AND c.relname='event_inbox' AND c.relkind='r';
    IF event_inbox_oid IS NULL OR inbox_owner <> 'paddock_migrator' THEN
        RAISE EXCEPTION 'raw.event_inbox must be a migrator-owned ordinary table';
    END IF;
    IF (SELECT count(*) FROM pg_catalog.pg_attribute a
        WHERE a.attrelid=event_inbox_oid AND a.attnum>0 AND NOT a.attisdropped
          AND ((a.attname IN ('consumer_id','event_id') AND a.atttypid='text'::pg_catalog.regtype AND a.attnotnull)
            OR (a.attname='received_at' AND a.atttypid='timestamp with time zone'::pg_catalog.regtype AND a.attnotnull)
            OR (a.attname='processed_at' AND a.atttypid='timestamp with time zone'::pg_catalog.regtype AND NOT a.attnotnull))) <> 4
       OR (SELECT count(*) FROM pg_catalog.pg_attribute a WHERE a.attrelid=event_inbox_oid AND a.attnum>0 AND NOT a.attisdropped) <> 4
       OR NOT EXISTS (
           SELECT 1 FROM pg_catalog.pg_attribute a
           JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
           WHERE a.attrelid=event_inbox_oid AND a.attname='received_at' AND a.attnum>0 AND NOT a.attisdropped
       ) THEN
        RAISE EXCEPTION 'raw.event_inbox does not have the expected four-column/default shape';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint c
        WHERE c.conrelid=event_inbox_oid AND c.contype='p' AND c.convalidated
          AND c.conkey=ARRAY[
              (SELECT a.attnum FROM pg_catalog.pg_attribute a WHERE a.attrelid=event_inbox_oid AND a.attname='consumer_id' AND a.attnum>0 AND NOT a.attisdropped),
              (SELECT a.attnum FROM pg_catalog.pg_attribute a WHERE a.attrelid=event_inbox_oid AND a.attname='event_id' AND a.attnum>0 AND NOT a.attisdropped)
          ]::smallint[]
    ) THEN
        RAISE EXCEPTION 'raw.event_inbox primary key must be (consumer_id,event_id)';
    END IF;
    IF (SELECT count(*) FROM pg_catalog.pg_index i WHERE i.indrelid=event_inbox_oid AND i.indisunique AND i.indisvalid) <> 1 THEN
        RAISE EXCEPTION 'raw.event_inbox must have exactly one valid unique index (its primary key)';
    END IF;

    SELECT oid INTO app_oid FROM pg_catalog.pg_roles WHERE rolname='paddock_app';
    IF pg_catalog.to_regclass('raw.event_consumer_projection') IS NOT NULL THEN
        RAISE EXCEPTION 'raw.event_consumer_projection already exists; refusing partial/repeated migration';
    END IF;
    IF pg_catalog.has_table_privilege(app_oid,event_inbox_oid,'SELECT')
       OR pg_catalog.has_table_privilege(app_oid,event_inbox_oid,'INSERT')
       OR pg_catalog.has_table_privilege(app_oid,event_inbox_oid,'UPDATE')
       OR pg_catalog.has_table_privilege(app_oid,event_inbox_oid,'DELETE')
       OR pg_catalog.has_table_privilege(app_oid,event_inbox_oid,'TRUNCATE')
       OR pg_catalog.has_table_privilege(app_oid,event_inbox_oid,'REFERENCES')
       OR pg_catalog.has_table_privilege(app_oid,event_inbox_oid,'TRIGGER')
       OR EXISTS (
           SELECT 1 FROM pg_catalog.pg_attribute a
           WHERE a.attrelid=event_inbox_oid AND a.attnum>0 AND NOT a.attisdropped
             AND (pg_catalog.has_column_privilege(app_oid,event_inbox_oid,a.attnum,'SELECT')
               OR pg_catalog.has_column_privilege(app_oid,event_inbox_oid,a.attnum,'INSERT')
               OR pg_catalog.has_column_privilege(app_oid,event_inbox_oid,a.attnum,'UPDATE')
               OR pg_catalog.has_column_privilege(app_oid,event_inbox_oid,a.attnum,'REFERENCES'))
       ) THEN
        RAISE EXCEPTION 'paddock_app must not have pre-existing direct raw.event_inbox privileges';
    END IF;
    IF pg_catalog.has_table_privilege(app_oid,'raw.event_outbox','SELECT')
       OR pg_catalog.has_table_privilege(app_oid,'raw.event_outbox','INSERT')
       OR pg_catalog.has_table_privilege(app_oid,'raw.event_outbox','UPDATE')
       OR pg_catalog.has_table_privilege(app_oid,'raw.event_outbox','DELETE')
       OR pg_catalog.has_table_privilege(app_oid,'raw.event_outbox','TRUNCATE')
       OR pg_catalog.has_table_privilege(app_oid,'raw.event_outbox','REFERENCES')
       OR pg_catalog.has_table_privilege(app_oid,'raw.event_outbox','TRIGGER')
       OR EXISTS (
           SELECT 1 FROM pg_catalog.pg_attribute a
           WHERE a.attrelid=pg_catalog.to_regclass('raw.event_outbox') AND a.attnum>0 AND NOT a.attisdropped
             AND (pg_catalog.has_column_privilege(app_oid,a.attrelid,a.attnum,'SELECT')
               OR pg_catalog.has_column_privilege(app_oid,a.attrelid,a.attnum,'INSERT')
               OR pg_catalog.has_column_privilege(app_oid,a.attrelid,a.attnum,'UPDATE')
               OR pg_catalog.has_column_privilege(app_oid,a.attrelid,a.attnum,'REFERENCES'))
       ) THEN
        RAISE EXCEPTION 'paddock_app must not have direct raw.event_outbox privileges';
    END IF;
END
$consumer_inbox_guard$;

CREATE TABLE raw.event_consumer_projection (
    consumer_id            text NOT NULL,
    processed_event_count  bigint NOT NULL,
    CONSTRAINT event_consumer_projection_consumer_pk PRIMARY KEY (consumer_id),
    CONSTRAINT event_consumer_projection_consumer_ck CHECK (consumer_id <> ''),
    CONSTRAINT event_consumer_projection_count_ck CHECK (processed_event_count >= 0)
);

REVOKE ALL ON TABLE raw.event_inbox FROM PUBLIC,paddock_app;
REVOKE ALL (consumer_id,event_id,received_at,processed_at) ON TABLE raw.event_inbox FROM PUBLIC,paddock_app;
GRANT INSERT (consumer_id,event_id,processed_at) ON TABLE raw.event_inbox TO paddock_app;

REVOKE ALL ON TABLE raw.event_consumer_projection FROM PUBLIC,paddock_app;
REVOKE ALL (consumer_id,processed_event_count) ON TABLE raw.event_consumer_projection FROM PUBLIC,paddock_app;
GRANT SELECT (consumer_id,processed_event_count), INSERT (consumer_id,processed_event_count), UPDATE (processed_event_count)
    ON TABLE raw.event_consumer_projection TO paddock_app;

DO $consumer_inbox_readback$
DECLARE
    app_oid oid := (SELECT oid FROM pg_catalog.pg_roles WHERE rolname='paddock_app');
    projection_oid oid := pg_catalog.to_regclass('raw.event_consumer_projection');
    inbox_oid oid := pg_catalog.to_regclass('raw.event_inbox');
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_roles r ON r.oid=c.relowner
        WHERE c.oid=projection_oid AND r.rolname='paddock_migrator' AND c.relkind='r'
    ) THEN
        RAISE EXCEPTION 'consumer projection table must be a migrator-owned ordinary table';
    END IF;
    IF (SELECT count(*) FROM pg_catalog.pg_attribute a
        WHERE a.attrelid=projection_oid AND a.attnum>0 AND NOT a.attisdropped
          AND ((a.attname='consumer_id' AND a.atttypid='text'::pg_catalog.regtype AND a.attnotnull)
            OR (a.attname='processed_event_count' AND a.atttypid='bigint'::pg_catalog.regtype AND a.attnotnull))) <> 2
       OR (SELECT count(*) FROM pg_catalog.pg_attribute a WHERE a.attrelid=projection_oid AND a.attnum>0 AND NOT a.attisdropped) <> 2
       OR (SELECT count(*) FROM pg_catalog.pg_constraint c WHERE c.conrelid=projection_oid AND c.convalidated
           AND c.conname IN ('event_consumer_projection_consumer_pk','event_consumer_projection_consumer_ck','event_consumer_projection_count_ck')) <> 3
       OR NOT EXISTS (
           SELECT 1 FROM pg_catalog.pg_constraint c
           WHERE c.conrelid=projection_oid AND c.contype='p' AND c.convalidated
             AND c.conkey=ARRAY[(SELECT a.attnum FROM pg_catalog.pg_attribute a WHERE a.attrelid=projection_oid AND a.attname='consumer_id' AND a.attnum>0 AND NOT a.attisdropped)]::smallint[]
       ) THEN
        RAISE EXCEPTION 'consumer projection table shape/constraints do not match the expected contract';
    END IF;
    IF pg_catalog.has_table_privilege(app_oid,inbox_oid,'SELECT')
       OR pg_catalog.has_table_privilege(app_oid,inbox_oid,'UPDATE')
       OR pg_catalog.has_table_privilege(app_oid,inbox_oid,'DELETE')
       OR pg_catalog.has_table_privilege(app_oid,inbox_oid,'TRUNCATE')
       OR pg_catalog.has_table_privilege(app_oid,inbox_oid,'REFERENCES')
       OR pg_catalog.has_table_privilege(app_oid,inbox_oid,'TRIGGER')
       OR NOT pg_catalog.has_column_privilege(app_oid,inbox_oid,'consumer_id','INSERT')
       OR NOT pg_catalog.has_column_privilege(app_oid,inbox_oid,'event_id','INSERT')
       OR NOT pg_catalog.has_column_privilege(app_oid,inbox_oid,'processed_at','INSERT')
       OR pg_catalog.has_column_privilege(app_oid,inbox_oid,'received_at','INSERT') THEN
        RAISE EXCEPTION 'paddock_app raw.event_inbox column privileges do not match the minimal contract';
    END IF;
    IF pg_catalog.has_table_privilege(app_oid,projection_oid,'SELECT')
       OR pg_catalog.has_table_privilege(app_oid,projection_oid,'INSERT')
       OR pg_catalog.has_table_privilege(app_oid,projection_oid,'UPDATE')
       OR pg_catalog.has_table_privilege(app_oid,projection_oid,'DELETE')
       OR pg_catalog.has_table_privilege(app_oid,projection_oid,'TRUNCATE')
       OR pg_catalog.has_table_privilege(app_oid,projection_oid,'REFERENCES')
       OR pg_catalog.has_table_privilege(app_oid,projection_oid,'TRIGGER')
       OR NOT pg_catalog.has_column_privilege(app_oid,projection_oid,'consumer_id','SELECT')
       OR NOT pg_catalog.has_column_privilege(app_oid,projection_oid,'processed_event_count','SELECT')
       OR NOT pg_catalog.has_column_privilege(app_oid,projection_oid,'consumer_id','INSERT')
       OR NOT pg_catalog.has_column_privilege(app_oid,projection_oid,'processed_event_count','INSERT')
       OR NOT pg_catalog.has_column_privilege(app_oid,projection_oid,'processed_event_count','UPDATE')
       OR pg_catalog.has_column_privilege(app_oid,projection_oid,'consumer_id','UPDATE') THEN
        RAISE EXCEPTION 'paddock_app projection column privileges do not match the minimal contract';
    END IF;
    IF pg_catalog.has_table_privilege(app_oid,'raw.event_outbox','SELECT')
       OR pg_catalog.has_table_privilege(app_oid,'raw.event_outbox','INSERT')
       OR pg_catalog.has_table_privilege(app_oid,'raw.event_outbox','UPDATE')
       OR pg_catalog.has_table_privilege(app_oid,'raw.event_outbox','DELETE')
       OR EXISTS (
           SELECT 1 FROM pg_catalog.pg_attribute a
           WHERE a.attrelid=pg_catalog.to_regclass('raw.event_outbox') AND a.attnum>0 AND NOT a.attisdropped
             AND (pg_catalog.has_column_privilege(app_oid,a.attrelid,a.attnum,'SELECT')
               OR pg_catalog.has_column_privilege(app_oid,a.attrelid,a.attnum,'INSERT')
               OR pg_catalog.has_column_privilege(app_oid,a.attrelid,a.attnum,'UPDATE')
               OR pg_catalog.has_column_privilege(app_oid,a.attrelid,a.attnum,'REFERENCES'))
       ) THEN
        RAISE EXCEPTION 'paddock_app must not have direct raw.event_outbox privileges';
    END IF;
END
$consumer_inbox_readback$;

COMMIT;

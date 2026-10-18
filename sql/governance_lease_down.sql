-- Narrow, guarded rollback for the additive M08-S03 lease migration.
BEGIN;
DO $$ BEGIN
 IF current_database()<>'paddock_test' THEN RAISE EXCEPTION 'refusing lease rollback outside paddock_test'; END IF;
 IF current_user<>'paddock_migrator' THEN RAISE EXCEPTION 'lease rollback must run as paddock_migrator'; END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='paddock_migrator' AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls)
 OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='paddock_app' AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls)
 OR EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid=m.roleid JOIN pg_catalog.pg_roles u ON u.oid=m.member WHERE r.rolname IN ('paddock_app','paddock_migrator') OR u.rolname IN ('paddock_app','paddock_migrator')) THEN RAISE EXCEPTION 'non-elevated isolated app/migrator roles required'; END IF;
 IF to_regclass('raw.work_order_leases') IS NULL OR to_regclass('raw.work_orders') IS NULL OR to_regclass('raw.work_order_attempts') IS NULL THEN RAISE EXCEPTION 'lease migration objects missing'; END IF;
 IF EXISTS (
   SELECT 1 FROM (VALUES
     ('raw.issue_work_order_lease(text,text,text,text,text,jsonb,jsonb,interval)'),
     ('raw.heartbeat_work_order_lease(text,text,text,text,bigint,interval)'),
     ('raw.reap_work_order_leases(integer)'),
     ('raw.complete_work_order_lease(text,text,text,text,bigint)')
   ) AS expected(signature)
   WHERE to_regprocedure(expected.signature) IS NULL
      OR NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_proc p
        JOIN pg_catalog.pg_roles r ON r.oid=p.proowner
        WHERE p.oid=to_regprocedure(expected.signature)::oid
          AND r.rolname='paddock_migrator'
      )
 ) THEN RAISE EXCEPTION 'exact S03 lease functions and migrator ownership required'; END IF;
 IF EXISTS (
   SELECT 1 FROM (VALUES ('work_order_leases'),('work_orders'),('work_order_attempts')) AS expected(name)
   WHERE NOT EXISTS (
     SELECT 1 FROM pg_catalog.pg_class c
     JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
     JOIN pg_catalog.pg_roles r ON r.oid=c.relowner
     WHERE n.nspname='raw' AND c.relname=expected.name AND c.relkind='r' AND r.rolname='paddock_migrator'
   )
 ) THEN RAISE EXCEPTION 'expected lease tables must be ordinary tables owned by paddock_migrator'; END IF;
 IF NOT EXISTS (
   SELECT 1 FROM pg_catalog.pg_attribute a
   WHERE a.attrelid='raw.work_orders'::regclass AND a.attname='lease_epoch'
     AND a.atttypid='pg_catalog.int8'::regtype AND a.attnotnull AND NOT a.attisdropped
 ) THEN RAISE EXCEPTION 'expected non-null bigint lease_epoch column missing'; END IF;
 IF NOT EXISTS (
   SELECT 1 FROM pg_catalog.pg_constraint c
   WHERE c.conrelid='raw.work_order_attempts'::regclass
     AND c.conname='work_order_attempts_attempt_order_uq' AND c.contype='u'
     AND c.conkey=ARRAY[
       (SELECT attnum FROM pg_catalog.pg_attribute WHERE attrelid='raw.work_order_attempts'::regclass AND attname='attempt_id' AND NOT attisdropped),
       (SELECT attnum FROM pg_catalog.pg_attribute WHERE attrelid='raw.work_order_attempts'::regclass AND attname='work_order_id' AND NOT attisdropped)
     ]::smallint[]
 ) THEN RAISE EXCEPTION 'expected composite attempt-order constraint missing'; END IF;
 IF has_function_privilege('paddock_app','raw.reserve_work_order_pull(text,text,text,text,jsonb,jsonb)','EXECUTE') THEN RAISE EXCEPTION 'legacy lease-free reserve must remain non-executable by paddock_app'; END IF;
 IF EXISTS(SELECT 1 FROM raw.work_order_leases) THEN RAISE EXCEPTION 'refusing rollback while active lease rows exist'; END IF;
 IF EXISTS(SELECT 1 FROM raw.work_orders WHERE lease_epoch<>0) THEN RAISE EXCEPTION 'refusing rollback after any lease epoch has been issued'; END IF;
END $$;
REVOKE ALL ON FUNCTION raw.issue_work_order_lease(text,text,text,text,text,jsonb,jsonb,interval),raw.heartbeat_work_order_lease(text,text,text,text,bigint,interval),raw.reap_work_order_leases(integer),raw.complete_work_order_lease(text,text,text,text,bigint) FROM PUBLIC,paddock_app;
DROP FUNCTION raw.issue_work_order_lease(text,text,text,text,text,jsonb,jsonb,interval);
DROP FUNCTION raw.heartbeat_work_order_lease(text,text,text,text,bigint,interval);
DROP FUNCTION raw.reap_work_order_leases(integer);
DROP FUNCTION raw.complete_work_order_lease(text,text,text,text,bigint);
DROP TABLE raw.work_order_leases;
ALTER TABLE raw.work_order_attempts DROP CONSTRAINT work_order_attempts_attempt_order_uq;
ALTER TABLE raw.work_orders DROP COLUMN lease_epoch;
-- Never re-enable the obsolete lease-free reservation function.
COMMIT;

-- Remove only the M08-S02 pull slot and state additions.
BEGIN;
DO $$ BEGIN
 IF current_database()<>'paddock_test' THEN RAISE EXCEPTION 'refusing pull rollback outside paddock_test'; END IF;
 IF current_user<>'paddock_migrator' THEN RAISE EXCEPTION 'refusing pull rollback unless current_user is paddock_migrator'; END IF;
 IF to_regclass('raw.work_order_pull_slots') IS NULL
    OR to_regclass('raw.work_order_capability_requirements') IS NULL
    OR to_regclass('raw.work_orders') IS NULL
    OR to_regclass('raw.work_order_dependencies') IS NULL
    OR to_regclass('raw.work_order_attempts') IS NULL
    OR to_regprocedure('raw.mark_work_order_pull_ready(text)') IS NULL
    OR to_regprocedure('raw.reserve_work_order_pull(text,text,text,text,jsonb,jsonb)') IS NULL
    OR to_regprocedure('raw.configure_work_order_capabilities(text,jsonb)') IS NULL THEN
   RAISE EXCEPTION 'expected M08-S02 Pull objects or work_orders missing';
 END IF;
 IF EXISTS (
   SELECT 1 FROM (VALUES
     ('raw.work_orders'::regclass),
     ('raw.work_order_dependencies'::regclass),
     ('raw.work_order_attempts'::regclass),
     ('raw.work_order_pull_slots'::regclass),
     ('raw.work_order_capability_requirements'::regclass)
   ) AS expected(oid)
   JOIN pg_catalog.pg_class c ON c.oid=expected.oid
   WHERE c.relowner <> (SELECT oid FROM pg_catalog.pg_roles WHERE rolname='paddock_migrator')
 ) OR EXISTS (
   SELECT 1 FROM (VALUES
     ('raw.mark_work_order_pull_ready(text)'::regprocedure::oid),
     ('raw.reserve_work_order_pull(text,text,text,text,jsonb,jsonb)'::regprocedure::oid),
     ('raw.configure_work_order_capabilities(text,jsonb)'::regprocedure::oid)
   ) AS expected(oid)
   JOIN pg_catalog.pg_proc p ON p.oid=expected.oid
   WHERE p.proowner <> (SELECT oid FROM pg_catalog.pg_roles WHERE rolname='paddock_migrator')
 ) THEN
   RAISE EXCEPTION 'Pull objects and work_orders must be owned by paddock_migrator';
 END IF;
END $$;
DROP FUNCTION raw.mark_work_order_pull_ready(text);
DROP FUNCTION raw.reserve_work_order_pull(text,text,text,text,jsonb,jsonb);
DROP FUNCTION raw.configure_work_order_capabilities(text,jsonb);
DROP TABLE raw.work_order_pull_slots;
DROP TABLE raw.work_order_capability_requirements;
ALTER TABLE raw.work_orders DROP COLUMN capability_requirements_configured;
ALTER TABLE raw.work_orders DROP COLUMN pull_state;
COMMIT;

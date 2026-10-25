-- Explicit migration approval required; never run automatically by tests.
\set ON_ERROR_STOP on
BEGIN;
DO $$ BEGIN
 IF current_database()<>'paddock_test' THEN RAISE EXCEPTION 'worker credential down requires paddock_test'; END IF;
 IF current_user<>'paddock_migrator' OR session_user<>'paddock_migrator' THEN RAISE EXCEPTION 'worker credential down requires paddock_migrator'; END IF;
 IF EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_roles r ON r.oid=c.relowner WHERE c.oid=ANY(ARRAY[pg_catalog.to_regclass('raw.worker_credentials'),pg_catalog.to_regclass('raw.worker_issuer_context')]) AND r.rolname<>'paddock_migrator')
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_roles r ON r.oid=p.proowner WHERE p.oid=ANY(ARRAY[pg_catalog.to_regprocedure('raw.issue_worker_credential(text,text,text,text,text,text,bigint,text,text,text,text)'),pg_catalog.to_regprocedure('raw.lock_worker_credential(text)'),pg_catalog.to_regprocedure('raw.lock_current_worker_issuer_context(text)'),pg_catalog.to_regprocedure('raw.revoke_worker_credential(text)')]) AND r.rolname<>'paddock_migrator') THEN RAISE EXCEPTION 'unexpected credential object owner'; END IF;
END $$;
DROP FUNCTION raw.revoke_worker_credential(text) RESTRICT;
DROP FUNCTION raw.lock_worker_credential(text) RESTRICT;
DROP FUNCTION raw.lock_current_worker_issuer_context(text) RESTRICT;
DROP FUNCTION raw.issue_worker_credential(text,text,text,text,text,text,bigint,text,text,text,text) RESTRICT;
DROP TABLE raw.worker_credentials RESTRICT;
DROP TABLE raw.worker_issuer_context RESTRICT;
COMMIT;

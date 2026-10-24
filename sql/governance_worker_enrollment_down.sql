-- Source only: reverse exactly the M10-S01 enrollment objects; never CASCADE.
\set ON_ERROR_STOP on
BEGIN;
DO $$ BEGIN
 IF current_database()<>'paddock_test' OR current_user<>'paddock_migrator' OR session_user<>'paddock_migrator' THEN
  RAISE EXCEPTION 'worker enrollment rollback requires paddock_test as paddock_migrator';
 END IF;
END $$;
DROP FUNCTION raw.consume_worker_enrollment(text,text,text,text,text,bytea,text);
DROP FUNCTION raw.read_worker_enrollment_challenge(text);
DROP FUNCTION raw.issue_worker_enrollment_challenge(text,text,text,text,text);
DROP TABLE raw.worker_enrollment_challenges;
DROP TABLE raw.worker_enrollment_workers;
COMMIT;

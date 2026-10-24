-- M10-S01 source only. Apply separately with explicit database approval.
-- The trusted Coordinator verifies Ed25519 before invoking consume. These are
-- app-only capabilities, not public endpoints or DB-native Ed25519 verification.
-- No TTL, quota, rate, or admission policy is selected here (M10-S05).
\set ON_ERROR_STOP on
BEGIN;
DO $$ BEGIN
 IF current_database()<>'paddock_test' THEN RAISE EXCEPTION 'worker enrollment requires paddock_test'; END IF;
 IF current_user<>'paddock_migrator' OR session_user<>'paddock_migrator' THEN RAISE EXCEPTION 'worker enrollment requires paddock_migrator'; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='paddock_migrator' AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls)
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='paddock_app' AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid=m.roleid JOIN pg_catalog.pg_roles u ON u.oid=m.member WHERE r.rolname IN ('paddock_app','paddock_migrator') OR u.rolname IN ('paddock_app','paddock_migrator')) THEN RAISE EXCEPTION 'isolated non-elevated app/migrator roles required'; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n JOIN pg_catalog.pg_roles r ON r.oid=n.nspowner WHERE n.nspname='raw' AND r.rolname='paddock_migrator') THEN RAISE EXCEPTION 'migrator must own raw schema'; END IF;
 IF pg_catalog.to_regprocedure('pg_catalog.sha256(bytea)') IS NULL THEN RAISE EXCEPTION 'built-in SHA-256 required'; END IF;
END $$;

-- Opaque WorkerID is independent of the public-key fingerprint. These rows have
-- no Scope membership, promoted Trust, execution lease, or Authority columns.
CREATE TABLE raw.worker_enrollment_workers (
 worker_id text COLLATE "C" PRIMARY KEY CHECK(octet_length(worker_id)=71 AND worker_id ~ '^worker_[0-9a-f]{64}$'),
 fingerprint text COLLATE "C" NOT NULL CONSTRAINT worker_enrollment_workers_fingerprint_key UNIQUE
  CHECK(octet_length(fingerprint)=64 AND fingerprint ~ '^[0-9a-f]{64}$'),
 public_key bytea NOT NULL CHECK(octet_length(public_key)=32),
 quarantine_tier text NOT NULL DEFAULT 'Q0' CHECK(quarantine_tier='Q0'),
 state text NOT NULL DEFAULT 'QUARANTINED' CHECK(state='QUARANTINED'),
 CHECK(fingerprint=encode(pg_catalog.sha256(public_key),'hex'))
);
CREATE TABLE raw.worker_enrollment_challenges (
 challenge_id text COLLATE "C" PRIMARY KEY CHECK(octet_length(challenge_id)=64 AND challenge_id ~ '^[0-9a-f]{64}$'),
 nonce text COLLATE "C" NOT NULL UNIQUE CHECK(octet_length(nonce)=64 AND nonce ~ '^[0-9a-f]{64}$'),
 fingerprint text COLLATE "C" NOT NULL CHECK(octet_length(fingerprint)=64 AND fingerprint ~ '^[0-9a-f]{64}$'),
 schema_version text COLLATE "C" NOT NULL CHECK(schema_version='paddock.worker-enrollment/1'),
 audience text COLLATE "C" NOT NULL CHECK(audience='paddock.coordinator'),
 consumed_worker_id text COLLATE "C" UNIQUE REFERENCES raw.worker_enrollment_workers(worker_id)
);

CREATE FUNCTION raw.issue_worker_enrollment_challenge(p_id text,p_nonce text,p_fingerprint text,p_schema text,p_audience text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF session_user<>'paddock_app' THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='enrollment requires app session'; END IF;
 IF p_id IS NULL OR octet_length(p_id)<>64 OR p_id !~ '^[0-9a-f]{64}$'
 OR p_nonce IS NULL OR octet_length(p_nonce)<>64 OR p_nonce !~ '^[0-9a-f]{64}$'
 OR p_fingerprint IS NULL OR octet_length(p_fingerprint)<>64 OR p_fingerprint !~ '^[0-9a-f]{64}$'
 OR p_schema IS DISTINCT FROM 'paddock.worker-enrollment/1' OR p_audience IS DISTINCT FROM 'paddock.coordinator'
 THEN RAISE EXCEPTION USING ERRCODE='P1001', MESSAGE='invalid enrollment challenge'; END IF;
 IF EXISTS(SELECT 1 FROM raw.worker_enrollment_workers w WHERE w.fingerprint=p_fingerprint COLLATE "C")
 THEN RAISE EXCEPTION USING ERRCODE='P1002', MESSAGE='public key already enrolled'; END IF;
 INSERT INTO raw.worker_enrollment_challenges(challenge_id,nonce,fingerprint,schema_version,audience)
 VALUES(p_id,p_nonce,p_fingerprint,p_schema,p_audience);
 RETURN true;
END $$;

CREATE FUNCTION raw.read_worker_enrollment_challenge(p_id text)
RETURNS TABLE(challenge_id text,nonce text,fingerprint text,schema_version text,audience text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT c.challenge_id,c.nonce,c.fingerprint,c.schema_version,c.audience
 FROM raw.worker_enrollment_challenges c WHERE session_user='paddock_app' AND c.challenge_id=p_id COLLATE "C" AND c.consumed_worker_id IS NULL
$$;

CREATE FUNCTION raw.consume_worker_enrollment(p_id text,p_nonce text,p_fingerprint text,p_schema text,p_audience text,p_key bytea,p_worker text)
RETURNS TABLE(worker_id text,fingerprint text,quarantine_tier text,state text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE ticket raw.worker_enrollment_challenges%ROWTYPE;
BEGIN
 IF session_user<>'paddock_app' THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='enrollment requires app session'; END IF;
 -- Recheck every signing-input field while holding the shared-state row lock.
 -- Concurrent Coordinator proofs may both verify, but only one can consume.
 SELECT c.* INTO ticket FROM raw.worker_enrollment_challenges c
 WHERE c.challenge_id=p_id COLLATE "C" FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P1001', MESSAGE='enrollment ticket unavailable'; END IF;
 IF ticket.consumed_worker_id IS NOT NULL
 OR ticket.nonce IS DISTINCT FROM p_nonce COLLATE "C"
 OR ticket.fingerprint IS DISTINCT FROM p_fingerprint COLLATE "C"
 OR ticket.schema_version IS DISTINCT FROM p_schema COLLATE "C"
 OR ticket.audience IS DISTINCT FROM p_audience COLLATE "C"
 OR p_key IS NULL OR octet_length(p_key)<>32
 OR encode(pg_catalog.sha256(p_key),'hex') IS DISTINCT FROM ticket.fingerprint
 OR p_worker IS NULL OR octet_length(p_worker)<>71 OR p_worker !~ '^worker_[0-9a-f]{64}$'
 THEN RAISE EXCEPTION USING ERRCODE='P1001', MESSAGE='enrollment ticket unavailable or mismatched'; END IF;
 -- The unique fingerprint index also serializes distinct tickets for one key.
 -- Conflict/any exception rolls back insertion and leaves the ticket unused.
 INSERT INTO raw.worker_enrollment_workers(worker_id,fingerprint,public_key,quarantine_tier,state)
 VALUES(p_worker,p_fingerprint,p_key,'Q0','QUARANTINED')
 ON CONFLICT ON CONSTRAINT worker_enrollment_workers_fingerprint_key DO NOTHING;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P1002', MESSAGE='public key already enrolled'; END IF;
 UPDATE raw.worker_enrollment_challenges c SET consumed_worker_id=p_worker WHERE c.challenge_id=p_id COLLATE "C";
 RETURN QUERY SELECT p_worker,p_fingerprint,'Q0'::text,'QUARANTINED'::text;
END $$;

REVOKE ALL ON TABLE raw.worker_enrollment_challenges,raw.worker_enrollment_workers FROM PUBLIC,paddock_app;
REVOKE ALL ON FUNCTION raw.issue_worker_enrollment_challenge(text,text,text,text,text),raw.read_worker_enrollment_challenge(text),raw.consume_worker_enrollment(text,text,text,text,text,bytea,text) FROM PUBLIC,paddock_app;
GRANT EXECUTE ON FUNCTION raw.issue_worker_enrollment_challenge(text,text,text,text,text),raw.read_worker_enrollment_challenge(text),raw.consume_worker_enrollment(text,text,text,text,text,bytea,text) TO paddock_app;
-- Fail closed if site-specific default ACLs supplied any extra API grantee.
-- Do not silently inherit those grants or modify unrelated defaults.
DO $$ BEGIN
 IF EXISTS(
  SELECT 1 FROM pg_catalog.pg_proc p
  CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) acl
  WHERE p.oid=ANY(ARRAY[
   'raw.issue_worker_enrollment_challenge(text,text,text,text,text)'::regprocedure,
   'raw.read_worker_enrollment_challenge(text)'::regprocedure,
   'raw.consume_worker_enrollment(text,text,text,text,text,bytea,text)'::regprocedure])
  AND acl.grantee NOT IN (p.proowner,(SELECT oid FROM pg_catalog.pg_roles WHERE rolname='paddock_app'))
 ) THEN RAISE EXCEPTION 'unexpected enrollment API grantee'; END IF;
END $$;
COMMIT;

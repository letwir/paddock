-- M10-S02 additive source only. Apply after enrollment and SafetyGate Lease APIs.
-- Authentication only; no permissions, nonce ledger, Root/Security epoch pin,
-- TTL, or admission quotas. Those live checks stay in the existing Gate.
\set ON_ERROR_STOP on
BEGIN;
DO $$ BEGIN
 IF current_database()<>'paddock_test' THEN RAISE EXCEPTION 'worker credential requires paddock_test'; END IF;
 IF current_user<>'paddock_migrator' OR session_user<>'paddock_migrator' THEN RAISE EXCEPTION 'worker credential requires paddock_migrator'; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='paddock_migrator' AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls)
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='paddock_app' AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid=m.roleid JOIN pg_catalog.pg_roles u ON u.oid=m.member WHERE r.rolname IN ('paddock_app','paddock_migrator') OR u.rolname IN ('paddock_app','paddock_migrator')) THEN RAISE EXCEPTION 'isolated non-elevated roles required'; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n JOIN pg_catalog.pg_roles r ON r.oid=n.nspowner WHERE n.nspname='raw' AND r.rolname='paddock_migrator') THEN RAISE EXCEPTION 'migrator must own raw schema'; END IF;
 IF pg_catalog.to_regclass('raw.worker_enrollment_workers') IS NULL THEN RAISE EXCEPTION 'enrollment required'; END IF;
END $$;

-- Current authoritative Issuer state. Only the migrator owner may seed/change
-- it through guarded deployment migrations; no app mutation API is provided.
CREATE TABLE raw.worker_issuer_context (
 issuer_id text COLLATE "C" PRIMARY KEY CHECK(issuer_id<>'' AND issuer_id=btrim(issuer_id)),
 issuer_revision numeric(20,0) NOT NULL CHECK(issuer_revision>0 AND issuer_revision<=18446744073709551615),
 ceiling_digest text COLLATE "C" NOT NULL CHECK(ceiling_digest ~ '^[0-9a-f]{64}$' AND octet_length(ceiling_digest)=64)
);

CREATE TABLE raw.worker_credentials (
 credential_id text COLLATE "C" PRIMARY KEY CHECK(octet_length(credential_id)=64 AND credential_id ~ '^[0-9a-f]{64}$'),
 fingerprint text COLLATE "C" NOT NULL CHECK(octet_length(fingerprint)=64 AND fingerprint ~ '^[0-9a-f]{64}$'),
 work_order_id text COLLATE "C" NOT NULL CHECK(work_order_id<>'' AND work_order_id=btrim(work_order_id)),
 attempt_id text COLLATE "C" NOT NULL CHECK(attempt_id<>'' AND attempt_id=btrim(attempt_id)),
 worker_id text COLLATE "C" NOT NULL REFERENCES raw.worker_enrollment_workers(worker_id),
 session_id text COLLATE "C" NOT NULL CHECK(session_id<>'' AND session_id=btrim(session_id)),
 lease_epoch bigint NOT NULL CHECK(lease_epoch>0),
 audience text COLLATE "C" NOT NULL CHECK(audience<>'' AND audience=btrim(audience)),
 issuer_id text COLLATE "C" NOT NULL CHECK(issuer_id<>'' AND issuer_id=btrim(issuer_id)),
 issuer_revision numeric(20,0) NOT NULL CHECK(issuer_revision>0 AND issuer_revision<=18446744073709551615),
 ceiling_digest text COLLATE "C" NOT NULL CHECK(ceiling_digest ~ '^[0-9a-f]{64}$' AND octet_length(ceiling_digest)=64),
 revoked boolean NOT NULL DEFAULT false
);

CREATE FUNCTION raw.issue_worker_credential(p_id text,p_fingerprint text,p_work text,p_attempt text,p_worker text,p_session text,p_epoch bigint,p_audience text,p_issuer text,p_revision text,p_ceiling text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF session_user<>'paddock_app' THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='credential requires app session'; END IF;
 IF p_revision IS NULL OR p_revision !~ '^[1-9][0-9]{0,19}$' THEN RAISE EXCEPTION USING ERRCODE='P1010', MESSAGE='invalid credential'; END IF;
 PERFORM 1 FROM raw.worker_enrollment_workers w WHERE w.worker_id=p_worker COLLATE "C" AND w.fingerprint=p_fingerprint COLLATE "C" FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P1010', MESSAGE='enrolled key binding unavailable'; END IF;
 -- Hold the current state against deployment updates/deletion until insertion
 -- commits. A trusted Coordinator snapshot is not itself freshness evidence.
 PERFORM 1 FROM raw.worker_issuer_context i WHERE i.issuer_id=p_issuer COLLATE "C" AND i.issuer_revision=p_revision::numeric AND i.ceiling_digest=p_ceiling COLLATE "C" FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P1010', MESSAGE='current issuer context unavailable'; END IF;
 INSERT INTO raw.worker_credentials(credential_id,fingerprint,work_order_id,attempt_id,worker_id,session_id,lease_epoch,audience,issuer_id,issuer_revision,ceiling_digest)
 VALUES(p_id,p_fingerprint,p_work,p_attempt,p_worker,p_session,p_epoch,p_audience,p_issuer,p_revision::numeric,p_ceiling);
 RETURN true;
END $$;

-- Called in the SAME SafetyGate transaction as Scope/Root/Security and Lease.
-- The row lock serializes revocation; a successful check never caches status.
CREATE FUNCTION raw.lock_worker_credential(p_id text)
RETURNS TABLE(credential_id text,fingerprint text,work_order_id text,attempt_id text,worker_id text,session_id text,lease_epoch bigint,audience text,issuer_id text,issuer_revision text,ceiling_digest text,revoked boolean,public_key bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF session_user<>'paddock_app' THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='credential requires app session'; END IF;
 RETURN QUERY SELECT c.credential_id,c.fingerprint,c.work_order_id,c.attempt_id,c.worker_id,c.session_id,c.lease_epoch,c.audience,c.issuer_id,c.issuer_revision::text,c.ceiling_digest,c.revoked,w.public_key
 FROM raw.worker_credentials c JOIN raw.worker_enrollment_workers w ON w.worker_id=c.worker_id AND w.fingerprint=c.fingerprint
 WHERE c.credential_id=p_id COLLATE "C" FOR UPDATE OF c FOR SHARE OF w;
END $$;

-- Read-only app capability; FOR SHARE conflicts with UPDATE and DELETE, even
-- when only non-key revision/digest columns change. The Gate keeps this lock
-- alongside the Credential/revocation lock in its existing transaction.
CREATE FUNCTION raw.lock_current_worker_issuer_context(p_issuer text)
RETURNS TABLE(issuer_id text,issuer_revision text,ceiling_digest text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF session_user<>'paddock_app' THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='credential requires app session'; END IF;
 RETURN QUERY SELECT i.issuer_id,i.issuer_revision::text,i.ceiling_digest
 FROM raw.worker_issuer_context i WHERE i.issuer_id=p_issuer COLLATE "C" FOR SHARE OF i;
END $$;

CREATE FUNCTION raw.revoke_worker_credential(p_id text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF session_user<>'paddock_app' THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='credential requires app session'; END IF;
 UPDATE raw.worker_credentials c SET revoked=true WHERE c.credential_id=p_id COLLATE "C";
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P1010', MESSAGE='credential unavailable'; END IF;
 RETURN true;
END $$;

REVOKE ALL ON TABLE raw.worker_credentials FROM PUBLIC,paddock_app;
REVOKE ALL ON TABLE raw.worker_issuer_context FROM PUBLIC,paddock_app;
REVOKE ALL ON FUNCTION raw.issue_worker_credential(text,text,text,text,text,text,bigint,text,text,text,text),raw.lock_worker_credential(text),raw.lock_current_worker_issuer_context(text),raw.revoke_worker_credential(text) FROM PUBLIC,paddock_app;
GRANT EXECUTE ON FUNCTION raw.issue_worker_credential(text,text,text,text,text,text,bigint,text,text,text,text),raw.lock_worker_credential(text),raw.lock_current_worker_issuer_context(text),raw.revoke_worker_credential(text) TO paddock_app;
DO $$ BEGIN
 IF EXISTS(
  SELECT 1 FROM pg_catalog.pg_proc p
  CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) acl
  WHERE p.oid=ANY(ARRAY['raw.issue_worker_credential(text,text,text,text,text,text,bigint,text,text,text,text)'::regprocedure,'raw.lock_worker_credential(text)'::regprocedure,'raw.lock_current_worker_issuer_context(text)'::regprocedure,'raw.revoke_worker_credential(text)'::regprocedure])
  AND acl.grantee NOT IN (p.proowner,(SELECT oid FROM pg_catalog.pg_roles WHERE rolname='paddock_app'))
 ) OR EXISTS(
  SELECT 1 FROM pg_catalog.pg_class c
  CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(c.relacl,pg_catalog.acldefault('r',c.relowner))) acl
  WHERE c.oid IN ('raw.worker_credentials'::regclass,'raw.worker_issuer_context'::regclass) AND acl.grantee<>c.relowner
 ) OR EXISTS(
  SELECT 1 FROM pg_catalog.pg_attribute a
  CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl
  WHERE a.attrelid IN ('raw.worker_credentials'::regclass,'raw.worker_issuer_context'::regclass) AND acl.grantee<>(SELECT relowner FROM pg_catalog.pg_class WHERE oid=a.attrelid)
 ) THEN RAISE EXCEPTION 'unexpected credential ACL'; END IF;
END $$;
COMMIT;

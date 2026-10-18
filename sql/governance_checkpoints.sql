-- Additive source-only migration for immutable, budget-charged semantic checkpoints.
BEGIN;
DO $$ BEGIN
 IF current_database()<>'paddock_test' THEN RAISE EXCEPTION 'checkpoint migration requires paddock_test'; END IF;
 IF current_user<>'paddock_migrator' THEN RAISE EXCEPTION 'checkpoint migration requires paddock_migrator'; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='paddock_migrator' AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls)
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='paddock_app' AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid=m.roleid JOIN pg_catalog.pg_roles u ON u.oid=m.member WHERE r.rolname IN ('paddock_app','paddock_migrator') OR u.rolname IN ('paddock_app','paddock_migrator')) THEN RAISE EXCEPTION 'isolated non-elevated roles required'; END IF;
 IF to_regprocedure('pg_catalog.sha256(bytea)') IS NULL THEN RAISE EXCEPTION 'PostgreSQL sha256(bytea) required'; END IF;
 IF pg_catalog.getdatabaseencoding()<>'UTF8' THEN RAISE EXCEPTION 'UTF8 database required'; END IF;
 IF to_regprocedure('raw.jcs_quote(text)') IS NULL OR to_regprocedure('raw.jcs_utf16_sort_key(text)') IS NULL THEN RAISE EXCEPTION 'JCS helpers required'; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n JOIN pg_catalog.pg_roles r ON r.oid=n.nspowner WHERE n.nspname='raw' AND r.rolname='paddock_migrator') THEN RAISE EXCEPTION 'migrator must own raw'; END IF;
 IF to_regclass('raw.roots') IS NULL OR to_regclass('raw.work_orders') IS NULL OR to_regclass('raw.work_order_attempts') IS NULL OR to_regclass('raw.work_order_leases') IS NULL OR to_regclass('raw.budget_accounts') IS NULL THEN RAISE EXCEPTION 'required roots/work-order/lease/budget objects missing'; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute WHERE attrelid='raw.roots'::regclass AND attname='effective_bundle_digest' AND NOT attisdropped)
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute WHERE attrelid='raw.work_orders'::regclass AND attname='policy_digest' AND NOT attisdropped)
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_constraint WHERE conrelid='raw.budget_accounts'::regclass AND conname='budget_accounts_storage_bytes_unit_check' AND contype='c') THEN RAISE EXCEPTION 'effective definition/policy digest or STORAGE_BYTES/byte guard missing'; END IF;
 IF EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace JOIN pg_catalog.pg_roles r ON r.oid=c.relowner WHERE n.nspname='raw' AND c.relname IN ('roots','work_orders','work_order_attempts','work_order_leases','budget_accounts') AND r.rolname<>'paddock_migrator') THEN RAISE EXCEPTION 'migrator must own required tables'; END IF;
 IF to_regclass('raw.checkpoint_policies') IS NOT NULL OR to_regclass('raw.work_order_checkpoints') IS NOT NULL OR to_regprocedure('raw.store_work_order_checkpoint(text,text,text,text,bigint,bytea,bytea,bigint)') IS NOT NULL THEN RAISE EXCEPTION 'checkpoint objects already exist'; END IF;
END $$;
CREATE TABLE raw.checkpoint_policies(
 root_id text PRIMARY KEY REFERENCES raw.roots(root_id),
 max_bytes_per_checkpoint bigint NOT NULL CHECK(max_bytes_per_checkpoint>0),
 max_total_checkpoint_bytes bigint NOT NULL CHECK(max_total_checkpoint_bytes>0 AND max_total_checkpoint_bytes>=max_bytes_per_checkpoint),
 storage_account_id text NOT NULL,
 configured_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK(storage_account_id<>'' AND storage_account_id=btrim(storage_account_id))
);
CREATE TABLE raw.work_order_checkpoints(
 checkpoint_id text PRIMARY KEY CHECK(checkpoint_id<>'' AND checkpoint_id=btrim(checkpoint_id)),
 root_id text NOT NULL REFERENCES raw.roots(root_id),
 work_order_id text NOT NULL REFERENCES raw.work_orders(work_order_id),
 attempt_id text NOT NULL REFERENCES raw.work_order_attempts(attempt_id),
 lease_epoch bigint NOT NULL CHECK(lease_epoch>0),
 manifest bytea NOT NULL,
 payload bytea NOT NULL,
 payload_sha256 text NOT NULL CHECK(payload_sha256 ~ '^[0-9a-f]{64}$'),
 state text NOT NULL CHECK(state IN ('L2','QUARANTINED')),
 stored_bytes bigint NOT NULL CHECK(stored_bytes=octet_length(manifest)+octet_length(payload)),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK(octet_length(manifest)>0)
);
CREATE INDEX work_order_checkpoints_root_idx ON raw.work_order_checkpoints(root_id);
CREATE FUNCTION raw.reject_checkpoint_mutation() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$ BEGIN RAISE EXCEPTION 'checkpoints and policies are append-only'; END $$;
CREATE TRIGGER checkpoint_policy_immutable BEFORE UPDATE OR DELETE ON raw.checkpoint_policies FOR EACH ROW EXECUTE FUNCTION raw.reject_checkpoint_mutation();
CREATE TRIGGER checkpoint_immutable BEFORE UPDATE OR DELETE ON raw.work_order_checkpoints FOR EACH ROW EXECUTE FUNCTION raw.reject_checkpoint_mutation();
CREATE FUNCTION raw.configure_checkpoint_policy(text,bigint,bigint,text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE rid ALIAS FOR $1; per_limit ALIAS FOR $2; total_limit ALIAS FOR $3; account ALIAS FOR $4; granted bigint;
BEGIN
 IF session_user<>'paddock_app' THEN RAISE EXCEPTION 'trusted Coordinator required'; END IF;
 IF rid IS NULL OR per_limit IS NULL OR total_limit IS NULL OR per_limit<=0 OR total_limit<per_limit OR account IS NULL OR account='' THEN RAISE EXCEPTION 'finite checkpoint policy required'; END IF;
 SELECT b.granted INTO granted FROM raw.budget_accounts b WHERE b.account_id=account AND b.root_id=rid AND b.resource_kind='STORAGE_BYTES' AND b.unit_code='byte';
 IF NOT FOUND OR total_limit>granted THEN RAISE EXCEPTION 'checkpoint total cap exceeds Root STORAGE_BYTES grant'; END IF;
 INSERT INTO raw.checkpoint_policies(root_id,max_bytes_per_checkpoint,max_total_checkpoint_bytes,storage_account_id) VALUES(rid,per_limit,total_limit,account);
 RETURN true;
END $$;
CREATE FUNCTION raw.checkpoint_storage_account(text) RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$ SELECT storage_account_id FROM raw.checkpoint_policies WHERE root_id=$1 $$;
CREATE FUNCTION raw.store_work_order_checkpoint(text,text,text,text,bigint,bytea,bytea,bigint)
RETURNS TABLE(checkpoint_id text,state text,stored_bytes bigint) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE op ALIAS FOR $1; rid ALIAS FOR $2; wid ALIAS FOR $3; aid ALIAS FOR $4; epoch ALIAS FOR $5; m ALIAS FOR $6; p ALIAS FOR $7; n ALIAS FOR $8;
 old raw.work_order_checkpoints%ROWTYPE; pol raw.checkpoint_policies%ROWTYPE; live boolean; hashtext text; manifest_json jsonb; used bigint; result_state text; now_at timestamptz; canonical bytea; structural boolean; reserve_valid boolean;
BEGIN
 IF session_user<>'paddock_app' THEN RAISE EXCEPTION 'trusted Coordinator required'; END IF;
 IF op IS NULL OR op='' OR op<>btrim(op) OR n IS NULL OR n<=0 OR m IS NULL OR p IS NULL OR n<>octet_length(m)+octet_length(p) THEN RAISE EXCEPTION 'invalid checkpoint request'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(op,0));
 SELECT * INTO old FROM raw.work_order_checkpoints WHERE work_order_checkpoints.checkpoint_id=op;
 IF FOUND THEN IF old.root_id<>rid OR old.work_order_id<>wid OR old.attempt_id<>aid OR old.lease_epoch<>epoch OR old.manifest<>m OR old.payload<>p OR old.stored_bytes<>n THEN RAISE EXCEPTION 'checkpoint operation replay conflict'; END IF; RETURN QUERY SELECT old.checkpoint_id,old.state,old.stored_bytes; RETURN; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('checkpoint-root:'||rid,0));
 SELECT * INTO pol FROM raw.checkpoint_policies WHERE root_id=rid;
 IF NOT FOUND THEN RAISE EXCEPTION 'checkpoint policy missing'; END IF;
 IF n>pol.max_bytes_per_checkpoint THEN RAISE EXCEPTION 'checkpoint per-item cap exceeded'; END IF;
 SELECT EXISTS(
  SELECT 1 FROM raw.budget_operations bo
  WHERE bo.operation_id=op||':reserve'
    AND bo.operation_kind='RESERVE'
    AND jsonb_typeof(bo.request)='object'
    AND jsonb_typeof(bo.request->'account_id')='string'
    AND bo.request->>'account_id'=pol.storage_account_id
    AND jsonb_typeof(bo.request->'amount')='number'
    AND bo.request->>'amount'=n::text
    AND bo.result=jsonb_build_object('account_id',pol.storage_account_id,'reserved',n)
 ) INTO reserve_valid;
 IF NOT reserve_valid THEN RAISE EXCEPTION 'matching checkpoint storage reservation required'; END IF;
  SELECT COALESCE(sum(checkpoint.stored_bytes),0) INTO used FROM raw.work_order_checkpoints AS checkpoint WHERE checkpoint.root_id=rid;
 IF n>pol.max_total_checkpoint_bytes-used THEN RAISE EXCEPTION 'checkpoint total cap exceeded'; END IF;
 -- Decode only the exact JCS object fields required by the manifest contract.
 manifest_json:=convert_from(m,'UTF8')::jsonb;
  IF jsonb_typeof(manifest_json) IS DISTINCT FROM 'object'
  OR (SELECT count(*) FROM jsonb_object_keys(manifest_json))<>9
  OR NOT (manifest_json ?& ARRAY['schema_version','root_id','work_order_id','attempt_id','lease_epoch','definition_digest','policy_digest','payload_sha256','payload_size'])
  OR jsonb_typeof(manifest_json->'schema_version') IS DISTINCT FROM 'string'
  OR jsonb_typeof(manifest_json->'root_id') IS DISTINCT FROM 'string'
  OR jsonb_typeof(manifest_json->'work_order_id') IS DISTINCT FROM 'string'
  OR jsonb_typeof(manifest_json->'attempt_id') IS DISTINCT FROM 'string'
  OR jsonb_typeof(manifest_json->'lease_epoch') IS DISTINCT FROM 'number'
  OR jsonb_typeof(manifest_json->'definition_digest') IS DISTINCT FROM 'string'
  OR jsonb_typeof(manifest_json->'policy_digest') IS DISTINCT FROM 'string'
  OR jsonb_typeof(manifest_json->'payload_sha256') IS DISTINCT FROM 'string'
  OR jsonb_typeof(manifest_json->'payload_size') IS DISTINCT FROM 'number'
  OR manifest_json->>'schema_version' IS DISTINCT FROM 'paddock.checkpoint/1' OR manifest_json->>'root_id' IS DISTINCT FROM rid
  OR manifest_json->>'work_order_id' IS DISTINCT FROM wid OR manifest_json->>'attempt_id' IS DISTINCT FROM aid
 OR (manifest_json->>'lease_epoch')::bigint<>epoch OR (manifest_json->>'payload_size')::bigint<>octet_length(p)
 OR manifest_json->>'payload_sha256' IS NULL OR manifest_json->>'definition_digest' IS NULL OR manifest_json->>'policy_digest' IS NULL THEN RAISE EXCEPTION 'checkpoint manifest mismatch'; END IF;
 hashtext:=manifest_json->>'payload_sha256';
 IF length(hashtext)<>64 OR hashtext !~ '^[0-9a-f]{64}$' THEN RAISE EXCEPTION 'invalid payload digest'; END IF;
 IF hashtext<>encode(pg_catalog.sha256(p),'hex') THEN RAISE EXCEPTION 'payload digest mismatch'; END IF;
 canonical:=convert_to('{"attempt_id":'||raw.jcs_quote(manifest_json->>'attempt_id')||',"definition_digest":'||raw.jcs_quote(manifest_json->>'definition_digest')||',"lease_epoch":'||epoch::text||',"payload_sha256":'||raw.jcs_quote(hashtext)||',"payload_size":'||octet_length(p)::text||',"policy_digest":'||raw.jcs_quote(manifest_json->>'policy_digest')||',"root_id":'||raw.jcs_quote(manifest_json->>'root_id')||',"schema_version":'||raw.jcs_quote(manifest_json->>'schema_version')||',"work_order_id":'||raw.jcs_quote(manifest_json->>'work_order_id')||'}','UTF8');
  IF canonical IS DISTINCT FROM m THEN RAISE EXCEPTION 'manifest is not exact canonical JCS'; END IF;
 SELECT EXISTS(SELECT 1 FROM raw.work_orders w JOIN raw.roots r ON r.root_id=w.root_id JOIN raw.work_order_attempts a ON a.work_order_id=w.work_order_id AND a.attempt_id=aid WHERE w.work_order_id=wid AND w.root_id=rid AND r.root_id=rid) INTO structural;
 IF NOT structural THEN RAISE EXCEPTION 'checkpoint identity relationship mismatch'; END IF;
 now_at:=clock_timestamp();
 SELECT EXISTS(SELECT 1 FROM raw.work_orders w JOIN raw.roots r ON r.root_id=w.root_id JOIN raw.work_order_attempts a ON a.work_order_id=w.work_order_id AND a.attempt_id=aid JOIN raw.work_order_leases l ON l.work_order_id=w.work_order_id AND l.attempt_id=aid AND l.lease_epoch=epoch WHERE w.work_order_id=wid AND w.root_id=rid AND w.lease_epoch=epoch AND w.policy_digest=manifest_json->>'policy_digest' AND r.effective_bundle_digest::text=manifest_json->>'definition_digest' AND l.expires_at>now_at) INTO live;
 result_state:=CASE WHEN live THEN 'L2' ELSE 'QUARANTINED' END;
 INSERT INTO raw.work_order_checkpoints(checkpoint_id,root_id,work_order_id,attempt_id,lease_epoch,manifest,payload,payload_sha256,state,stored_bytes)
 VALUES(op,rid,wid,aid,epoch,m,p,hashtext,result_state,n);
 RETURN QUERY SELECT op,result_state,n;
END $$;
CREATE FUNCTION raw.restore_work_order_checkpoint(text)
RETURNS TABLE(checkpoint_id text,manifest bytea,payload bytea,state text,stored_bytes bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE op ALIAS FOR $1; c raw.work_order_checkpoints%ROWTYPE; current_state text; now_at timestamptz;
BEGIN
 IF session_user<>'paddock_app' THEN RAISE EXCEPTION 'trusted Coordinator required'; END IF;
 SELECT * INTO c FROM raw.work_order_checkpoints WHERE work_order_checkpoints.checkpoint_id=op;
 IF NOT FOUND THEN RAISE EXCEPTION 'checkpoint not found'; END IF;
 -- Enforce structural provenance independently of current authority.
 IF NOT EXISTS(SELECT 1 FROM raw.work_orders w JOIN raw.roots r ON r.root_id=w.root_id JOIN raw.work_order_attempts a ON a.work_order_id=w.work_order_id WHERE w.work_order_id=c.work_order_id AND w.root_id=c.root_id AND r.root_id=c.root_id AND a.attempt_id=c.attempt_id) THEN
   RAISE EXCEPTION 'checkpoint identity relationship mismatch';
 END IF;
 now_at:=clock_timestamp();
  current_state:=CASE WHEN c.state='L2' AND EXISTS(
    SELECT 1 FROM raw.work_orders w JOIN raw.roots r ON r.root_id=w.root_id
   JOIN raw.work_order_attempts a ON a.work_order_id=w.work_order_id AND a.attempt_id=c.attempt_id
   JOIN raw.work_order_leases l ON l.work_order_id=w.work_order_id AND l.attempt_id=c.attempt_id AND l.lease_epoch=c.lease_epoch
   WHERE w.work_order_id=c.work_order_id AND w.root_id=c.root_id AND w.lease_epoch=c.lease_epoch
     AND r.effective_bundle_digest::text=(convert_from(c.manifest,'UTF8')::jsonb->>'definition_digest')
     AND w.policy_digest=(convert_from(c.manifest,'UTF8')::jsonb->>'policy_digest') AND l.expires_at>now_at
  ) AND c.payload_sha256=encode(pg_catalog.sha256(c.payload),'hex')
    AND c.payload_sha256=(convert_from(c.manifest,'UTF8')::jsonb->>'payload_sha256')
    THEN 'L2' ELSE 'QUARANTINED' END;
 RETURN QUERY SELECT c.checkpoint_id,c.manifest,CASE WHEN current_state='L2' THEN c.payload ELSE NULL::bytea END,current_state,c.stored_bytes;
END $$;
ALTER TABLE raw.checkpoint_policies OWNER TO paddock_migrator;
ALTER TABLE raw.work_order_checkpoints OWNER TO paddock_migrator;
ALTER FUNCTION raw.reject_checkpoint_mutation() OWNER TO paddock_migrator;
ALTER FUNCTION raw.configure_checkpoint_policy(text,bigint,bigint,text) OWNER TO paddock_migrator;
ALTER FUNCTION raw.checkpoint_storage_account(text) OWNER TO paddock_migrator;
ALTER FUNCTION raw.store_work_order_checkpoint(text,text,text,text,bigint,bytea,bytea,bigint) OWNER TO paddock_migrator;
ALTER FUNCTION raw.restore_work_order_checkpoint(text) OWNER TO paddock_migrator;
REVOKE ALL ON TABLE raw.checkpoint_policies,raw.work_order_checkpoints FROM PUBLIC,paddock_app;
REVOKE ALL ON FUNCTION raw.configure_checkpoint_policy(text,bigint,bigint,text),raw.checkpoint_storage_account(text),raw.store_work_order_checkpoint(text,text,text,text,bigint,bytea,bytea,bigint),raw.restore_work_order_checkpoint(text) FROM PUBLIC,paddock_app;
GRANT EXECUTE ON FUNCTION raw.configure_checkpoint_policy(text,bigint,bigint,text) TO paddock_app;
GRANT EXECUTE ON FUNCTION raw.checkpoint_storage_account(text),raw.store_work_order_checkpoint(text,text,text,text,bigint,bytea,bytea,bigint) TO paddock_app;
GRANT EXECUTE ON FUNCTION raw.restore_work_order_checkpoint(text) TO paddock_app;
COMMIT;

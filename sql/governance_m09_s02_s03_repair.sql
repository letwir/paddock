-- Additive, guarded repair for the already-installed M09-S02/S03 functions.
-- Source only: this file does not apply itself. Never run without separate approval.
BEGIN;
DO $guard$
BEGIN
 IF current_database()<>'paddock_test' OR current_user<>'paddock_migrator' OR session_user<>'paddock_migrator' THEN RAISE EXCEPTION 'M09 S02/S03 repair requires paddock_test as paddock_migrator'; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='paddock_migrator' AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls)
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='paddock_app' AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid=m.roleid JOIN pg_catalog.pg_roles u ON u.oid=m.member WHERE r.rolname IN('paddock_app','paddock_migrator') OR u.rolname IN('paddock_app','paddock_migrator')) THEN RAISE EXCEPTION 'isolated non-elevated app/migrator roles required'; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n JOIN pg_catalog.pg_roles r ON r.oid=n.nspowner WHERE n.nspname='raw' AND r.rolname='paddock_migrator') THEN RAISE EXCEPTION 'migrator must own raw'; END IF;
  IF to_regclass('raw.roots') IS NULL OR to_regclass('raw.work_orders') IS NULL OR to_regclass('raw.work_order_dependencies') IS NULL OR to_regclass('raw.work_order_attempts') IS NULL OR to_regclass('raw.work_order_pull_slots') IS NULL OR to_regclass('raw.work_order_leases') IS NULL OR to_regclass('raw.spawn_policies') IS NULL OR to_regclass('raw.spawn_operations') IS NULL OR to_regclass('raw.spawn_fingerprints') IS NULL OR to_regclass('raw.checkpoint_policies') IS NULL OR to_regclass('raw.work_order_checkpoints') IS NULL OR to_regclass('raw.budget_accounts') IS NULL OR to_regclass('raw.budget_operations') IS NULL OR to_regclass('raw.budget_journal') IS NULL OR to_regclass('raw.budget_allocations') IS NULL THEN RAISE EXCEPTION 'required base/S02/S03/budget tables missing'; END IF;
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a WHERE a.attrelid='raw.roots'::regclass AND a.attname='effective_bundle_digest' AND NOT a.attisdropped) THEN RAISE EXCEPTION 'repair preflight failed: raw.roots.effective_bundle_digest column missing or dropped'; END IF;
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a WHERE a.attrelid='raw.work_orders'::regclass AND a.attname='policy_digest' AND NOT a.attisdropped) THEN RAISE EXCEPTION 'repair preflight failed: raw.work_orders.policy_digest column missing or dropped'; END IF;
 IF EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace JOIN pg_catalog.pg_roles r ON r.oid=c.relowner WHERE n.nspname='raw' AND c.relname IN('roots','work_orders','work_order_dependencies','work_order_attempts','work_order_pull_slots','work_order_leases','spawn_policies','spawn_operations','spawn_fingerprints','checkpoint_policies','work_order_checkpoints','budget_accounts','budget_operations','budget_journal','budget_allocations') AND r.rolname<>'paddock_migrator') THEN RAISE EXCEPTION 'migrator must own required base/S02/S03/budget tables'; END IF;
 IF to_regprocedure('raw.issue_work_order_lease(text,text,text,text,text,jsonb,jsonb,interval)') IS NULL OR to_regprocedure('raw.spawn_policy_set(text,text,jsonb)') IS NULL OR to_regprocedure('raw.spawn_admit(text,text,jsonb,text,text,jsonb)') IS NULL OR to_regprocedure('raw.configure_checkpoint_policy(text,bigint,bigint,text)') IS NULL OR to_regprocedure('raw.checkpoint_storage_account(text)') IS NULL OR to_regprocedure('raw.store_work_order_checkpoint(text,text,text,text,bigint,bytea,bytea,bigint)') IS NULL OR to_regprocedure('raw.restore_work_order_checkpoint(text)') IS NULL THEN RAISE EXCEPTION 'required S02/S03 functions missing'; END IF;
 IF EXISTS(SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace JOIN pg_catalog.pg_roles r ON r.oid=p.proowner WHERE n.nspname='raw' AND p.oid IN(to_regprocedure('raw.spawn_policy_set(text,text,jsonb)'),to_regprocedure('raw.spawn_admit(text,text,jsonb,text,text,jsonb)'),to_regprocedure('raw.configure_checkpoint_policy(text,bigint,bigint,text)'),to_regprocedure('raw.checkpoint_storage_account(text)'),to_regprocedure('raw.store_work_order_checkpoint(text,text,text,text,bigint,bytea,bytea,bigint)'),to_regprocedure('raw.restore_work_order_checkpoint(text)')) AND r.rolname<>'paddock_migrator') THEN RAISE EXCEPTION 'migrator must own required S02/S03 functions'; END IF;
 IF to_regprocedure('pg_catalog.sha256(bytea)') IS NULL OR to_regprocedure('raw.jcs_quote(text)') IS NULL OR to_regprocedure('raw.jcs_utf16_sort_key(text)') IS NULL OR to_regprocedure('raw.budget_apply(text,text,jsonb)') IS NULL OR pg_catalog.getdatabaseencoding()<>'UTF8' OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_constraint WHERE conrelid='raw.budget_accounts'::regclass AND conname='budget_accounts_storage_bytes_unit_check' AND contype='c') THEN RAISE EXCEPTION 'M09-S01 budget/STORAGE_BYTES/JCS/SHA-256 prerequisites missing'; END IF;
END $guard$;

CREATE OR REPLACE FUNCTION raw.spawn_fingerprint_context(p_root text,p_parent_work_order_id text)
RETURNS TABLE(effective_bundle_digest text,policy_digest text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF session_user<>'paddock_app' THEN RAISE EXCEPTION 'spawn digest context requires trusted Coordinator session'; END IF;
 IF p_root IS NULL OR p_root !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' OR p_parent_work_order_id IS NULL OR p_parent_work_order_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN RAISE EXCEPTION 'invalid spawn digest context'; END IF;
  SELECT r.effective_bundle_digest::text,w.policy_digest::text INTO effective_bundle_digest,policy_digest FROM raw.roots AS r JOIN raw.work_orders AS w ON w.root_id=r.root_id WHERE r.root_id=p_root AND w.work_order_id=p_parent_work_order_id;
  IF NOT FOUND OR effective_bundle_digest IS NULL OR policy_digest IS NULL THEN RAISE EXCEPTION 'spawn digest context missing or null'; END IF;
  RETURN NEXT;
END $$;
ALTER FUNCTION raw.spawn_fingerprint_context(text,text) OWNER TO paddock_migrator;
REVOKE ALL ON FUNCTION raw.spawn_fingerprint_context(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION raw.spawn_fingerprint_context(text,text) TO paddock_app;

CREATE OR REPLACE FUNCTION raw.store_work_order_checkpoint(text,text,text,text,bigint,bytea,bytea,bigint)
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
 SELECT EXISTS(SELECT 1 FROM raw.budget_operations bo WHERE bo.operation_id=op||':reserve' AND bo.operation_kind='RESERVE' AND jsonb_typeof(bo.request)='object' AND jsonb_typeof(bo.request->'account_id')='string' AND bo.request->>'account_id'=pol.storage_account_id AND jsonb_typeof(bo.request->'amount')='number' AND bo.request->>'amount'=n::text AND bo.result=jsonb_build_object('account_id',pol.storage_account_id,'reserved',n)) INTO reserve_valid;
 IF NOT reserve_valid THEN RAISE EXCEPTION 'matching checkpoint storage reservation required'; END IF;
 SELECT COALESCE(sum(checkpoint.stored_bytes),0) INTO used FROM raw.work_order_checkpoints AS checkpoint WHERE checkpoint.root_id=rid;
 IF n>pol.max_total_checkpoint_bytes-used THEN RAISE EXCEPTION 'checkpoint total cap exceeded'; END IF;
 manifest_json:=convert_from(m,'UTF8')::jsonb;
 IF jsonb_typeof(manifest_json) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(manifest_json))<>9 OR NOT (manifest_json ?& ARRAY['schema_version','root_id','work_order_id','attempt_id','lease_epoch','definition_digest','policy_digest','payload_sha256','payload_size']) OR jsonb_typeof(manifest_json->'schema_version') IS DISTINCT FROM 'string' OR jsonb_typeof(manifest_json->'root_id') IS DISTINCT FROM 'string' OR jsonb_typeof(manifest_json->'work_order_id') IS DISTINCT FROM 'string' OR jsonb_typeof(manifest_json->'attempt_id') IS DISTINCT FROM 'string' OR jsonb_typeof(manifest_json->'lease_epoch') IS DISTINCT FROM 'number' OR jsonb_typeof(manifest_json->'definition_digest') IS DISTINCT FROM 'string' OR jsonb_typeof(manifest_json->'policy_digest') IS DISTINCT FROM 'string' OR jsonb_typeof(manifest_json->'payload_sha256') IS DISTINCT FROM 'string' OR jsonb_typeof(manifest_json->'payload_size') IS DISTINCT FROM 'number' OR manifest_json->>'schema_version' IS DISTINCT FROM 'paddock.checkpoint/1' OR manifest_json->>'root_id' IS DISTINCT FROM rid OR manifest_json->>'work_order_id' IS DISTINCT FROM wid OR manifest_json->>'attempt_id' IS DISTINCT FROM aid OR (manifest_json->>'lease_epoch')::bigint<>epoch OR (manifest_json->>'payload_size')::bigint<>octet_length(p) OR manifest_json->>'payload_sha256' IS NULL OR manifest_json->>'definition_digest' IS NULL OR manifest_json->>'policy_digest' IS NULL THEN RAISE EXCEPTION 'checkpoint manifest mismatch'; END IF;
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
 INSERT INTO raw.work_order_checkpoints(checkpoint_id,root_id,work_order_id,attempt_id,lease_epoch,manifest,payload,payload_sha256,state,stored_bytes) VALUES(op,rid,wid,aid,epoch,m,p,hashtext,result_state,n);
 RETURN QUERY SELECT op,result_state,n;
END $$;
ALTER FUNCTION raw.store_work_order_checkpoint(text,text,text,text,bigint,bytea,bytea,bigint) OWNER TO paddock_migrator;
REVOKE ALL ON FUNCTION raw.store_work_order_checkpoint(text,text,text,text,bigint,bytea,bytea,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION raw.store_work_order_checkpoint(text,text,text,text,bigint,bytea,bytea,bigint) TO paddock_app;
COMMIT;

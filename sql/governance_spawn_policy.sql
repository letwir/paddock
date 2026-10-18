-- Root-wide spawn admission. Source migration only; never applies itself.
BEGIN;
DO $guard$
BEGIN
 IF current_database()<>'paddock_test' OR current_user<>'paddock_migrator' THEN RAISE EXCEPTION 'governance_spawn_policy requires paddock_test/paddock_migrator'; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='paddock_app' AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls)
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='paddock_migrator' AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid=m.roleid JOIN pg_catalog.pg_roles u ON u.oid=m.member WHERE r.rolname IN('paddock_app','paddock_migrator') OR u.rolname IN('paddock_app','paddock_migrator')) THEN RAISE EXCEPTION 'isolated application/migrator roles required'; END IF;
 IF to_regclass('raw.work_orders') IS NULL OR to_regclass('raw.work_order_dependencies') IS NULL OR to_regclass('raw.roots') IS NULL OR to_regclass('raw.work_order_attempts') IS NULL THEN RAISE EXCEPTION 'required work-order schema missing'; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n JOIN pg_catalog.pg_roles r ON r.oid=n.nspowner WHERE n.nspname='raw' AND r.rolname='paddock_migrator') OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace JOIN pg_catalog.pg_roles r ON r.oid=c.relowner WHERE n.nspname='raw' AND c.relname IN('roots','work_orders','work_order_dependencies','work_order_attempts','work_order_pull_slots','work_order_leases') AND r.rolname<>'paddock_migrator') THEN RAISE EXCEPTION 'paddock_migrator must own raw schema and required objects'; END IF;
 IF pg_catalog.to_regprocedure('raw.issue_work_order_lease(text,text,text,text,text,jsonb,jsonb,interval)') IS NULL OR to_regclass('raw.work_order_pull_slots') IS NULL OR to_regclass('raw.work_order_leases') IS NULL THEN RAISE EXCEPTION 'existing lease transaction schema missing'; END IF;
END $guard$;
CREATE TABLE raw.spawn_policies(root_id text PRIMARY KEY REFERENCES raw.roots(root_id),max_spawn_depth integer NOT NULL CHECK(max_spawn_depth>0),max_total_descendants integer NOT NULL CHECK(max_total_descendants>0),max_live_children integer NOT NULL CHECK(max_live_children>0),max_attempts_per_work_order integer NOT NULL CHECK(max_attempts_per_work_order>0),root_deadline timestamptz NOT NULL,max_repeat_fingerprint integer NOT NULL CHECK(max_repeat_fingerprint>0));
CREATE TABLE raw.spawn_operations(root_id text NOT NULL,operation_id text NOT NULL,request jsonb NOT NULL,result jsonb NOT NULL,PRIMARY KEY(root_id,operation_id));
CREATE TABLE raw.spawn_fingerprints(root_id text NOT NULL,fingerprint text NOT NULL,occurrence_count integer NOT NULL CHECK(occurrence_count>0),PRIMARY KEY(root_id,fingerprint));
CREATE FUNCTION raw.spawn_policy_set(p_root text,p_operation text,p jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,raw AS $$
 DECLARE prior raw.spawn_operations%ROWTYPE; result jsonb;
BEGIN
 IF session_user<>'paddock_app' THEN RAISE EXCEPTION 'spawn policy requires trusted Coordinator session'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(p_root,0));
 IF p_root IS NULL OR p_root='' OR p_operation IS NULL OR p_operation='' OR p IS NULL OR jsonb_typeof(p)<>'object' OR (p->>'max_spawn_depth')::integer<=0 OR (p->>'max_total_descendants')::integer<=0 OR (p->>'max_live_children')::integer<=0 OR (p->>'max_attempts_per_work_order')::integer<=0 OR (p->>'max_repeat_fingerprint')::integer<=0 OR (p->>'root_deadline') IS NULL THEN RAISE EXCEPTION 'invalid finite spawn policy'; END IF;
 SELECT so.* INTO prior FROM raw.spawn_operations AS so WHERE so.root_id=p_root AND so.operation_id=p_operation;
 IF FOUND THEN
  IF prior.request<>jsonb_build_object('kind','policy','policy',p) THEN RAISE EXCEPTION 'operation id conflict'; END IF;
  SELECT so.result INTO result FROM raw.spawn_operations AS so WHERE so.root_id=p_root AND so.operation_id=p_operation;
  RETURN result;
 END IF;
 IF EXISTS(SELECT 1 FROM raw.spawn_policies WHERE root_id=p_root) THEN RAISE EXCEPTION 'spawn policy immutable'; END IF;
 INSERT INTO raw.spawn_policies VALUES(p_root,(p->>'max_spawn_depth')::integer,(p->>'max_total_descendants')::integer,(p->>'max_live_children')::integer,(p->>'max_attempts_per_work_order')::integer,(p->>'root_deadline')::timestamptz,(p->>'max_repeat_fingerprint')::integer);
 result:=jsonb_build_object('root_id',p_root,'policy',p); INSERT INTO raw.spawn_operations VALUES(p_root,p_operation,jsonb_build_object('kind','policy','policy',p),result); RETURN result;
END $$;
CREATE FUNCTION raw.spawn_fingerprint_context(p_root text,p_parent_work_order_id text)
RETURNS TABLE(effective_bundle_digest text,policy_digest text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF session_user<>'paddock_app' THEN RAISE EXCEPTION 'spawn digest context requires trusted Coordinator session'; END IF;
 IF p_root IS NULL OR p_root !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' OR p_parent_work_order_id IS NULL OR p_parent_work_order_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN RAISE EXCEPTION 'invalid spawn digest context'; END IF;
  SELECT r.effective_bundle_digest::text,w.policy_digest::text INTO effective_bundle_digest,policy_digest
   FROM raw.roots AS r JOIN raw.work_orders AS w ON w.root_id=r.root_id
   WHERE r.root_id=p_root AND w.work_order_id=p_parent_work_order_id;
  IF NOT FOUND OR effective_bundle_digest IS NULL OR policy_digest IS NULL THEN RAISE EXCEPTION 'spawn digest context missing or null'; END IF;
  RETURN NEXT;
END $$;
CREATE FUNCTION raw.spawn_admit(p_root text,p_operation text,p jsonb,p_definition_digest text,p_policy_digest text,p_fingerprints jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,raw AS $$
DECLARE policy raw.spawn_policies%ROWTYPE; prior raw.spawn_operations%ROWTYPE; parentrow raw.work_orders%ROWTYPE; task jsonb; dep text; ids jsonb:='{}'::jsonb; result jsonb:='{}'::jsonb; k text; wid text; fp text; depth integer; descendants bigint; live bigint; occurrence integer; current_definition text; current_policy text; n integer; stored_request jsonb;
BEGIN
 IF session_user<>'paddock_app' THEN RAISE EXCEPTION 'spawn requires trusted Coordinator session'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(p_root,0));
  IF p_root IS NULL OR p_root !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' OR p_operation IS NULL OR p_operation !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' OR p IS NULL OR p='null'::jsonb OR jsonb_typeof(p)<>'object' OR (SELECT count(*) FROM jsonb_object_keys(p))<>2 OR NOT (p ? 'parent_work_order_id' AND p ? 'tasks') OR jsonb_typeof(p->'parent_work_order_id')<>'string' OR (p->>'parent_work_order_id') !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' OR jsonb_typeof(p->'tasks')<>'array' OR jsonb_array_length(p->'tasks')=0 OR p_fingerprints IS NULL OR jsonb_typeof(p_fingerprints)<>'object' THEN RAISE EXCEPTION 'invalid spawn request'; END IF;
  stored_request:=p||jsonb_build_object('_root_id',p_root,'_semantic_fingerprints',p_fingerprints,'_definition_digest',p_definition_digest,'_policy_digest',p_policy_digest);
  SELECT so.* INTO prior FROM raw.spawn_operations AS so WHERE so.root_id=p_root AND so.operation_id=p_operation;
  IF FOUND THEN IF prior.request<>stored_request THEN RAISE EXCEPTION 'operation id conflict'; END IF; RETURN prior.result; END IF;
 SELECT * INTO policy FROM raw.spawn_policies WHERE root_id=p_root;
 IF NOT FOUND OR clock_timestamp()>=policy.root_deadline THEN RAISE EXCEPTION 'spawn policy missing or deadline elapsed'; END IF;
 SELECT * INTO parentrow FROM raw.work_orders WHERE root_id=p_root AND work_order_id=p->>'parent_work_order_id' FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'parent WorkOrder not in Root'; END IF;
 SELECT r.effective_bundle_digest::text,w.policy_digest INTO current_definition,current_policy FROM raw.roots r JOIN raw.work_orders w ON w.root_id=r.root_id WHERE r.root_id=p_root AND w.work_order_id=parentrow.work_order_id FOR UPDATE OF r,w;
   IF current_definition IS NULL OR current_policy IS NULL OR p_definition_digest IS NULL OR p_policy_digest IS NULL OR current_definition<>p_definition_digest OR current_policy<>p_policy_digest THEN RAISE EXCEPTION 'current digest context mismatch'; END IF;
  IF (SELECT count(*) FROM jsonb_object_keys(p_fingerprints))<>jsonb_array_length(p->'tasks') OR EXISTS(SELECT 1 FROM jsonb_object_keys(p_fingerprints) f(key) WHERE NOT EXISTS(SELECT 1 FROM jsonb_array_elements(p->'tasks') x WHERE x->>'key'=f.key)) THEN RAISE EXCEPTION 'fingerprint keys must match proposal tasks'; END IF;
 WITH RECURSIVE tree(work_order_id,parent_id,depth) AS (SELECT work_order_id,parent_id,0 FROM raw.work_orders WHERE root_id=p_root AND parent_id IS NULL UNION ALL SELECT c.work_order_id,c.parent_id,t.depth+1 FROM raw.work_orders c JOIN tree t ON c.parent_id=t.work_order_id WHERE c.root_id=p_root) SELECT t.depth INTO depth FROM tree t WHERE t.work_order_id=parentrow.work_order_id;
 IF depth IS NULL OR depth+1>policy.max_spawn_depth THEN RAISE EXCEPTION 'spawn depth cap'; END IF;
 SELECT count(*) INTO descendants FROM raw.work_orders WHERE root_id=p_root AND parent_id IS NOT NULL;
 IF descendants+jsonb_array_length(p->'tasks')>policy.max_total_descendants THEN RAISE EXCEPTION 'total descendant cap'; END IF;
 SELECT count(*) INTO live FROM raw.work_orders WHERE root_id=p_root AND parent_id=parentrow.work_order_id AND pull_state IN('QUEUED','READY','RUNNING');
 IF live+jsonb_array_length(p->'tasks')>policy.max_live_children THEN RAISE EXCEPTION 'live child cap'; END IF;
  FOR task IN SELECT value FROM jsonb_array_elements(p->'tasks') LOOP
   IF jsonb_typeof(task->'key')<>'string' THEN RAISE EXCEPTION 'invalid task key/content/fingerprint'; END IF;
   k:=task->>'key'; fp:=p_fingerprints->>k;
   IF jsonb_typeof(task)<>'object' OR (SELECT count(*) FROM jsonb_object_keys(task))<>5 OR NOT (task ? 'key' AND task ? 'title' AND task ? 'goal' AND task ? 'acceptance' AND task ? 'depends_on') OR k IS NULL OR k !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' OR fp IS NULL OR fp !~ '^[0-9a-f]{64}$' OR jsonb_typeof(task->'title')<>'string' OR btrim(task->>'title')='' OR jsonb_typeof(task->'goal')<>'string' OR btrim(task->>'goal')='' OR jsonb_typeof(task->'acceptance')<>'string' OR btrim(task->>'acceptance')='' THEN RAISE EXCEPTION 'invalid task key/content/fingerprint'; END IF;
  IF (SELECT count(*) FROM jsonb_array_elements(p->'tasks') x WHERE x->>'key'=k)<>1 THEN RAISE EXCEPTION 'duplicate temporary key'; END IF;
    IF jsonb_typeof(task->'depends_on')<>'array' OR EXISTS(SELECT 1 FROM jsonb_array_elements(task->'depends_on') d(value) WHERE jsonb_typeof(d.value)<>'string' OR d.value#>>'{}'=k OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(p->'tasks') x WHERE x->>'key'=d.value#>>'{}')) THEN RAISE EXCEPTION 'dependency outside proposal or self edge'; END IF;
   IF (SELECT count(*) FROM jsonb_array_elements_text(task->'depends_on'))<>(SELECT count(DISTINCT value) FROM jsonb_array_elements_text(task->'depends_on') d(value)) THEN RAISE EXCEPTION 'duplicate dependency edge'; END IF;
  SELECT COALESCE(occurrence_count,0) INTO occurrence FROM raw.spawn_fingerprints WHERE root_id=p_root AND fingerprint=fp;
  IF COALESCE(occurrence,0)+(SELECT count(*) FROM jsonb_array_elements(p->'tasks') x WHERE p_fingerprints->>(x->>'key')=fp)>policy.max_repeat_fingerprint THEN RAISE EXCEPTION 'fingerprint occurrence cap'; END IF;
 END LOOP;
 FOR task IN SELECT value FROM jsonb_array_elements(p->'tasks') LOOP
  k:=task->>'key'; wid:='wo-'||replace(gen_random_uuid()::text,'-',''); ids:=ids||jsonb_build_object(k,wid);
 END LOOP;
  FOR task IN SELECT value FROM jsonb_array_elements(p->'tasks') LOOP
   k:=task->>'key'; wid:=ids->>k; fp:=p_fingerprints->>k;
   INSERT INTO raw.work_orders(work_order_id,root_id,parent_id,pull_state,offline_policy_mode,checkpointability,policy_canonical,policy_digest,external_action_allowlist,low_risk_actions)
    SELECT wid,p_root,parentrow.work_order_id,'QUEUED',w.offline_policy_mode,w.checkpointability,w.policy_canonical,w.policy_digest,w.external_action_allowlist,w.low_risk_actions FROM raw.work_orders w WHERE w.work_order_id=parentrow.work_order_id;
  END LOOP;
  FOR task IN SELECT value FROM jsonb_array_elements(p->'tasks') LOOP
   k:=task->>'key'; wid:=ids->>k;
   FOR dep IN SELECT jsonb_array_elements_text(task->'depends_on') LOOP INSERT INTO raw.work_order_dependencies(root_id,work_order_id,depends_on_id) VALUES(p_root,wid,ids->>dep); END LOOP;
  END LOOP;
  FOR task IN SELECT value FROM jsonb_array_elements(p->'tasks') LOOP
   k:=task->>'key'; wid:=ids->>k; fp:=p_fingerprints->>k;
   INSERT INTO raw.spawn_fingerprints(root_id,fingerprint,occurrence_count) VALUES(p_root,fp,1) ON CONFLICT(root_id,fingerprint) DO UPDATE SET occurrence_count=raw.spawn_fingerprints.occurrence_count+1;
   result:=result||jsonb_build_object(k,wid);
  END LOOP;
 INSERT INTO raw.spawn_operations VALUES(p_root,p_operation,stored_request,result); RETURN result;
END $$;
ALTER FUNCTION raw.spawn_policy_set(text,text,jsonb) OWNER TO paddock_migrator;
ALTER FUNCTION raw.spawn_fingerprint_context(text,text) OWNER TO paddock_migrator;
ALTER FUNCTION raw.spawn_admit(text,text,jsonb,text,text,jsonb) OWNER TO paddock_migrator;
REVOKE ALL ON raw.spawn_policies,raw.spawn_operations,raw.spawn_fingerprints FROM PUBLIC,paddock_app;
REVOKE ALL ON raw.roots,raw.work_orders,raw.work_order_dependencies,raw.work_order_attempts,raw.work_order_pull_slots,raw.work_order_leases FROM paddock_app;
REVOKE ALL ON FUNCTION raw.spawn_policy_set(text,text,jsonb),raw.spawn_admit(text,text,jsonb,text,text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION raw.spawn_fingerprint_context(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION raw.spawn_policy_set(text,text,jsonb),raw.spawn_admit(text,text,jsonb,text,text,jsonb) TO paddock_app;
GRANT EXECUTE ON FUNCTION raw.spawn_fingerprint_context(text,text) TO paddock_app;
-- Extend the existing lease transaction with a Root-scoped retry cap. Preserve its exact signature and validation/write order.
CREATE OR REPLACE FUNCTION raw.issue_work_order_lease(text,text,text,text,text,jsonb,jsonb,interval)
RETURNS TABLE(attempt_id text,slot_id text,lease_epoch bigint,expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE p_work_order_id ALIAS FOR $1; p_worker_id ALIAS FOR $2; p_session_id ALIAS FOR $3; p_attempt_id ALIAS FOR $4; p_slot_id ALIAS FOR $5; p_requirements ALIAS FOR $6; p_evidence ALIAS FOR $7; p_ttl ALIAS FOR $8;
 st text; configured boolean; next_number bigint; new_epoch bigint; op_time timestamptz; order_root text; attempts bigint; attempt_cap integer;
BEGIN
 SELECT pull_state,capability_requirements_configured,root_id INTO st,configured,order_root FROM raw.work_orders WHERE work_order_id=p_work_order_id FOR UPDATE;
 IF NOT FOUND OR st<>'READY' OR NOT configured OR p_work_order_id IS NULL OR btrim(p_work_order_id)='' OR p_worker_id IS NULL OR btrim(p_worker_id)='' OR p_session_id IS NULL OR btrim(p_session_id)='' OR p_attempt_id IS NULL OR btrim(p_attempt_id)='' OR p_slot_id IS NULL OR btrim(p_slot_id)='' OR p_ttl IS NULL OR NOT isfinite(p_ttl) OR p_ttl<=interval '0' OR p_requirements IS NULL OR jsonb_typeof(p_requirements)<>'array' OR p_evidence IS NULL OR jsonb_typeof(p_evidence)<>'array' THEN RETURN; END IF;
 IF EXISTS(SELECT 1 FROM raw.work_order_capability_requirements r WHERE r.work_order_id=p_work_order_id AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(p_requirements) x(item) WHERE jsonb_typeof(item)='object' AND item->>'name'=r.capability_name AND item->>'value'=r.capability_value)) OR (SELECT count(*) FROM raw.work_order_capability_requirements WHERE work_order_id=p_work_order_id)<>(SELECT count(*) FROM jsonb_array_elements(p_requirements)) THEN RETURN; END IF;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(p_requirements) x(item) WHERE CASE WHEN jsonb_typeof(item)='object' THEN (SELECT count(*) FROM jsonb_object_keys(item))<>2 OR jsonb_typeof(item->'name')<>'string' OR item->>'name' IS NULL OR item->>'name'='' OR item->>'name'<>btrim(item->>'name') OR jsonb_typeof(item->'value')<>'string' OR item->>'value' IS NULL OR item->>'value'='' OR item->>'value'<>btrim(item->>'value') ELSE true END) THEN RETURN; END IF;
 IF EXISTS(SELECT 1 FROM raw.work_order_capability_requirements r WHERE r.work_order_id=p_work_order_id AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(p_evidence) x(item) WHERE item->>'name'=r.capability_name AND item->>'value'=r.capability_value)) OR (SELECT count(*) FROM raw.work_order_capability_requirements WHERE work_order_id=p_work_order_id)<>(SELECT count(*) FROM jsonb_array_elements(p_evidence)) THEN RETURN; END IF;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(p_evidence) x(item) WHERE CASE WHEN jsonb_typeof(item)='object' THEN (SELECT count(*) FROM jsonb_object_keys(item))<>2 OR jsonb_typeof(item->'name')<>'string' OR item->>'name' IS NULL OR item->>'name'='' OR item->>'name'<>btrim(item->>'name') OR jsonb_typeof(item->'value')<>'string' OR item->>'value' IS NULL OR item->>'value'='' OR item->>'value'<>btrim(item->>'value') ELSE true END) THEN RETURN; END IF;
 IF (SELECT count(*) FROM jsonb_array_elements(p_requirements) x(item))<>(SELECT count(DISTINCT item->>'name') FROM jsonb_array_elements(p_requirements) x(item)) OR (SELECT count(*) FROM jsonb_array_elements(p_evidence) x(item))<>(SELECT count(DISTINCT item->>'name') FROM jsonb_array_elements(p_evidence) x(item)) THEN RETURN; END IF;
 IF EXISTS(SELECT 1 FROM raw.work_order_dependencies d JOIN raw.work_orders p ON p.work_order_id=d.depends_on_id WHERE d.work_order_id=p_work_order_id AND p.pull_state<>'DONE') THEN RETURN; END IF;
 SELECT count(*) INTO attempts FROM raw.work_order_attempts WHERE work_order_id=p_work_order_id;
 SELECT max_attempts_per_work_order INTO attempt_cap FROM raw.spawn_policies WHERE root_id=order_root;
 IF (attempt_cap IS NULL AND attempts>0) OR (attempt_cap IS NOT NULL AND attempts>=attempt_cap) THEN RETURN; END IF;
 op_time:=clock_timestamp(); SELECT COALESCE(max(attempt_number),0)+1 INTO next_number FROM raw.work_order_attempts WHERE work_order_id=p_work_order_id;
 SELECT w.lease_epoch+1 INTO new_epoch FROM raw.work_orders w WHERE w.work_order_id=p_work_order_id;
 INSERT INTO raw.work_order_attempts(attempt_id,work_order_id,attempt_number) VALUES(p_attempt_id,p_work_order_id,next_number);
 INSERT INTO raw.work_order_pull_slots(work_order_id,slot_id,worker_id,reserved_at) VALUES(p_work_order_id,p_slot_id,p_worker_id,op_time);
 UPDATE raw.work_orders SET pull_state='RUNNING',lease_epoch=new_epoch WHERE work_order_id=p_work_order_id AND pull_state='READY'; IF NOT FOUND THEN RAISE EXCEPTION 'locked Pull state changed'; END IF;
 INSERT INTO raw.work_order_leases VALUES(p_work_order_id,p_attempt_id,new_epoch,p_worker_id,p_session_id,op_time,op_time,op_time+p_ttl);
 RETURN QUERY SELECT p_attempt_id,p_slot_id,new_epoch,op_time+p_ttl;
END $$;
ALTER FUNCTION raw.issue_work_order_lease(text,text,text,text,text,jsonb,jsonb,interval) OWNER TO paddock_migrator;
REVOKE ALL ON FUNCTION raw.issue_work_order_lease(text,text,text,text,text,jsonb,jsonb,interval) FROM PUBLIC,paddock_app;
GRANT EXECUTE ON FUNCTION raw.issue_work_order_lease(text,text,text,text,text,jsonb,jsonb,interval) TO paddock_app;
COMMIT;

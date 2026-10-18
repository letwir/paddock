-- M08-S03 additive lease persistence. Source migration only; do not apply implicitly.
BEGIN;
DO $$ BEGIN
 IF current_database()<>'paddock_test' THEN RAISE EXCEPTION 'refusing lease migration outside paddock_test'; END IF;
 IF current_user<>'paddock_migrator' THEN RAISE EXCEPTION 'lease migration must run as paddock_migrator'; END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='paddock_migrator' AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls)
 OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='paddock_app' AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls)
 OR EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid=m.roleid JOIN pg_catalog.pg_roles u ON u.oid=m.member WHERE r.rolname IN ('paddock_app','paddock_migrator') OR u.rolname IN ('paddock_app','paddock_migrator')) THEN RAISE EXCEPTION 'non-elevated isolated app/migrator roles required'; END IF;
 IF to_regclass('raw.work_orders') IS NULL OR to_regclass('raw.work_order_attempts') IS NULL OR to_regclass('raw.work_order_pull_slots') IS NULL OR to_regclass('raw.work_order_capability_requirements') IS NULL OR to_regclass('raw.work_order_dependencies') IS NULL THEN RAISE EXCEPTION 'S02 tables required'; END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace JOIN pg_catalog.pg_roles r ON r.oid=c.relowner WHERE n.nspname='raw' AND c.relname IN ('work_orders','work_order_attempts','work_order_pull_slots','work_order_capability_requirements','work_order_dependencies') AND r.rolname<>'paddock_migrator') THEN RAISE EXCEPTION 'paddock_migrator must own S02 tables'; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n JOIN pg_catalog.pg_roles r ON r.oid=n.nspowner WHERE n.nspname='raw' AND r.rolname='paddock_migrator') THEN RAISE EXCEPTION 'paddock_migrator must own raw schema'; END IF;
  IF EXISTS (SELECT 1 FROM raw.work_orders WHERE pull_state='RUNNING') OR EXISTS (SELECT 1 FROM raw.work_order_pull_slots) THEN RAISE EXCEPTION 'S02 RUNNING work or pull slots prevent lease migration'; END IF;
END $$;
ALTER TABLE raw.work_orders ADD COLUMN lease_epoch bigint NOT NULL DEFAULT 0 CHECK (lease_epoch>=0);
ALTER TABLE raw.work_order_attempts ADD CONSTRAINT work_order_attempts_attempt_order_uq UNIQUE (attempt_id,work_order_id);
CREATE TABLE raw.work_order_leases (
 work_order_id text PRIMARY KEY REFERENCES raw.work_orders(work_order_id),
 attempt_id text NOT NULL UNIQUE,
 lease_epoch bigint NOT NULL CHECK(lease_epoch>0),
 worker_id text NOT NULL CHECK(worker_id<>'' AND worker_id=btrim(worker_id)),
 session_id text NOT NULL CHECK(session_id<>'' AND session_id=btrim(session_id)),
 issued_at timestamptz NOT NULL, heartbeat_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
 CHECK(issued_at<=heartbeat_at AND heartbeat_at<expires_at),
 CONSTRAINT work_order_leases_attempt_order_fk FOREIGN KEY(attempt_id,work_order_id) REFERENCES raw.work_order_attempts(attempt_id,work_order_id)
);
DO $$ BEGIN
 IF (SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace JOIN pg_catalog.pg_roles r ON r.oid=c.relowner WHERE n.nspname='raw' AND c.relname IN ('work_orders','work_order_attempts','work_order_pull_slots','work_order_leases') AND r.rolname='paddock_migrator')<>4 THEN RAISE EXCEPTION 'migrator ownership preflight failed'; END IF;
END $$;
CREATE FUNCTION raw.issue_work_order_lease(text,text,text,text,text,jsonb,jsonb,interval)
RETURNS TABLE(attempt_id text,slot_id text,lease_epoch bigint,expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE p_work_order_id ALIAS FOR $1; p_worker_id ALIAS FOR $2; p_session_id ALIAS FOR $3; p_attempt_id ALIAS FOR $4; p_slot_id ALIAS FOR $5; p_requirements ALIAS FOR $6; p_evidence ALIAS FOR $7; p_ttl ALIAS FOR $8;
 st text; configured boolean; next_number bigint; new_epoch bigint; op_time timestamptz;
BEGIN
 SELECT pull_state,capability_requirements_configured INTO st,configured FROM raw.work_orders WHERE work_order_id=p_work_order_id FOR UPDATE;
  IF NOT FOUND OR st<>'READY' OR NOT configured OR p_work_order_id IS NULL OR btrim(p_work_order_id)='' OR p_worker_id IS NULL OR btrim(p_worker_id)='' OR p_session_id IS NULL OR btrim(p_session_id)='' OR p_attempt_id IS NULL OR btrim(p_attempt_id)='' OR p_slot_id IS NULL OR btrim(p_slot_id)='' OR p_ttl IS NULL OR NOT isfinite(p_ttl) OR p_ttl<=interval '0' OR p_requirements IS NULL OR jsonb_typeof(p_requirements)<>'array' OR p_evidence IS NULL OR jsonb_typeof(p_evidence)<>'array' THEN RETURN; END IF;
 IF EXISTS(SELECT 1 FROM raw.work_order_capability_requirements r WHERE r.work_order_id=p_work_order_id AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(p_requirements) x(item) WHERE jsonb_typeof(item)='object' AND item->>'name'=r.capability_name AND item->>'value'=r.capability_value)) OR (SELECT count(*) FROM raw.work_order_capability_requirements WHERE work_order_id=p_work_order_id)<>(SELECT count(*) FROM jsonb_array_elements(p_requirements)) THEN RETURN; END IF;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(p_requirements) x(item) WHERE CASE WHEN jsonb_typeof(item)='object' THEN (SELECT count(*) FROM jsonb_object_keys(item))<>2 OR jsonb_typeof(item->'name')<>'string' OR item->>'name' IS NULL OR item->>'name'='' OR item->>'name'<>btrim(item->>'name') OR jsonb_typeof(item->'value')<>'string' OR item->>'value' IS NULL OR item->>'value'='' OR item->>'value'<>btrim(item->>'value') ELSE true END) THEN RETURN; END IF;
 IF EXISTS(SELECT 1 FROM raw.work_order_capability_requirements r WHERE r.work_order_id=p_work_order_id AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(p_evidence) x(item) WHERE item->>'name'=r.capability_name AND item->>'value'=r.capability_value)) OR (SELECT count(*) FROM raw.work_order_capability_requirements WHERE work_order_id=p_work_order_id)<>(SELECT count(*) FROM jsonb_array_elements(p_evidence)) THEN RETURN; END IF;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(p_evidence) x(item) WHERE CASE WHEN jsonb_typeof(item)='object' THEN (SELECT count(*) FROM jsonb_object_keys(item))<>2 OR jsonb_typeof(item->'name')<>'string' OR item->>'name' IS NULL OR item->>'name'='' OR item->>'name'<>btrim(item->>'name') OR jsonb_typeof(item->'value')<>'string' OR item->>'value' IS NULL OR item->>'value'='' OR item->>'value'<>btrim(item->>'value') ELSE true END) THEN RETURN; END IF;
 IF (SELECT count(*) FROM jsonb_array_elements(p_requirements) x(item))<>(SELECT count(DISTINCT item->>'name') FROM jsonb_array_elements(p_requirements) x(item)) OR (SELECT count(*) FROM jsonb_array_elements(p_evidence) x(item))<>(SELECT count(DISTINCT item->>'name') FROM jsonb_array_elements(p_evidence) x(item)) THEN RETURN; END IF;
 IF EXISTS(SELECT 1 FROM raw.work_order_dependencies d JOIN raw.work_orders p ON p.work_order_id=d.depends_on_id WHERE d.work_order_id=p_work_order_id AND p.pull_state<>'DONE') THEN RETURN; END IF;
 op_time:=clock_timestamp();
 SELECT COALESCE(max(attempt_number),0)+1 INTO next_number FROM raw.work_order_attempts WHERE work_order_id=p_work_order_id;
  SELECT w.lease_epoch+1 INTO new_epoch FROM raw.work_orders w WHERE w.work_order_id=p_work_order_id;
 INSERT INTO raw.work_order_attempts(attempt_id,work_order_id,attempt_number) VALUES(p_attempt_id,p_work_order_id,next_number);
 INSERT INTO raw.work_order_pull_slots(work_order_id,slot_id,worker_id,reserved_at) VALUES(p_work_order_id,p_slot_id,p_worker_id,op_time);
 UPDATE raw.work_orders SET pull_state='RUNNING',lease_epoch=new_epoch WHERE work_order_id=p_work_order_id AND pull_state='READY';
 IF NOT FOUND THEN RAISE EXCEPTION 'locked Pull state changed'; END IF;
 INSERT INTO raw.work_order_leases VALUES(p_work_order_id,p_attempt_id,new_epoch,p_worker_id,p_session_id,op_time,op_time,op_time+p_ttl);
 RETURN QUERY SELECT p_attempt_id,p_slot_id,new_epoch,op_time+p_ttl;
END $$;
CREATE FUNCTION raw.heartbeat_work_order_lease(text,text,text,text,bigint,interval) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE p_work_order_id ALIAS FOR $1; p_attempt_id ALIAS FOR $2; p_worker_id ALIAS FOR $3; p_session_id ALIAS FOR $4; p_epoch ALIAS FOR $5; p_ttl ALIAS FOR $6; st text; op_time timestamptz;
BEGIN
 SELECT pull_state INTO st FROM raw.work_orders WHERE work_order_id=p_work_order_id FOR UPDATE;
  IF NOT FOUND OR st<>'RUNNING' OR p_ttl IS NULL OR NOT isfinite(p_ttl) OR p_ttl<=interval '0' OR p_epoch IS NULL OR p_attempt_id IS NULL OR btrim(p_attempt_id)='' OR p_worker_id IS NULL OR btrim(p_worker_id)='' OR p_session_id IS NULL OR btrim(p_session_id)='' THEN RETURN false; END IF;
 op_time:=clock_timestamp();
 UPDATE raw.work_order_leases SET heartbeat_at=op_time,expires_at=op_time+p_ttl WHERE work_order_id=p_work_order_id AND attempt_id=p_attempt_id AND worker_id=p_worker_id AND session_id=p_session_id AND lease_epoch=p_epoch AND expires_at>op_time;
 RETURN FOUND;
END $$;
CREATE FUNCTION raw.reap_work_order_leases(integer) RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE p_batch_size ALIAS FOR $1; item record; n integer:=0; op_time timestamptz;
BEGIN
 IF p_batch_size IS NULL OR p_batch_size<=0 THEN RAISE EXCEPTION 'batch size must be positive'; END IF;
 op_time:=clock_timestamp();
 FOR item IN SELECT w.work_order_id FROM raw.work_orders w JOIN raw.work_order_leases l ON l.work_order_id=w.work_order_id WHERE w.pull_state='RUNNING' AND l.expires_at<=op_time ORDER BY w.work_order_id LIMIT p_batch_size FOR UPDATE OF w SKIP LOCKED LOOP
  -- Recheck lease and state only after acquiring the WorkOrder lock.
  DELETE FROM raw.work_order_leases WHERE work_order_id=item.work_order_id AND expires_at<=op_time;
  IF FOUND THEN
   DELETE FROM raw.work_order_pull_slots WHERE work_order_id=item.work_order_id;
   UPDATE raw.work_orders SET pull_state='READY' WHERE work_order_id=item.work_order_id AND pull_state='RUNNING';
   IF FOUND THEN n:=n+1; END IF;
  END IF;
 END LOOP;
 RETURN n;
END $$;
CREATE FUNCTION raw.complete_work_order_lease(text,text,text,text,bigint) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE p_work_order_id ALIAS FOR $1; p_attempt_id ALIAS FOR $2; p_worker_id ALIAS FOR $3; p_session_id ALIAS FOR $4; p_epoch ALIAS FOR $5; st text; op_time timestamptz;
BEGIN
 SELECT pull_state INTO st FROM raw.work_orders WHERE work_order_id=p_work_order_id FOR UPDATE;
 IF NOT FOUND OR st<>'RUNNING' OR p_epoch IS NULL OR p_attempt_id IS NULL OR btrim(p_attempt_id)='' OR p_worker_id IS NULL OR btrim(p_worker_id)='' OR p_session_id IS NULL OR btrim(p_session_id)='' THEN RETURN false; END IF;
 op_time:=clock_timestamp();
 IF NOT EXISTS(SELECT 1 FROM raw.work_order_leases WHERE work_order_id=p_work_order_id AND attempt_id=p_attempt_id AND worker_id=p_worker_id AND session_id=p_session_id AND lease_epoch=p_epoch AND expires_at>op_time) THEN RETURN false; END IF;
 UPDATE raw.work_orders SET pull_state='DONE' WHERE work_order_id=p_work_order_id AND pull_state='RUNNING';
 IF NOT FOUND THEN RETURN false; END IF;
 DELETE FROM raw.work_order_leases WHERE work_order_id=p_work_order_id AND attempt_id=p_attempt_id AND worker_id=p_worker_id AND session_id=p_session_id AND lease_epoch=p_epoch;
 DELETE FROM raw.work_order_pull_slots WHERE work_order_id=p_work_order_id;
 RETURN true;
END $$;
ALTER FUNCTION raw.issue_work_order_lease(text,text,text,text,text,jsonb,jsonb,interval) OWNER TO paddock_migrator;
ALTER FUNCTION raw.heartbeat_work_order_lease(text,text,text,text,bigint,interval) OWNER TO paddock_migrator;
ALTER FUNCTION raw.reap_work_order_leases(integer) OWNER TO paddock_migrator;
ALTER FUNCTION raw.complete_work_order_lease(text,text,text,text,bigint) OWNER TO paddock_migrator;
REVOKE ALL ON FUNCTION raw.issue_work_order_lease(text,text,text,text,text,jsonb,jsonb,interval),raw.heartbeat_work_order_lease(text,text,text,text,bigint,interval),raw.reap_work_order_leases(integer),raw.complete_work_order_lease(text,text,text,text,bigint),raw.reserve_work_order_pull(text,text,text,text,jsonb,jsonb) FROM PUBLIC,paddock_app;
GRANT EXECUTE ON FUNCTION raw.issue_work_order_lease(text,text,text,text,text,jsonb,jsonb,interval),raw.heartbeat_work_order_lease(text,text,text,text,bigint,interval),raw.complete_work_order_lease(text,text,text,text,bigint),raw.reap_work_order_leases(integer) TO paddock_app;
REVOKE ALL ON TABLE raw.work_order_leases FROM PUBLIC,paddock_app;
REVOKE ALL (lease_epoch) ON TABLE raw.work_orders FROM PUBLIC,paddock_app;
COMMENT ON TABLE raw.work_order_leases IS 'One current lease per WorkOrder; session identifiers are opaque identity fields, not SQL authentication.';
COMMIT;

-- M08-S02: additive Worker Pull reservation seam; no lease/completion API.
BEGIN;
-- This database function is a narrow atomic storage API. Authority/Trust/Budget/Permit
-- gates execute in the trusted Coordinator before it calls the API. The paddock_app
-- credential is Coordinator-only, never exposed to Workers or external callers.
-- This PoC boundary is not DB validation of those gates: a caller obtaining app
-- credentials could still invoke the granted functions.
DO $$ BEGIN
 IF current_database()<>'paddock_test' THEN RAISE EXCEPTION 'refusing pull migration outside paddock_test'; END IF;
 IF current_user<>'paddock_migrator' THEN RAISE EXCEPTION 'Pull migration must run as paddock_migrator'; END IF;
 IF to_regclass('raw.work_orders') IS NULL OR to_regclass('raw.work_order_attempts') IS NULL OR to_regclass('raw.work_order_dependencies') IS NULL THEN RAISE EXCEPTION 'required WorkOrder persistence tables missing'; END IF;
END $$;
-- Validate both provisioned roles and their isolation before any DDL.
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='paddock_migrator' AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls) THEN RAISE EXCEPTION 'trusted non-elevated paddock_migrator is required'; END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='paddock_app' AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls) THEN RAISE EXCEPTION 'trusted non-elevated paddock_app is required'; END IF;
 IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles granted_role ON granted_role.oid=m.roleid JOIN pg_catalog.pg_roles member_role ON member_role.oid=m.member WHERE granted_role.rolname IN ('paddock_app','paddock_migrator') OR member_role.rolname IN ('paddock_app','paddock_migrator')) THEN RAISE EXCEPTION 'paddock_app and paddock_migrator must have no role memberships'; END IF;
 IF EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace JOIN pg_catalog.pg_roles r ON r.oid=c.relowner WHERE n.nspname='raw' AND c.relname IN ('work_orders','work_order_dependencies','work_order_attempts') AND r.rolname<>'paddock_migrator') THEN RAISE EXCEPTION 'paddock_migrator must own pre-existing WorkOrder relations'; END IF;
END $$;
ALTER TABLE raw.work_orders ADD COLUMN pull_state text NOT NULL DEFAULT 'QUEUED' CHECK (pull_state IN ('QUEUED','READY','RUNNING','DONE'));
-- Distinguish absent policy from explicitly configured empty requirements.
ALTER TABLE raw.work_orders ADD COLUMN capability_requirements_configured boolean NOT NULL DEFAULT false;
CREATE TABLE raw.work_order_capability_requirements (
 work_order_id text NOT NULL REFERENCES raw.work_orders(work_order_id),
 capability_name text NOT NULL CHECK (capability_name<>'' AND capability_name=btrim(capability_name)),
 capability_value text NOT NULL CHECK (capability_value<>'' AND capability_value=btrim(capability_value)),
 PRIMARY KEY(work_order_id, capability_name)
);
CREATE TABLE raw.work_order_pull_slots (
 work_order_id text PRIMARY KEY REFERENCES raw.work_orders(work_order_id),
 slot_id text NOT NULL UNIQUE CHECK (slot_id<>'' AND slot_id=btrim(slot_id)),
 worker_id text NOT NULL CHECK (worker_id<>'' AND worker_id=btrim(worker_id)),
 reserved_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
-- Tables are created under paddock_migrator; check all five touched relations before
-- creating/assigning SECURITY DEFINER functions. Fail closed on wrong owner or absence.
DO $$ BEGIN
 IF (SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace JOIN pg_catalog.pg_roles r ON r.oid=c.relowner WHERE n.nspname='raw' AND c.relname IN ('work_orders','work_order_dependencies','work_order_attempts','work_order_pull_slots','work_order_capability_requirements') AND r.rolname='paddock_migrator')<>5 THEN RAISE EXCEPTION 'paddock_migrator must own all five Pull relations'; END IF;
END $$;
-- zero requirement rows is explicitly unconstrained; candidate requirements and evidence must then be empty.
CREATE FUNCTION raw.configure_work_order_capabilities(p_work_order_id text, p_requirements jsonb) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE changed integer; current_state text; is_configured boolean;
BEGIN
 SELECT pull_state,capability_requirements_configured INTO current_state,is_configured FROM raw.work_orders WHERE work_order_id=p_work_order_id FOR UPDATE;
 IF NOT FOUND OR current_state<>'QUEUED' OR is_configured THEN RETURN false; END IF;
 IF p_requirements IS NULL OR jsonb_typeof(p_requirements)<>'array' THEN RAISE EXCEPTION 'requirements must be a JSON array'; END IF;
 IF EXISTS (SELECT 1 FROM jsonb_array_elements(p_requirements) AS requirements(item) WHERE CASE WHEN jsonb_typeof(item)='object' THEN (SELECT count(*) FROM jsonb_object_keys(item))<>2 OR jsonb_typeof(item->'name')<>'string' OR item->>'name' IS NULL OR item->>'name'='' OR item->>'name'<>btrim(item->>'name') OR jsonb_typeof(item->'value')<>'string' OR item->>'value' IS NULL OR item->>'value'='' OR item->>'value'<>btrim(item->>'value') ELSE true END) THEN RAISE EXCEPTION 'malformed capability requirement'; END IF;
 IF (SELECT count(*) FROM jsonb_array_elements(p_requirements))<>(SELECT count(DISTINCT item->>'name') FROM jsonb_array_elements(p_requirements) AS requirements(item)) THEN RAISE EXCEPTION 'duplicate capability requirement name'; END IF;
 INSERT INTO raw.work_order_capability_requirements(work_order_id,capability_name,capability_value) SELECT p_work_order_id,item->>'name',item->>'value' FROM jsonb_array_elements(p_requirements) AS requirements(item);
 UPDATE raw.work_orders SET capability_requirements_configured=true WHERE work_order_id=p_work_order_id AND pull_state='QUEUED' AND NOT capability_requirements_configured;
 GET DIAGNOSTICS changed=ROW_COUNT;
 IF changed<>1 THEN RAISE EXCEPTION 'WorkOrder capability policy changed concurrently'; END IF;
 RETURN true;
END $$;
CREATE FUNCTION raw.mark_work_order_pull_ready(p_work_order_id text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE changed integer;
BEGIN
 UPDATE raw.work_orders w SET pull_state='READY' WHERE w.work_order_id=p_work_order_id AND w.pull_state='QUEUED' AND w.capability_requirements_configured AND NOT EXISTS (SELECT 1 FROM raw.work_order_dependencies d JOIN raw.work_orders predecessor ON predecessor.work_order_id=d.depends_on_id WHERE d.work_order_id=w.work_order_id AND predecessor.pull_state<>'DONE');
 GET DIAGNOSTICS changed=ROW_COUNT;
 RETURN changed=1;
END $$;
CREATE FUNCTION raw.reserve_work_order_pull(p_work_order_id text,p_worker_id text,p_attempt_id text,p_slot_id text,p_requirements jsonb,p_evidence jsonb)
RETURNS TABLE(attempt_id text,slot_id text) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE current_state text; configured boolean; next_number integer;
BEGIN
 SELECT w.pull_state,w.capability_requirements_configured INTO current_state,configured FROM raw.work_orders w WHERE w.work_order_id=p_work_order_id FOR UPDATE;
 IF NOT FOUND OR current_state<>'READY' OR NOT configured THEN RETURN; END IF;
 IF p_worker_id IS NULL OR p_worker_id='' OR p_attempt_id IS NULL OR p_attempt_id='' OR p_slot_id IS NULL OR p_slot_id='' THEN RETURN; END IF;
 IF p_requirements IS NULL OR jsonb_typeof(p_requirements)<>'array' OR p_evidence IS NULL OR jsonb_typeof(p_evidence)<>'array' THEN RETURN; END IF;
 IF EXISTS (SELECT 1 FROM raw.work_order_capability_requirements r WHERE r.work_order_id=p_work_order_id AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(p_requirements) x(item) WHERE item->>'name'=r.capability_name AND item->>'value'=r.capability_value)) OR (SELECT count(*) FROM raw.work_order_capability_requirements r WHERE r.work_order_id=p_work_order_id)<>(SELECT count(*) FROM jsonb_array_elements(p_requirements)) THEN RETURN; END IF;
 IF EXISTS (SELECT 1 FROM raw.work_order_capability_requirements r WHERE r.work_order_id=p_work_order_id AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(p_evidence) x(item) WHERE item->>'name'=r.capability_name AND item->>'value'=r.capability_value)) OR (SELECT count(*) FROM raw.work_order_capability_requirements r WHERE r.work_order_id=p_work_order_id)<>(SELECT count(*) FROM jsonb_array_elements(p_evidence)) THEN RETURN; END IF;
 IF EXISTS (SELECT 1 FROM raw.work_order_dependencies d JOIN raw.work_orders predecessor ON predecessor.work_order_id=d.depends_on_id WHERE d.work_order_id=p_work_order_id AND predecessor.pull_state<>'DONE') THEN RETURN; END IF;
 INSERT INTO raw.work_order_pull_slots(work_order_id,slot_id,worker_id) VALUES(p_work_order_id,p_slot_id,p_worker_id);
 SELECT COALESCE(MAX(a.attempt_number),0)+1 INTO next_number FROM raw.work_order_attempts a WHERE a.work_order_id=p_work_order_id;
 INSERT INTO raw.work_order_attempts(attempt_id,work_order_id,attempt_number) VALUES(p_attempt_id,p_work_order_id,next_number);
 UPDATE raw.work_orders SET pull_state='RUNNING' WHERE work_order_id=p_work_order_id AND pull_state='READY';
 IF NOT FOUND THEN RAISE EXCEPTION 'locked Pull state changed'; END IF;
 RETURN QUERY SELECT p_attempt_id,p_slot_id;
END $$;
COMMENT ON COLUMN raw.work_orders.pull_state IS 'M08-S02 pull state; DONE is dependency-terminal only. Lease/completion APIs are not implemented here.';
COMMENT ON COLUMN raw.work_orders.capability_requirements_configured IS 'False means capability requirements are absent and Pull fails closed; true with zero requirement rows is explicitly unconstrained.';
COMMENT ON TABLE raw.work_order_capability_requirements IS 'Canonical WorkOrder capability requirements; empty rows are valid only when capability_requirements_configured is true.';
COMMENT ON TABLE raw.work_order_attempts IS 'Attempt numbering is serialized by locking the parent work_orders row in the M08-S02 pull adapter. Application DB roles must not insert attempts directly.';
-- Function creation is complete before owner changes or grants.
ALTER FUNCTION raw.configure_work_order_capabilities(text,jsonb) OWNER TO paddock_migrator;
ALTER FUNCTION raw.mark_work_order_pull_ready(text) OWNER TO paddock_migrator;
ALTER FUNCTION raw.reserve_work_order_pull(text,text,text,text,jsonb,jsonb) OWNER TO paddock_migrator;
REVOKE ALL ON FUNCTION raw.configure_work_order_capabilities(text,jsonb),raw.mark_work_order_pull_ready(text),raw.reserve_work_order_pull(text,text,text,text,jsonb,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION raw.configure_work_order_capabilities(text,jsonb),raw.mark_work_order_pull_ready(text),raw.reserve_work_order_pull(text,text,text,text,jsonb,jsonb) TO paddock_app;
-- No direct table or column access for app/public; Pull is function-only for the app.
REVOKE ALL ON TABLE raw.work_orders,raw.work_order_dependencies,raw.work_order_attempts,raw.work_order_pull_slots,raw.work_order_capability_requirements FROM PUBLIC,paddock_app;
DO $$ DECLARE c record; BEGIN
 FOR c IN SELECT n.nspname,t.relname,a.attname FROM pg_catalog.pg_class t JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace JOIN pg_catalog.pg_attribute a ON a.attrelid=t.oid WHERE n.nspname='raw' AND t.relname IN ('work_orders','work_order_dependencies','work_order_attempts','work_order_pull_slots','work_order_capability_requirements') AND a.attnum>0 AND NOT a.attisdropped LOOP
  EXECUTE format('REVOKE ALL (%I) ON TABLE %I.%I FROM PUBLIC,paddock_app',c.attname,c.nspname,c.relname);
 END LOOP;
END $$;
COMMIT;

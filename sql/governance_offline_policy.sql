-- S04 additive policy persistence and online authorization. Source only: never apply implicitly.
BEGIN;
DO $$ BEGIN
 IF current_database()<>'paddock_test' THEN RAISE EXCEPTION 'refusing S04 policy migration outside paddock_test'; END IF;
 IF current_user<>'paddock_migrator' THEN RAISE EXCEPTION 'S04 policy migration must run as paddock_migrator'; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='paddock_migrator' AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls)
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='paddock_app' AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid=m.roleid JOIN pg_catalog.pg_roles u ON u.oid=m.member WHERE r.rolname IN ('paddock_app','paddock_migrator') OR u.rolname IN ('paddock_app','paddock_migrator')) THEN RAISE EXCEPTION 'isolated non-elevated app/migrator roles required'; END IF;
 IF to_regclass('raw.work_orders') IS NULL OR to_regclass('raw.work_order_attempts') IS NULL OR to_regclass('raw.work_order_leases') IS NULL THEN RAISE EXCEPTION 'S02/S03 WorkOrder, Attempt, and Lease tables required'; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n JOIN pg_catalog.pg_roles r ON r.oid=n.nspowner WHERE n.nspname='raw' AND r.rolname='paddock_migrator') THEN RAISE EXCEPTION 'paddock_migrator must own raw schema'; END IF;
 IF EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace JOIN pg_catalog.pg_roles r ON r.oid=c.relowner WHERE n.nspname='raw' AND c.relname IN ('work_orders','work_order_attempts','work_order_leases') AND r.rolname<>'paddock_migrator') THEN RAISE EXCEPTION 'migrator must own existing S02/S03 relations'; END IF;
 -- No extension fallback: PostgreSQL 17+ built-in SHA-256 is mandatory.
 IF pg_catalog.to_regprocedure('pg_catalog.sha256(bytea)') IS NULL THEN RAISE EXCEPTION 'built-in pg_catalog.sha256(bytea) is required'; END IF;
 IF current_setting('server_encoding')<>'UTF8' THEN RAISE EXCEPTION 'UTF8 server encoding is required for Unicode RFC 8785 policies'; END IF;
END $$;

-- JCS string quoting: controls use RFC 8785 short escapes where defined and
-- lowercase \u00xx otherwise; all other Unicode scalar values remain UTF-8.
CREATE FUNCTION raw.jcs_quote(p_value text) RETURNS text
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
DECLARE i integer; cp integer; ch text; result text:='"'; backslash text:=chr(92);
BEGIN
 FOR i IN 1..char_length(p_value) LOOP
  ch:=substr(p_value,i,1); cp:=ascii(ch);
  IF cp=34 THEN result:=result||backslash||'"';
  ELSIF cp=92 THEN result:=result||backslash||backslash;
  ELSIF cp=8 THEN result:=result||backslash||'b';
  ELSIF cp=9 THEN result:=result||backslash||'t';
  ELSIF cp=10 THEN result:=result||backslash||'n';
  ELSIF cp=12 THEN result:=result||backslash||'f';
  ELSIF cp=13 THEN result:=result||backslash||'r';
  ELSIF cp<32 THEN result:=result||backslash||'u00'||lpad(to_hex(cp),2,'0');
  ELSE result:=result||ch;
  END IF;
 END LOOP;
 RETURN result||'"';
END $$;

-- Sort key is big-endian UTF-16 code units, so bytea ordering matches RFC 8785.
CREATE FUNCTION raw.jcs_utf16_sort_key(p_value text) RETURNS bytea
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
DECLARE i integer; cp integer; result bytea:=''::bytea;
BEGIN
 FOR i IN 1..char_length(p_value) LOOP
  cp:=ascii(substr(p_value,i,1));
  IF cp>65535 THEN
   cp:=cp-65536;
   result:=result||decode(lpad(to_hex(55296+(cp/1024)),4,'0')||lpad(to_hex(56320+(cp%1024)),4,'0'),'hex');
  ELSE
   result:=result||decode(lpad(to_hex(cp),4,'0'),'hex');
  END IF;
 END LOOP;
 RETURN result;
END $$;

ALTER TABLE raw.work_orders
 ADD COLUMN offline_policy_mode text,
 ADD COLUMN checkpointability text,
 ADD COLUMN policy_canonical bytea,
 ADD COLUMN policy_digest text,
  ADD COLUMN external_action_allowlist text[],
  ADD COLUMN low_risk_actions text[] NOT NULL DEFAULT ARRAY[]::text[];
ALTER TABLE raw.work_orders ADD CONSTRAINT work_orders_offline_policy_fields_ck CHECK (
 (offline_policy_mode IS NULL AND checkpointability IS NULL AND policy_canonical IS NULL AND policy_digest IS NULL AND external_action_allowlist IS NULL AND low_risk_actions=ARRAY[]::text[])
 OR (offline_policy_mode IN ('ONLINE_REQUIRED','OFFLINE_COMPUTE') AND checkpointability IN ('CHECKPOINTABLE','NOT_CHECKPOINTABLE')
 AND octet_length(policy_digest)=64 AND policy_digest ~ '^[0-9a-f]{64}$' AND policy_canonical IS NOT NULL
 AND external_action_allowlist IS NOT NULL AND array_position(external_action_allowlist,NULL) IS NULL
  AND NOT ('*'=ANY(external_action_allowlist)) AND NOT ('%'=ANY(external_action_allowlist)))
);

CREATE FUNCTION raw.configure_work_order_offline_policy(text,text,text,text,bytea,text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE p_root ALIAS FOR $1; p_order ALIAS FOR $2; p_mode ALIAS FOR $3; p_checkpoint ALIAS FOR $4; p_canonical ALIAS FOR $5; p_digest ALIAS FOR $6;
  st text; configured text; supplied jsonb; action_list text[]; low_action_list text[]; expected_actions text; expected_low_actions text; expected_bytes bytea; actual_digest text;
BEGIN
 IF pg_catalog.to_regprocedure('pg_catalog.sha256(bytea)') IS NULL THEN RAISE EXCEPTION 'built-in pg_catalog.sha256(bytea) unavailable'; END IF;
 IF p_root IS NULL OR btrim(p_root)='' OR p_order IS NULL OR btrim(p_order)='' OR p_mode IS NULL OR p_mode NOT IN ('ONLINE_REQUIRED','OFFLINE_COMPUTE') OR p_checkpoint IS NULL OR p_checkpoint NOT IN ('CHECKPOINTABLE','NOT_CHECKPOINTABLE') OR p_canonical IS NULL OR p_digest IS NULL OR p_digest !~ '^[0-9a-f]{64}$' THEN RETURN NULL; END IF;
 -- Parse only to recover the candidate action strings. The caller's serialization
 -- is never trusted: exact fixed-schema RFC 8785 bytes are rebuilt below.
 BEGIN supplied:=convert_from(p_canonical,'UTF8')::jsonb;
 EXCEPTION WHEN OTHERS THEN RETURN NULL; END;
  IF jsonb_typeof(supplied)<>'object' OR (SELECT count(*) FROM jsonb_object_keys(supplied))<>4
  OR NOT (supplied ? 'checkpointability' AND supplied ? 'external_actions' AND supplied ? 'low_risk_actions' AND supplied ? 'mode')
 OR jsonb_typeof(supplied->'checkpointability')<>'string' OR supplied->>'checkpointability'<>p_checkpoint
 OR jsonb_typeof(supplied->'mode')<>'string' OR supplied->>'mode'<>p_mode
  OR jsonb_typeof(supplied->'external_actions')<>'array' OR jsonb_typeof(supplied->'low_risk_actions')<>'array' THEN RETURN NULL; END IF;
  IF EXISTS(SELECT 1 FROM jsonb_array_elements(supplied->'external_actions') e WHERE jsonb_typeof(e)<>'string') OR
     EXISTS(SELECT 1 FROM jsonb_array_elements(supplied->'low_risk_actions') e WHERE jsonb_typeof(e)<>'string') THEN RETURN NULL; END IF;
 SELECT COALESCE(array_agg(v ORDER BY raw.jcs_utf16_sort_key(v)),ARRAY[]::text[]) INTO action_list
 FROM (SELECT e#>>'{}' AS v FROM jsonb_array_elements(supplied->'external_actions') e) a;
  IF EXISTS(SELECT 1 FROM unnest(action_list) x WHERE convert_to(x,'UTF8')=convert_to('','UTF8')
    OR convert_to(x,'UTF8')<>convert_to(btrim(x),'UTF8')
    OR convert_to(x,'UTF8') IN (convert_to('*','UTF8'),convert_to('%','UTF8')))
  OR cardinality(action_list)<>(SELECT count(DISTINCT convert_to(x,'UTF8')) FROM unnest(action_list) x) THEN RETURN NULL; END IF;
  SELECT COALESCE(array_agg(v ORDER BY raw.jcs_utf16_sort_key(v)),ARRAY[]::text[]) INTO low_action_list
  FROM (SELECT e#>>'{}' AS v FROM jsonb_array_elements(supplied->'low_risk_actions') e) a;
  IF EXISTS(SELECT 1 FROM unnest(low_action_list) x WHERE convert_to(x,'UTF8')=convert_to('','UTF8')
    OR convert_to(x,'UTF8')<>convert_to(btrim(x),'UTF8')
    OR convert_to(x,'UTF8') IN (convert_to('*','UTF8'),convert_to('%','UTF8')))
  OR cardinality(low_action_list)<>(SELECT count(DISTINCT convert_to(x,'UTF8')) FROM unnest(low_action_list) x)
  OR EXISTS(SELECT 1 FROM unnest(low_action_list) x WHERE NOT EXISTS
    (SELECT 1 FROM unnest(action_list) y WHERE convert_to(x,'UTF8')=convert_to(y,'UTF8'))) THEN RETURN NULL; END IF;
  SELECT COALESCE(string_agg(raw.jcs_quote(v),',' ORDER BY raw.jcs_utf16_sort_key(v)),'') INTO expected_actions FROM unnest(action_list) v;
  SELECT COALESCE(string_agg(raw.jcs_quote(v),',' ORDER BY raw.jcs_utf16_sort_key(v)),'') INTO expected_low_actions FROM unnest(low_action_list) v;
  expected_bytes:=convert_to('{"checkpointability":'||raw.jcs_quote(p_checkpoint)||',"external_actions":['||expected_actions||'],"low_risk_actions":['||expected_low_actions||'],"mode":'||raw.jcs_quote(p_mode)||'}','UTF8');
 IF p_canonical<>expected_bytes THEN RETURN NULL; END IF;
 actual_digest:=encode(pg_catalog.sha256(expected_bytes),'hex');
 IF actual_digest<>p_digest THEN RETURN NULL; END IF;
 SELECT pull_state,offline_policy_mode INTO st,configured FROM raw.work_orders WHERE work_order_id=p_order AND root_id=p_root FOR UPDATE;
 IF NOT FOUND OR st<>'QUEUED' OR configured IS NOT NULL THEN RETURN NULL; END IF;
  UPDATE raw.work_orders SET offline_policy_mode=p_mode,checkpointability=p_checkpoint,policy_canonical=expected_bytes,policy_digest=actual_digest,external_action_allowlist=action_list,low_risk_actions=low_action_list
  WHERE work_order_id=p_order AND root_id=p_root AND pull_state='QUEUED' AND offline_policy_mode IS NULL;
 IF NOT FOUND THEN RETURN NULL; END IF;
 RETURN actual_digest;
END $$;

CREATE FUNCTION raw.authorize_work_order_external_action(text,text,text,text,text,bigint,text,text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE p_root ALIAS FOR $1; p_order ALIAS FOR $2; p_attempt ALIAS FOR $3; p_worker ALIAS FOR $4; p_session ALIAS FOR $5; p_epoch ALIAS FOR $6; p_digest ALIAS FOR $7; p_action ALIAS FOR $8; op_time timestamptz;
BEGIN
 IF p_root IS NULL OR p_order IS NULL OR p_attempt IS NULL OR p_worker IS NULL OR p_session IS NULL OR p_epoch IS NULL OR p_digest IS NULL OR p_action IS NULL OR p_action='' OR p_action<>btrim(p_action) OR p_action IN ('*','%') THEN RETURN false; END IF;
 op_time:=clock_timestamp();
 RETURN EXISTS (
  SELECT 1 FROM raw.work_orders w
  JOIN raw.work_order_attempts a ON a.work_order_id=w.work_order_id AND a.attempt_id=p_attempt
  JOIN raw.work_order_leases l ON l.work_order_id=w.work_order_id AND l.attempt_id=a.attempt_id
  WHERE w.root_id=p_root AND w.work_order_id=p_order AND w.pull_state='RUNNING'
   AND w.lease_epoch=p_epoch AND l.lease_epoch=p_epoch
   AND l.worker_id=p_worker AND l.session_id=p_session AND l.expires_at>op_time
   AND w.offline_policy_mode='ONLINE_REQUIRED' AND w.policy_digest=p_digest
    AND convert_to(p_action,'UTF8')=ANY(
      SELECT convert_to(allowed_action,'UTF8')
      FROM unnest(w.external_action_allowlist) AS actions(allowed_action)
    )
 );
END $$;

CREATE FUNCTION raw.read_work_order_authorization(text,text,text,text,text,bigint,text,text)
RETURNS TABLE(allowed boolean,risk_tier text,lease_remaining_us bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE p_root ALIAS FOR $1; p_order ALIAS FOR $2; p_attempt ALIAS FOR $3; p_worker ALIAS FOR $4; p_session ALIAS FOR $5; p_epoch ALIAS FOR $6; p_digest ALIAS FOR $7; p_action ALIAS FOR $8;
 op_time timestamptz; matched boolean:=false; action_allowed boolean:=false; is_low boolean:=false; remaining bigint:=0;
BEGIN
 op_time:=clock_timestamp();
 IF p_root IS NOT NULL AND p_order IS NOT NULL AND p_attempt IS NOT NULL AND p_worker IS NOT NULL AND p_session IS NOT NULL
    AND p_epoch IS NOT NULL AND p_digest IS NOT NULL AND p_action IS NOT NULL AND p_action<>'' AND p_action=btrim(p_action) AND p_action NOT IN ('*','%') THEN
  SELECT true,
    convert_to(p_action,'UTF8')=ANY(SELECT convert_to(x,'UTF8') FROM unnest(w.external_action_allowlist) AS ext(x)),
    convert_to(p_action,'UTF8')=ANY(SELECT convert_to(x,'UTF8') FROM unnest(w.low_risk_actions) AS low(x)),
    floor(extract(epoch FROM (l.expires_at-op_time))*1000000)::bigint
   INTO matched,action_allowed,is_low,remaining
   FROM raw.work_orders w
   JOIN raw.work_order_attempts a ON a.work_order_id=w.work_order_id AND a.attempt_id=p_attempt
   JOIN raw.work_order_leases l ON l.work_order_id=w.work_order_id AND l.attempt_id=a.attempt_id
   WHERE w.root_id=p_root AND w.work_order_id=p_order AND w.pull_state='RUNNING'
    AND w.lease_epoch=p_epoch AND l.lease_epoch=p_epoch
    AND l.worker_id=p_worker AND l.session_id=p_session AND l.expires_at>op_time
    AND w.offline_policy_mode='ONLINE_REQUIRED' AND w.policy_digest=p_digest;
 END IF;
 allowed:=COALESCE(matched AND action_allowed,false);
 risk_tier:=CASE WHEN allowed AND is_low THEN 'LOW' ELSE 'HIGH' END;
 IF NOT allowed THEN lease_remaining_us:=0;
 ELSE lease_remaining_us:=GREATEST(COALESCE(remaining,0),0); END IF;
 RETURN NEXT;
END $$;


ALTER FUNCTION raw.jcs_quote(text) OWNER TO paddock_migrator;
ALTER FUNCTION raw.jcs_utf16_sort_key(text) OWNER TO paddock_migrator;
ALTER FUNCTION raw.configure_work_order_offline_policy(text,text,text,text,bytea,text) OWNER TO paddock_migrator;
ALTER FUNCTION raw.authorize_work_order_external_action(text,text,text,text,text,bigint,text,text) OWNER TO paddock_migrator;
ALTER FUNCTION raw.read_work_order_authorization(text,text,text,text,text,bigint,text,text) OWNER TO paddock_migrator;
REVOKE ALL ON FUNCTION raw.jcs_quote(text),raw.jcs_utf16_sort_key(text) FROM PUBLIC,paddock_app;
REVOKE ALL ON FUNCTION raw.configure_work_order_offline_policy(text,text,text,text,bytea,text),raw.authorize_work_order_external_action(text,text,text,text,text,bigint,text,text),raw.read_work_order_authorization(text,text,text,text,text,bigint,text,text) FROM PUBLIC,paddock_app;
GRANT EXECUTE ON FUNCTION raw.configure_work_order_offline_policy(text,text,text,text,bytea,text),raw.authorize_work_order_external_action(text,text,text,text,text,bigint,text,text),raw.read_work_order_authorization(text,text,text,text,text,bigint,text,text) TO paddock_app;
REVOKE ALL ON TABLE raw.work_orders,raw.work_order_attempts,raw.work_order_leases FROM PUBLIC,paddock_app;
REVOKE ALL (offline_policy_mode,checkpointability,policy_canonical,policy_digest,external_action_allowlist,low_risk_actions) ON TABLE raw.work_orders FROM PUBLIC,paddock_app;
COMMENT ON COLUMN raw.work_orders.policy_canonical IS 'RFC 8785 JCS bytes; digest is SHA-256 of these exact bytes.';
COMMENT ON COLUMN raw.work_orders.external_action_allowlist IS 'Explicit Unicode Action-ID allowlist ordered by UTF-16 code units; wildcard or implicit default allow is forbidden.';
COMMIT;

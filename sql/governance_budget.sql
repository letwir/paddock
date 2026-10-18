-- M09 additive budget escrow ledger. Source-only migration; never applied implicitly.
BEGIN;
DO $$ BEGIN
 IF current_database()<>'paddock_test' THEN RAISE EXCEPTION 'refusing budget migration outside paddock_test'; END IF;
 IF current_user<>'paddock_migrator' THEN RAISE EXCEPTION 'budget migration must run as paddock_migrator'; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='paddock_migrator' AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls)
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='paddock_app' AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid=m.roleid JOIN pg_catalog.pg_roles u ON u.oid=m.member WHERE r.rolname IN ('paddock_app','paddock_migrator') OR u.rolname IN ('paddock_app','paddock_migrator')) THEN RAISE EXCEPTION 'isolated non-elevated roles required'; END IF;
 IF current_setting('server_encoding')<>'UTF8' THEN RAISE EXCEPTION 'budget migration requires UTF8 server_encoding'; END IF;
 IF to_regprocedure('pg_catalog.gen_random_uuid()') IS NULL THEN RAISE EXCEPTION 'gen_random_uuid() is required'; END IF;
 IF to_regclass('raw.roots') IS NULL THEN RAISE EXCEPTION 'required base table raw.roots is missing'; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n JOIN pg_catalog.pg_roles r ON r.oid=n.nspowner WHERE n.nspname='raw' AND r.rolname='paddock_migrator') THEN RAISE EXCEPTION 'paddock_migrator must own raw schema'; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace JOIN pg_catalog.pg_roles r ON r.oid=c.relowner WHERE n.nspname='raw' AND c.relname='roots' AND r.rolname='paddock_migrator') THEN RAISE EXCEPTION 'paddock_migrator must own raw.roots'; END IF;
END $$;
CREATE FUNCTION raw.budget_unit_valid(v text) RETURNS boolean LANGUAGE plpgsql IMMUTABLE STRICT SET search_path=pg_catalog AS $$ DECLARE ch text; cp integer; firstcp integer; lastcp integer; BEGIN IF v='' OR convert_to(v,'UTF8')<>convert_to(normalize(v,NFC),'UTF8') THEN RETURN false; END IF; firstcp:=ascii(substr(v,1,1)); lastcp:=ascii(substr(v,char_length(v),1)); IF firstcp IN (9,10,11,12,13,32,133,160,5760,8192,8193,8194,8195,8196,8197,8198,8199,8200,8201,8202,8232,8233,8239,8287,12288) OR lastcp IN (9,10,11,12,13,32,133,160,5760,8192,8193,8194,8195,8196,8197,8198,8199,8200,8201,8202,8232,8233,8239,8287,12288) THEN RETURN false; END IF; FOR ch IN SELECT regexp_split_to_table(v,'') LOOP cp:=ascii(ch); IF cp BETWEEN 0 AND 31 OR cp BETWEEN 127 AND 159 THEN RETURN false; END IF; END LOOP; RETURN true; END $$;
CREATE TABLE raw.budget_accounts (
 account_id text PRIMARY KEY CHECK(account_id<>'' AND account_id=btrim(account_id)),
 root_id text NOT NULL REFERENCES raw.roots(root_id), resource_kind text NOT NULL CHECK(resource_kind IN ('CURRENCY','TOKENS','COMPUTE')),
 unit_code text COLLATE "C" NOT NULL CHECK(raw.budget_unit_valid(unit_code)), parent_account_id text REFERENCES raw.budget_accounts(account_id),
 granted bigint NOT NULL CHECK(granted>=0), spent bigint NOT NULL DEFAULT 0 CHECK(spent>=0), reserved bigint NOT NULL DEFAULT 0 CHECK(reserved>=0), delegated bigint NOT NULL DEFAULT 0 CHECK(delegated>=0), terminal boolean NOT NULL DEFAULT false, settled boolean NOT NULL DEFAULT false, CHECK(NOT settled OR (terminal AND reserved=0 AND delegated=0)),
 UNIQUE(account_id,root_id,resource_kind,unit_code),
 FOREIGN KEY(parent_account_id,root_id,resource_kind,unit_code) REFERENCES raw.budget_accounts(account_id,root_id,resource_kind,unit_code),
 CHECK(spent<=granted AND reserved<=granted-spent AND delegated<=granted-spent-reserved)
);
CREATE INDEX raw_budget_accounts_parent_idx ON raw.budget_accounts(parent_account_id);
CREATE TABLE raw.budget_allocations (allocation_id uuid PRIMARY KEY DEFAULT gen_random_uuid(), parent_account_id text NOT NULL REFERENCES raw.budget_accounts(account_id), child_account_id text NOT NULL UNIQUE REFERENCES raw.budget_accounts(account_id), amount bigint NOT NULL CHECK(amount>=0), state text NOT NULL CHECK(state IN ('OPEN','SETTLED')), UNIQUE(allocation_id,parent_account_id,child_account_id));
ALTER TABLE raw.budget_accounts ADD COLUMN allocation_id uuid UNIQUE REFERENCES raw.budget_allocations(allocation_id);
CREATE UNIQUE INDEX budget_accounts_one_root_key_uidx ON raw.budget_accounts(root_id,resource_kind,unit_code) WHERE parent_account_id IS NULL;
CREATE TABLE raw.budget_operations (
 operation_id text PRIMARY KEY CHECK(operation_id<>'' AND operation_id=btrim(operation_id)), operation_kind text NOT NULL,
 request jsonb NOT NULL, result jsonb NOT NULL, recorded_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE raw.budget_journal (
 event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, operation_id text NOT NULL REFERENCES raw.budget_operations(operation_id), event_seq integer NOT NULL CHECK(event_seq>0),
 account_id text NOT NULL REFERENCES raw.budget_accounts(account_id), allocation_id uuid REFERENCES raw.budget_allocations(allocation_id), event_kind text NOT NULL,
 granted_delta bigint NOT NULL, spent_delta bigint NOT NULL, reserved_delta bigint NOT NULL, delegated_delta bigint NOT NULL,
 related_account_id text REFERENCES raw.budget_accounts(account_id), recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(operation_id,event_seq)
);
CREATE FUNCTION raw.reject_budget_journal_mutation() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$ BEGIN RAISE EXCEPTION 'budget journal is append-only'; END $$;
CREATE TRIGGER budget_journal_immutable BEFORE UPDATE OR DELETE ON raw.budget_journal FOR EACH ROW EXECUTE FUNCTION raw.reject_budget_journal_mutation();
CREATE OR REPLACE FUNCTION raw.budget_apply(text,text,jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE opid ALIAS FOR $1; kind ALIAS FOR $2; req ALIAS FOR $3; oldreq jsonb; oldresult jsonb; a raw.budget_accounts%ROWTYPE; p raw.budget_allocations%ROWTYPE; c raw.budget_accounts%ROWTYPE; aid text; childid text; rootid text; resource text; unit text; allocid uuid; amount bigint; actual bigint; reserve_amount bigint; child_open boolean; result jsonb;
BEGIN
 IF opid IS NULL OR opid='' OR opid<>btrim(opid) OR kind NOT IN ('GRANT','DELEGATE','RESERVE','SETTLE_RESERVATION','RELEASE','CLOSE','SETTLE_CHILD') OR req IS NULL OR jsonb_typeof(req)<>'object' THEN RAISE EXCEPTION 'invalid budget operation'; END IF;
 IF kind='GRANT' THEN IF session_user<>'paddock_migrator' THEN RAISE EXCEPTION 'root grants require paddock_migrator session'; END IF; END IF;
 -- Serialize globally by operation id; collision with a different canonical JSON request is denied.
 PERFORM pg_advisory_xact_lock(hashtextextended(opid,0));
 SELECT bo.request,bo.result INTO oldreq,oldresult FROM raw.budget_operations AS bo WHERE bo.operation_id=opid;
 IF FOUND THEN IF oldreq<>req OR (SELECT bo.operation_kind FROM raw.budget_operations AS bo WHERE bo.operation_id=opid)<>kind THEN RAISE EXCEPTION 'operation id replay conflict'; END IF; RETURN oldresult; END IF;
 aid:=req->>'account_id'; childid:=req->>'child_id'; rootid:=req->>'root_id'; resource:=req->>'resource_kind'; unit:=req->>'unit_code';
 IF aid IS NULL OR aid='' THEN RAISE EXCEPTION 'missing account_id'; END IF;
 IF kind='GRANT' THEN
  amount:=COALESCE((req->>'amount')::bigint,0);
  IF amount<0 OR rootid IS NULL OR resource IS NULL OR unit IS NULL THEN RAISE EXCEPTION 'invalid root grant'; END IF;
  INSERT INTO raw.budget_accounts(account_id,root_id,resource_kind,unit_code,granted) VALUES(aid,rootid,resource,unit,amount);
  result:=jsonb_build_object('account_id',aid,'granted',amount);
  INSERT INTO raw.budget_operations(operation_id,operation_kind,request,result) VALUES(opid,kind,req,result);
  INSERT INTO raw.budget_journal(operation_id,event_seq,account_id,event_kind,granted_delta,spent_delta,reserved_delta,delegated_delta) VALUES(opid,1,aid,'GRANT',amount,0,0,0); RETURN result;
 END IF;
 -- Lock account rows before checking counters. Parent/child operations use a stable ID order.
 SELECT * INTO a FROM raw.budget_accounts WHERE account_id=aid FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'budget account missing'; END IF;
 amount:=COALESCE((req->>'amount')::bigint,0); actual:=COALESCE((req->>'actual')::bigint,0); reserve_amount:=COALESCE((req->>'reserved')::bigint,0);
 IF amount<0 OR actual<0 OR reserve_amount<0 THEN RAISE EXCEPTION 'negative budget amount'; END IF;
 IF kind='DELEGATE' THEN
  IF a.terminal OR childid IS NULL OR childid='' OR (req->>'root_id') IS DISTINCT FROM a.root_id OR (req->>'resource_kind') IS DISTINCT FROM a.resource_kind OR req->>'unit_code' IS NULL OR NOT raw.budget_unit_valid(req->>'unit_code') OR convert_to(req->>'unit_code','UTF8') IS DISTINCT FROM convert_to(a.unit_code,'UTF8') OR amount>a.granted-a.spent-a.reserved-a.delegated THEN RAISE EXCEPTION 'delegation denied'; END IF;
  UPDATE raw.budget_accounts SET delegated=delegated+amount WHERE account_id=aid;
  INSERT INTO raw.budget_accounts(account_id,root_id,resource_kind,unit_code,parent_account_id,granted) VALUES(childid,a.root_id,a.resource_kind,a.unit_code,aid,amount);
  INSERT INTO raw.budget_allocations(parent_account_id,child_account_id,amount,state) VALUES(aid,childid,amount,'OPEN') RETURNING allocation_id INTO allocid;
  UPDATE raw.budget_accounts SET allocation_id=allocid WHERE account_id=childid;
  result:=jsonb_build_object('account_id',aid,'child_id',childid,'amount',amount,'allocation_id',allocid);
 ELSIF kind='RESERVE' THEN
  IF a.terminal OR amount>a.granted-a.spent-a.reserved-a.delegated THEN RAISE EXCEPTION 'reservation denied'; END IF;
  UPDATE raw.budget_accounts SET reserved=reserved+amount WHERE account_id=aid; result:=jsonb_build_object('account_id',aid,'reserved',amount);
 ELSIF kind IN ('SETTLE_RESERVATION','RELEASE') THEN
  IF reserve_amount>a.reserved OR actual>reserve_amount OR (kind='RELEASE' AND actual<>0) OR actual>9223372036854775807-a.spent THEN RAISE EXCEPTION 'reservation settlement denied'; END IF;
  UPDATE raw.budget_accounts SET reserved=reserved-reserve_amount,spent=spent+actual WHERE account_id=aid; result:=jsonb_build_object('account_id',aid,'released',reserve_amount,'spent',actual);
 ELSIF kind='CLOSE' THEN
  IF a.reserved<>0 OR a.delegated<>0 OR EXISTS(SELECT 1 FROM raw.budget_accounts WHERE parent_account_id=aid AND NOT terminal) THEN RAISE EXCEPTION 'account has open commitments or descendants'; END IF;
  UPDATE raw.budget_accounts SET terminal=true WHERE account_id=aid; result:=jsonb_build_object('account_id',aid,'terminal',true);
 ELSIF kind='SETTLE_CHILD' THEN
  childid:=req->>'child_id'; allocid:=(req->>'allocation_id')::uuid;
  SELECT * INTO p FROM raw.budget_allocations WHERE allocation_id=allocid FOR UPDATE;
  SELECT * INTO c FROM raw.budget_accounts WHERE account_id=childid FOR UPDATE;
  IF NOT FOUND OR p.allocation_id IS NULL OR p.state<>'OPEN' OR p.parent_account_id<>aid OR p.child_account_id<>childid OR p.amount<>c.granted OR c.allocation_id<>allocid OR c.settled OR c.parent_account_id IS NULL OR c.parent_account_id<>aid OR NOT c.terminal OR c.reserved<>0 OR c.delegated<>0 OR EXISTS(SELECT 1 FROM raw.budget_accounts WHERE parent_account_id=childid AND NOT terminal) THEN RAISE EXCEPTION 'child settlement denied'; END IF;
  IF p.amount>a.delegated OR c.spent>9223372036854775807-a.spent THEN RAISE EXCEPTION 'child settlement overflow'; END IF;
  UPDATE raw.budget_accounts SET delegated=delegated-p.amount,spent=spent+c.spent WHERE account_id=aid;
  UPDATE raw.budget_accounts SET settled=true WHERE account_id=childid;
  UPDATE raw.budget_allocations SET state='SETTLED' WHERE allocation_id=allocid AND state='OPEN';
  result:=jsonb_build_object('parent_id',aid,'child_id',childid,'allocation_id',allocid,'charged',c.spent,'refunded',p.amount-c.spent);
 ELSE RAISE EXCEPTION 'unsupported budget operation'; END IF;
 INSERT INTO raw.budget_operations(operation_id,operation_kind,request,result) VALUES(opid,kind,req,result);
  IF kind='DELEGATE' THEN
   INSERT INTO raw.budget_journal(operation_id,event_seq,account_id,allocation_id,event_kind,granted_delta,spent_delta,reserved_delta,delegated_delta,related_account_id)
    VALUES(opid,1,aid,allocid,kind,0,0,0,amount,childid),(opid,2,childid,allocid,kind,amount,0,0,0,aid);
  ELSIF kind='SETTLE_CHILD' THEN
   INSERT INTO raw.budget_journal(operation_id,event_seq,account_id,allocation_id,event_kind,granted_delta,spent_delta,reserved_delta,delegated_delta,related_account_id)
    VALUES(opid,1,aid,allocid,kind,0,c.spent,0,-p.amount,childid),(opid,2,childid,allocid,kind,0,0,0,0,aid);
  ELSE
   INSERT INTO raw.budget_journal(operation_id,event_seq,account_id,allocation_id,event_kind,granted_delta,spent_delta,reserved_delta,delegated_delta,related_account_id)
    VALUES(opid,1,aid,a.allocation_id,kind,0,CASE WHEN kind='SETTLE_RESERVATION' THEN actual ELSE 0 END,CASE WHEN kind IN ('SETTLE_RESERVATION','RELEASE') THEN -reserve_amount WHEN kind='RESERVE' THEN amount ELSE 0 END,0,childid);
  END IF;
 RETURN result;
END $$;
ALTER TABLE raw.budget_accounts OWNER TO paddock_migrator;
ALTER TABLE raw.budget_operations OWNER TO paddock_migrator;
ALTER TABLE raw.budget_allocations OWNER TO paddock_migrator;
ALTER TABLE raw.budget_journal OWNER TO paddock_migrator;
ALTER FUNCTION raw.reject_budget_journal_mutation() OWNER TO paddock_migrator;
ALTER FUNCTION raw.budget_apply(text,text,jsonb) OWNER TO paddock_migrator;
REVOKE ALL ON raw.budget_accounts,raw.budget_allocations,raw.budget_operations,raw.budget_journal FROM PUBLIC,paddock_app;
REVOKE ALL ON FUNCTION raw.budget_unit_valid(text) FROM PUBLIC,paddock_app;
REVOKE ALL ON FUNCTION raw.budget_apply(text,text,jsonb) FROM PUBLIC,paddock_app;
GRANT EXECUTE ON FUNCTION raw.budget_apply(text,text,jsonb) TO paddock_app;
COMMIT;

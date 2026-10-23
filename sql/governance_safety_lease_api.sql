-- M07-S04 source only: additive read-only authorization capability, not fencing.
\set ON_ERROR_STOP on
BEGIN;
DO $migration_guard$
DECLARE relation_name text;
BEGIN
    IF current_database() <> 'paddock_test' THEN
        RAISE EXCEPTION 'safety lease API requires paddock_test';
    END IF;
    IF current_user <> 'paddock_migrator' OR session_user <> 'paddock_migrator' THEN
        RAISE EXCEPTION 'safety lease API requires paddock_migrator';
    END IF;
    IF (SELECT count(*) FROM pg_catalog.pg_roles
        WHERE rolname IN ('paddock_app','paddock_migrator')
          AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb
          AND NOT rolreplication AND NOT rolbypassrls) <> 2
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m
          JOIN pg_catalog.pg_roles r ON r.oid=m.roleid
          JOIN pg_catalog.pg_roles u ON u.oid=m.member
          WHERE r.rolname IN ('paddock_app','paddock_migrator')
             OR u.rolname IN ('paddock_app','paddock_migrator')) THEN
        RAISE EXCEPTION 'isolated non-elevated roles without memberships required';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n
        JOIN pg_catalog.pg_roles r ON r.oid=n.nspowner
        WHERE n.nspname='raw' AND r.rolname='paddock_migrator') THEN
        RAISE EXCEPTION 'migrator must own raw';
    END IF;
    FOREACH relation_name IN ARRAY ARRAY['policy_scopes','roots','work_orders','work_order_attempts','work_order_leases'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class c
            JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
            JOIN pg_catalog.pg_roles r ON r.oid=c.relowner
            WHERE n.nspname='raw' AND c.relname=relation_name AND c.relkind='r'
              AND r.rolname='paddock_migrator') THEN
            RAISE EXCEPTION 'required migrator-owned safety/lease relation missing';
        END IF;
        IF pg_catalog.has_table_privilege('paddock_app', 'raw.' || relation_name, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
           OR pg_catalog.has_any_column_privilege('paddock_app', 'raw.' || relation_name, 'SELECT,INSERT,UPDATE,REFERENCES') THEN
            RAISE EXCEPTION 'app direct safety/lease privileges forbidden';
        END IF;
    END LOOP;
    IF pg_catalog.to_regprocedure('raw.safety_lock_scope(text)') IS NULL
       OR pg_catalog.to_regprocedure('raw.issue_work_order_lease(text,text,text,text,text,jsonb,jsonb,interval)') IS NULL THEN
        RAISE EXCEPTION 'existing safety and M08 lease APIs required';
    END IF;
    IF pg_catalog.to_regprocedure('raw.safety_validate_current_lease(text,text,text,text,text,text,bigint)') IS NOT NULL THEN
        RAISE EXCEPTION 'safety lease validator already exists';
    END IF;
END
$migration_guard$;

CREATE FUNCTION raw.safety_validate_current_lease(
    p_scope_id text, p_root_id text, p_work_order_id text, p_attempt_id text,
    p_worker_id text, p_session_id text, p_lease_epoch bigint
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog
AS $safety_validate_current_lease$
DECLARE
    work raw.work_orders%ROWTYPE;
    lease raw.work_order_leases%ROWTYPE;
BEGIN
    IF session_user <> 'paddock_app' THEN
        RAISE EXCEPTION 'safety lease validator requires session_user paddock_app'
            USING ERRCODE='42501';
    END IF;
    IF p_scope_id IS NULL OR p_scope_id='' OR p_scope_id<>btrim(p_scope_id)
       OR p_root_id IS NULL OR p_root_id='' OR p_root_id<>btrim(p_root_id)
       OR p_work_order_id IS NULL OR p_work_order_id='' OR p_work_order_id<>btrim(p_work_order_id)
       OR p_attempt_id IS NULL OR p_attempt_id='' OR p_attempt_id<>btrim(p_attempt_id)
       OR p_worker_id IS NULL OR p_worker_id='' OR p_worker_id<>btrim(p_worker_id)
       OR p_session_id IS NULL OR p_session_id='' OR p_session_id<>btrim(p_session_id)
       OR p_lease_epoch IS NULL OR p_lease_epoch<=0 THEN
        RETURN false;
    END IF;
    -- Match the lifecycle lock order. Hold both through this short gate transaction.
    SELECT w.* INTO work FROM raw.work_orders w
        WHERE w.work_order_id=p_work_order_id FOR SHARE;
    IF NOT FOUND OR work.root_id IS DISTINCT FROM p_root_id
       OR work.pull_state IS DISTINCT FROM 'RUNNING'
       OR work.lease_epoch IS DISTINCT FROM p_lease_epoch THEN
        RETURN false;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM raw.roots r JOIN raw.policy_scopes s ON s.scope_id=r.scope_id
        WHERE r.root_id=p_root_id AND s.scope_id=p_scope_id) THEN
        RETURN false;
    END IF;
    SELECT l.* INTO lease FROM raw.work_order_leases l
        WHERE l.work_order_id=p_work_order_id FOR SHARE;
    IF NOT FOUND OR ROW(lease.work_order_id,lease.attempt_id,lease.worker_id,lease.session_id,lease.lease_epoch)
        IS DISTINCT FROM ROW(p_work_order_id,p_attempt_id,p_worker_id,p_session_id,p_lease_epoch) THEN
        RETURN false;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM raw.work_order_attempts a
        WHERE a.work_order_id=p_work_order_id AND a.attempt_id=p_attempt_id) THEN
        RETURN false;
    END IF;
    -- A transaction-start timestamp would incorrectly allow a lease that expired
    -- while waiting on either lock. Errors propagate; they are never denials-as-success.
    RETURN lease.expires_at > clock_timestamp();
END
$safety_validate_current_lease$;
ALTER FUNCTION raw.safety_validate_current_lease(text,text,text,text,text,text,bigint) OWNER TO paddock_migrator;
REVOKE ALL ON FUNCTION raw.safety_validate_current_lease(text,text,text,text,text,text,bigint) FROM PUBLIC,paddock_app;
GRANT EXECUTE ON FUNCTION raw.safety_validate_current_lease(text,text,text,text,text,text,bigint) TO paddock_app;
DO $acl_guard$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_proc p
        CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
        WHERE p.oid='raw.safety_validate_current_lease(text,text,text,text,text,text,bigint)'::pg_catalog.regprocedure
          AND a.privilege_type='EXECUTE'
          AND a.grantee NOT IN (p.proowner,(SELECT oid FROM pg_catalog.pg_roles WHERE rolname='paddock_app'))) THEN
        RAISE EXCEPTION 'unexpected safety lease validator EXECUTE privilege';
    END IF;
END
$acl_guard$;
COMMIT;

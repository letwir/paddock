-- Narrow M08-S02 correction for an already-applied Pull migration.
-- Replaces only configure_work_order_capabilities on the isolated test DB.
-- Does not change role attributes, ownership, grants, data, or other objects.
BEGIN;
DO $guard$
DECLARE
    existing_definition text;
BEGIN
    IF current_database() <> 'paddock_test' THEN
        RAISE EXCEPTION 'refusing capability repair outside paddock_test';
    END IF;
    IF current_user <> 'paddock_migrator' THEN
        RAISE EXCEPTION 'capability repair must run as paddock_migrator';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
        WHERE rolname = 'paddock_migrator'
          AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb
          AND NOT rolreplication AND NOT rolbypassrls
    ) OR NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
        WHERE rolname = 'paddock_app'
          AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb
          AND NOT rolreplication AND NOT rolbypassrls
    ) THEN
        RAISE EXCEPTION 'expected non-elevated PADDOCK roles';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_auth_members m
        JOIN pg_catalog.pg_roles granted_role ON granted_role.oid = m.roleid
        JOIN pg_catalog.pg_roles member_role ON member_role.oid = m.member
        WHERE granted_role.rolname IN ('paddock_app', 'paddock_migrator')
           OR member_role.rolname IN ('paddock_app', 'paddock_migrator')
    ) THEN
        RAISE EXCEPTION 'PADDOCK roles must have no role memberships';
    END IF;
    IF (
        SELECT count(*)
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_catalog.pg_roles r ON r.oid = c.relowner
        WHERE n.nspname = 'raw'
          AND c.relname IN (
              'work_orders', 'work_order_dependencies', 'work_order_attempts',
              'work_order_pull_slots', 'work_order_capability_requirements'
          )
          AND r.rolname = 'paddock_migrator'
    ) <> 5 THEN
        RAISE EXCEPTION 'paddock_migrator must own all five Pull relations';
    END IF;
    IF to_regprocedure('raw.configure_work_order_capabilities(text,jsonb)') IS NULL THEN
        RAISE EXCEPTION 'expected M08-S02 capability configuration function is missing';
    END IF;
    IF (
        SELECT p.proowner <> (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = 'paddock_migrator')
            OR NOT p.prosecdef
            OR NOT COALESCE(p.proconfig @> ARRAY['search_path=pg_catalog'], false)
        FROM pg_catalog.pg_proc p
        WHERE p.oid = to_regprocedure('raw.configure_work_order_capabilities(text,jsonb)')
    ) THEN
        RAISE EXCEPTION 'capability function ownership or security attributes mismatch';
    END IF;
    SELECT pg_catalog.pg_get_functiondef(
        'raw.configure_work_order_capabilities(text,jsonb)'::regprocedure
    ) INTO existing_definition;
    IF position('jsonb_object_length' IN existing_definition) = 0 THEN
        RAISE EXCEPTION 'refusing unexpected capability function definition';
    END IF;
END
$guard$;

CREATE OR REPLACE FUNCTION raw.configure_work_order_capabilities(
    p_work_order_id text,
    p_requirements jsonb
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE
    changed integer;
    current_state text;
    is_configured boolean;
BEGIN
    SELECT pull_state, capability_requirements_configured
      INTO current_state, is_configured
      FROM raw.work_orders
     WHERE work_order_id = p_work_order_id
     FOR UPDATE;

    IF NOT FOUND OR current_state <> 'QUEUED' OR is_configured THEN
        RETURN false;
    END IF;
    IF p_requirements IS NULL OR jsonb_typeof(p_requirements) <> 'array' THEN
        RAISE EXCEPTION 'requirements must be a JSON array';
    END IF;
    IF EXISTS (
        SELECT 1
          FROM jsonb_array_elements(p_requirements) AS requirements(item)
         WHERE CASE
             WHEN jsonb_typeof(item) = 'object' THEN
                 (SELECT count(*) FROM jsonb_object_keys(item)) <> 2
                 OR jsonb_typeof(item->'name') <> 'string'
                 OR item->>'name' IS NULL
                 OR item->>'name' = ''
                 OR item->>'name' <> btrim(item->>'name')
                 OR jsonb_typeof(item->'value') <> 'string'
                 OR item->>'value' IS NULL
                 OR item->>'value' = ''
                 OR item->>'value' <> btrim(item->>'value')
             ELSE true
         END
    ) THEN
        RAISE EXCEPTION 'malformed capability requirement';
    END IF;
    IF (
        SELECT count(*) FROM jsonb_array_elements(p_requirements)
    ) <> (
        SELECT count(DISTINCT item->>'name')
          FROM jsonb_array_elements(p_requirements) AS requirements(item)
    ) THEN
        RAISE EXCEPTION 'duplicate capability requirement name';
    END IF;

    INSERT INTO raw.work_order_capability_requirements(
        work_order_id, capability_name, capability_value
    )
    SELECT p_work_order_id, item->>'name', item->>'value'
      FROM jsonb_array_elements(p_requirements) AS requirements(item);

    UPDATE raw.work_orders
       SET capability_requirements_configured = true
     WHERE work_order_id = p_work_order_id
       AND pull_state = 'QUEUED'
       AND NOT capability_requirements_configured;
    GET DIAGNOSTICS changed = ROW_COUNT;
    IF changed <> 1 THEN
        RAISE EXCEPTION 'WorkOrder capability policy changed concurrently';
    END IF;
    RETURN true;
END
$$;

COMMIT;

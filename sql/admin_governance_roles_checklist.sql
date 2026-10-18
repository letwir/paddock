-- PADDOCK M02-S03 operator checklist: least-privilege raw-schema roles.
--
-- This file is a READ-ONLY checklist. It does not create roles, change ownership,
-- grant/revoke privileges, or otherwise mutate the database. It is safe to run
-- for inventory only. Do not put passwords or DSNs in this file or its output.
--
-- Target requirement: dedicated database paddock_test; roles must be provisioned
-- out-of-band by an authorized administrator. Required exact roles:
--   paddock_app       : application login (expected LOGIN, non-owner, no elevated attrs)
--   paddock_migrator  : migration login (expected LOGIN, non-owner before transfer,
--                       no elevated attrs; no membership in either direction)
--
-- If anything is unexpected, STOP. Do not repair it by creating roles, granting
-- membership, or broadening privileges without a separately reviewed approval.
--
-- Admin actions to coordinate (not executed by this file):
-- 1. Confirm target identity and maintenance window; confirm this is a disposable,
--    dedicated paddock_test database, not llm-memory or production.
-- 2. Confirm both roles exist, intended login attributes are correct, elevated
--    role attributes are false, and neither role has memberships.
-- 3. Confirm raw contains exactly the expected 11 base tables and inspect other
--    objects, owners, ACLs, column grants, and default privileges.
-- 4. Confirm the applying principal can transfer raw/schema/table ownership. The
--    current jockey principal was observed not to own raw and not to be a member
--    of paddock_migrator; it cannot be assumed to perform the transfer.
-- 5. Review sql/governance_roles.sql. With explicit authorization for the exact
--    target and ownership/grant changes, an authorized current owner/superuser
--    runs (from a trusted local session; never paste credentials into shell text):
--
--   psql "$PADDOCK_DB_URL" -X -v ON_ERROR_STOP=1 \
--     -v app_role=paddock_app -v migration_role=paddock_migrator \
--     -f sql/governance_roles.sql
--
-- 6. Check the command's actual exit status. On any error, stop and inspect state;
--    do not blindly rerun. The apply script is transactional but its effects must
--    be confirmed by readback.
-- 7. Run the read-only verification section below. Require raw schema and all 11
--    base tables owned by paddock_migrator; app has only USAGE plus SELECT/INSERT
--    on policy_bundles and domain_events, no effective UPDATE/DELETE, and PUBLIC
--    has no raw schema/table access. Re-check role flags and memberships.
-- 8. Record non-secret receipt evidence: database name/version, acting role name,
--    apply exit code, catalog checks and hashes. Never record a DSN/password.
--
-- No live apply is authorized by this checklist. The apply step requires explicit
-- current-task approval for the database target and privilege/ownership changes.

\set ON_ERROR_STOP on
\echo 'READ-ONLY inventory only; expected target is paddock_test'

SELECT current_database() AS database_name,
       current_user AS session_role,
       current_setting('server_version') AS server_version,
       CASE WHEN current_database() = 'paddock_test' THEN 'TARGET_OK' ELSE 'STOP_WRONG_DATABASE' END AS target_check;

SELECT r.rolname,
       r.rolcanlogin,
       r.rolsuper,
       r.rolcreaterole,
       r.rolcreatedb,
       r.rolreplication,
       r.rolbypassrls
FROM pg_roles AS r
WHERE r.rolname IN ('paddock_app', 'paddock_migrator')
ORDER BY r.rolname;

SELECT granted.rolname AS granted_role,
       member.rolname AS member_role,
       m.admin_option
FROM pg_auth_members AS m
JOIN pg_roles AS granted ON granted.oid = m.roleid
JOIN pg_roles AS member ON member.oid = m.member
WHERE granted.rolname IN ('paddock_app', 'paddock_migrator')
   OR member.rolname IN ('paddock_app', 'paddock_migrator')
ORDER BY granted.rolname, member.rolname;

SELECT n.nspname AS schema_name, owner.rolname AS schema_owner
FROM pg_namespace AS n
JOIN pg_roles AS owner ON owner.oid = n.nspowner
WHERE n.nspname = 'raw';

SELECT c.relname AS relation_name,
       CASE c.relkind
         WHEN 'r' THEN 'table'
         WHEN 'p' THEN 'partitioned_table'
         WHEN 'v' THEN 'view'
         WHEN 'm' THEN 'materialized_view'
         WHEN 'S' THEN 'sequence'
         WHEN 'f' THEN 'foreign_table'
         ELSE c.relkind::text
       END AS relation_kind,
       owner.rolname AS relation_owner
FROM pg_class AS c
JOIN pg_namespace AS n ON n.oid = c.relnamespace
JOIN pg_roles AS owner ON owner.oid = c.relowner
WHERE n.nspname = 'raw'
  AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
ORDER BY c.relname;

SELECT grantee,
       table_schema,
       table_name,
       privilege_type,
       is_grantable
FROM information_schema.role_table_grants
WHERE table_schema = 'raw'
  AND grantee IN ('PUBLIC', 'paddock_app', 'paddock_migrator')
ORDER BY grantee, table_name, privilege_type;

SELECT table_name,
       column_name,
       grantee,
       privilege_type,
       is_grantable
FROM information_schema.column_privileges
WHERE table_schema = 'raw'
  AND grantee IN ('PUBLIC', 'paddock_app', 'paddock_migrator')
ORDER BY grantee, table_name, column_name, privilege_type;

SELECT n.nspname AS schema_name,
       r.rolname AS grantee,
       has_schema_privilege(r.oid, n.oid, 'USAGE') AS has_usage,
       has_schema_privilege(r.oid, n.oid, 'CREATE') AS has_create
FROM pg_namespace AS n
CROSS JOIN pg_roles AS r
WHERE n.nspname = 'raw'
  AND r.rolname IN ('PUBLIC', 'paddock_app', 'paddock_migrator')
ORDER BY r.rolname;

-- This script intentionally contains no CREATE/ALTER/GRANT/REVOKE/DROP statement.

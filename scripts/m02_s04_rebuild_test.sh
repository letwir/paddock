#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/m02_s04_rebuild_test.sh [--help | --run]

Default and --help are side-effect free. --run creates and destroys a private,
local-only PostgreSQL cluster under .build and rebuilds its paddock_test DB.
Running --run requires separate, explicit task authorization.
USAGE
}

fail() { printf 'FAIL %s\n' "$1" >&2; exit 1; }

case "${1-}" in
  --help) [[ $# -eq 1 ]] || fail 'unexpected arguments'; usage; exit 0 ;;
  --run) [[ $# -eq 1 ]] || fail 'unexpected arguments' ;;
  '') usage; exit 0 ;;
  *) fail 'unknown option (use --help)' ;;
esac

# Do not allow inherited project database configuration or password auth into
# any child process. This runner uses only the disposable cluster below.
unset PADDOCK_DB_URL PADDOCK_APP_DB_URL PADDOCK_ADMIN_DSN \
  PGHOST PGHOSTADDR PGPORT PGUSER PGDATABASE PGPASSWORD PGPASSFILE \
  PGOPTIONS PGAPPNAME PGCONNECT_TIMEOUT PGSSLMODE PGSSLROOTCERT \
  PGSSLCERT PGSSLKEY PGCHANNELBINDING PGSERVICE PGSERVICEFILE

if [[ $(id -u) -eq 0 ]]; then
  fail 'refusing to run as OS root; initdb does not permit root'
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd -P)
build_dir="$repo_root/.build"
[[ ! -L "$build_dir" ]] || fail '.build must not be a symlink'
if [[ -e "$build_dir" ]]; then
  [[ -d "$build_dir" ]] || fail '.build exists but is not a directory'
  build_real=$(CDPATH= cd -- "$build_dir" && pwd -P)
  [[ "$build_real" == "$repo_root/.build" ]] || fail '.build resolves outside repository'
else
  mkdir -- "$build_dir"
  build_real=$(CDPATH= cd -- "$build_dir" && pwd -P)
  [[ "$build_real" == "$repo_root/.build" ]] || fail '.build resolves outside repository'
fi
work_dir=$(mktemp -d "$build_dir/m02-s04.XXXXXXXXXX") || fail 'could not allocate private work directory'
work_real=''
pgdata="$work_dir/pgdata"
socket_dir="$work_dir/socket"
port=55439

cleanup() {
  local rc=$?
  trap - EXIT
  local status_rc=3 stop_rc=0 confirm_rc=4 safe_to_remove=1
  if [[ -d "$pgdata" ]]; then
    status_rc=0
    pg_ctl -D "$pgdata" status >/dev/null 2>&1 || status_rc=$?
    if (( status_rc == 0 )); then
      pg_ctl -D "$pgdata" -m fast -w stop >/dev/null 2>&1 || stop_rc=$?
      if (( stop_rc != 0 )); then
        printf 'FAIL cleanup-stop (Exit Code: %s); preserving temporary cluster directory\n' "$stop_rc" >&2
        safe_to_remove=0; rc=1
      else
        confirm_rc=0
        pg_ctl -D "$pgdata" status >/dev/null 2>&1 || confirm_rc=$?
        if (( confirm_rc != 3 )); then
          printf 'FAIL cleanup-confirm-stopped (Exit Code: %s); preserving temporary cluster directory\n' "$confirm_rc" >&2
          safe_to_remove=0; rc=1
        fi
      fi
    elif (( status_rc != 3 )); then
      printf 'FAIL cleanup-status (Exit Code: %s); preserving temporary cluster directory\n' "$status_rc" >&2
      safe_to_remove=0; rc=1
    fi
  fi
  if (( safe_to_remove )) && [[ -n "${work_dir:-}" && -d "$work_dir" && "$work_dir" == "$build_dir"/m02-s04.* && -n "${work_real:-}" && "$(CDPATH= cd -- "$work_dir" && pwd -P)" == "$work_real" ]]; then
    if ! rm -rf -- "$work_dir"; then
      printf 'FAIL cleanup-remove (Exit Code: nonzero)\n' >&2
      rc=1
    fi
  elif (( ! safe_to_remove )); then
    printf 'Preserved work directory: %s\n' "$work_real" >&2
  fi
  exit "$rc"
}
trap cleanup EXIT
case "$work_dir" in "$build_dir"/m02-s04.*) ;; *) fail 'temporary path escaped .build' ;; esac
work_real=$(CDPATH= cd -- "$work_dir" && pwd -P)
case "$work_real" in "$build_real"/m02-s04.*) ;; *) fail 'temporary directory resolves outside .build' ;; esac

mkdir -- "$socket_dir"

for tool in initdb pg_ctl psql; do command -v "$tool" >/dev/null 2>&1 || fail "required tool missing: $tool"; done

step() {
  local name=$1; shift
  local rc=0
  local output="$work_dir/step-output"
  "$@" >"$output" 2>&1 || rc=$?
  if [[ -s "$output" ]]; then
    cat -- "$output"
  fi
  printf '%s Exit Code: %s\n' "$name" "$rc"
  (( rc == 0 )) || fail "$name"
}

step initdb initdb -D "$pgdata" --auth-local=trust --auth-host=reject --no-instructions
step pg_ctl-start pg_ctl -D "$pgdata" -l "$work_dir/postgres.log" -o "-F -h '' -k '$socket_dir' -p $port" -w start
# Bootstrap superuser name follows initdb's invoking OS account; never printed.
bootstrap_user=$(id -un)
step create-private-database psql -X -q -v ON_ERROR_STOP=1 -v VERBOSITY=verbose -h "$socket_dir" -p "$port" -U "$bootstrap_user" -d postgres -c 'CREATE DATABASE paddock_test'
step provision-private-roles psql -X -q -v ON_ERROR_STOP=1 -v VERBOSITY=verbose -h "$socket_dir" -p "$port" -U "$bootstrap_user" -d postgres -c "CREATE ROLE paddock_app LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS; CREATE ROLE paddock_migrator LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS"

# psql runner accepts no arbitrary user-provided arguments.
apply_sql() {
  local label=$1 dbrole=$2 file=$3; shift 3
  case "$dbrole" in
    bootstrap-admin) dbrole=$bootstrap_user ;;
    paddock_migrator) ;;
    *) fail "unsupported database role for $label" ;;
  esac
  step "$label" psql -X -q -v ON_ERROR_STOP=1 -v VERBOSITY=verbose -h "$socket_dir" -p "$port" -U "$dbrole" -d paddock_test "$@" --file="$repo_root/sql/$file"
}
assert_sql() {
  local label=$1 query=$2
  step "$label" psql -X -q -v ON_ERROR_STOP=1 -v VERBOSITY=verbose -h "$socket_dir" -p "$port" -U "$bootstrap_user" -d paddock_test -c "$query"
}

apply_sql up-init bootstrap-admin init.sql
apply_sql up-governance-constraints bootstrap-admin governance_constraints.sql
apply_sql up-governance-roles bootstrap-admin governance_roles.sql -v app_role=paddock_app -v migration_role=paddock_migrator
apply_sql up-safety-constraints paddock_migrator governance_safety_constraints.sql

base_tables="'policy_bundles','policy_scopes','roots','policy_rollouts','rollout_targets','governance_approvals','command_receipts','domain_events','event_outbox','event_inbox','security_generation'"
assert_rebuild_state() {
  local label=$1
  local query
  query="DO \$\$
  DECLARE app_oid oid; mig_oid oid;
  BEGIN
    SELECT oid INTO app_oid FROM pg_roles WHERE rolname='paddock_app';
    SELECT oid INTO mig_oid FROM pg_roles WHERE rolname='paddock_migrator';
    IF app_oid IS NULL OR mig_oid IS NULL THEN RAISE EXCEPTION 'required roles missing'; END IF;
    IF (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='raw' AND c.relkind IN ('r','p')) <> 11
       OR (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
           WHERE n.nspname='raw' AND c.relkind IN ('r','p') AND c.relname IN ($base_tables)) <> 11
    THEN RAISE EXCEPTION 'raw must contain exactly the 11 base tables'; END IF;
    IF (SELECT nspowner FROM pg_namespace WHERE nspname='raw') <> mig_oid
       OR (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
           WHERE n.nspname='raw' AND c.relkind IN ('r','p') AND c.relname IN ($base_tables) AND c.relowner=mig_oid) <> 11
    THEN RAISE EXCEPTION 'raw ownership'; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_index i JOIN pg_class x ON x.oid=i.indexrelid
                   WHERE i.indrelid='raw.policy_rollouts'::regclass AND x.relname='policy_rollouts_one_active_per_scope_uidx'
                     AND i.indisunique AND i.indisvalid AND i.indisready)
       OR NOT EXISTS (SELECT 1 FROM pg_constraint c
                      WHERE c.conrelid='raw.policy_scopes'::regclass
                        AND c.conname='policy_scopes_frozen_requires_live_rollout_ck' AND c.contype='c' AND c.convalidated)
       OR (SELECT count(*) FROM pg_trigger t
           WHERE t.tgrelid IN ('raw.policy_scopes'::regclass,'raw.policy_rollouts'::regclass)
             AND ((t.tgrelid='raw.policy_scopes'::regclass AND t.tgname='policy_scopes_frozen_rollback_ct')
               OR (t.tgrelid='raw.policy_rollouts'::regclass AND t.tgname='policy_rollouts_frozen_rollback_ct'))
             AND NOT t.tgisinternal AND t.tgenabled='O') <> 2
    THEN RAISE EXCEPTION 'M02 unique index, S06 constraint, or triggers missing'; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE oid=app_oid AND rolcanlogin)
       OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE oid=mig_oid AND rolcanlogin)
       OR EXISTS (SELECT 1 FROM pg_roles r WHERE r.oid IN (app_oid,mig_oid)
               AND (r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls))
       OR EXISTS (SELECT 1 FROM pg_auth_members m
                  WHERE m.member IN (app_oid,mig_oid) OR m.roleid IN (app_oid,mig_oid))
    THEN RAISE EXCEPTION 'role elevation or membership'; END IF;
    IF NOT has_schema_privilege(mig_oid,'raw','CREATE')
    THEN RAISE EXCEPTION 'migrator lacks raw CREATE'; END IF;
    IF EXISTS (SELECT 1 FROM pg_namespace n
               CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl,acldefault('n',n.nspowner))) a
               WHERE n.nspname='raw' AND a.grantee=0)
    THEN RAISE EXCEPTION 'PUBLIC has raw schema ACL'; END IF;
    IF NOT has_schema_privilege(app_oid,'raw','USAGE') OR has_schema_privilege(app_oid,'raw','CREATE')
    THEN RAISE EXCEPTION 'application schema privileges'; END IF;
    IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
               WHERE n.nspname='raw' AND c.relkind IN ('r','p') AND
                 (has_table_privilege(app_oid,c.oid,'UPDATE') OR has_table_privilege(app_oid,c.oid,'DELETE')
                  OR has_table_privilege(app_oid,c.oid,'TRUNCATE') OR has_table_privilege(app_oid,c.oid,'REFERENCES')
                  OR has_table_privilege(app_oid,c.oid,'TRIGGER')
                  OR (c.relname NOT IN ('policy_bundles','domain_events') AND
                      (has_table_privilege(app_oid,c.oid,'SELECT') OR has_table_privilege(app_oid,c.oid,'INSERT')))))
    THEN RAISE EXCEPTION 'application has forbidden effective table privileges'; END IF;
    IF NOT has_table_privilege(app_oid,'raw.policy_bundles','SELECT')
       OR NOT has_table_privilege(app_oid,'raw.policy_bundles','INSERT')
       OR NOT has_table_privilege(app_oid,'raw.domain_events','SELECT')
       OR NOT has_table_privilege(app_oid,'raw.domain_events','INSERT')
    THEN RAISE EXCEPTION 'application missing expected SELECT/INSERT privileges'; END IF;
    IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
               CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a
               WHERE n.nspname='raw' AND c.relkind IN ('r','p') AND a.grantee IN (0,app_oid)
                 AND NOT (a.grantee=app_oid AND c.relname IN ('policy_bundles','domain_events')
                          AND a.privilege_type IN ('SELECT','INSERT') AND NOT a.is_grantable))
    THEN RAISE EXCEPTION 'PUBLIC or app has extra relation ACL'; END IF;
    IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
               JOIN pg_attribute col ON col.attrelid=c.oid AND col.attnum>0 AND NOT col.attisdropped
               CROSS JOIN LATERAL aclexplode(col.attacl) a
               WHERE n.nspname='raw' AND c.relkind IN ('r','p') AND a.grantee IN (0,app_oid))
    THEN RAISE EXCEPTION 'PUBLIC or app has column ACL'; END IF;
  END \$\$"
  assert_sql "$label" "$query"
}
assert_rebuild_state first-up-assertions

apply_sql down-safety paddock_migrator governance_safety_constraints_down.sql
apply_sql down-base paddock_migrator down.sql
assert_sql down-assertions "DO \$\$ BEGIN
  IF (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='raw' AND c.relkind IN ('r','p')) <> 0
  THEN RAISE EXCEPTION 'raw base tables remain'; END IF;
  IF to_regclass('raw.policy_rollouts_one_active_per_scope_uidx') IS NOT NULL
     OR EXISTS (SELECT 1 FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid
                JOIN pg_namespace n ON n.oid=t.relnamespace
                WHERE n.nspname='raw' AND c.conname='policy_scopes_frozen_requires_live_rollout_ck')
     OR EXISTS (SELECT 1 FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
                JOIN pg_namespace n ON n.oid=c.relnamespace
                WHERE n.nspname='raw' AND t.tgname IN ('policy_scopes_frozen_rollback_ct','policy_rollouts_frozen_rollback_ct')
                  AND NOT t.tgisinternal)
     OR to_regprocedure('raw.enforce_frozen_scope_rollback()') IS NOT NULL
     OR to_regprocedure('raw.prevent_frozen_rollout_leaving_rollback()') IS NOT NULL
  THEN RAISE EXCEPTION 'M02 named index, S06 constraint, trigger, or function remains'; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname='raw')
     OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='paddock_app')
     OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='paddock_migrator')
  THEN RAISE EXCEPTION 'persistent schema/roles missing'; END IF;
END \$\$"

apply_sql reup-init bootstrap-admin init.sql
apply_sql reup-governance-constraints bootstrap-admin governance_constraints.sql
apply_sql reup-governance-roles bootstrap-admin governance_roles.sql -v app_role=paddock_app -v migration_role=paddock_migrator
apply_sql reup-safety-constraints paddock_migrator governance_safety_constraints.sql
assert_rebuild_state reup-assertions
printf 'PASS m02-s04-rebuild (Exit Code: 0)\n'

#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/init_test_db.sh --check
       scripts/init_test_db.sh --apply
       scripts/init_test_db.sh --help

Initialize the dedicated PADDOCK test database from sql/init.sql.

This script never drops or recreates a database. It requires the database
name to be exactly "paddock_test". Set PADDOCK_DB_URL in the environment.
--check performs read-only checks; --apply also initializes an empty raw schema.

Options:
  --check   Verify database identity, version, and raw relation count only.
  --apply   Connect to the configured test database and apply sql/init.sql.
  --help    Show this help without checking configuration or connecting.
USAGE
}

fail() {
  printf 'init_test_db.sh: %s\n' "$1" >&2
  exit 1
}

action=${1-}
case "$action" in
  --help)
    [[ $# -eq 1 ]] || fail 'unexpected extra arguments (use --help)'
    usage
    exit 0
    ;;
  --check)
    [[ $# -eq 1 ]] || fail 'unexpected extra arguments (use --help)'
    ;;
  --apply)
    [[ $# -eq 1 ]] || fail 'unexpected extra arguments (use --help)'
    ;;
  '')
    fail 'no action taken; pass --check for read-only verification or --apply to initialize, or --help for usage'
    ;;
  *)
    fail "unknown option: $1 (use --help)"
    ;;
esac

# No database-dependent work may occur until the explicit --apply branch above.
[[ -n "${PADDOCK_DB_URL:-}" ]] || fail 'PADDOCK_DB_URL is not set'
command -v psql >/dev/null 2>&1 || fail 'psql was not found in PATH'

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
sql_file="$script_dir/../sql/init.sql"
[[ -r "$sql_file" ]] || fail 'sql/init.sql is missing or unreadable'

# Keep the DSN out of script output and suppress raw connection diagnostics.
psql_test_db() {
  psql "$PADDOCK_DB_URL" --no-psqlrc "$@"
}

# Keep connection diagnostics internal; failures are reported without raw output
# because client diagnostics can include connection metadata.
if ! db_info=$(psql_test_db --quiet --tuples-only --no-align \
  --set=ON_ERROR_STOP=1 \
  --command="SELECT current_database() || E'\t' || current_setting('server_version');" \
  2>/dev/null); then
  fail 'could not verify the configured database (psql connection/query failed)'
fi
[[ "$db_info" == *$'\t'* ]] || fail 'refusing: database identity/version response was incomplete'
IFS=$'\t' read -r db_name server_version <<< "$db_info"
[[ "$db_name" == 'paddock_test' ]] || fail 'refusing: connected database is not exactly paddock_test'
server_version=${server_version%% *}
[[ "$server_version" =~ ^[0-9]+([.][0-9]+)*$ ]] || fail 'refusing: server version response was invalid'

if ! raw_relation_count=$(psql_test_db --quiet --tuples-only --no-align \
  --set=ON_ERROR_STOP=1 \
  --command="SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'raw';" \
  2>/dev/null); then
  fail 'could not inspect schema raw (psql query failed)'
fi
[[ "$raw_relation_count" =~ ^[0-9]+$ ]] || fail 'refusing: schema raw relation count was invalid'

if [[ "$action" == '--check' ]]; then
  printf 'Database=paddock_test PostgreSQL=%s raw_relations=%s (read-only; no DDL)\n' \
    "$server_version" "$raw_relation_count"
  exit 0
fi

[[ "$raw_relation_count" == '0' ]] || fail 'refusing: schema raw already contains relations'

printf 'Initializing paddock_test (PostgreSQL %s) from sql/init.sql...\n' "$server_version"
if ! psql_test_db --set=ON_ERROR_STOP=1 --file="$sql_file"; then
  fail 'sql/init.sql failed; database state was not automatically dropped or reset'
fi
printf 'Initialization completed.\n'

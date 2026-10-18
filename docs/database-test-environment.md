# PADDOCK test database setup

## Record DB-00 — Isolation and secret handling

- **DB-00.1 · Dedicated identity:** All PADDOCK local/integration database tests use the exact database name `paddock_test`.
- **DB-00.2 · Isolation:** The `raw` schema/database is separate from `llm-memory` and every production database. A PostgreSQL server may be shared; the database must not be shared.
- **DB-00.3 · Secrets:** Never store or print a DSN, password, or full connection URL in the repository, logs, or receipts.
- **DB-00.4 · Target:** Before create/init, confirm server and database identity out of band. Neither variable may target `llm-memory` or production.
- **DB-00.5 · Process-list warning:** `psql` receives its URL as a connection argument. Run only in a trusted local session; do not capture or share process listings.

## Record DB-01 — Operator-injected connection variables

| Variable | Role | Handling |
|---|---|---|
| `PADDOCK_ADMIN_DSN` | Maintenance database connection, used only for intentional creation via `sql/create_database.sql`. | Operator-injected; never log/store its value. |
| `PADDOCK_DB_URL` | Privileged connection to `paddock_test` for the initializer and isolated integration-test fixture setup, readback, and cleanup. It is not the application connection. | Operator-injected outside the repository; never echo, print, or log its value. |
| `PADDOCK_APP_DB_URL` | Operator-injected application connection. It must log in as and have effective `current_user` `paddock_app` in `paddock_test`; used only for application entrypoint checks such as Pull readiness, capability configuration, and reservation. | Injected outside the repository; never echo, print, or log its value. |

The privileged fixture connection can perform fixture SQL and read back persisted test results. The app connection is intentionally limited to the expected application functions and has no direct WorkOrder-table access; the integration test checks those grants using the privileged connection's catalog view. The `paddock_app` credential is a trusted-Coordinator-only credential and must never be given to Workers or external callers. Coordinator Authority/Trust/Budget/Permit gates run before the database function call; those gates are not validated or enforced by the database function itself. These variable descriptions do not indicate that either value is configured, and this document grants no database access or permission to run tests.

## Flow DB-02 — Create database (only if absent)

**Guard:** `paddock_test` must not exist. The script rejects names outside `paddock_*` and fails if the requested database already exists. Creation is an intentional operator action from a maintenance connection.

Exact command:

```sh
psql "$PADDOCK_ADMIN_DSN" -X -v ON_ERROR_STOP=1 \
  -v dbname='paddock_test' -f sql/create_database.sql
```

## Flow DB-03 — Read-only check

Exact command:

```sh
scripts/init_test_db.sh --check
```

Confirms database name/version and reports the `raw` relation count.

- **Compatibility:** PostgreSQL 18.6 is an environment observation; its source sentence has no specified date/context. It is not a general PostgreSQL compatibility guarantee.
- **Historical snapshot (date/context unspecified):** The observed test environment was `paddock_test`, PostgreSQL 18.6, with all 11 expected base tables present. This read-only observation does not establish which command created them.
- **Count distinction:** 11 is the expected base-table count; `--check` reports the `raw` relation count. These are different units and observations.

## Flow DB-04 — Initialize an empty database

**Preconditions / guards:** `raw` must be empty; review the target and explicitly request initialization. The runner requires `--apply`, verifies the connected database is exactly `paddock_test`, reports server version, and refuses any existing `raw` relations.

Exact command:

```sh
scripts/init_test_db.sh --apply
```

On approval, the runner invokes `sql/init.sql` with `ON_ERROR_STOP`. The SQL independently checks the database name and wraps schema setup in a transaction. The runner never drops or recreates a database.

## Record DB-05 — Existing/failed initialization and reset

- `sql/init.sql` is intentionally non-idempotent for existing tables. If any `raw` relation exists, the runner stops before DDL.
- **No bypass:** Do not run the SQL directly to work around the guard.
- No automated database disposal or rebuild command is provided.
- Reset requires a separately reviewed, exact operator action and explicit authorization. Until then, preserve the database; migration/rebuild verification remains blocked. No reset authorization is implied here.

## Record DB-06 — Verification evidence and limits

- Shell-level `--apply` tests using fake `psql` do **not** prove that SQL applies successfully to a clean database.
- **Historical task-relative evidence (original wording retained):** “No DDL was run in this task.” This is not a claim about the current/live database; the source's environment-observation date/context is unknown.
- The source also records a snapshot observation that database identity, PostgreSQL 18.6, and all 11 expected table names were verified through `--check` and a separate read-only query. The current database was described there as already initialized, so guarded apply refused it; a fresh disposable DB is still needed to verify a clean `sql/init.sql` run. These are historical/source statements, not a fresh query or current-state assertion.
- No automated drop/rebuild path is provided or authorized.

-- Create the dedicated PADDOCK database on the PostgreSQL server.
-- Connect to a maintenance database (usually `postgres`) as an operator with
-- CREATEDB privilege, NOT to the llm-memory database and not to the target DB.
-- PostgreSQL forbids CREATE DATABASE inside a transaction; do not wrap this file
-- in BEGIN/COMMIT and run psql with autocommit enabled.
--
-- Usage:
--   psql "$PADDOCK_ADMIN_DSN" -v ON_ERROR_STOP=1 -v dbname='paddock_test' \
--     -f sql/create_database.sql
-- Then initialize only an empty raw schema with the guarded runner:
--   scripts/init_test_db.sh --apply (requires PADDOCK_DB_URL)
-- Both DSNs are operator-injected secret values; never store or print them.
-- Review the target name and server before execution. This script intentionally
-- fails if the DB already exists; it never drops or overwrites a database.

\set ON_ERROR_STOP on

SELECT format('CREATE DATABASE %I', :'dbname')
WHERE :'dbname' ~ '^paddock_[a-z0-9_]+$'
\gexec

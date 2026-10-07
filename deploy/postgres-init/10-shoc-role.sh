#!/bin/sh
# shoc must not run as a Postgres superuser: superusers bypass row-level
# security, which is what keeps one tenant's events away from another. The
# image's superuser stays `postgres`; this creates the three ordinary roles
# shoc needs:
#   shoc        owns the database and its schema; only `shoc migrate` and
#               `shoc rotate-key` connect as it (SHOC_MIGRATE_DSN)
#   shoc_app    what serve and worker connect as (SHOC_DSN). It does not own
#               the schema, so it cannot disable the audit log's triggers or
#               delete its rows (RFC 0024). `shoc migrate` grants it the rest.
#   shoc_agent  the read-only role agents query through (SHOC_READONLY_DSN)
# `shoc` is a member of `shoc_app` so that migrate can grant on the tenant
# schemas shoc_app creates; shoc_app is a member of nothing.
set -e

APP_PASSWORD="${SHOC_DB_PASSWORD:-shoc}"
RUNTIME_PASSWORD="${SHOC_APP_DB_PASSWORD:-shoc_app}"
AGENT_PASSWORD="${SHOC_AGENT_DB_PASSWORD:-shoc_agent}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres <<SQL
CREATE ROLE shoc LOGIN PASSWORD '${APP_PASSWORD}';
CREATE ROLE shoc_app LOGIN PASSWORD '${RUNTIME_PASSWORD}';
CREATE ROLE shoc_agent LOGIN PASSWORD '${AGENT_PASSWORD}';
GRANT shoc_app TO shoc;
CREATE DATABASE shoc OWNER shoc;
REVOKE ALL ON DATABASE shoc FROM PUBLIC;
GRANT CONNECT, CREATE ON DATABASE shoc TO shoc;
GRANT CONNECT, CREATE ON DATABASE shoc TO shoc_app;
GRANT CONNECT ON DATABASE shoc TO shoc_agent;
SQL

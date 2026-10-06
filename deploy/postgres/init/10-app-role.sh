#!/bin/sh
# Runs once on first database initialisation (docker-entrypoint-initdb.d).
# Creates the runtime role used by scanX. It is deliberately NOT a superuser
# and has no BYPASSRLS, so row-level security applies to every query.
set -eu

: "${SCANX_APP_DB_PASSWORD:?SCANX_APP_DB_PASSWORD must be set}"

psql -v ON_ERROR_STOP=1 \
  -v app_pw="$SCANX_APP_DB_PASSWORD" \
  -v db="$POSTGRES_DB" \
  --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
CREATE ROLE scanx_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  PASSWORD :'app_pw';
REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"db" TO scanx_app;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO scanx_app;
SQL

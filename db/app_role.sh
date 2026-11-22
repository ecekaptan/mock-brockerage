#!/bin/sh
# FIX (app ran as DB superuser): the app used to connect as `miniapp`, the
# Postgres superuser, so any SQL injection or app bug had full control of the
# database (drop tables, read other databases, run programs on the server).
# This creates `miniapp_app` with only what the code needs.
#
# Runs once, after init.sql, when the database volume is first created.
set -eu

psql -v ON_ERROR_STOP=1 -v app_password="$APP_DB_PASSWORD" \
     --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
CREATE ROLE miniapp_app LOGIN PASSWORD :'app_password';

GRANT CONNECT ON DATABASE miniapp TO miniapp_app;
GRANT USAGE ON SCHEMA public TO miniapp_app;

-- Column-level UPDATE: the app can change an IBAN or a balance, nothing else.
GRANT SELECT, INSERT ON users TO miniapp_app;
GRANT UPDATE (iban) ON users TO miniapp_app;
GRANT SELECT, INSERT ON accounts TO miniapp_app;
GRANT UPDATE (balance) ON accounts TO miniapp_app;
GRANT SELECT, INSERT ON holdings TO miniapp_app;
GRANT UPDATE (quantity) ON holdings TO miniapp_app;

-- Orders and withdrawals are append-only for the app: no UPDATE, no DELETE,
-- so a bug can't rewrite or erase the payout history.
GRANT SELECT, INSERT ON orders, withdrawals TO miniapp_app;

GRANT USAGE ON SEQUENCE users_id_seq, orders_id_seq, withdrawals_id_seq TO miniapp_app;
SQL

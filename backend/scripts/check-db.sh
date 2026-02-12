#!/usr/bin/env bash
set -euo pipefail

DB_URL="${DATABASE_URL:-}"

if [ -z "$DB_URL" ]; then
  env_file="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/.env"
  if [ -f "$env_file" ]; then
    DB_URL=$(sed -n 's/^DATABASE_URL=//p' "$env_file" | head -n 1 | sed 's/^"//; s/"$//')
  fi
fi

if [ -z "$DB_URL" ]; then
  echo "DATABASE_URL is not set and could not be read from backend/.env" >&2
  exit 1
fi

echo "Connecting with DATABASE_URL..."
PGCONNECT_TIMEOUT="${PGCONNECT_TIMEOUT:-5}" psql "$DB_URL" -v ON_ERROR_STOP=1 <<'SQL'
select now() as now, inet_server_addr() as server_ip, current_database() as db;
select count(*) as users from "User";
select count(*) as licensees from "Licensee";
select count(*) as batches from "Batch";
select count(*) as qrcodes from "QRCode";
select count(*) as scanlogs from "QrScanLog";
select count(*) as auditlogs from "AuditLog";
SQL

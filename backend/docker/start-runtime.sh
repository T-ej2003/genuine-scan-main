#!/bin/sh
set -eu

if [ "${RUN_DB_MIGRATIONS_ON_START:-false}" = "true" ]; then
  echo "Running prisma migrate deploy before backend start..."
  npx prisma migrate deploy
fi

exec npm run start

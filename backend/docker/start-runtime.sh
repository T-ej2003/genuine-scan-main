#!/bin/sh
set -eu

if [ "${RUN_DB_MIGRATIONS_ON_START:-false}" = "true" ]; then
  echo "Running prisma migrate deploy before backend start..."
  node node_modules/prisma/build/index.js migrate deploy
fi

exec node dist/index.js

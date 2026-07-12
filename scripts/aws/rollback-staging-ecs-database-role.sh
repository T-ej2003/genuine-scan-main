#!/usr/bin/env bash
set -euo pipefail
umask 077
exec node "$(dirname "$0")/staging-database-role-credentials.mjs" rollback "$@"

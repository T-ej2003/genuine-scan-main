#!/usr/bin/env bash
set -euo pipefail
umask 077
[[ "${TRACE-}" != "1" ]] || { echo "TRACE is refused for credential workflows." >&2; exit 2; }
exec node "$(dirname "$0")/staging-database-role-credentials.mjs" provision "$@"

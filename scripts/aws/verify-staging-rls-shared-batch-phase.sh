#!/usr/bin/env bash
set -euo pipefail
umask 077
[[ "${TRACE-}" != "1" ]] || { echo "TRACE is refused for staging RLS verification." >&2; exit 2; }
exec node "$(dirname "$0")/staging-rls-shared-batch-phase.mjs" verify

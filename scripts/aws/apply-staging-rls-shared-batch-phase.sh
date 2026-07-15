#!/usr/bin/env bash
set -euo pipefail
umask 077
[[ "${TRACE-}" != "1" ]] || { echo "TRACE is refused for staging RLS execution." >&2; exit 2; }
[[ "${MSCQR_CONFIRM_STAGING_RLS_SHARED_BATCH_PHASE-}" == "YES" ]] || { echo "Set MSCQR_CONFIRM_STAGING_RLS_SHARED_BATCH_PHASE=YES." >&2; exit 2; }
exec node "$(dirname "$0")/staging-rls-shared-batch-phase.mjs" apply

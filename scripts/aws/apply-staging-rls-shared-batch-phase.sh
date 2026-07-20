#!/usr/bin/env bash
set -euo pipefail
umask 077
[[ "${TRACE-}" != "1" ]] || { echo "TRACE is refused for staging RLS execution." >&2; exit 2; }
[[ "${MSCQR_CONFIRM_STAGING_RLS_SHARED_BATCH_PHASE-}" == "MSCQR_APPLY_STAGING_RLS_SHARED_BATCH_PHASE" ]] || { echo "Set MSCQR_CONFIRM_STAGING_RLS_SHARED_BATCH_PHASE=MSCQR_APPLY_STAGING_RLS_SHARED_BATCH_PHASE." >&2; exit 2; }
exec node "$(dirname "$0")/staging-rls-shared-batch-phase.mjs" apply

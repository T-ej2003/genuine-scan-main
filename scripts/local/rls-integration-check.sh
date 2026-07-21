#!/usr/bin/env bash
set -Eeuo pipefail
exec node scripts/rls/local-production-readiness.mjs --phase static

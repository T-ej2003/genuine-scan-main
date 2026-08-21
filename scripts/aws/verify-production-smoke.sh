#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/aws/verify-production-smoke.sh

Verify the production public endpoints after an ECS deployment.

Environment:
  PUBLIC_BASE_URL   Default: https://www.mscqr.com
  SMOKE_PATHS       Optional space-separated paths. Default:
                    / /login /api/health/ready
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required." >&2
  exit 1
fi
if ! command -v node >/dev/null 2>&1; then
  echo "node is required." >&2
  exit 1
fi

PUBLIC_BASE_URL="${PUBLIC_BASE_URL:-https://www.mscqr.com}"
SMOKE_PATHS="${SMOKE_PATHS:-/ /login /api/health/ready}"

base_url="${PUBLIC_BASE_URL%/}"

for path in $SMOKE_PATHS; do
  case "$path" in
    /*) url="${base_url}${path}" ;;
    *) url="${base_url}/${path}" ;;
  esac

  response_file="$(mktemp)"
  status_code="$(
    curl \
      --silent \
      --show-error \
      --location \
      --output "$response_file" \
      --write-out '%{http_code}' \
      "$url"
  )"

  if [[ ! "$status_code" =~ ^2[0-9][0-9]$ ]]; then
    echo "Smoke check failed for ${url}: HTTP ${status_code}" >&2
    rm -f "$response_file"
    exit 1
  fi

  if [[ "$path" == "/api/health/ready" ]]; then
    node --input-type=module - "$url" "$response_file" <<'NODE'
import fs from "node:fs";
import { parseProductionBackendReadiness } from "./scripts/aws/production-backend-readiness-contract.mjs";

const [url, responsePath] = process.argv.slice(2);
parseProductionBackendReadiness(fs.readFileSync(responsePath));
NODE
  fi

  rm -f "$response_file"
  echo "Verified ${url} returned HTTP ${status_code}"
done

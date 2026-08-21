#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/aws/verify-ready-endpoint.sh <ready-url>

Fetch a backend /health/ready endpoint and enforce the production readiness
payload, including all required dependency checks.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

READY_URL="${1:-}"
if [[ -z "$READY_URL" ]]; then
  usage >&2
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required." >&2
  exit 1
fi
if ! command -v node >/dev/null 2>&1; then
  echo "node is required." >&2
  exit 1
fi

RESPONSE_FILE="$(mktemp)"
trap 'rm -f "$RESPONSE_FILE"' EXIT

curl --fail --silent --show-error --location "$READY_URL" >"$RESPONSE_FILE"

node --input-type=module - "$READY_URL" "$RESPONSE_FILE" <<'NODE'
import fs from "node:fs";
import { assertProductionBackendReadiness } from "./scripts/aws/production-backend-readiness-contract.mjs";

const [readyUrl, responsePath] = process.argv.slice(2);
const payload = JSON.parse(fs.readFileSync(responsePath, "utf8"));
assertProductionBackendReadiness(payload);

console.log(`Verified ${readyUrl} returned production-ready dependency health`);
NODE

#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/aws/verify-ready-endpoint.sh <ready-url>

Fetch a backend /health/ready endpoint and fail unless the payload reports
success=true.
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

const [readyUrl, responsePath] = process.argv.slice(2);
const payload = JSON.parse(fs.readFileSync(responsePath, "utf8"));

if (payload?.success !== true) {
  console.error(`Ready endpoint ${readyUrl} did not return success=true.`);
  process.exit(1);
}

console.log(`Verified ${readyUrl} returned success=true`);
NODE

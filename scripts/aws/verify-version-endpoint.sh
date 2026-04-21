#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/aws/verify-version-endpoint.sh <version-url> <expected-git-sha>

Fetch a backend /version endpoint and fail unless the payload reports the
expected git SHA.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

VERSION_URL="${1:-}"
EXPECTED_GIT_SHA="${2:-}"

if [[ -z "$VERSION_URL" || -z "$EXPECTED_GIT_SHA" ]]; then
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

curl --fail --silent --show-error --location "$VERSION_URL" >"$RESPONSE_FILE"

node --input-type=module - "$VERSION_URL" "$EXPECTED_GIT_SHA" "$RESPONSE_FILE" <<'NODE'
import fs from "node:fs";

const [versionUrl, expectedGitSha, responsePath] = process.argv.slice(2);
const payload = JSON.parse(fs.readFileSync(responsePath, "utf8"));
const actualGitSha = String(payload?.gitSha || "").trim();

if (!actualGitSha) {
  console.error(`Version endpoint ${versionUrl} did not return gitSha.`);
  process.exit(1);
}

if (actualGitSha !== expectedGitSha) {
  console.error(`Version endpoint ${versionUrl} returned gitSha=${actualGitSha}, expected ${expectedGitSha}.`);
  process.exit(1);
}

console.log(`Verified ${versionUrl} is serving gitSha=${actualGitSha}`);
NODE

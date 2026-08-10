#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/aws/verify-version-endpoint.sh <version-url> <expected-git-sha>

Fetch a backend release endpoint and fail unless the payload reports the
expected full git SHA.
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

if [[ ! "$EXPECTED_GIT_SHA" =~ ^[a-f0-9]{40}$ ]]; then
  echo "EXPECTED_GIT_SHA must be a 40-character lowercase hexadecimal SHA." >&2
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
const shaPattern = /^[a-f0-9]{40}$/;
const hasTopLevelGitSha = payload !== null && typeof payload === "object" && Object.hasOwn(payload, "gitSha");
const hasHealthGitSha = payload?.release !== null && typeof payload?.release === "object" && Object.hasOwn(payload.release, "gitSha");
const topLevelGitSha = hasTopLevelGitSha ? payload.gitSha : undefined;
const healthGitSha = hasHealthGitSha ? payload.release.gitSha : undefined;

for (const [location, value] of [["gitSha", topLevelGitSha], ["release.gitSha", healthGitSha]]) {
  if (value !== undefined && (typeof value !== "string" || !shaPattern.test(value))) {
    console.error(`Version endpoint ${versionUrl} returned malformed ${location}.`);
    process.exit(1);
  }
}

if (topLevelGitSha === undefined && healthGitSha === undefined) {
  console.error(`Version endpoint ${versionUrl} did not return gitSha or release.gitSha.`);
  process.exit(1);
}

if (topLevelGitSha !== undefined && healthGitSha !== undefined && topLevelGitSha !== healthGitSha) {
  console.error(`Version endpoint ${versionUrl} returned conflicting gitSha values.`);
  process.exit(1);
}

const actualGitSha = topLevelGitSha ?? healthGitSha;

if (actualGitSha !== expectedGitSha) {
  console.error(`Version endpoint ${versionUrl} returned gitSha=${actualGitSha}, expected ${expectedGitSha}.`);
  process.exit(1);
}

console.log(`Verified ${versionUrl} is serving gitSha=${actualGitSha}`);
NODE

#!/usr/bin/env bash
set -euo pipefail

failures=0

check_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "MISSING: $cmd"
    failures=$((failures + 1))
  else
    echo "OK: $cmd -> $(command -v "$cmd")"
  fi
}

echo "=== MSCQR Dev Doctor ==="
echo "PATH=$PATH"

if [[ "$PATH" == *'Unknown command: "bin"'* ]]; then
  echo "FAIL: PATH contains corrupted segment: Unknown command: \"bin\""
  failures=$((failures + 1))
fi

for cmd in node npm git docker gh openssl jq psql rg; do
  check_cmd "$cmd"
done

if command -v node >/dev/null 2>&1; then
  node_major="$(node -p 'process.versions.node.split(".")[0]')"
  if [[ "$node_major" -lt 20 ]]; then
    echo "FAIL: Node.js major version must be >=20 (found $(node -v))"
    failures=$((failures + 1))
  else
    echo "OK: Node.js version $(node -v)"
  fi
fi

if command -v docker >/dev/null 2>&1; then
  if ! docker compose version >/dev/null 2>&1; then
    echo "FAIL: docker compose plugin missing"
    failures=$((failures + 1))
  else
    echo "OK: $(docker compose version)"
  fi
fi

if [[ "$failures" -gt 0 ]]; then
  echo "Doctor failed with $failures issue(s)."
  exit 1
fi

echo "Doctor passed."


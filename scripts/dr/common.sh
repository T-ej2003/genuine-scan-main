#!/bin/sh

repo_root() {
  git rev-parse --show-toplevel 2>/dev/null
}

require_repo_root() {
  root="$(repo_root || true)"
  if [ -z "$root" ] || [ ! -f "$root/package.json" ] || [ ! -d "$root/.git" ]; then
    echo "Run this command from inside the MSCQR repository." >&2
    exit 1
  fi
  cd "$root"
}

utc_timestamp() {
  /bin/date -u '+%Y%m%dT%H%M%SZ'
}

ensure_artifact_root() {
  /bin/mkdir -p artifacts/dr
  {
    printf '%s\n' '*'
    printf '%s\n' '!.gitignore'
  } > artifacts/dr/.gitignore
}

create_artifact_dir() {
  ensure_artifact_root
  DR_TIMESTAMP="$(utc_timestamp)"
  DR_ARTIFACT_DIR="artifacts/dr/$DR_TIMESTAMP"
  /bin/mkdir -p "$DR_ARTIFACT_DIR"
}

validate_target() {
  case "$1" in
    mumbai|capetown|standby|standby_regions) ;;
    *)
      echo "Unsupported target: $1" >&2
      echo "Allowed targets: mumbai, capetown, standby, standby_regions" >&2
      exit 2
      ;;
  esac
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Required command not found: $1" >&2
    exit 127
  fi
}

run_logged() {
  log_file="$1"
  shift
  set +e
  "$@" > "$log_file" 2>&1
  status="$?"
  set -e
  /bin/cat "$log_file"
  return "$status"
}

json_escape() {
  node --input-type=module -e 'process.stdout.write(JSON.stringify(process.argv[1] || "").slice(1, -1));' "$1"
}

print_missing() {
  name="$1"
  echo "Missing required value: $name" >&2
}

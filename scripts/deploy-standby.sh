#!/bin/sh
set -eu

usage() {
  cat <<'USAGE'
Usage: scripts/deploy-standby.sh [mumbai|capetown|standby_regions] [inventory]

Defaults:
  limit:     standby_regions
  inventory: ops/deploy/inventory.ini
USAGE
}

LIMIT="${1:-standby_regions}"
INVENTORY="${2:-ops/deploy/inventory.ini}"
PLAYBOOK="ops/deploy/deploy-standby.yml"

case "$LIMIT" in
  mumbai|capetown|standby_regions) ;;
  -h|--help)
    usage
    exit 0
    ;;
  *)
    echo "Unsupported limit: $LIMIT" >&2
    usage >&2
    exit 2
    ;;
esac

if [ ! -f "$INVENTORY" ]; then
  echo "Inventory not found: $INVENTORY" >&2
  echo "Copy ops/deploy/inventory.example.ini to ops/deploy/inventory.ini and fill local values." >&2
  exit 1
fi

ansible-playbook -i "$INVENTORY" "$PLAYBOOK" --limit "$LIMIT"

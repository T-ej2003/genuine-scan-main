#!/bin/sh
set -eu

usage() {
  printf '%s\n' \
    'Usage: scripts/health-check-regions.sh [mumbai|capetown|standby|standby_regions] [inventory]' \
    '' \
    'Defaults:' \
    '  limit:     standby' \
    '  inventory: ops/deploy/inventory.ini'
}

LIMIT="${1:-standby}"
INVENTORY="${2:-ops/deploy/inventory.ini}"
PLAYBOOK="ops/deploy/health-check-standby.yml"

case "$LIMIT" in
  mumbai|capetown|standby|standby_regions) ;;
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

has_inventory_group() {
  group_name="$1"
  /usr/bin/grep -Eq "^\\[$group_name(:children)?\\]" "$INVENTORY"
}

if [ "$LIMIT" = "standby_regions" ] && ! has_inventory_group standby_regions && has_inventory_group standby; then
  echo "Inventory has [standby] but not [standby_regions]; using --limit standby." >&2
  LIMIT="standby"
fi

if [ "$LIMIT" = "standby" ] && ! has_inventory_group standby && has_inventory_group standby_regions; then
  echo "Inventory has [standby_regions] but not [standby]; using --limit standby_regions." >&2
  LIMIT="standby_regions"
fi

if [ "$LIMIT" = "standby_regions" ] && ! has_inventory_group standby_regions; then
  echo "Inventory does not define [standby_regions]. Add this alias or use: scripts/health-check-regions.sh standby" >&2
  echo "[standby_regions:children]" >&2
  echo "standby" >&2
  exit 2
fi

if [ "$LIMIT" = "standby" ] && ! has_inventory_group standby; then
  echo "Inventory does not define [standby]. Add this group or use: scripts/health-check-regions.sh standby_regions" >&2
  echo "[standby:children]" >&2
  echo "mumbai" >&2
  echo "capetown" >&2
  exit 2
fi

ansible-playbook -i "$INVENTORY" "$PLAYBOOK" --limit "$LIMIT"

#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
# shellcheck source=scripts/dr/common.sh
. "$SCRIPT_DIR/common.sh"

require_repo_root

HOSTED_ZONE_ID="${HOSTED_ZONE_ID:-Z0569586VLFIGGVI7HAZ}"
DOMAIN_NAME="${DOMAIN_NAME:-mscqr.com}"
WWW_DOMAIN_NAME="${WWW_DOMAIN_NAME:-www.mscqr.com}"
AFRICA_ALB_DNS_NAME="${AFRICA_ALB_DNS_NAME:-${CAPETOWN_ALB_DNS_NAME:-}}"
AFRICA_ALB_HOSTED_ZONE_ID="${AFRICA_ALB_HOSTED_ZONE_ID:-${CAPETOWN_ALB_HOSTED_ZONE_ID:-}}"
DEFAULT_ALB_DNS_NAME="${DEFAULT_ALB_DNS_NAME:-${MUMBAI_ALB_DNS_NAME:-}}"
DEFAULT_ALB_HOSTED_ZONE_ID="${DEFAULT_ALB_HOSTED_ZONE_ID:-${MUMBAI_ALB_HOSTED_ZONE_ID:-}}"
CURRENT_GLOBAL_ALB_DNS_NAME="${CURRENT_GLOBAL_ALB_DNS_NAME:-$DEFAULT_ALB_DNS_NAME}"
CURRENT_GLOBAL_ALB_HOSTED_ZONE_ID="${CURRENT_GLOBAL_ALB_HOSTED_ZONE_ID:-$DEFAULT_ALB_HOSTED_ZONE_ID}"
AFRICA_SET_IDENTIFIER="${AFRICA_SET_IDENTIFIER:-africa-capetown}"
DEFAULT_SET_IDENTIFIER="${DEFAULT_SET_IDENTIFIER:-default-mumbai}"
INCLUDE_WWW_CNAME="${INCLUDE_WWW_CNAME:-true}"

usage() {
  cat <<'USAGE'
Usage: scripts/dr/generate-route53-africa-dns-plan.sh

Plan-only Route 53 change-batch generator for Africa geolocation routing.
It does not call AWS and does not apply Route 53 changes.

Required environment:
  AFRICA_ALB_DNS_NAME             Cape Town ALB DNS name
  AFRICA_ALB_HOSTED_ZONE_ID       Cape Town ALB canonical hosted zone ID
  DEFAULT_ALB_DNS_NAME            Current default/global Mumbai ALB DNS name
  DEFAULT_ALB_HOSTED_ZONE_ID      Current default/global Mumbai ALB hosted zone ID

Optional environment:
  HOSTED_ZONE_ID                  Route 53 hosted zone ID, default MSCQR zone
  DOMAIN_NAME                     Default mscqr.com
  WWW_DOMAIN_NAME                 Default www.mscqr.com
  CURRENT_GLOBAL_ALB_DNS_NAME     Existing simple/global ALB alias to delete in cutover
  CURRENT_GLOBAL_ALB_HOSTED_ZONE_ID
  AFRICA_SET_IDENTIFIER           Default africa-capetown
  DEFAULT_SET_IDENTIFIER          Default default-mumbai
  INCLUDE_WWW_CNAME               true/false, default true

The cutover plan converts the apex from one simple Mumbai ALB alias into:
  - geolocation default (*) alias to Mumbai
  - geolocation Africa (AF) alias to Cape Town

The rollback plan removes those geolocation records and restores the simple
Mumbai ALB alias. Review both JSON files before any future approved apply.
USAGE
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

[ -n "$AFRICA_ALB_DNS_NAME" ] || { echo "AFRICA_ALB_DNS_NAME is required." >&2; exit 2; }
[ -n "$AFRICA_ALB_HOSTED_ZONE_ID" ] || { echo "AFRICA_ALB_HOSTED_ZONE_ID is required." >&2; exit 2; }
[ -n "$DEFAULT_ALB_DNS_NAME" ] || { echo "DEFAULT_ALB_DNS_NAME is required." >&2; exit 2; }
[ -n "$DEFAULT_ALB_HOSTED_ZONE_ID" ] || { echo "DEFAULT_ALB_HOSTED_ZONE_ID is required." >&2; exit 2; }
[ -n "$CURRENT_GLOBAL_ALB_DNS_NAME" ] || { echo "CURRENT_GLOBAL_ALB_DNS_NAME is required." >&2; exit 2; }
[ -n "$CURRENT_GLOBAL_ALB_HOSTED_ZONE_ID" ] || { echo "CURRENT_GLOBAL_ALB_HOSTED_ZONE_ID is required." >&2; exit 2; }

case "$INCLUDE_WWW_CNAME" in
  true|false) ;;
  *) echo "INCLUDE_WWW_CNAME must be true or false." >&2; exit 2 ;;
esac

for value_name in \
  AFRICA_ALB_DNS_NAME \
  DEFAULT_ALB_DNS_NAME \
  CURRENT_GLOBAL_ALB_DNS_NAME \
  DOMAIN_NAME \
  WWW_DOMAIN_NAME \
  AFRICA_SET_IDENTIFIER \
  DEFAULT_SET_IDENTIFIER
do
  eval "value=\${$value_name}"
  case "$value" in
    ""|*[[:space:]]*) echo "$value_name must be non-empty and must not contain whitespace." >&2; exit 2 ;;
  esac
done

create_artifact_dir
plan_dir="$DR_ARTIFACT_DIR/route53-africa-dns-plan"
/bin/mkdir -p "$plan_dir"

cutover_file="$plan_dir/cutover-africa-to-capetown-preserve-mumbai-default.json"
rollback_file="$plan_dir/rollback-africa-to-mumbai-global.json"
summary_file="$plan_dir/summary.md"

node --input-type=module - \
  "$cutover_file" \
  "$rollback_file" \
  "$DOMAIN_NAME" \
  "$WWW_DOMAIN_NAME" \
  "$AFRICA_ALB_DNS_NAME" \
  "$AFRICA_ALB_HOSTED_ZONE_ID" \
  "$DEFAULT_ALB_DNS_NAME" \
  "$DEFAULT_ALB_HOSTED_ZONE_ID" \
  "$CURRENT_GLOBAL_ALB_DNS_NAME" \
  "$CURRENT_GLOBAL_ALB_HOSTED_ZONE_ID" \
  "$AFRICA_SET_IDENTIFIER" \
  "$DEFAULT_SET_IDENTIFIER" \
  "$INCLUDE_WWW_CNAME" <<'NODE'
import fs from "node:fs";

const [
  cutoverFile,
  rollbackFile,
  domainName,
  wwwDomainName,
  africaAlbDnsName,
  africaAlbHostedZoneId,
  defaultAlbDnsName,
  defaultAlbHostedZoneId,
  currentGlobalAlbDnsName,
  currentGlobalAlbHostedZoneId,
  africaSetIdentifier,
  defaultSetIdentifier,
  includeWwwCname,
] = process.argv.slice(2);

const withDot = (value) => (String(value).endsWith(".") ? String(value) : `${value}.`);
const aliasA = ({ name, setIdentifier, geoLocation, hostedZoneId, dnsName }) => ({
  Name: withDot(name),
  Type: "A",
  ...(setIdentifier ? { SetIdentifier: setIdentifier } : {}),
  ...(geoLocation ? { GeoLocation: geoLocation } : {}),
  AliasTarget: {
    HostedZoneId: hostedZoneId,
    DNSName: withDot(dnsName),
    EvaluateTargetHealth: true,
  },
});
const wwwCname = {
  Name: withDot(wwwDomainName),
  Type: "CNAME",
  TTL: 300,
  ResourceRecords: [{ Value: domainName }],
};

const simpleMumbai = aliasA({
  name: domainName,
  hostedZoneId: currentGlobalAlbHostedZoneId,
  dnsName: currentGlobalAlbDnsName,
});
const defaultMumbai = aliasA({
  name: domainName,
  setIdentifier: defaultSetIdentifier,
  geoLocation: { CountryCode: "*" },
  hostedZoneId: defaultAlbHostedZoneId,
  dnsName: defaultAlbDnsName,
});
const africaCapeTown = aliasA({
  name: domainName,
  setIdentifier: africaSetIdentifier,
  geoLocation: { ContinentCode: "AF" },
  hostedZoneId: africaAlbHostedZoneId,
  dnsName: africaAlbDnsName,
});

const cutoverChanges = [
  { Action: "DELETE", ResourceRecordSet: simpleMumbai },
  { Action: "CREATE", ResourceRecordSet: defaultMumbai },
  { Action: "CREATE", ResourceRecordSet: africaCapeTown },
];
if (includeWwwCname === "true") {
  cutoverChanges.push({ Action: "UPSERT", ResourceRecordSet: wwwCname });
}

const rollbackChanges = [
  { Action: "DELETE", ResourceRecordSet: africaCapeTown },
  { Action: "DELETE", ResourceRecordSet: defaultMumbai },
  { Action: "CREATE", ResourceRecordSet: simpleMumbai },
];
if (includeWwwCname === "true") {
  rollbackChanges.push({ Action: "UPSERT", ResourceRecordSet: wwwCname });
}

fs.writeFileSync(
  cutoverFile,
  `${JSON.stringify({
    Comment: "MSCQR PLAN ONLY: Africa geolocation to Cape Town ALB while preserving Mumbai as default/global routing",
    Changes: cutoverChanges,
  }, null, 2)}\n`,
);
fs.writeFileSync(
  rollbackFile,
  `${JSON.stringify({
    Comment: "MSCQR PLAN ONLY: rollback Africa geolocation and restore Mumbai as simple global ALB alias",
    Changes: rollbackChanges,
  }, null, 2)}\n`,
);
NODE

{
  printf '# Route 53 Africa DNS plan\n\n'
  printf '%s\n' "- Hosted zone: \`$HOSTED_ZONE_ID\`"
  printf '%s\n' "- Apex/domain record: \`$DOMAIN_NAME\`"
  printf '%s\n' "- Africa geolocation target: Cape Town ALB \`$AFRICA_ALB_DNS_NAME\`"
  printf '%s\n' "- Africa ALB hosted zone ID: \`$AFRICA_ALB_HOSTED_ZONE_ID\`"
  printf '%s\n' "- Default/global target preserved: Mumbai ALB \`$DEFAULT_ALB_DNS_NAME\`"
  printf '%s\n' "- Default/global ALB hosted zone ID: \`$DEFAULT_ALB_HOSTED_ZONE_ID\`"
  printf '%s\n' "- Cutover change batch: \`$cutover_file\`"
  printf '%s\n\n' "- Rollback change batch: \`$rollback_file\`"
  printf '%s\n' "This generator is plan-only. It does not call AWS and does not apply Route 53 changes."
  printf '%s\n' "Do not apply either JSON file until Cape Town evidence is clean, the proposed batch is reviewed, and an approved DNS apply workflow has explicit manual approval."
  printf '%s\n' "The production/global Mumbai route is preserved as the geolocation default (*) record; Africa (AF) is the only new regional route in this plan."
} > "$summary_file"

/bin/cat "$summary_file"

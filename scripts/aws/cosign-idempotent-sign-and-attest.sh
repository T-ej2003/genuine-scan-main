#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage:
  scripts/aws/cosign-idempotent-sign-and-attest.sh sign <image@sha256:digest>
  scripts/aws/cosign-idempotent-sign-and-attest.sh attest <image@sha256:digest> <type> <predicate-file>

Required environment:
  COSIGN_CERT_IDENTITY_REGEXP
  COSIGN_CERT_OIDC_ISSUER
EOF
}

operation="${1:-}"
image_ref="${2:-}"
identity_regexp="${COSIGN_CERT_IDENTITY_REGEXP:-}"
oidc_issuer="${COSIGN_CERT_OIDC_ISSUER:-}"

if [[ -z "$identity_regexp" || -z "$oidc_issuer" || ! "$image_ref" =~ @sha256:[a-f0-9]{64}$ ]]; then
  usage
  exit 2
fi

sign_args=(sign --yes "$image_ref")
verify_args=(verify --certificate-identity-regexp "$identity_regexp" --certificate-oidc-issuer "$oidc_issuer" "$image_ref")

case "$operation" in
  sign)
    [[ "$#" -eq 2 ]] || { usage; exit 2; }
    ;;
  attest)
    attestation_type="${3:-}"
    predicate_path="${4:-}"
    [[ "$#" -eq 4 && -f "$predicate_path" ]] || { usage; exit 2; }
    case "$attestation_type" in
      spdxjson|https://mscqr.com/attestations/stage-b-provenance/v1) ;;
      *) echo "Unsupported Stage B attestation type." >&2; exit 2 ;;
    esac
    sign_args=(attest --yes --type "$attestation_type" --predicate "$predicate_path" "$image_ref")
    verify_args=(verify-attestation --output text --type "$attestation_type" --certificate-identity-regexp "$identity_regexp" --certificate-oidc-issuer "$oidc_issuer" "$image_ref")
    ;;
  *)
    usage
    exit 2
    ;;
esac

failure_log="$(mktemp)"
verified_output="$(mktemp)"
trap 'rm -f "$failure_log" "$verified_output"' EXIT

if cosign "${sign_args[@]}" >"$failure_log" 2>&1; then
  exit 0
else
  status=$?
fi

if [[ "$status" -ne 1 ]] || ! grep -Fq 'createLogEntryConflict' "$failure_log" || ! grep -Fq 'an equivalent entry already exists in the transparency log' "$failure_log"; then
  cat "$failure_log" >&2
  exit "$status"
fi

echo "Cosign reported an equivalent Rekor entry; verifying the existing signed artifact before continuing." >&2
if [[ "$operation" == "sign" ]]; then
  cosign "${verify_args[@]}"
  exit 0
fi

cosign "${verify_args[@]}" >"$verified_output"

node --input-type=module - "$verified_output" "$predicate_path" "$attestation_type" "$image_ref" <<'NODE'
import fs from "node:fs";

const [verifiedPath, predicatePath, attestationType, imageRef] = process.argv.slice(2);
const expectedPredicate = JSON.parse(fs.readFileSync(predicatePath, "utf8"));
const expectedDigest = imageRef.match(/@sha256:([a-f0-9]{64})$/)?.[1];
const expectedPredicateType = attestationType === "spdxjson" ? "https://spdx.dev/Document" : attestationType;

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

if (!expectedDigest || expectedPredicate === null || typeof expectedPredicate !== "object" || Array.isArray(expectedPredicate)) {
  throw new Error("Requested attestation predicate or image digest is malformed.");
}

const verifiedLines = fs.readFileSync(verifiedPath, "utf8").split(/\r?\n/).filter(Boolean);
if (verifiedLines.length === 0) throw new Error("Cosign returned no verified attestation payloads.");

let matchingAttestation = false;
for (const line of verifiedLines) {
  const envelope = JSON.parse(line);
  if (!envelope || typeof envelope !== "object" || envelope.payloadType !== "application/vnd.in-toto+json" || typeof envelope.payload !== "string" || !Array.isArray(envelope.signatures) || envelope.signatures.length === 0) {
    throw new Error("Cosign verified output is not a complete in-toto DSSE envelope.");
  }
  const encodedPayload = envelope.payload.replace(/\s/g, "");
  const decodedPayload = Buffer.from(encodedPayload, "base64");
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encodedPayload) || decodedPayload.toString("base64").replace(/=+$/, "") !== encodedPayload.replace(/=+$/, "")) throw new Error("Verified attestation DSSE payload encoding is malformed.");
  const statement = JSON.parse(decodedPayload.toString("utf8"));
  if (!statement || typeof statement !== "object" || Array.isArray(statement) || statement._type !== "https://in-toto.io/Statement/v1" || !Array.isArray(statement.subject) || statement.subject.length !== 1 || !statement.subject[0] || typeof statement.subject[0] !== "object" || !statement.subject[0].digest || typeof statement.subject[0].digest !== "object" || !/^[a-f0-9]{64}$/.test(statement.subject[0].digest.sha256 || "") || !Object.hasOwn(statement, "predicate") || typeof statement.predicate !== "object" || statement.predicate === null || Array.isArray(statement.predicate) || typeof statement.predicateType !== "string") {
    throw new Error("Verified in-toto statement is malformed.");
  }
  if (statement.predicateType !== expectedPredicateType) throw new Error("Verified attestation predicate type does not match the requested type.");
  if (statement.subject[0].digest.sha256 !== expectedDigest) continue;
  if (canonicalJson(statement.predicate) === canonicalJson(expectedPredicate)) matchingAttestation = true;
}

if (!matchingAttestation) throw new Error("No cryptographically verified attestation matched the requested predicate.");
NODE

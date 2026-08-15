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
    verify_args=(verify-attestation --type "$attestation_type" --certificate-identity-regexp "$identity_regexp" --certificate-oidc-issuer "$oidc_issuer" "$image_ref")
    ;;
  *)
    usage
    exit 2
    ;;
esac

failure_log="$(mktemp)"
trap 'rm -f "$failure_log"' EXIT

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
cosign "${verify_args[@]}"

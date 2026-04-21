#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/aws/verify-release-artifacts.sh <image-ref>

Verify production release controls for an image:
- required manifest platforms
- cosign signature
- cosign SBOM attestation
- cosign provenance attestation

Environment:
  REQUIRED_PLATFORMS              Default: linux/amd64
  COSIGN_CERT_IDENTITY_REGEXP     Required regex for signing workflow identity
  COSIGN_CERT_OIDC_ISSUER         Default: https://token.actions.githubusercontent.com
  PROVENANCE_ATTESTATION_TYPE     Default: mscqr-release-provenance
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

IMAGE_REF="${1:-}"
if [[ -z "$IMAGE_REF" ]]; then
  usage >&2
  exit 1
fi

if ! command -v cosign >/dev/null 2>&1; then
  echo "cosign is required." >&2
  exit 1
fi

REQUIRED_PLATFORMS="${REQUIRED_PLATFORMS:-linux/amd64}"
COSIGN_CERT_IDENTITY_REGEXP="${COSIGN_CERT_IDENTITY_REGEXP:-}"
COSIGN_CERT_OIDC_ISSUER="${COSIGN_CERT_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"
PROVENANCE_ATTESTATION_TYPE="${PROVENANCE_ATTESTATION_TYPE:-mscqr-release-provenance}"

if [[ -z "$COSIGN_CERT_IDENTITY_REGEXP" ]]; then
  echo "Set COSIGN_CERT_IDENTITY_REGEXP before verifying release artifacts." >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
"$REPO_ROOT/scripts/aws/verify-image-manifest.sh" "$IMAGE_REF"

cosign verify \
  --certificate-identity-regexp "$COSIGN_CERT_IDENTITY_REGEXP" \
  --certificate-oidc-issuer "$COSIGN_CERT_OIDC_ISSUER" \
  "$IMAGE_REF" >/dev/null

cosign verify-attestation \
  --type spdxjson \
  --certificate-identity-regexp "$COSIGN_CERT_IDENTITY_REGEXP" \
  --certificate-oidc-issuer "$COSIGN_CERT_OIDC_ISSUER" \
  "$IMAGE_REF" >/dev/null

cosign verify-attestation \
  --type "$PROVENANCE_ATTESTATION_TYPE" \
  --certificate-identity-regexp "$COSIGN_CERT_IDENTITY_REGEXP" \
  --certificate-oidc-issuer "$COSIGN_CERT_OIDC_ISSUER" \
  "$IMAGE_REF" >/dev/null

echo "Verified manifest, signature, SBOM attestation, and provenance attestation for ${IMAGE_REF}"

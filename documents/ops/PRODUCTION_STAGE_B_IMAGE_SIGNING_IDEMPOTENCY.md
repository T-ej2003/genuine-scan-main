# Production Stage-B image signing idempotency

The protected `production-green-stage-b-image-build.yml` workflow installs Cosign
v3.0.6 through `sigstore/cosign-installer@v4.1.2`. Cosign v3 uses the
standardized protobuf bundle format by default; verification remains tlog-backed
and accepts only the configured GitHub Actions certificate identity and OIDC
issuer.

The workflow signs and attests each immutable digest, then verifies the signature,
SPDX SBOM attestation, and Stage-B provenance attestation with
`scripts/aws/verify-release-artifacts.sh`.

## Release/source and workflow/tooling revisions

The workflow definition is dispatched only from protected `main`. The job checks
out that workflow revision into the default workspace and authenticates it against
the fetched `origin/main` commit before using its signing and verification tools.
The requested merged `release_sha` is checked out separately under
`release-source`; package verification and Docker build context come only from
that directory. This preserves the two-SHA contract: `release_sha` remains the
image source and image-release binding, while the protected workflow revision
supplies trusted signing/recovery tooling. An older merged release may therefore
predate the helper without changing image contents or release identity.

## Equivalent Rekor entry handling

Cosign normally returns success after signing or attesting. If the operation
returns a failure containing both:

- `createLogEntryConflict`
- `an equivalent entry already exists in the transparency log`

the wrapper does not treat that response as success. It runs the corresponding
constrained `cosign verify` or `cosign verify-attestation` against the exact
immutable digest. That verification must validate the certificate identity,
GitHub OIDC issuer, signature/attestation, and transparency-log inclusion. Any
other error, malformed response, or verification failure remains fatal.

No `--insecure-ignore-tlog`, certificate bypass, OIDC bypass, or generic exit-code
fallback is permitted. The downstream release-artifact verifier remains mandatory,
so recovered evidence follows the same image-authorization path as a fresh
successful signing operation.

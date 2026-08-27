import { createProductionCommandRunner, createProductionCutoverAdapters, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-cutover-production-adapters.mjs";
import { verifyImageEvidenceSignature } from "./production-green-stage-b-image-evidence.mjs";
import { createReleasePreflightCheckerTrustSignatureVerifier } from "./production-release-preflight-checker-attestation.mjs";

export const PRODUCTION_RELEASE_PROFILE = "mscqr-production-release-deployer";

export function createProductionCutoverRuntimeComposition({ releaseRun = createProductionCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: PRODUCTION_RELEASE_PROFILE }) } = {}) {
  if (typeof releaseRun !== "function") throw new Error("Production cutover runtime requires the canonical release command runner.");
  const verifyReleasePreflightAttestationSignature = createReleasePreflightCheckerTrustSignatureVerifier({ releaseRun });
  return Object.freeze({
    releaseRun,
    verifyReleasePreflightAttestationSignature,
    imageAuthorizationValidation: Object.freeze({ verifyImageEvidence: (options) => verifyImageEvidenceSignature({ ...options, run: releaseRun }) }),
    constructAdapters: ({ config, sourceSha, rotationId, runtimeConfigSha256 }) => createProductionCutoverAdapters({ config, sourceSha, rotationId, runtimeConfigSha256, verifyReleasePreflightAttestationSignature }),
  });
}

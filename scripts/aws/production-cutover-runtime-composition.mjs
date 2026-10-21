import { createProductionCommandRunner, createProductionCutoverAdapters, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-cutover-production-adapters.mjs";
import { verifyImageEvidenceSignature } from "./production-green-stage-b-image-evidence.mjs";
import { createReleasePreflightCheckerTrustSignatureVerifier } from "./production-release-preflight-checker-attestation.mjs";
import { verifyPermissionReportSignature } from "./validate-production-green-stage-b-permissions.mjs";

const compositions = new WeakSet();
export const isProductionCutoverRuntimeComposition = value => compositions.has(value);

export const PRODUCTION_RELEASE_PROFILE = "mscqr-production-release-deployer";

export function createProductionCutoverRuntimeComposition({ releaseRun, env, exec } = {}) {
  releaseRun ||= createProductionCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: PRODUCTION_RELEASE_PROFILE, ...(env ? { env } : {}), ...(exec ? { exec } : {}) });
  if (typeof releaseRun !== "function") throw new Error("Production cutover runtime requires the canonical release command runner.");
  const verifyReleasePreflightAttestationSignature = createReleasePreflightCheckerTrustSignatureVerifier({ releaseRun });
  const composition = Object.freeze({
    releaseRun,
    verifyReleasePreflightAttestationSignature,
    verifyAdministratorEvidenceSignature: (options) => verifyPermissionReportSignature({ ...options, run: releaseRun }),
    imageAuthorizationValidation: Object.freeze({ verifyImageEvidence: (options) => verifyImageEvidenceSignature({ ...options, run: releaseRun }) }),
  constructAdapters: ({ config, sourceSha, rotationId, runtimeConfigSha256, verifierStsAdapter, conditionalContext }) => createProductionCutoverAdapters({ config, sourceSha, rotationId, runtimeConfigSha256, verifyReleasePreflightAttestationSignature, verifierStsAdapter, conditionalContext, ...(exec?{processExec:exec}:{}), createCommandRunner:options=>createProductionCommandRunner({...options,...(exec?{exec}:{}),...(env?{env}: {})}) }),
  });
  compositions.add(composition);
  return composition;
}

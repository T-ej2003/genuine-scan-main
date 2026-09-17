import { canonicalSha256 } from "../../aws/stage-b-task-definition-recovery-contract.mjs";

export function completedBackendRecoveryEvidence({ sourceSha, imageReleaseSha, recoveryImageDigest, targetArn, candidateFingerprint, evidenceSha256: _oldHash, ...terminal }) {
  const binding = "a".repeat(64);
  const body = {
    schemaVersion: 7, kind: "BACKEND_HEALTH_RECOVERY_EVIDENCE", status: "RECOVERY_COMPLETE",
    sourceSha, imageReleaseSha, recoveryImageDigest, targetArn, candidateFingerprint,
    currentTaskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:1",
    account: "368992683803", region: "eu-west-2",
    ...Object.fromEntries(["authorizationFileSha256", "authorizationSha256", "environmentApprovalFileSha256", "environmentApprovalSha256", "imageAuthorizationFileSha256", "imageAuthorizationSha256", "artifactSigningBindingSha256", "runtimeConsumabilitySha256", "initialRevisionCensusSha256", "expectedRevisionCensusSha256", "predecessorHistoryLineageSha256"].map((key) => [key, binding])),
    rollbackProofSha256: null, failedRecoveryEvidenceReferenceSha256: null,
    artifactSigningVerification: "VERIFIED", artifactSigningFailure: null, knownFailedRevisions: [],
    registrations: 1, updates: 1, generatedAt: "2026-09-17T00:00:00.000Z",
    backendHealthy: true, rotationRequired: true,
    health: { healthy: true, success: true, status: "ready", dependencies: { database: "ready", redis: "ready", objectStorage: "ready" }, release: { gitSha: imageReleaseSha }, timestamp: "2026-09-17T00:00:00.000Z" },
    ...terminal,
  };
  return { ...body, evidenceSha256: canonicalSha256(body) };
}

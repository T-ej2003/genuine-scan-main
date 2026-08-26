import { createHash } from "node:crypto";

export const STRICT_ONBOARDING_CHECKS = Object.freeze([
  "deployedReleaseSha", "deployedImageDigest", "serviceStable", "taskDefinition", "taskMarker", "ecsExecProof",
  "health", "databaseReady", "redisReady", "objectStorageReady", "superAdminLogin", "mfa", "authMe", "refresh",
  "dashboardStats", "qrStats", "publicQrVerification", "artifactSigning", "tenantIsolation", "rbac", "auditPath",
  "printerTrust", "antiCloning", "rotationState", "jwtCurrentRuntimeVerify", "jwtPreviousRuntimeVerify",
  "jwtInvalidRuntimeRejected", "qrCurrentRuntimeVerify", "qrPreviousRuntimeVerify", "qrTamperMatchingKeyTest",
  "qrUnknownKeyRejected", "artifactCurrentRuntimeVerify", "artifactHistoricalRuntimeVerify",
]);

const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const SENSITIVE = /database_url|postgres(?:ql)?:\/\/|password|secret|token|private.?key|qr.?payload|mfa.?seed|authorization|cookie|bearer/i;

export function assertNoOnboardingEvidenceLeak(value, path = "evidence") {
  if (typeof value === "string" && SENSITIVE.test(value)) throw new Error(`Onboarding evidence contains sensitive material at ${path}.`);
  if (Array.isArray(value)) value.forEach((entry, index) => assertNoOnboardingEvidenceLeak(entry, `${path}[${index}]`));
  else if (value && typeof value === "object") Object.entries(value).forEach(([key, entry]) => {
    if (SENSITIVE.test(key) && typeof entry !== "boolean") throw new Error(`Onboarding evidence contains a sensitive field at ${path}.${key}.`);
    assertNoOnboardingEvidenceLeak(entry, `${path}.${key}`);
  });
  return true;
}

const asBoolean = (value, name) => {
  if (value !== true) throw new Error(`Mandatory onboarding check failed: ${name}.`);
  return true;
};

export function buildOnboardingEvidenceFingerprint(evidence) {
  return {
    sourceSha: evidence.sourceSha,
    imageDigest: evidence.imageDigest,
    taskDefinitionArn: evidence.taskDefinitionArn,
    taskArn: evidence.taskArn,
    rotationId: evidence.rotationId,
    rotationStateSha256: evidence.rotationStateSha256,
    rotationPhase: evidence.rotationPhase,
    checks: { ...Object.fromEntries(STRICT_ONBOARDING_CHECKS.map((name) => [name, evidence.checks[name]])), legacyQrKeypairUnrecoverable: evidence.checks.legacyQrKeypairUnrecoverable },
  };
}

/** The only strict onboarding producer. Missing probe functions are failures, never skips. */
export async function runStrictOnboardingProbes({ probes, expected } = {}) {
  if (!probes || typeof probes !== "object") throw new Error("Strict onboarding probes are required.");
  if (!SHA40.test(expected?.sourceSha || "") || !DIGEST.test(expected?.imageDigest || "") || typeof expected.taskDefinitionArn !== "string" || typeof expected.taskArn !== "string" || typeof expected.rotationId !== "string" || !SHA256.test(expected.rotationStateSha256 || "")) throw new Error("Strict onboarding identity is incomplete.");
  const checks = {};
  for (const name of STRICT_ONBOARDING_CHECKS) {
    if (typeof probes[name] !== "function") throw new Error(`Mandatory onboarding probe is unavailable: ${name}.`);
    const result = await probes[name]({ expected });
    checks[name] = name === "qrPreviousRuntimeVerify" ? result === true : asBoolean(result, name);
  }
  checks.legacyQrKeypairUnrecoverable = typeof probes.legacyQrKeypairUnrecoverable === "function" && await probes.legacyQrKeypairUnrecoverable({ expected }) === true;
  if (checks.qrPreviousRuntimeVerify === checks.legacyQrKeypairUnrecoverable) throw new Error("Mandatory onboarding QR continuity check failed.");
  const evidence = {
    sourceSha: expected.sourceSha,
    imageDigest: expected.imageDigest,
    taskDefinitionArn: expected.taskDefinitionArn,
    taskArn: expected.taskArn,
    rotationId: expected.rotationId,
    rotationStateSha256: expected.rotationStateSha256,
    rotationPhase: "overlap-ready",
    serviceStable: checks.serviceStable,
    targetTaskDefinitionMatch: checks.taskDefinition,
    targetImageDigestMatch: checks.deployedImageDigest,
    taskMarker: checks.taskMarker,
    ecsExecProof: checks.ecsExecProof,
    health: { serviceHealthy: checks.health, healthReleaseGitSha: expected.sourceSha },
    runtime: {
      jwtCurrentRuntimeVerify: checks.jwtCurrentRuntimeVerify,
      jwtPreviousRuntimeVerify: checks.jwtPreviousRuntimeVerify,
      jwtInvalidRuntimeRejected: checks.jwtInvalidRuntimeRejected,
      qrCurrentRuntimeVerify: checks.qrCurrentRuntimeVerify,
      qrPreviousRuntimeVerify: checks.qrPreviousRuntimeVerify,
      legacyQrKeypairUnrecoverable: checks.legacyQrKeypairUnrecoverable,
      qrTamperMatchingKeyTest: checks.qrTamperMatchingKeyTest,
      qrUnknownKeyRejected: checks.qrUnknownKeyRejected,
      cookieCurrentSealOnly: checks.refresh,
      cookiePreviousOpenDuringOverlap: checks.refresh,
      artifactCurrentRuntimeVerify: checks.artifactCurrentRuntimeVerify,
      artifactHistoricalRuntimeVerify: checks.artifactHistoricalRuntimeVerify,
    },
    acceptance: {
      superAdminLogin: checks.superAdminLogin,
      mfa: checks.mfa,
      authMe: checks.authMe,
      refresh: checks.refresh,
      dashboardStats: checks.dashboardStats,
      qrStats: checks.qrStats,
      tenantIsolation: checks.tenantIsolation,
      rbac: checks.rbac,
      auditPath: checks.auditPath,
      printerTrust: checks.printerTrust,
      antiCloning: checks.antiCloning,
      dbReady: checks.databaseReady,
      redisReady: checks.redisReady,
      objectStorageReady: checks.objectStorageReady,
      stageANetworkingReady: checks.taskMarker,
    },
    checks,
  };
  assertNoOnboardingEvidenceLeak(evidence);
  const evidenceFingerprint = buildOnboardingEvidenceFingerprint(evidence);
  return { ...evidence, valid: true, evidenceRef: `onboarding:${expected.taskArn}`, evidenceSha256: createHash("sha256").update(JSON.stringify(evidenceFingerprint)).digest("hex") };
}

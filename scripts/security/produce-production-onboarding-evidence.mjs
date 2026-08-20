import { createHash } from "node:crypto";
import { validateOnboardingContract } from "./production-onboarding-contract.mjs";
import { assertNoOnboardingEvidenceLeak } from "./production-strict-onboarding.mjs";

// The probe adapter is the production smoke caller; strict mode rejects every
// skipped mandatory assertion rather than interpreting absence as success.
export async function produceOnboardingEvidence({ runStrictProbes, expectedSourceSha, expectedImageDigest, expectedTaskDefinitionArn, expectedTaskArn, expectedRotationId, expectedRotationStateSha256, expectedRotationFixtureSha256 } = {}) {
  if (typeof runStrictProbes !== "function") throw new Error("Strict onboarding probe adapter is required.");
  const evidence = await runStrictProbes({ sourceSha: expectedSourceSha, imageDigest: expectedImageDigest, taskDefinitionArn: expectedTaskDefinitionArn, taskArn: expectedTaskArn, rotationId: expectedRotationId, rotationStateSha256: expectedRotationStateSha256, rotationFixtureSha256: expectedRotationFixtureSha256, strict: true });
  assertNoOnboardingEvidenceLeak(evidence);
  if (evidence?.sourceSha !== expectedSourceSha || evidence?.imageDigest !== expectedImageDigest) throw new Error("Strict onboarding evidence identity does not match the deployment.");
  validateOnboardingContract(evidence);
  const bytes = Buffer.from(JSON.stringify(evidence));
  return { valid: true, evidenceRef: `onboarding:${expectedSourceSha}`, evidenceSha256: createHash("sha256").update(bytes).digest("hex"), evidence };
}

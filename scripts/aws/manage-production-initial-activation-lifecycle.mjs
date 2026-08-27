#!/usr/bin/env node
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import {
  buildInitialActivationClaim,
  buildInitialActivationCompletion,
  createInitialActivationClaim,
  createInitialActivationCompletion,
  createProductionInitialActivationAws,
  readInitialActivationClaim,
} from "./production-initial-activation-lifecycle.mjs";
import { canonicalJson } from "./production-green-stage-b-contract.mjs";
import {
  validateProductionInitialActivationClaimCandidateDuringAuthenticatedOverlap,
  validateProductionInitialActivationDuringAuthenticatedOverlap,
} from "../security/production-initial-overlap-activation-contract.mjs";
import { validateOnboardingContract } from "../security/production-onboarding-contract.mjs";
import { assertProductionRlsReleaseReceipt } from "./production-normal-backend-activation.mjs";

const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const args = (argv) => {
  const values = new Map();
  for (let i = 0; i < argv.length; i += 2) {
    if (!argv[i]?.startsWith("--") || !argv[i + 1] || argv[i + 1].startsWith("--") || values.has(argv[i])) throw new Error(`Invalid or duplicate argument: ${argv[i] || "<missing>"}`);
    values.set(argv[i], argv[i + 1]);
  }
  return values;
};
const required = (values, key) => { const value = values.get(key); if (!value) throw new Error(`${key} is required.`); return value; };
const writeCanonical = (file, value) => writeFileSync(file, `${canonicalJson(value)}\n`, { mode: 0o600, flag: "wx" });

export async function runCli(argv = process.argv.slice(2), dependencies = {}) {
  const values = args(argv);
  const mode = required(values, "--mode");
  const aws = dependencies.aws || (mode === "validate-candidate" ? undefined : createProductionInitialActivationAws({ credentialSource: required(values, "--credential-source") }));
  if (mode === "validate-candidate" || mode === "claim") {
    const rawState = readFileSync(required(values, "--state-file"));
    const expected = {
      sourceSha: required(values, "--source-sha"), rotationId: required(values, "--rotation-id"), deploymentSha: required(values, "--deployment-sha"),
      taskDefinitionArn: required(values, "--task-definition"), imageDigest: required(values, "--image-digest"),
    };
    const overlap = validateProductionInitialActivationClaimCandidateDuringAuthenticatedOverlap({ rawState, stateSha256: required(values, "--state-sha256"), expected });
    if (mode === "validate-candidate") {
      process.stdout.write(`${JSON.stringify({ contract: overlap.contract, overlapRuntimeProofSha256: overlap.overlapRuntimeProofSha256 })}\n`);
      return overlap;
    }
    const claim = buildInitialActivationClaim({ ...expected, overlapDeploymentSha: expected.deploymentSha, activationTaskDefinitionArn: required(values, "--activation-task-definition"), overlapRuntimeProofSha256: overlap.overlapRuntimeProofSha256, createdAt: dependencies.now?.() || new Date().toISOString() });
    const result = await createInitialActivationClaim({ claim, aws });
    writeCanonical(required(values, "--claim-out"), result.value);
    process.stdout.write(`${JSON.stringify({ status: result.status, claimSha256: result.sha256, claimVersionId: result.versionId, activationTransactionId: claim.activationTransactionId })}\n`);
    return result;
  }
  if (mode === "verify-claim") {
    const expected = JSON.parse(readFileSync(required(values, "--expected-identity"), "utf8"));
    const result = readInitialActivationClaim({ expected, aws });
    if (result.sha256 !== required(values, "--claim-sha256")) throw new Error("Production initial activation claim digest changed.");
    writeCanonical(required(values, "--claim-out"), result.value);
    return result;
  }
  if (mode === "complete") {
    const claimRaw = readFileSync(required(values, "--claim-file"));
    const claimSha256 = required(values, "--claim-sha256");
    if (sha256(claimRaw) !== claimSha256) throw new Error("Production initial activation claim digest is invalid.");
    const claim = JSON.parse(claimRaw);
    const liveClaim = readInitialActivationClaim({ expected: claim, aws });
    if (liveClaim.sha256 !== claimSha256) throw new Error("Production initial activation live claim digest changed.");
    const stateRaw = readFileSync(required(values, "--state-file"));
    const stateSha256 = required(values, "--state-sha256");
    (dependencies.validateOverlap || validateProductionInitialActivationDuringAuthenticatedOverlap)({
      rawState: stateRaw,
      stateSha256,
      claimRaw,
      claimSha256,
      expected: {
        sourceSha: claim.sourceSha,
        rotationId: claim.rotationId,
        deploymentSha: claim.overlapDeploymentSha,
        taskDefinitionArn: claim.taskDefinitionArn,
        imageDigest: claim.imageDigest,
      },
    });
    const receiptRaw = readFileSync(required(values, "--rls-receipt"));
    const onboardingRaw = readFileSync(required(values, "--onboarding-evidence"));
    const onboardingBundle = JSON.parse(onboardingRaw);
    const onboarding = onboardingBundle?.evidence;
    assertProductionRlsReleaseReceipt(JSON.parse(receiptRaw), { sourceSha: claim.sourceSha, imageDigest: claim.imageDigest });
    if (onboardingBundle?.valid !== true || onboardingBundle.evidenceRef !== `onboarding:${claim.sourceSha}`
      || onboardingBundle.evidenceSha256 !== sha256(Buffer.from(JSON.stringify(onboarding)))) throw new Error("Strict onboarding evidence bundle is invalid.");
    validateOnboardingContract(onboarding);
    if (onboarding.sourceSha !== claim.sourceSha || onboarding.rotationId !== claim.rotationId
      || onboarding.rotationStateSha256 !== stateSha256 || onboarding.taskDefinitionArn !== claim.activationTaskDefinitionArn
      || onboarding.imageDigest !== claim.imageDigest) throw new Error("Strict onboarding evidence is not bound to the activation claim and overlap runtime.");
    const completion = buildInitialActivationCompletion({ claim, claimSha256, claimVersionId: liveClaim.versionId, rlsReceiptSha256: sha256(receiptRaw), onboardingEvidenceSha256: sha256(onboardingRaw), completedAt: dependencies.now?.() || new Date().toISOString() });
    const result = await createInitialActivationCompletion({ completion, claim, claimSha256, claimVersionId: liveClaim.versionId, aws });
    process.stdout.write(`${JSON.stringify({ status: result.status, completionSha256: result.sha256, completionVersionId: result.versionId })}\n`);
    return result;
  }
  throw new Error("Production initial activation lifecycle mode is invalid.");
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) runCli().catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });

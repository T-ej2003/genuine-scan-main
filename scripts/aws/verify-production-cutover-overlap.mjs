#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { runPostOverlapVerification } from "./production-cutover-control-plane.mjs";
import { createProductionVerifierOnlyAdapters } from "./production-cutover-verifier-adapters.mjs";
import { promptProductionHiddenInput } from "../security/production-interactive-mfa-provider.mjs";
import { produceOnboardingEvidence } from "../security/produce-production-onboarding-evidence.mjs";
import { resolveProductionOverlapDeploymentReceipt } from "./production-overlap-deployment-receipt.mjs";
import { readAndAssertReadyForOverlapDeployment } from "./production-overlap-readiness-contract.mjs";
import { readFreshProtectedMainIdentity } from "./stage-b-deployment-identity.mjs";
import { readBoundStageBPrivateJson, readStageBPrivateFileBytes } from "./stage-b-artifact-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const required = (argv, name) => { const index = argv.indexOf(name); const value = index < 0 ? undefined : argv[index + 1]; if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const ONBOARDING_INPUTS = Object.freeze([
  Object.freeze({ name: "MSCQR_ONBOARDING_EMAIL", prompt: "Production strict-onboarding administrator email: " }),
  Object.freeze({ name: "MSCQR_ONBOARDING_PASSWORD", prompt: "Production strict-onboarding administrator password: " }),
  Object.freeze({ name: "MSCQR_CANARY_ORDINARY_EMAIL", prompt: "Production strict-onboarding tenant-canary email: " }),
  Object.freeze({ name: "MSCQR_CANARY_ORDINARY_PASSWORD", prompt: "Production strict-onboarding tenant-canary password: " }),
]);

const constructInheritedVerifierAdapters = (input) => createProductionVerifierOnlyAdapters(input);

export async function collectPostDeploymentOnboardingCredentials({ prompt = promptProductionHiddenInput } = {}) {
  const inputs = {};
  try {
    for (const { name, prompt: promptText } of ONBOARDING_INPUTS) {
      let supplied;
      try { supplied = await prompt({ prompt: promptText, validate: (value) => Boolean(value), errorMessage: `Interactive ${name} entry failed.` }); } catch { throw new Error(`Interactive ${name} entry failed.`); }
      if (typeof supplied !== "string") throw new Error(`Interactive ${name} entry failed.`);
      const value = supplied.trim();
      if (!value) throw new Error(`Interactive ${name} entry failed.`);
      inputs[name] = value;
    }
    return { email: inputs.MSCQR_ONBOARDING_EMAIL, password: inputs.MSCQR_ONBOARDING_PASSWORD, tenantEmail: inputs.MSCQR_CANARY_ORDINARY_EMAIL, tenantPassword: inputs.MSCQR_CANARY_ORDINARY_PASSWORD };
  } finally {
    for (const { name } of ONBOARDING_INPUTS) delete inputs[name];
  }
}

export function assertVerifierContinuationReceiptBindings({ receipt, authenticatedReadiness, sourceSha, rotationId, preparedStateSha256, readinessSha256, rotationFixtureSha256, config } = {}) {
  const authorizedTaskDefinitionArn = authenticatedReadiness?.evidence?.overlapTaskDefinition?.identityBindings?.taskDefinitionArn;
  if (typeof authorizedTaskDefinitionArn !== "string" || authorizedTaskDefinitionArn.trim() === "") throw new Error("Authenticated readiness does not bind the authorized overlap task definition.");
  for (const [field, expected] of Object.entries({ sourceSha, rotationId, rotationStateSha256: preparedStateSha256, readinessSha256, rotationFixtureSha256, expectedCurrentTaskDefinitionArn: config.expectedCurrentTaskDefinitionArn, taskDefinitionArn: authorizedTaskDefinitionArn, imageDigest: config.backendImageDigest, deploymentSha: config.rotationDeploymentSha })) {
    if (receipt[field] !== expected) throw new Error(`Verifier continuation ${field} binding is wrong.`);
  }
  return authorizedTaskDefinitionArn;
}

export async function verifyProductionCutoverOverlap({ configFile, configSha256, sourceSha, rotationId, workflowRunId, workflowRunAttempt, githubRun = (command, args) => execFileSync(command, args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }), protectedMain = readFreshProtectedMainIdentity, constructAdapters = constructInheritedVerifierAdapters, collectOnboardingCredentials = collectPostDeploymentOnboardingCredentials } = {}) {
  protectedMain({ cwd: root, expectedSourceSha: sourceSha });
  const config = readBoundStageBPrivateJson({ filePath: configFile, expectedSha256: configSha256, repositoryRoot: root, label: "Production cutover runtime config" });
  if (config.sourceSha !== sourceSha || config.rotationId !== rotationId) throw new Error("Verifier continuation config identity is wrong.");
  const state = readStageBPrivateFileBytes({ filePath: config.rotationStateFile, repositoryRoot: root, label: "Persisted rotation state" });
  const stateValue = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(state.bytes));
  const preparedStateSha256 = ["overlap-ready", "verified"].includes(stateValue.phase)
    ? stateValue.verification?.preparedStateSha256
    : state.sha256;
  if (!/^[a-f0-9]{64}$/.test(preparedStateSha256 || "")) throw new Error("Verifier continuation prepared-state predecessor binding is missing.");
  const fixture = readStageBPrivateFileBytes({ filePath: config.rotationFixtureFile, repositoryRoot: root, label: "Persisted rotation fixture" });
  const readiness = readStageBPrivateFileBytes({ filePath: config.readinessEvidenceFile, repositoryRoot: root, label: "Persisted overlap readiness" });
  const authenticatedReadiness = readAndAssertReadyForOverlapDeployment({ filePath: config.readinessEvidenceFile, evidenceSha256: readiness.sha256, sourceSha, rotationId, rotationStateSha256: preparedStateSha256 });
  const resolved = resolveProductionOverlapDeploymentReceipt({ workflowRunId, workflowRunAttempt, sourceSha, run: githubRun });
  const receipt = resolved.receipt;
  assertVerifierContinuationReceiptBindings({ receipt, authenticatedReadiness, sourceSha, rotationId, preparedStateSha256, readinessSha256: readiness.sha256, rotationFixtureSha256: fixture.sha256, config });
  const adapters = constructAdapters({ config, sourceSha, rotationId, runtimeConfigSha256: configSha256 });
  const identities = await adapters.identities.establish();
  if (!/^arn:aws:sts::368992683803:assumed-role\/mscqr-production-ecs-exec-verifier\//.test(identities.verifier?.callerArn || "") || /^arn:aws:sts::368992683803:assumed-role\/mscqr-production-release-deployer\//.test(identities.verifier?.callerArn || "")) throw new Error("Independent MFA verifier identity is required.");
  const persistedProof = ["overlap-ready", "verified"].includes(stateValue.phase) ? stateValue.overlapRuntime : null;
  const resumePersistedProof = Boolean(persistedProof);
  if (resumePersistedProof && (persistedProof.rotationId !== rotationId || persistedProof.phase !== "overlap" || persistedProof.deploymentSha !== receipt.deploymentSha || persistedProof.targetTaskDefinitionArn !== receipt.taskDefinitionArn || persistedProof.targetImageDigest !== receipt.imageDigest || typeof persistedProof.targetTaskArn !== "string" || persistedProof.serviceHealthy !== true || typeof persistedProof.runtimeInvocationRef !== "string" || stateValue.verification?.runtimeInvocationRef !== persistedProof.runtimeInvocationRef)) throw new Error("Persisted overlap proof is not bound to the authorized deployment receipt.");
  if (resumePersistedProof) adapters.onboarding.bindPersistedEcsExecProof(persistedProof);
  const result = await runPostOverlapVerification({ deployment: { updateServiceCount: resumePersistedProof ? 0 : 1, propagateTags: "TASK_DEFINITION", taskDefinitionArn: receipt.taskDefinitionArn, receipt, ...(resumePersistedProof ? { resumePersistedProof: true, persistedDeployed: { valid: true, taskArn: persistedProof.targetTaskArn, taskDefinitionArn: persistedProof.targetTaskDefinitionArn, imageDigest: persistedProof.targetImageDigest, taskTag: "MSCQRExecTarget=production-backend" }, persistedExecProof: { valid: true, proof: persistedProof } } : {}) }, sourceSha, rotationId, rotationStateSha256: preparedStateSha256, rotationFixtureSha256: fixture.sha256, taskDefinitionArn: receipt.taskDefinitionArn, expectedImageDigest: receipt.imageDigest, verifierSession: identities.verifier.session, postDeploy: adapters.postDeploy, ecsExec: adapters.ecsExec, rotationVerify: adapters.rotationPrepare.verifyOverlap });
  const credentials = await collectOnboardingCredentials();
  let onboarding;
  try {
    onboarding = await produceOnboardingEvidence({ runStrictProbes: (expected) => adapters.onboarding.run({ credentials, ...expected }), expectedSourceSha: sourceSha, expectedImageDigest: receipt.imageDigest, expectedTaskDefinitionArn: receipt.taskDefinitionArn, expectedTaskArn: result.deployed.taskArn, expectedRotationId: rotationId, expectedRotationStateSha256: result.verified.rotationStateSha256, expectedRotationFixtureSha256: fixture.sha256 });
  } finally {
    for (const name of Object.keys(credentials)) delete credentials[name];
  }
  return { terminalState: result.terminalState, readyForOnboarding: onboarding.valid, onboardingEvidenceSha256: onboarding.evidenceSha256, workflowRunId: String(workflowRunId), workflowRunAttempt: String(workflowRunAttempt), receiptArtifactId: resolved.artifact.id, receiptArtifactDigest: resolved.artifact.digest, receiptSha256: receipt.receiptSha256, reviewer: resolved.reviewer, tailFailures: resolved.tailFailures, rotationId, overlapReadyAt: result.verified.overlapReadyAt, cleanupEligibleAt: result.verified.cleanupEligibleAt, updateServiceCount: 0 };
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  verifyProductionCutoverOverlap({ configFile: required(process.argv, "--config"), configSha256: required(process.argv, "--config-sha256"), sourceSha: required(process.argv, "--source-sha"), rotationId: required(process.argv, "--rotation-id"), workflowRunId: required(process.argv, "--workflow-run-id"), workflowRunAttempt: required(process.argv, "--workflow-run-attempt") })
    .then((result) => process.stdout.write(`${JSON.stringify(result)}\n`))
    .catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
}

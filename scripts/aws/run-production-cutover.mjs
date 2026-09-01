#!/usr/bin/env node
import { createProductionCommandRunner, createProductionOverlapDeploymentAdapter, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-cutover-production-adapters.mjs";
import { createProductionCutoverRuntimeComposition } from "./production-cutover-runtime-composition.mjs";
import { PRODUCTION_CUTOVER_MODE, runProductionCutoverControlPlane, runProductionCutoverOverlapControlPlane } from "./production-cutover-control-plane.mjs";
import { readAndAssertReadyForOverlapDeployment } from "./production-overlap-readiness-contract.mjs";
import { buildProductionOverlapDeploymentReceipt, persistProductionOverlapDeploymentReceipt, readProductionOverlapDeploymentReceipt } from "./production-overlap-deployment-receipt.mjs";
import { readBoundStageBPrivateJson, readStageBPrivateFileBytes } from "./stage-b-artifact-contract.mjs";

const argv = process.argv.slice(2);
const value = (name) => { const index = argv.indexOf(name); if (index < 0 || !argv[index + 1] || argv[index + 1].startsWith("--")) throw new Error(`${name} is required`); return argv[index + 1]; };
const optionalValue = (name) => { const index = argv.indexOf(name); return index < 0 || !argv[index + 1] || argv[index + 1].startsWith("--") ? undefined : argv[index + 1]; };
const mode = value("--mode");
if (mode === "rotation-overlap") {
  const credentialSource = value("--credential-source");
  if (credentialSource !== "github-oidc-release-deployer") throw new Error("Rotation overlap requires the source-bound GitHub OIDC release-deployer credential source.");
  const sourceSha = value("--source-sha");
  const transitionMode = value("--transition-mode");
  if (!new Set(["rotation-overlap", "rotation-cleanup"]).has(transitionMode)) throw new Error("Unsupported governed rotation transition mode.");
  const rotationId = value("--rotation-id");
  const rotationStateSha256 = value("--rotation-state-sha256");
  const taskDefinitionArn = value("--task-definition");
  const readinessFile = value("--readiness-file");
  const readinessSha256 = value("--readiness-sha256");
  const rotationFixtureSha256 = optionalValue("--rotation-fixture-sha256");
  const environmentApprovalFile = optionalValue("--environment-approval");
  const environmentApprovalSha256 = optionalValue("--environment-approval-sha256");
  const receiptOutput = optionalValue("--deployment-receipt-output");
  const readiness = readAndAssertReadyForOverlapDeployment({ filePath: readinessFile, evidenceSha256: readinessSha256, sourceSha, rotationId, rotationStateSha256 });
  const authorizedTaskDefinitionArn = readiness.evidence?.overlapTaskDefinition?.identityBindings?.taskDefinitionArn;
  if (typeof authorizedTaskDefinitionArn !== "string" || taskDefinitionArn !== authorizedTaskDefinitionArn) throw new Error("Rotation overlap task definition is not the exact authenticated readiness candidate.");
  const run = createProductionCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER });
  const receiptEnabled = [rotationFixtureSha256, environmentApprovalFile, environmentApprovalSha256, receiptOutput].every(Boolean);
  if ([rotationFixtureSha256, environmentApprovalFile, environmentApprovalSha256, receiptOutput].some(Boolean) && !receiptEnabled) throw new Error("Overlap deployment receipt inputs must be supplied together.");
  if (transitionMode === "rotation-overlap" && !receiptEnabled) throw new Error("Rotation overlap requires authenticated deployment receipt inputs.");
  if (transitionMode === "rotation-cleanup" && receiptEnabled) throw new Error("Rotation cleanup cannot publish an overlap deployment receipt.");
  const receiptExpected = { sourceSha, rotationId, rotationStateSha256, readinessSha256, rotationFixtureSha256, taskDefinitionArn, imageDigest: process.env.EXPECTED_IMAGE_DIGEST, deploymentSha: process.env.ROTATION_DEPLOYMENT_SHA, workflowRunId: process.env.GITHUB_RUN_ID, workflowRunAttempt: process.env.GITHUB_RUN_ATTEMPT };
  const deploymentReceipt = receiptEnabled ? (() => { const environmentApproval = readBoundStageBPrivateJson({ filePath: environmentApprovalFile, expectedSha256: environmentApprovalSha256, label: "Production environment approval evidence" }); return { persist: async ({ deployment }) => { const receipt = buildProductionOverlapDeploymentReceipt({ ...receiptExpected, environmentApproval, deployment, expectedCurrentTaskDefinitionArn: process.env.EXPECTED_CURRENT_TASK_DEFINITION_ARN, deployedAt: new Date().toISOString() }); return { ...persistProductionOverlapDeploymentReceipt({ outputPath: receiptOutput, receipt }), receipt }; }, authenticate: async ({ receipt }) => readProductionOverlapDeploymentReceipt({ filePath: receiptOutput, receiptSha256: readStageBPrivateFileBytes({ filePath: receiptOutput, label: "Overlap deployment receipt" }).sha256, ...receiptExpected }) }; })() : undefined;
  const result = await runProductionCutoverOverlapControlPlane({ readiness: readiness.evidence, sourceSha, rotationId, rotationStateSha256, taskDefinitionArn, readinessSha256, deployOverlap: createProductionOverlapDeploymentAdapter({ run, credentialSource, readinessFile, readinessSha256, sourceSha, rotationId, imageDigest: process.env.EXPECTED_IMAGE_DIGEST, cluster: process.env.CLUSTER_NAME, service: process.env.SERVICE_NAME, expectedCurrentTaskDefinitionArn: process.env.EXPECTED_CURRENT_TASK_DEFINITION_ARN, versionUrl: process.env.VERSION_URL, expectedGitSha: process.env.EXPECTED_GIT_SHA }), deploymentReceipt, transitionMode });
  process.stdout.write(`${JSON.stringify({ terminalState: result.terminalState || "DEPLOYED", ...(result.deploymentReceipt ? { deploymentReceiptSha256: result.deploymentReceipt.receiptSha256 } : {}), taskDefinitionArn: result.deployment.taskDefinitionArn, propagateTags: result.deployment.propagateTags, updateServiceCount: result.deployment.updateServiceCount, mutationSequence: result.mutationSequence })}\n`);
} else {
const config = readBoundStageBPrivateJson({ filePath: value("--config"), expectedSha256: value("--config-sha256"), label: "Production cutover runtime config" });
if (!["production", "prepare-overlap"].includes(mode)) throw new Error("Unsupported production cutover mode.");
const sourceSha = value("--source-sha");
const rotationId = value("--rotation-id");
if (optionalValue("--rotation-state-sha256")) throw new Error("Full cutover mode must consume the rotation state SHA generated by rotation preparation.");
const runtimeConfigSha256 = value("--config-sha256");
const adapters = createProductionCutoverRuntimeComposition().constructAdapters({ config, sourceSha, rotationId, runtimeConfigSha256 });
const result = await runProductionCutoverControlPlane({
  mode: mode === "prepare-overlap" ? PRODUCTION_CUTOVER_MODE.PREPARE_OVERLAP : PRODUCTION_CUTOVER_MODE.FULL,
  sourceSha,
  rotationId,
  imageAuthorization: readBoundStageBPrivateJson({ filePath: config.imageAuthorizationFile, expectedSha256: config.imageAuthorizationSha256, label: "Image authorization evidence" }),
  ...adapters,
});
process.stdout.write(`${JSON.stringify(mode === "prepare-overlap"
  ? { preparedForOverlapAuthorization: true, sourceSha, rotationId, rotationStateFile: config.rotationStateFile, rotationStateSha256: result.rotationStateSha256, rotationFixtureSha256: result.rotationFixtureSha256, taskDefinitionArn: result.taskDefinitionArn, expectedCurrentTaskDefinitionArn: config.expectedCurrentTaskDefinitionArn, imageDigest: config.backendImageDigest, deploymentSha: config.rotationDeploymentSha, readinessFile: result.readinessFile, readinessSha256: result.readinessSha256, ecsUpdateServiceCount: 0, mutationSequence: result.mutationSequence }
  : { readyForOnboarding: result.readyForOnboarding, mutationSequence: result.mutationSequence, transitionMatrix: result.transitionMatrix, readiness: result.readiness, onboardingEvidence: { valid: result.onboardingEvidence.valid, evidenceRef: result.onboardingEvidence.evidenceRef, evidenceSha256: result.onboardingEvidence.evidenceSha256 } })}\n`);
}

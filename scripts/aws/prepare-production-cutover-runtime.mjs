#!/usr/bin/env node
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { createProductionCutoverRuntimeComposition } from "./production-cutover-runtime-composition.mjs";
import { createProductionGithubCommandRunner } from "./production-credential-source-contract.mjs";
import { ensureStageBPrivateDirectory, readStageBPrivateFileBytes } from "./stage-b-artifact-contract.mjs";
import { parseBootstrapArgs, prepareProductionCutoverRuntime } from "./production-cutover-runtime-bootstrap.mjs";
import { REBASELINE_ABANDONED_HISTORICAL_TOPOLOGY_SHA256, resolvePartialRebaselineRecoveryAuthorizationArtifact, resolveProductionDualSlotRebaselineAuthorizationArtifact, verifyLiveProductionDualSlotRebaselineWithRunner } from "./production-dual-slot-rebaseline-contract.mjs";
import { verifyLiveInitialDualSlotBindingWithRunner } from "./production-initial-dual-slot-bootstrap.mjs";

const args = parseBootstrapArgs(process.argv.slice(2));
const required = (name) => { const value = args.get(name); if (!value) throw new Error(`--${name} is required.`); return value; };
const outputDirectory = args.get("output-directory") || path.join(os.homedir(), ".mscqr", "production-cutover", Date.now().toString(36));
const capture = (name, label = name) => readStageBPrivateFileBytes({ filePath: required(name), repositoryRoot: process.cwd(), label });
const read = (name, label) => JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(capture(name, label).bytes));
const imageAuthorizationPath = required("image-authorization");
const iamEvidencePath = required("iam-evidence");
const iamEvidenceSignaturePath = required("iam-evidence-signature");
const releasePreflightEvidencePath = required("release-preflight-evidence");
const releasePreflightAttestationPath = required("release-preflight-attestation");
const releasePreflightAttestationSignaturePath = required("release-preflight-attestation-signature");
const temporaryKmsCapabilityPath = args.get("temporary-kms-capability");
const imageAuthorization = read("image-authorization", "Image authorization evidence");
const iamEvidence = read("iam-evidence", "IAM evidence");
capture("iam-evidence-signature", "Administrator capability evidence signature");
capture("release-preflight-evidence", "Release-preflight checker-trust evidence");
capture("release-preflight-attestation", "Release-preflight checker-trust attestation");
capture("release-preflight-attestation-signature", "Release-preflight checker-trust attestation signature");
if (temporaryKmsCapabilityPath) readStageBPrivateFileBytes({ filePath: temporaryKmsCapabilityPath, repositoryRoot: process.cwd(), label: "Temporary Stage-A KMS capability evidence" });
for (const [name, label] of [["artifact-binding", "Artifact-signing runtime binding"], ["root-drop-evidence", "Root-drop evidence"], ["stage-a-plan", "Preserved Stage-A saved plan"], ["stage-a-recovery-evidence", "Stage-A recovery evidence"], ["stage-a-state", "Stage-A state"], ["stage-a-handoff", "Stage-A handoff"], ["stage-b-state", "Historical Stage-B state"], ["current-stage-b-state", "Current Stage-B state"], ["stage-b-tfvars", "Canonical Stage B tfvars"], ["stage-b-tfvars-binding-report", "Canonical Stage B tfvars binding report"]]) if (args.has(name)) capture(name, label);
const rotationBindingCapture = args.has("rotation-bindings") ? capture("rotation-bindings", "Rotation secret binding manifest") : null;
const rotationSupersessionCapture = args.has("rotation-supersession-evidence") ? capture("rotation-supersession-evidence", "Rotation supersession evidence") : null;
const recoveryEnvelopeCapture = args.has("recovery-envelope") ? capture("recovery-envelope", "Partial rebaseline recovery envelope") : null;
const originalPreparationCapture = args.has("original-rebaseline-preparation") ? capture("original-rebaseline-preparation", "Original dual-slot rebaseline preparation") : null;
if (Boolean(recoveryEnvelopeCapture) !== Boolean(originalPreparationCapture)) throw new Error("Recovery runtime consumption requires both anchored recovery evidence files.");
if (args.has("onboarding-paths")) capture("onboarding-paths", "Onboarding path manifest");
ensureStageBPrivateDirectory({ directory: required("stage-b-terraform-data-dir"), repositoryRoot: process.cwd(), create: false, label: "Canonical Stage B Terraform data directory" });
iamEvidence.filePath = path.resolve(required("iam-evidence"));
imageAuthorization.filePath = path.resolve(required("image-authorization"));
const decode = (captured) => JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(captured.bytes));
const rotationBindings = rotationBindingCapture ? decode(rotationBindingCapture) : undefined;
const rotationSupersessionEvidence = rotationSupersessionCapture ? decode(rotationSupersessionCapture) : undefined;
if (rotationBindings?.abandonmentEvidence?.historicalTopologySha256 !== undefined && rotationBindings.abandonmentEvidence.historicalTopologySha256 !== REBASELINE_ABANDONED_HISTORICAL_TOPOLOGY_SHA256) throw new Error("Rebaseline rotation bindings do not contain the protected-source abandoned topology identity.");
if (rotationBindings?.abandonmentEvidence?.historicalTopologySha256 === undefined && args.has("rebaseline-authorization-run-id")) throw new Error("Rebaseline authorization coordinates cannot be supplied without authenticated rebaseline evidence.");
const rebaselineAuthorizationCoordinates = args.has("rebaseline-authorization-run-id") || args.has("rebaseline-authorization-run-attempt")
  ? { workflowRunId: required("rebaseline-authorization-run-id"), workflowRunAttempt: required("rebaseline-authorization-run-attempt") }
  : undefined;
const composition = createProductionCutoverRuntimeComposition();
const { releaseRun } = composition;
const recoveryEnvelope = recoveryEnvelopeCapture ? decode(recoveryEnvelopeCapture) : undefined;
const originalPreparation = originalPreparationCapture ? decode(originalPreparationCapture) : undefined;
const proveRecoveryDescendant = ({ ancestorSha, descendantSha }) => {
  try { execFileSync("git", ["merge-base", "--is-ancestor", ancestorSha, descendantSha], { stdio: "ignore" }); return true; } catch { return false; }
};
const rebaselineAuthorization = rebaselineAuthorizationCoordinates
  ? recoveryEnvelope
    ? resolvePartialRebaselineRecoveryAuthorizationArtifact({
      ...rebaselineAuthorizationCoordinates, sourceSha: rotationBindings.sourceSha, recoveryEnvelope, imageAuthorization,
      imageAuthorizationValidation: composition.imageAuthorizationValidation, proveDescendant: proveRecoveryDescendant, run: createProductionGithubCommandRunner(),
    }).authorization
    : resolveProductionDualSlotRebaselineAuthorizationArtifact({
    ...rebaselineAuthorizationCoordinates,
    sourceSha: rotationBindings.sourceSha, rotationId: rotationBindings.rotationId,
    resources: { jwtPending: rotationBindings.jwt.pendingSecretId, qrPrivatePending: rotationBindings.qr.privatePendingSecretId, qrPublicPending: rotationBindings.qr.publicPendingSecretId, jwtPrevious: rotationBindings.jwt.previousSecretId, qrPublicPrevious: rotationBindings.qr.publicPreviousSecretId, qrCurrentVersion: rotationBindings.qr.currentKeyVersionSecretId, qrPreviousVersion: rotationBindings.qr.previousKeyVersionSecretId },
    run: createProductionGithubCommandRunner(),
  }).authorization
  : undefined;
const onboardingPaths = args.has("onboarding-paths") ? read("onboarding-paths") : undefined;
const verifyRebaselineLivePostWrite = rebaselineAuthorizationCoordinates
  ? ({ bindings, authorization }) => verifyLiveProductionDualSlotRebaselineWithRunner({ run: releaseRun, bindings, authorization, recoveryEnvelope, originalPreparation, imageAuthorization, proveDescendant: proveRecoveryDescendant })
  : undefined;
const verifyInitialBindingOrigin = ({ bindings }) => verifyLiveInitialDualSlotBindingWithRunner({ run: releaseRun, bindings });
const loadCurrentTaskDefinition = () => {
  const currentService = JSON.parse(releaseRun(["ecs", "describe-services", "--cluster", "mscqr-prod-euw2-main", "--services", "mscqr-backend-servi-euw2"])).services?.[0];
  if (!currentService?.taskDefinition) throw new Error("Current production task definition is unavailable.");
  return JSON.parse(releaseRun(["ecs", "describe-task-definition", "--task-definition", currentService.taskDefinition, "--include", "TAGS"]));
};
const approval = {
  ticket: required("ticket"),
  approvedBy: required("approved-by"),
  approverRole: required("approver-role"),
  reason: required("reason"),
  verificationRef: required("verification-ref"),
  minimumGraceSeconds: Number(required("minimum-grace-seconds")),
};
const result = prepareProductionCutoverRuntime({
  outputDirectory,
  approval,
  rotationBindings,
  rebaselineAuthorization,
  rebaselineAuthorizationCoordinates,
  recoveryEnvelope,
  originalPreparation,
  proveRecoveryDescendant,
  verifyRebaselineLivePostWrite,
  verifyInitialBindingOrigin,
  rotationSupersessionEvidence,
  rotationId: rotationBindings?.rotationId,
  imageAuthorization,
  iamEvidence,
  iamEvidenceSignatureFile: path.resolve(iamEvidenceSignaturePath),
  releasePreflightEvidenceFile: path.resolve(releasePreflightEvidencePath),
  releasePreflightAttestationFile: path.resolve(releasePreflightAttestationPath),
  releasePreflightAttestationSignatureFile: path.resolve(releasePreflightAttestationSignaturePath),
  artifactBindingFile: required("artifact-binding"),
  rootDropEvidenceFile: required("root-drop-evidence"),
  temporaryKmsCapabilityFile: temporaryKmsCapabilityPath,
  stageAPlanPath: args.get("stage-a-plan"),
  stageARecoveryEvidenceFile: args.get("stage-a-recovery-evidence"),
  stageAStatePath: args.get("stage-a-state"),
  stageAHandoffPath: args.get("stage-a-handoff"),
  stageBStatePath: args.get("stage-b-state"),
  currentStageBStatePath: args.get("current-stage-b-state"),
  loadCurrentTaskDefinition,
  inventoryApprovalId: args.get("inventory-approval-id"),
  inventoryTaskDefinitionArn: args.get("inventory-task-definition-arn"),
  onboardingPaths,
  stageBTfvarsPath: required("stage-b-tfvars"),
  stageBTfvarsBindingReportPath: required("stage-b-tfvars-binding-report"),
  stageBTfvarsBindingReportSha256: required("stage-b-tfvars-binding-report-sha256"),
  stageBTerraformDataDir: required("stage-b-terraform-data-dir"),
  ...composition,
});
process.stdout.write(`${JSON.stringify({
  RUNTIME_DIRECTORY: result.runtimeDirectory,
  ROTATION_CONFIG: result.configPath || null,
  ROTATION_CONFIG_SHA256: result.runtimeConfigSha256 || null,
  STATIC_BINDING_SHA256: result.staticBindingSha256 || null,
  PROTECTED_MAIN_SHA: result.protectedMainSha,
  READY_TO_CONSUME_MFA: result.readyToConsumeMfa,
  FIRST_BLOCKER: result.blockers?.[0] || null,
  NEXT_COMMAND: result.nextCommand || null,
}, null, 2)}\n`);

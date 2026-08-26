#!/usr/bin/env node
import os from "node:os";
import path from "node:path";
import { createProductionCommandRunner, createProductionCutoverAdapters } from "./production-cutover-production-adapters.mjs";
import { ensureStageBPrivateDirectory, readStageBPrivateFileBytes } from "./stage-b-artifact-contract.mjs";
import { parseBootstrapArgs, prepareProductionCutoverRuntime } from "./production-cutover-runtime-bootstrap.mjs";

const args = parseBootstrapArgs(process.argv.slice(2));
const required = (name) => { const value = args.get(name); if (!value) throw new Error(`--${name} is required.`); return value; };
const outputDirectory = args.get("output-directory") || path.join(os.homedir(), ".mscqr", "production-cutover", Date.now().toString(36));
const capture = (name, label = name) => readStageBPrivateFileBytes({ filePath: required(name), repositoryRoot: process.cwd(), label });
const read = (name, label) => JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(capture(name, label).bytes));
const imageAuthorizationPath = required("image-authorization");
const iamEvidencePath = required("iam-evidence");
const temporaryKmsCapabilityPath = args.get("temporary-kms-capability");
const imageAuthorization = read("image-authorization", "Image authorization evidence");
const iamEvidence = read("iam-evidence", "IAM evidence");
if (temporaryKmsCapabilityPath) readStageBPrivateFileBytes({ filePath: temporaryKmsCapabilityPath, repositoryRoot: process.cwd(), label: "Temporary Stage-A KMS capability evidence" });
for (const [name, label] of [["artifact-binding", "Artifact-signing runtime binding"], ["root-drop-evidence", "Root-drop evidence"], ["stage-a-plan", "Preserved Stage-A saved plan"], ["stage-a-recovery-evidence", "Stage-A recovery evidence"], ["stage-a-state", "Stage-A state"], ["stage-a-handoff", "Stage-A handoff"], ["stage-b-state", "Historical Stage-B state"], ["current-stage-b-state", "Current Stage-B state"], ["stage-b-tfvars", "Canonical Stage B tfvars"], ["stage-b-tfvars-binding-report", "Canonical Stage B tfvars binding report"]]) if (args.has(name)) capture(name, label);
const rotationBindingCapture = args.has("rotation-bindings") ? capture("rotation-bindings", "Rotation secret binding manifest") : null;
const rotationSupersessionCapture = args.has("rotation-supersession-evidence") ? capture("rotation-supersession-evidence", "Rotation supersession evidence") : null;
if (args.has("onboarding-paths")) capture("onboarding-paths", "Onboarding path manifest");
ensureStageBPrivateDirectory({ directory: required("stage-b-terraform-data-dir"), repositoryRoot: process.cwd(), create: false, label: "Canonical Stage B Terraform data directory" });
iamEvidence.filePath = path.resolve(required("iam-evidence"));
imageAuthorization.filePath = path.resolve(required("image-authorization"));
const decode = (captured) => JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(captured.bytes));
const rotationBindings = rotationBindingCapture ? decode(rotationBindingCapture) : undefined;
const rotationSupersessionEvidence = rotationSupersessionCapture ? decode(rotationSupersessionCapture) : undefined;
const onboardingPaths = args.has("onboarding-paths") ? read("onboarding-paths") : undefined;
const loadCurrentTaskDefinition = () => {
  const run = createProductionCommandRunner({ profile: "mscqr-production-release-deployer" });
  const currentService = JSON.parse(run(["ecs", "describe-services", "--cluster", "mscqr-prod-euw2-main", "--services", "mscqr-backend-servi-euw2"])).services?.[0];
  if (!currentService?.taskDefinition) throw new Error("Current production task definition is unavailable.");
  return JSON.parse(run(["ecs", "describe-task-definition", "--task-definition", currentService.taskDefinition, "--include", "TAGS"]));
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
  rotationBindingsSha256: rotationBindingCapture?.sha256,
  rotationSupersessionEvidence,
  rotationSupersessionEvidenceSha256: rotationSupersessionCapture?.sha256,
  rotationId: rotationBindings?.rotationId,
  imageAuthorization,
  iamEvidence,
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
  onboardingPaths,
  stageBTfvarsPath: required("stage-b-tfvars"),
  stageBTfvarsBindingReportPath: required("stage-b-tfvars-binding-report"),
  stageBTfvarsBindingReportSha256: required("stage-b-tfvars-binding-report-sha256"),
  stageBTerraformDataDir: required("stage-b-terraform-data-dir"),
  constructAdapters: ({ config, sourceSha, rotationId, runtimeConfigSha256 }) => createProductionCutoverAdapters({ config, sourceSha, rotationId, runtimeConfigSha256 }),
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

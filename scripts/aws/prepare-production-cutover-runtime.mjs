#!/usr/bin/env node
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createProductionCommandRunner, createProductionCutoverAdapters } from "./production-cutover-production-adapters.mjs";
import { ensureStageBPrivateFile } from "./stage-b-artifact-contract.mjs";
import { parseBootstrapArgs, prepareProductionCutoverRuntime } from "./production-cutover-runtime-bootstrap.mjs";

const args = parseBootstrapArgs(process.argv.slice(2));
const required = (name) => { const value = args.get(name); if (!value) throw new Error(`--${name} is required.`); return value; };
const outputDirectory = args.get("output-directory") || path.join(os.homedir(), ".mscqr", "production-cutover", Date.now().toString(36));
const read = (name) => JSON.parse(fs.readFileSync(required(name), "utf8"));
const run = createProductionCommandRunner({ profile: "mscqr-production-release-deployer" });
const currentService = JSON.parse(run(["ecs", "describe-services", "--cluster", "mscqr-prod-euw2-main", "--services", "mscqr-backend-servi-euw2"])).services?.[0];
if (!currentService?.taskDefinition) throw new Error("Current production task definition is unavailable.");
const currentTaskDefinition = JSON.parse(run(["ecs", "describe-task-definition", "--task-definition", currentService.taskDefinition, "--include", "TAGS"]));
const imageAuthorizationPath = required("image-authorization");
const iamEvidencePath = required("iam-evidence");
ensureStageBPrivateFile({ filePath: imageAuthorizationPath, repositoryRoot: process.cwd(), label: "Image authorization evidence" });
ensureStageBPrivateFile({ filePath: iamEvidencePath, repositoryRoot: process.cwd(), label: "IAM evidence" });
const imageAuthorization = read("image-authorization");
const iamEvidence = read("iam-evidence");
iamEvidence.filePath = path.resolve(required("iam-evidence"));
imageAuthorization.filePath = path.resolve(required("image-authorization"));
const rotationBindings = args.has("rotation-bindings") ? read("rotation-bindings") : undefined;
const onboardingPaths = args.has("onboarding-paths") ? read("onboarding-paths") : undefined;
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
  rotationId: rotationBindings?.rotationId,
  imageAuthorization,
  iamEvidence,
  artifactBindingFile: required("artifact-binding"),
  rootDropEvidenceFile: required("root-drop-evidence"),
  stageAPlanPath: required("stage-a-plan"),
  currentTaskDefinition,
  inventoryApprovalId: args.get("inventory-approval-id"),
  onboardingPaths,
  constructAdapters: ({ config, sourceSha, rotationId }) => createProductionCutoverAdapters({ config, sourceSha, rotationId }),
});
process.stdout.write(`${JSON.stringify({
  RUNTIME_DIRECTORY: result.runtimeDirectory,
  ROTATION_CONFIG: result.configPath || null,
  STATIC_BINDING_SHA256: result.staticBindingSha256 || null,
  PROTECTED_MAIN_SHA: result.protectedMainSha,
  READY_TO_CONSUME_MFA: result.readyToConsumeMfa,
  FIRST_BLOCKER: result.blockers?.[0] || null,
  NEXT_COMMAND: result.nextCommand || null,
}, null, 2)}\n`);

#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createProductionAwsCommandRunner, createProductionAwsCredentialEnvironment, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, ensureStageBPrivateFile, readBoundStageBPrivateJson, readStageBPrivateFileBytes, writeStageBPrivateFileExclusive } from "./stage-b-artifact-contract.mjs";
import { STAGE_B_TERRAFORM_BACKEND_CONFIG, assertStageBTerraformInitializedBackendMetadata, readStageBTerraformStateIdentity, writeStageBTerraformStateBackup } from "./stage-b-terraform-backend-contract.mjs";
import { readStageBProtectedMainCheckout, assertStageBProtectedCheckoutMatchesDeploymentIdentity } from "./stage-b-deployment-identity.mjs";
import { assertStageBTfvarsBinding } from "./generate-production-green-stage-b-tfvars.mjs";
import { assertExactStageBRefreshOnlyPlan, assertStageBStateReconciliationSourceAlignment, createStageBOutputOnlyEvidence, createStageBStateReconciliationPreparation, executeStageBStateReconciliation, STAGE_B_STATE_RECONCILIATION, STAGE_B_STATE_RECONCILIATION_MODES } from "./production-green-stage-b-state-reconciliation.mjs";
import { materializeStageBPrerequisites, writeStageBRuntimeMaterialization } from "./stage-b-prerequisite-bundle.mjs";
import { captureStageBTerraformJson } from "./capture-stage-b-terraform-json.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const terraformRoot = STAGE_B_STATE_RECONCILIATION.terraformRoot;
const hash = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const required = (argv, name) => { const index = argv.indexOf(name); const value = index < 0 ? undefined : argv[index + 1]; if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const exactArgs = (argv, allowed) => { const seen = new Set(); for (let index = 0; index < argv.length; index += 2) if (!allowed.has(argv[index]) || seen.has(argv[index]) || !argv[index + 1] || argv[index + 1].startsWith("--")) throw new Error("Stage B state reconciliation CLI arguments are not exact."); else seen.add(argv[index]); };
export function runStageBStateReconciliationTerraform(args, env, spawn = spawnSync) {
  const result = spawn("terraform", [`-chdir=${terraformRoot}`, ...args], { cwd: root, env, stdio: ["ignore", "inherit", "inherit"] });
  if (result.error) throw new Error(`Stage B state reconciliation Terraform failed to start: ${result.error.code || result.error.message}`);
  if (result.signal) throw new Error(`Stage B state reconciliation Terraform terminated by ${result.signal}.`);
  if (result.status !== 0) throw new Error(`Stage B state reconciliation Terraform failed with exit ${result.status}.`);
}
const privateJson = (filePath, expectedSha256, label) => readBoundStageBPrivateJson({ filePath: path.resolve(filePath), expectedSha256, repositoryRoot: root, label });
const stateIdentity = (run) => readStageBTerraformStateIdentity(run);
const outputOnlyEvidence = (run) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-b-output-only-"));
  let bytes;
  try {
    const output = path.join(directory, "terraform.tfstate");
    writeStageBTerraformStateBackup({ run, output });
    bytes = fs.readFileSync(output);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
  let state;
  try { state = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); }
  catch { throw new Error("Stage B output-only reconciliation requires valid UTF-8 JSON state bytes."); }
  const arns = {};
  for (const resource of state?.resources || []) {
    if (resource?.mode !== "managed" || resource?.type !== "aws_ecs_task_definition" || !["candidate", "executor"].includes(resource?.name)) continue;
    for (const instance of resource.instances || []) if (!instance?.deposed) arns[`aws_ecs_task_definition.${resource.name}[${JSON.stringify(instance?.index_key)}]`] = instance?.attributes?.arn;
  }
  const observedTaskDefinitions = Object.fromEntries(Object.entries(arns).map(([key, arn]) => {
    const response = JSON.parse(run(["ecs", "describe-task-definition", "--task-definition", arn, "--region", STAGE_B_STATE_RECONCILIATION.region, "--output", "json", "--no-cli-pager"]));
    return [key, response.taskDefinition];
  }));
  return createStageBOutputOnlyEvidence({ stateBytes: bytes, observedTaskDefinitions });
};

function initialize({ data, env, terraform = runStageBStateReconciliationTerraform }) {
  terraform(["init", "-input=false", "-lockfile=readonly", ...Object.entries(STAGE_B_TERRAFORM_BACKEND_CONFIG).map(([key, value]) => `-backend-config=${key}=${value}`)], env);
  const metadataPath = path.join(data, "terraform.tfstate"); ensureStageBPrivateFile({ filePath: metadataPath, repositoryRoot: root, normalize: true, label: "Stage B state reconciliation backend metadata" });
  assertStageBTerraformInitializedBackendMetadata(JSON.parse(fs.readFileSync(metadataPath, "utf8")).backend);
}

export function renderStageBStateReconciliationPlan(planPath, env) {
  return JSON.parse(captureStageBTerraformJson({ args: [`-chdir=${terraformRoot}`, "show", "-json", planPath], cwd: root, env }).toString("utf8"));
}
function assertSource(sourceSha) { const checkout = readStageBProtectedMainCheckout({ cwd: root, fetchOriginMain: true }); assertStageBProtectedCheckoutMatchesDeploymentIdentity({ protectedMainCheckout: checkout, deploymentIdentity: { toolingSha: sourceSha } }); return checkout; }
function assertBindings({ sourceSha, tfvars, binding, preflight, preflightSha256, checkPreflight = true, validatePrerequisiteFiles = true }) {
  const bindingBytes = readStageBPrivateFileBytes({ filePath: binding, repositoryRoot: root, label: "Stage B state reconciliation binding" }).bytes;
  const checked = assertStageBTfvarsBinding({ tfvarsPath: tfvars, bindingReportPath: binding, bindingReportSha256: hash(bindingBytes), expectedToolingSha: sourceSha, validatePrerequisiteFiles });
  const release = privateJson(preflight, preflightSha256, "Stage B state reconciliation release preflight");
  if (checkPreflight && (release.status !== "ready-for-plan" || release.sourceSha !== sourceSha || release.tfvarsSha256 !== checked.tfvarsSha256 || release.bindingReportSha256 !== hash(bindingBytes))) throw new Error("Stage B state reconciliation release preflight binding is invalid.");
  return { tfvarsSha256: checked.tfvarsSha256, bindingSha256: hash(bindingBytes), bindingReport: checked, preflightSha256: hash(readStageBPrivateFileBytes({ filePath: preflight, repositoryRoot: root, label: "Stage B state reconciliation release preflight" }).bytes) };
}

export function runStageBStateReconciliation(argv = process.argv.slice(2), deps = {}) {
  const mode = required(argv, "--mode");
  const prepare = mode === "prepare"; const execute = mode === "execute";
  if (!prepare && !execute) throw new Error("--mode must be prepare or execute.");
  const allowed = prepare ? new Set(["--mode", "--reconciliation-mode", "--source-sha", "--ticket-id", "--admin-profile", "--credential-source", "--release-preflight", "--release-preflight-sha256", "--prerequisite-bundle", "--prerequisite-producer-workflow-run-id", "--prerequisite-producer-workflow-run-attempt", "--prerequisite-bundle-artifact-id", "--prerequisite-bundle-artifact-digest", "--terraform-data-dir", "--saved-plan-out", "--preparation-out"]) : new Set(["--mode", "--source-sha", "--release-preflight", "--release-preflight-sha256", "--prerequisite-bundle", "--prerequisite-producer-workflow-run-id", "--prerequisite-producer-workflow-run-attempt", "--terraform-data-dir", "--saved-plan", "--saved-plan-sha256", "--preparation", "--preparation-file-sha256", "--authorization", "--authorization-file-sha256", "--result-out"]);
  exactArgs(argv, allowed);
  const sourceSha = required(argv, "--source-sha"); const data = path.resolve(required(argv, "--terraform-data-dir")); ensureStageBPrivateDirectory({ directory: data, repositoryRoot: root, create: true, label: "Stage B state reconciliation Terraform data" });
  const credentialSource = prepare && argv.includes("--credential-source") ? required(argv, "--credential-source") : prepare ? PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE : PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER;
  if (credentialSource !== PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE && credentialSource !== PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER) throw new Error("Stage B state reconciliation credential source is invalid.");
  const credentialOptions = credentialSource === PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE ? { profile: required(argv, "--admin-profile") } : { env: deps.env || process.env };
  const env = { ...createProductionAwsCredentialEnvironment({ credentialSource, ...credentialOptions }), TF_DATA_DIR: data, TF_WORKSPACE: "default" };
  const run = deps.run || createProductionAwsCommandRunner({ credentialSource, ...credentialOptions });
  const terraform = deps.runTerraform || runStageBStateReconciliationTerraform; const renderPlan = deps.renderPlan || renderStageBStateReconciliationPlan; const reauthenticateSource = deps.assertSource || assertSource;
  const prerequisiteMaterializationDirectory = path.join(path.dirname(data), "prerequisites");
  if (prepare) {
    const reconciliationMode = argv.includes("--reconciliation-mode") ? required(argv, "--reconciliation-mode") : STAGE_B_STATE_RECONCILIATION_MODES.HISTORICAL_TEN_ADDRESS;
    if (!Object.values(STAGE_B_STATE_RECONCILIATION_MODES).includes(reconciliationMode)) throw new Error("Stage B state reconciliation mode is invalid.");
    const caller = JSON.parse(run(["sts", "get-caller-identity", "--output", "json", "--no-cli-pager"]));
    if (caller.Account !== STAGE_B_STATE_RECONCILIATION.account || !new RegExp(`^arn:aws:sts::${STAGE_B_STATE_RECONCILIATION.account}:assumed-role/mscqr-production-release-deployer/[^/]+$`).test(caller.Arn || "")) throw new Error("Stage B state reconciliation preparation requires the exact release-deployer session.");
    reauthenticateSource(sourceSha);
    const prerequisite = materializeStageBPrerequisites({ bundlePath: required(argv, "--prerequisite-bundle"), sourceSha, ticketId: required(argv, "--ticket-id"), repository: STAGE_B_STATE_RECONCILIATION.repository, workflowRunId: required(argv, "--prerequisite-producer-workflow-run-id"), workflowRunAttempt: required(argv, "--prerequisite-producer-workflow-run-attempt"), headSha: sourceSha, outputDirectory: prerequisiteMaterializationDirectory });
    const originalTfvarsPath = prerequisite.paths["stage-b-tfvars"]; const originalBindingPath = prerequisite.paths["stage-b-tfvars-binding"]; const originalBindings = assertBindings({ sourceSha, tfvars: originalTfvarsPath, binding: originalBindingPath, preflight: required(argv, "--release-preflight"), preflightSha256: required(argv, "--release-preflight-sha256"), validatePrerequisiteFiles: false });
    const runtime = writeStageBRuntimeMaterialization({ prerequisite });
    const bindings = { ...assertBindings({ sourceSha, tfvars: runtime.runtimeTfvarsPath, binding: runtime.runtimeBindingPath, preflight: required(argv, "--release-preflight"), preflightSha256: required(argv, "--release-preflight-sha256"), checkPreflight: false }), runtimeMaterializationSha256: runtime.runtimeMaterializationSha256, relocationContractSha256: runtime.relocationContractSha256, prerequisiteManifestSha256: prerequisite.manifestSha256, brokerPackageSha256: prerequisite.manifest.members.find(({ logicalArtifactId }) => logicalArtifactId === "broker-package").sha256, brokerManifestSha256: prerequisite.manifest.members.find(({ logicalArtifactId }) => logicalArtifactId === "broker-package-manifest").sha256, stageAInputSha256: prerequisite.manifest.members.find(({ logicalArtifactId }) => logicalArtifactId === "stage-a-handoff").sha256, stageAStateBackupSha256: prerequisite.manifest.members.find(({ logicalArtifactId }) => logicalArtifactId === "stage-a-state-backup").sha256 };
    initialize({ data, env, terraform }); const beforeEvidence = reconciliationMode === STAGE_B_STATE_RECONCILIATION_MODES.OUTPUT_ONLY ? outputOnlyEvidence(run) : null; const before = beforeEvidence?.stateIdentity || stateIdentity(run);
    const saved = assertStageBArtifactPath({ artifactPath: path.resolve(required(argv, "--saved-plan-out")), repositoryRoot: root, label: "Stage B state reconciliation saved plan", allowExisting: false });
    terraform(["plan", "-refresh-only", `-var-file=${runtime.runtimeTfvarsPath}`, "-input=false", "-lock=true", "-out", saved], env); ensureStageBPrivateFile({ filePath: saved, repositoryRoot: root, normalize: true, label: "Stage B state reconciliation saved plan" });
    const terraformConfiguration = fs.readFileSync(path.join(root, terraformRoot, "main.tf"), "utf8");
    const planOptions = { sourceSha, stateIdentity: before, tfvarsSha256: bindings.tfvarsSha256, bindingSha256: bindings.bindingSha256, bindingReport: bindings.bindingReport, terraformConfiguration, reconciliationMode, outputOnlyEvidence: beforeEvidence };
    const bytes = readStageBPrivateFileBytes({ filePath: saved, repositoryRoot: root, label: "Stage B state reconciliation saved plan" }).bytes; const plan = renderPlan(saved, env); assertExactStageBRefreshOnlyPlan(plan, planOptions);
    let sourceAlignmentPlan; if (reconciliationMode === STAGE_B_STATE_RECONCILIATION_MODES.HISTORICAL_TEN_ADDRESS) { const sourcePlanPath = path.join(data, "source-alignment.tfplan"); terraform(["plan", `-var-file=${runtime.runtimeTfvarsPath}`, "-input=false", "-lock=true", "-out", sourcePlanPath], env); const normalPlan = renderPlan(sourcePlanPath, env); sourceAlignmentPlan = normalPlan; }
    assertStageBStateReconciliationSourceAlignment(plan, sourceAlignmentPlan, planOptions);
    const after = reconciliationMode === STAGE_B_STATE_RECONCILIATION_MODES.OUTPUT_ONLY ? outputOnlyEvidence(run) : stateIdentity(run); if (JSON.stringify(after) !== JSON.stringify(beforeEvidence || before)) throw new Error("Stage B state or registered successors changed during reconciliation preparation.");
    const preparation = createStageBStateReconciliationPreparation({ sourceSha, ticketId: required(argv, "--ticket-id"), stateIdentity: before, tfvarsSha256: originalBindings.tfvarsSha256, bindingSha256: originalBindings.bindingSha256, bindingReport: bindings.bindingReport, terraformConfiguration, preflightSha256: bindings.preflightSha256, runtimeTfvarsSha256: bindings.tfvarsSha256, runtimeBindingSha256: bindings.bindingSha256, runtimeMaterializationSha256: bindings.runtimeMaterializationSha256, relocationContractSha256: bindings.relocationContractSha256, prerequisiteManifestSha256: bindings.prerequisiteManifestSha256, brokerPackageSha256: bindings.brokerPackageSha256, brokerManifestSha256: bindings.brokerManifestSha256, stageAInputSha256: bindings.stageAInputSha256, stageAStateBackupSha256: bindings.stageAStateBackupSha256, prerequisiteProducerWorkflowRunId: required(argv, "--prerequisite-producer-workflow-run-id"), prerequisiteProducerWorkflowRunAttempt: required(argv, "--prerequisite-producer-workflow-run-attempt"), prerequisiteBundleArtifactId: required(argv, "--prerequisite-bundle-artifact-id"), prerequisiteBundleArtifactDigest: required(argv, "--prerequisite-bundle-artifact-digest"), planBytes: bytes, planJson: plan, normalPlan: sourceAlignmentPlan, reconciliationMode, outputOnlyEvidence: beforeEvidence });
    const output = assertStageBArtifactPath({ artifactPath: path.resolve(required(argv, "--preparation-out")), repositoryRoot: root, label: "Stage B state reconciliation preparation", allowExisting: false }); ensureStageBPrivateDirectory({ directory: path.dirname(output), repositoryRoot: root, label: "Stage B state reconciliation output" }); writeStageBPrivateFileExclusive({ filePath: output, bytes: Buffer.from(`${JSON.stringify(preparation, null, 2)}\n`), repositoryRoot: root, label: "Stage B state reconciliation preparation" });
    return { status: "prepared", awsResourceMutationCount: 0, terraformStateMutationCount: 0, preparation, savedPlanPath: saved };
  }
  const workflow = deps.env || process.env;
  if (workflow.GITHUB_ACTIONS !== "true" || workflow.GITHUB_REPOSITORY !== STAGE_B_STATE_RECONCILIATION.repository || workflow.GITHUB_WORKFLOW_REF !== `${STAGE_B_STATE_RECONCILIATION.repository}/${STAGE_B_STATE_RECONCILIATION.executionWorkflowPath}@refs/heads/main` || workflow.GITHUB_EVENT_NAME !== "workflow_dispatch" || workflow.GITHUB_RUN_ATTEMPT !== "1") throw new Error("Stage B state reconciliation execution is workflow-only.");
  const preparation = readBoundStageBPrivateJson({ filePath: path.resolve(required(argv, "--preparation")), expectedSha256: required(argv, "--preparation-file-sha256"), repositoryRoot: root, label: "Stage B state reconciliation preparation" });
  const prerequisite = materializeStageBPrerequisites({ bundlePath: required(argv, "--prerequisite-bundle"), sourceSha, ticketId: preparation.ticketId, repository: STAGE_B_STATE_RECONCILIATION.repository, workflowRunId: required(argv, "--prerequisite-producer-workflow-run-id"), workflowRunAttempt: required(argv, "--prerequisite-producer-workflow-run-attempt"), headSha: sourceSha, outputDirectory: prerequisiteMaterializationDirectory });
  const originalTfvarsPath = prerequisite.paths["stage-b-tfvars"]; const originalBindingPath = prerequisite.paths["stage-b-tfvars-binding"]; const originalBindings = assertBindings({ sourceSha, tfvars: originalTfvarsPath, binding: originalBindingPath, preflight: required(argv, "--release-preflight"), preflightSha256: required(argv, "--release-preflight-sha256"), validatePrerequisiteFiles: false });
  const runtime = writeStageBRuntimeMaterialization({ prerequisite });
  if (originalBindings.tfvarsSha256 !== preparation.tfvarsSha256 || originalBindings.bindingSha256 !== preparation.bindingSha256 || prerequisite.manifestSha256 !== preparation.prerequisiteManifestSha256) throw new Error("Stage B original prerequisite inputs are substituted.");
  const bindings = { ...assertBindings({ sourceSha, tfvars: runtime.runtimeTfvarsPath, binding: runtime.runtimeBindingPath, preflight: required(argv, "--release-preflight"), preflightSha256: required(argv, "--release-preflight-sha256"), checkPreflight: false }), runtimeMaterializationSha256: runtime.runtimeMaterializationSha256, relocationContractSha256: runtime.relocationContractSha256, prerequisiteManifestSha256: prerequisite.manifestSha256, brokerPackageSha256: prerequisite.manifest.members.find(({ logicalArtifactId }) => logicalArtifactId === "broker-package").sha256, brokerManifestSha256: prerequisite.manifest.members.find(({ logicalArtifactId }) => logicalArtifactId === "broker-package-manifest").sha256, stageAInputSha256: prerequisite.manifest.members.find(({ logicalArtifactId }) => logicalArtifactId === "stage-a-handoff").sha256, stageAStateBackupSha256: prerequisite.manifest.members.find(({ logicalArtifactId }) => logicalArtifactId === "stage-a-state-backup").sha256 };
  const authorization = privateJson(required(argv, "--authorization"), required(argv, "--authorization-file-sha256"), "Stage B state reconciliation authorization");
  const saved = assertStageBArtifactPath({ artifactPath: path.resolve(required(argv, "--saved-plan")), repositoryRoot: root, label: "Stage B state reconciliation saved plan", allowExisting: true }); const bytes = readStageBPrivateFileBytes({ filePath: saved, repositoryRoot: root, label: "Stage B state reconciliation saved plan" }).bytes; if (hash(bytes) !== required(argv, "--saved-plan-sha256") || hash(bytes) !== preparation.refreshOnlyPlanSha256) throw new Error("Stage B state reconciliation saved plan is substituted.");
  initialize({ data, env, terraform }); const plan = renderPlan(saved, env);
  const planPath = (name, refreshOnly) => {
    const output = path.join(data, name);
    terraform(["plan", ...(refreshOnly ? ["-refresh-only"] : []), `-var-file=${runtime.runtimeTfvarsPath}`, "-input=false", "-lock=true", "-out", output], env);
    return renderPlan(output, env);
  };
  const resultPath = assertStageBArtifactPath({ artifactPath: path.resolve(required(argv, "--result-out")), repositoryRoot: root, label: "Stage B state reconciliation result", allowExisting: false }); ensureStageBPrivateDirectory({ directory: path.dirname(resultPath), repositoryRoot: root, label: "Stage B state reconciliation result output" });
  try {
    const result = executeStageBStateReconciliation({ sourceSha, preparation, authorization, bindings, terraformConfiguration: fs.readFileSync(path.join(root, terraformRoot, "main.tf"), "utf8"), planBytes: bytes, planJson: plan, readState: () => stateIdentity(run), readOutputOnlyEvidence: () => outputOnlyEvidence(run), applyRefreshOnlyPlan: () => terraform(["apply", "-input=false", saved], env), renderPreApplyNormalPlan: () => planPath("pre-apply-normal.tfplan", false), renderRefreshClosurePlan: () => planPath("post-reconciliation-refresh.tfplan", true), renderNormalClosurePlan: () => planPath("post-reconciliation-normal.tfplan", false), reauthenticateSource: () => reauthenticateSource(sourceSha) });
    writeStageBPrivateFileExclusive({ filePath: resultPath, bytes: Buffer.from(`${JSON.stringify(result, null, 2)}\n`), repositoryRoot: root, label: "Stage B state reconciliation result" });
    return result;
  } catch (error) {
    if (error.reconciliationResult) writeStageBPrivateFileExclusive({ filePath: resultPath, bytes: Buffer.from(`${JSON.stringify(error.reconciliationResult, null, 2)}\n`), repositoryRoot: root, label: "Stage B state reconciliation result" });
    throw error;
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) { try { process.stdout.write(`${JSON.stringify(runStageBStateReconciliation(), null, 2)}\n`); } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; } }

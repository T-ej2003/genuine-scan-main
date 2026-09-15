#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createProductionAwsCommandRunner, createProductionAwsCredentialEnvironment, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, ensureStageBPrivateFile, readBoundStageBPrivateJson, readStageBPrivateFileBytes, writeStageBPrivateFileExclusive } from "./stage-b-artifact-contract.mjs";
import { STAGE_B_TERRAFORM_BACKEND_CONFIG, assertStageBTerraformInitializedBackendMetadata, readStageBTerraformStateIdentity } from "./stage-b-terraform-backend-contract.mjs";
import { readStageBProtectedMainCheckout, assertStageBProtectedCheckoutMatchesDeploymentIdentity } from "./stage-b-deployment-identity.mjs";
import { assertStageBTfvarsBinding } from "./generate-production-green-stage-b-tfvars.mjs";
import { assertExactStageBRefreshOnlyPlan, assertStageBStateReconciliationSourceAlignment, createStageBStateReconciliationPreparation, executeStageBStateReconciliation, STAGE_B_STATE_RECONCILIATION } from "./production-green-stage-b-state-reconciliation.mjs";
import { materializeStageBPrerequisites, writeStageBRuntimeMaterialization } from "./stage-b-prerequisite-bundle.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const terraformRoot = STAGE_B_STATE_RECONCILIATION.terraformRoot;
const hash = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const required = (argv, name) => { const index = argv.indexOf(name); const value = index < 0 ? undefined : argv[index + 1]; if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const exactArgs = (argv, allowed) => { const seen = new Set(); for (let index = 0; index < argv.length; index += 2) if (!allowed.has(argv[index]) || seen.has(argv[index]) || !argv[index + 1] || argv[index + 1].startsWith("--")) throw new Error("Stage B state reconciliation CLI arguments are not exact."); else seen.add(argv[index]); };
const runTerraform = (args, env) => execFileSync("terraform", [`-chdir=${terraformRoot}`, ...args], { cwd: root, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
const privateJson = (filePath, label) => readBoundStageBPrivateJson({ filePath: path.resolve(filePath), repositoryRoot: root, label }).value;
const stateIdentity = (run) => readStageBTerraformStateIdentity(run);

function initialize({ data, env }) {
  runTerraform(["init", "-input=false", "-lockfile=readonly", ...Object.entries(STAGE_B_TERRAFORM_BACKEND_CONFIG).map(([key, value]) => `-backend-config=${key}=${value}`)], env);
  const metadataPath = path.join(data, "terraform.tfstate"); ensureStageBPrivateFile({ filePath: metadataPath, repositoryRoot: root, normalize: true, label: "Stage B state reconciliation backend metadata" });
  assertStageBTerraformInitializedBackendMetadata(JSON.parse(fs.readFileSync(metadataPath, "utf8")).backend);
}

function renderPlan(planPath, env) { return JSON.parse(runTerraform(["show", "-json", planPath], env)); }
function assertSource(sourceSha) { const checkout = readStageBProtectedMainCheckout({ cwd: root, fetchOriginMain: true }); assertStageBProtectedCheckoutMatchesDeploymentIdentity({ protectedMainCheckout: checkout, deploymentIdentity: { toolingSha: sourceSha } }); return checkout; }
function assertBindings({ sourceSha, tfvars, binding, preflight, checkPreflight = true }) {
  const bindingBytes = readStageBPrivateFileBytes({ filePath: binding, repositoryRoot: root, label: "Stage B state reconciliation binding" }).bytes;
  const checked = assertStageBTfvarsBinding({ tfvarsPath: tfvars, bindingReportPath: binding, bindingReportSha256: hash(bindingBytes), expectedToolingSha: sourceSha });
  const release = privateJson(preflight, "Stage B state reconciliation release preflight");
  if (checkPreflight && (release.status !== "ready-for-plan" || release.sourceSha !== sourceSha || release.tfvarsSha256 !== checked.tfvarsSha256 || release.bindingReportSha256 !== hash(bindingBytes))) throw new Error("Stage B state reconciliation release preflight binding is invalid.");
  return { tfvarsSha256: checked.tfvarsSha256, bindingSha256: hash(bindingBytes), preflightSha256: hash(readStageBPrivateFileBytes({ filePath: preflight, repositoryRoot: root, label: "Stage B state reconciliation release preflight" }).bytes) };
}

export function runStageBStateReconciliation(argv = process.argv.slice(2), deps = {}) {
  const mode = required(argv, "--mode");
  const prepare = mode === "prepare"; const execute = mode === "execute";
  if (!prepare && !execute) throw new Error("--mode must be prepare or execute.");
  const allowed = prepare ? new Set(["--mode", "--source-sha", "--ticket-id", "--admin-profile", "--credential-source", "--tfvars", "--binding-report", "--release-preflight", "--prerequisite-bundle", "--prerequisite-producer-workflow-run-id", "--prerequisite-producer-workflow-run-attempt", "--prerequisite-bundle-artifact-id", "--prerequisite-bundle-artifact-digest", "--terraform-data-dir", "--saved-plan-out", "--preparation-out"]) : new Set(["--mode", "--source-sha", "--tfvars", "--binding-report", "--release-preflight", "--prerequisite-bundle", "--prerequisite-producer-workflow-run-id", "--prerequisite-producer-workflow-run-attempt", "--terraform-data-dir", "--saved-plan", "--saved-plan-sha256", "--preparation", "--preparation-file-sha256", "--authorization", "--result-out"]);
  exactArgs(argv, allowed);
  const sourceSha = required(argv, "--source-sha"); const data = path.resolve(required(argv, "--terraform-data-dir")); ensureStageBPrivateDirectory({ directory: data, repositoryRoot: root, create: true, label: "Stage B state reconciliation Terraform data" });
  const credentialSource = prepare && argv.includes("--credential-source") ? required(argv, "--credential-source") : prepare ? PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE : PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER;
  if (credentialSource !== PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE && credentialSource !== PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER) throw new Error("Stage B state reconciliation credential source is invalid.");
  const credentialOptions = credentialSource === PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE ? { profile: required(argv, "--admin-profile") } : { env: deps.env || process.env };
  const env = { ...createProductionAwsCredentialEnvironment({ credentialSource, ...credentialOptions }), TF_DATA_DIR: data, TF_WORKSPACE: "default" };
  const run = deps.run || createProductionAwsCommandRunner({ credentialSource, ...credentialOptions });
  if (prepare) {
    const caller = JSON.parse(run(["sts", "get-caller-identity", "--output", "json", "--no-cli-pager"]));
    if (caller.Account !== STAGE_B_STATE_RECONCILIATION.account || !new RegExp(`^arn:aws:sts::${STAGE_B_STATE_RECONCILIATION.account}:assumed-role/mscqr-production-release-deployer/[^/]+$`).test(caller.Arn || "")) throw new Error("Stage B state reconciliation preparation requires the exact release-deployer session.");
    assertSource(sourceSha); const originalBindings = assertBindings({ sourceSha, tfvars: required(argv, "--tfvars"), binding: required(argv, "--binding-report"), preflight: required(argv, "--release-preflight") });
    const prerequisite = materializeStageBPrerequisites({ bundlePath: required(argv, "--prerequisite-bundle"), sourceSha, ticketId: required(argv, "--ticket-id"), repository: STAGE_B_STATE_RECONCILIATION.repository, workflowRunId: required(argv, "--prerequisite-producer-workflow-run-id"), workflowRunAttempt: required(argv, "--prerequisite-producer-workflow-run-attempt"), headSha: sourceSha });
    const runtime = writeStageBRuntimeMaterialization({ originalTfvarsBytes: fs.readFileSync(path.resolve(required(argv, "--tfvars"))), originalBindingBytes: fs.readFileSync(path.resolve(required(argv, "--binding-report"))), prerequisite });
    const bindings = { ...assertBindings({ sourceSha, tfvars: runtime.runtimeTfvarsPath, binding: runtime.runtimeBindingPath, preflight: required(argv, "--release-preflight"), checkPreflight: false }), runtimeMaterializationSha256: runtime.runtimeMaterializationSha256, relocationContractSha256: runtime.relocationContractSha256, prerequisiteManifestSha256: prerequisite.manifestSha256, brokerPackageSha256: prerequisite.manifest.members.find(({ logicalArtifactId }) => logicalArtifactId === "broker-package").sha256, brokerManifestSha256: prerequisite.manifest.members.find(({ logicalArtifactId }) => logicalArtifactId === "broker-package-manifest").sha256, stageAInputSha256: prerequisite.manifest.members.find(({ logicalArtifactId }) => logicalArtifactId === "stage-a-handoff").sha256, stageAStateBackupSha256: prerequisite.manifest.members.find(({ logicalArtifactId }) => logicalArtifactId === "stage-a-state-backup").sha256 };
    initialize({ data, env }); const before = stateIdentity(run);
    const saved = assertStageBArtifactPath({ artifactPath: path.resolve(required(argv, "--saved-plan-out")), repositoryRoot: root, label: "Stage B state reconciliation saved plan", allowExisting: false });
    runTerraform(["plan", "-refresh-only", `-var-file=${runtime.runtimeTfvarsPath}`, "-input=false", "-lock=true", "-out", saved], env); ensureStageBPrivateFile({ filePath: saved, repositoryRoot: root, normalize: true, label: "Stage B state reconciliation saved plan" });
    const bytes = readStageBPrivateFileBytes({ filePath: saved, repositoryRoot: root, label: "Stage B state reconciliation saved plan" }).bytes; const plan = renderPlan(saved, env); assertExactStageBRefreshOnlyPlan(plan, { sourceSha, stateIdentity: before, tfvarsSha256: bindings.tfvarsSha256, bindingSha256: bindings.bindingSha256 });
    const sourcePlanPath = path.join(data, "source-alignment.tfplan"); runTerraform(["plan", `-var-file=${runtime.runtimeTfvarsPath}`, "-input=false", "-lock=true", "-out", sourcePlanPath], env); assertStageBStateReconciliationSourceAlignment(plan, renderPlan(sourcePlanPath, env), { sourceSha, stateIdentity: before, tfvarsSha256: bindings.tfvarsSha256, bindingSha256: bindings.bindingSha256 });
    const after = stateIdentity(run); if (JSON.stringify(after) !== JSON.stringify(before)) throw new Error("Stage B state changed during reconciliation preparation.");
    const preparation = createStageBStateReconciliationPreparation({ sourceSha, ticketId: required(argv, "--ticket-id"), stateIdentity: before, tfvarsSha256: originalBindings.tfvarsSha256, bindingSha256: originalBindings.bindingSha256, prerequisiteProducerWorkflowRunId: required(argv, "--prerequisite-producer-workflow-run-id"), prerequisiteProducerWorkflowRunAttempt: required(argv, "--prerequisite-producer-workflow-run-attempt"), prerequisiteBundleArtifactId: required(argv, "--prerequisite-bundle-artifact-id"), prerequisiteBundleArtifactDigest: required(argv, "--prerequisite-bundle-artifact-digest"), ...bindings, planBytes: bytes, planJson: plan, normalPlan: renderPlan(sourcePlanPath, env) });
    const output = assertStageBArtifactPath({ artifactPath: path.resolve(required(argv, "--preparation-out")), repositoryRoot: root, label: "Stage B state reconciliation preparation", allowExisting: false }); ensureStageBPrivateDirectory({ directory: path.dirname(output), repositoryRoot: root, label: "Stage B state reconciliation output" }); writeStageBPrivateFileExclusive({ filePath: output, bytes: Buffer.from(`${JSON.stringify(preparation, null, 2)}\n`), repositoryRoot: root, label: "Stage B state reconciliation preparation" });
    return { status: "prepared", awsResourceMutationCount: 0, terraformStateMutationCount: 0, preparation, savedPlanPath: saved };
  }
  const workflow = deps.env || process.env;
  if (workflow.GITHUB_ACTIONS !== "true" || workflow.GITHUB_REPOSITORY !== STAGE_B_STATE_RECONCILIATION.repository || workflow.GITHUB_WORKFLOW_REF !== `${STAGE_B_STATE_RECONCILIATION.repository}/${STAGE_B_STATE_RECONCILIATION.executionWorkflowPath}@refs/heads/main` || workflow.GITHUB_EVENT_NAME !== "workflow_dispatch" || workflow.GITHUB_RUN_ATTEMPT !== "1") throw new Error("Stage B state reconciliation execution is workflow-only.");
  const originalBindings = assertBindings({ sourceSha, tfvars: required(argv, "--tfvars"), binding: required(argv, "--binding-report"), preflight: required(argv, "--release-preflight") });
  const preparation = readBoundStageBPrivateJson({ filePath: path.resolve(required(argv, "--preparation")), expectedSha256: required(argv, "--preparation-file-sha256"), repositoryRoot: root, label: "Stage B state reconciliation preparation" }).value;
  const prerequisite = materializeStageBPrerequisites({ bundlePath: required(argv, "--prerequisite-bundle"), sourceSha, ticketId: preparation.ticketId, repository: STAGE_B_STATE_RECONCILIATION.repository, workflowRunId: required(argv, "--prerequisite-producer-workflow-run-id"), workflowRunAttempt: required(argv, "--prerequisite-producer-workflow-run-attempt"), headSha: sourceSha });
  const runtime = writeStageBRuntimeMaterialization({ originalTfvarsBytes: fs.readFileSync(path.resolve(required(argv, "--tfvars"))), originalBindingBytes: fs.readFileSync(path.resolve(required(argv, "--binding-report"))), prerequisite });
  if (originalBindings.tfvarsSha256 !== preparation.tfvarsSha256 || originalBindings.bindingSha256 !== preparation.bindingSha256 || prerequisite.manifestSha256 !== preparation.prerequisiteManifestSha256) throw new Error("Stage B original prerequisite inputs are substituted.");
  const bindings = { ...assertBindings({ sourceSha, tfvars: runtime.runtimeTfvarsPath, binding: runtime.runtimeBindingPath, preflight: required(argv, "--release-preflight"), checkPreflight: false }), runtimeMaterializationSha256: runtime.runtimeMaterializationSha256, relocationContractSha256: runtime.relocationContractSha256, prerequisiteManifestSha256: prerequisite.manifestSha256, brokerPackageSha256: prerequisite.manifest.members.find(({ logicalArtifactId }) => logicalArtifactId === "broker-package").sha256, brokerManifestSha256: prerequisite.manifest.members.find(({ logicalArtifactId }) => logicalArtifactId === "broker-package-manifest").sha256, stageAInputSha256: prerequisite.manifest.members.find(({ logicalArtifactId }) => logicalArtifactId === "stage-a-handoff").sha256, stageAStateBackupSha256: prerequisite.manifest.members.find(({ logicalArtifactId }) => logicalArtifactId === "stage-a-state-backup").sha256 };
  const authorization = privateJson(required(argv, "--authorization"), "Stage B state reconciliation authorization");
  const saved = assertStageBArtifactPath({ artifactPath: path.resolve(required(argv, "--saved-plan")), repositoryRoot: root, label: "Stage B state reconciliation saved plan", allowExisting: true }); const bytes = readStageBPrivateFileBytes({ filePath: saved, repositoryRoot: root, label: "Stage B state reconciliation saved plan" }).bytes; if (hash(bytes) !== required(argv, "--saved-plan-sha256") || hash(bytes) !== preparation.refreshOnlyPlanSha256) throw new Error("Stage B state reconciliation saved plan is substituted.");
  initialize({ data, env }); const plan = renderPlan(saved, env);
  const planPath = (name, refreshOnly) => {
    const output = path.join(data, name);
    runTerraform(["plan", ...(refreshOnly ? ["-refresh-only"] : []), `-var-file=${runtime.runtimeTfvarsPath}`, "-input=false", "-lock=true", "-out", output], env);
    return renderPlan(output, env);
  };
  const resultPath = assertStageBArtifactPath({ artifactPath: path.resolve(required(argv, "--result-out")), repositoryRoot: root, label: "Stage B state reconciliation result", allowExisting: false }); ensureStageBPrivateDirectory({ directory: path.dirname(resultPath), repositoryRoot: root, label: "Stage B state reconciliation result output" });
  try {
    const result = executeStageBStateReconciliation({ sourceSha, preparation, authorization, bindings, planBytes: bytes, planJson: plan, readState: () => stateIdentity(run), applyRefreshOnlyPlan: () => runTerraform(["apply", "-input=false", saved], env), renderRefreshClosurePlan: () => planPath("post-reconciliation-refresh.tfplan", true), renderNormalClosurePlan: () => planPath("post-reconciliation-normal.tfplan", false), reauthenticateSource: () => assertSource(sourceSha) });
    writeStageBPrivateFileExclusive({ filePath: resultPath, bytes: Buffer.from(`${JSON.stringify(result, null, 2)}\n`), repositoryRoot: root, label: "Stage B state reconciliation result" });
    return result;
  } catch (error) {
    if (error.reconciliationResult) writeStageBPrivateFileExclusive({ filePath: resultPath, bytes: Buffer.from(`${JSON.stringify(error.reconciliationResult, null, 2)}\n`), repositoryRoot: root, label: "Stage B state reconciliation result" });
    throw error;
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) { try { process.stdout.write(`${JSON.stringify(runStageBStateReconciliation(), null, 2)}\n`); } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; } }

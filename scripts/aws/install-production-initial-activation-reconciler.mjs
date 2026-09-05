#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createProductionAwsCommandRunner, createProductionAwsCredentialEnvironment, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { canonicalJson } from "./production-green-stage-b-contract.mjs";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, readBoundStageBPrivateJson, readStageBPrivateFileBytes, writeStageBPrivateFilesAtomic } from "./stage-b-artifact-contract.mjs";
import { INSTALLATION, assertFreshInstallationAuthorization, assertInstallationInitializedBackendMetadata, assertInstallationPlan, assertInstallationPreparation, assertInstallationStateResources, classifyInstallationStatePullError, stateIdentity } from "./production-initial-activation-reconciler-installation-contract.mjs";
import { discoverInstallationPredecessor, assertProtectedCheckout } from "./prepare-production-initial-activation-reconciler-installation.mjs";
import { assertProductionEnvironmentApprovalEvidence, PRODUCTION_ENVIRONMENT_APPROVAL } from "./production-github-environment-approval.mjs";
import { verifyInitialActivationPolicyReconciler } from "./verify-production-initial-activation-policy-reconciler.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const option = (argv, name) => { const index = argv.indexOf(name); return index < 0 ? undefined : argv[index + 1]; };
const required = (argv, name) => { const value = option(argv, name); if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
export function executeInstallation({ sourceSha, preparation, authorization, planBytes, planJson, executionRoleArn = INSTALLATION.executionRoleArn, livePredecessor, livePredecessorAddresses, applySavedPlan, verifyInstalled, readState, resultPath, now = new Date() } = {}) {
  assertInstallationPreparation(preparation, { sourceSha, planBytes });
  assertFreshInstallationAuthorization(authorization, { sourceSha, preparation, now });
  if (executionRoleArn !== INSTALLATION.executionRoleArn) throw new Error("Installation workflow role identity is not exact.");
  const semantics = assertInstallationPlan(planJson);
  if (canonicalJson(semantics) !== canonicalJson(preparation.planSemantics)) throw new Error("Rendered saved-plan semantics differ from the authorized preparation.");
  if (livePredecessor !== "ABSENT" && livePredecessor !== "EXACT_PARTIAL" && livePredecessor !== "EXACT_COMPLETE") throw new Error("Installation live predecessor is not a supported exact state.");
  if (livePredecessor === "ABSENT" && semantics.resourceChangeCount !== INSTALLATION.expectedAddresses.length) throw new Error("First-install plan mutation scope is not exact.");
  if (livePredecessor === "EXACT_PARTIAL" && semantics.resourceChangeCount < 1) throw new Error("Partial-install plan mutation scope is not exact.");
  if (livePredecessor !== preparation.livePredecessor || JSON.stringify(livePredecessorAddresses) !== JSON.stringify(preparation.livePredecessorAddresses)) throw new Error("Installation live predecessor changed after preparation.");
  const beforeStateBytes = readState?.();
  const beforeState = stateIdentity(beforeStateBytes);
  if (JSON.stringify(beforeState) !== JSON.stringify(preparation.predecessorState)) throw new Error("Installation Terraform state changed after preparation.");
  if (livePredecessor === "EXACT_COMPLETE" && (!beforeState.stateExists || semantics.resourceChangeCount !== 0)) throw new Error("Exact-complete replay requires an authenticated state and no-op plan.");
  if (livePredecessor === "EXACT_COMPLETE") assertInstallationStateResources(beforeStateBytes);
  if (livePredecessor === "EXACT_PARTIAL") assertInstallationStateResources(beforeStateBytes, { requiredAddresses: livePredecessorAddresses });
  const output = assertStageBArtifactPath({ artifactPath: resultPath, repositoryRoot: root, label: "Installation result", allowExisting: false });
  ensureStageBPrivateDirectory({ directory: path.dirname(output), repositoryRoot: root, create: true, label: "Installation result directory" });
  if (livePredecessor === "EXACT_COMPLETE") {
    if (typeof verifyInstalled !== "function") throw new Error("Canonical verifier is required for exact-complete replay.");
    verifyInstalled();
    const result = { kind: "PRODUCTION_INITIAL_ACTIVATION_POLICY_RECONCILER_INSTALLATION_RESULT", schemaVersion: 1, operation: INSTALLATION.operation, sourceSha, authorizationArtifactSha256: authorization.authorizationArtifactSha256, status: "COMPLETE", applyCount: 0, targetPolicyCreatePolicyVersionCount: 0, verifier: "PASS", state: beforeState, completedAt: new Date().toISOString() };
    writeStageBPrivateFilesAtomic({ repositoryRoot: root, files: [{ filePath: output, bytes: Buffer.from(`${JSON.stringify(result, null, 2)}\n`), label: "Installation result" }] });
    return Object.freeze(result);
  }
  if (typeof applySavedPlan !== "function") throw new Error("Installation saved-plan apply function is required.");
  if (typeof verifyInstalled !== "function") throw new Error("Canonical verifier is required after apply.");
  try {
    applySavedPlan({ planBytes });
  } catch (error) {
    // An apply process can exit after AWS/Terraform commits the resources but
    // before returning a success status. Recover only by read-only verifier;
    // never retry the saved plan blindly.
    let recoveredState;
    try { verifyInstalled(); recoveredState = assertInstallationStateResources(readState?.()); } catch { throw error; }
    const recovered = { kind: "PRODUCTION_INITIAL_ACTIVATION_POLICY_RECONCILER_INSTALLATION_RESULT", schemaVersion: 1, operation: INSTALLATION.operation, sourceSha, authorizationArtifactSha256: authorization.authorizationArtifactSha256, status: "COMPLETE", applyCount: 1, targetPolicyCreatePolicyVersionCount: 0, verifier: "PASS", state: recoveredState, completedAt: new Date().toISOString(), recoveredFromAmbiguousApply: true };
    writeStageBPrivateFilesAtomic({ repositoryRoot: root, files: [{ filePath: output, bytes: Buffer.from(`${JSON.stringify(recovered, null, 2)}\n`), label: "Installation result" }] });
    return Object.freeze(recovered);
  }
  verifyInstalled();
  const stateAfterBytes = readState?.();
  const stateAfter = assertInstallationStateResources(stateAfterBytes);
  const result = { kind: "PRODUCTION_INITIAL_ACTIVATION_POLICY_RECONCILER_INSTALLATION_RESULT", schemaVersion: 1, operation: INSTALLATION.operation, sourceSha, authorizationArtifactSha256: authorization.authorizationArtifactSha256, status: "COMPLETE", applyCount: 1, targetPolicyCreatePolicyVersionCount: 0, verifier: "PASS", state: stateAfter, completedAt: new Date().toISOString() };
  writeStageBPrivateFilesAtomic({ repositoryRoot: root, files: [{ filePath: output, bytes: Buffer.from(`${JSON.stringify(result, null, 2)}\n`), label: "Installation result" }] });
  return Object.freeze(result);
}

export function runInstallCli(argv = process.argv.slice(2), deps = {}) {
  if (!argv.includes("--execute")) throw new Error("Installation requires --execute.");
  const sourceSha = required(argv, "--source-sha");
  const preparationPath = path.resolve(required(argv, "--preparation"));
  const preparationFileSha256 = required(argv, "--preparation-file-sha256");
  const authorizationPath = path.resolve(required(argv, "--authorization"));
  const authorizationFileSha256 = required(argv, "--authorization-file-sha256");
  const planPath = path.resolve(required(argv, "--plan"));
  const planFileSha256 = required(argv, "--plan-file-sha256");
  const resultPath = path.resolve(required(argv, "--result"));
  const terraformDataDir = path.resolve(required(argv, "--terraform-data-dir"));
  const workflowEnvironment = deps.env || process.env;
  if (workflowEnvironment.GITHUB_ACTIONS !== "true" || workflowEnvironment.GITHUB_REPOSITORY !== INSTALLATION.repository || workflowEnvironment.GITHUB_WORKFLOW_REF !== PRODUCTION_ENVIRONMENT_APPROVAL.installationWorkflowRef || workflowEnvironment.GITHUB_EVENT_NAME !== "workflow_dispatch") throw new Error("Installation mutation is reachable only inside the canonical protected GitHub workflow.");
  const terraformEnvironment = { ...createProductionAwsCredentialEnvironment({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_INITIAL_ACTIVATION_BOOTSTRAP, env: workflowEnvironment }), TF_DATA_DIR: terraformDataDir, TF_WORKSPACE: "default" };
  const exec = deps.exec || execFileSync;
  assertProtectedCheckout({ sourceSha, repositoryRoot: root, exec });
  const preparation = readBoundStageBPrivateJson({ filePath: preparationPath, expectedSha256: preparationFileSha256, repositoryRoot: root, label: "Installation preparation artifact" });
  const authorization = readBoundStageBPrivateJson({ filePath: authorizationPath, expectedSha256: authorizationFileSha256, repositoryRoot: root, label: "Installation workflow authorization" });
  assertProductionEnvironmentApprovalEvidence(authorization.protectedEnvironmentApprovalEvidence, { sourceSha, repository: INSTALLATION.repository, environment: INSTALLATION.environment, workflowRef: workflowEnvironment.GITHUB_WORKFLOW_REF, eventName: workflowEnvironment.GITHUB_EVENT_NAME, workflowRunId: workflowEnvironment.GITHUB_RUN_ID, workflowRunAttempt: workflowEnvironment.GITHUB_RUN_ATTEMPT, executionActor: workflowEnvironment.GITHUB_ACTOR, githubActions: workflowEnvironment.GITHUB_ACTIONS, now: deps.now || new Date() });
  const planBeforeAuthorization = readStageBPrivateFileBytes({ filePath: planPath, repositoryRoot: root, label: "Installation saved Terraform plan" });
  if (planBeforeAuthorization.sha256 !== planFileSha256) throw new Error("Installation saved plan transport digest is invalid.");
  const run = deps.run || createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_INITIAL_ACTIVATION_BOOTSTRAP, env: deps.env || process.env });
  const identity = JSON.parse(run(["sts", "get-caller-identity", "--output", "json", "--no-cli-pager"]));
  if (!new RegExp(`^arn:aws:sts::368992683803:assumed-role/${INSTALLATION.executionRoleArn.split("/").at(-1)}/[^/]+$`).test(identity?.Arn || "")) throw new Error("Installation requires the exact workflow-only bootstrap role session.");
  const backendArgs = [`-backend-config=bucket=${INSTALLATION.backend.bucket}`, `-backend-config=key=${INSTALLATION.backend.key}`, `-backend-config=region=${INSTALLATION.backend.region}`, `-backend-config=encrypt=${INSTALLATION.backend.encrypt}`, `-backend-config=use_lockfile=${INSTALLATION.backend.useLockfile}`];
  exec("terraform", [`-chdir=${path.join(root, INSTALLATION.terraformRoot)}`, "init", "-input=false", ...backendArgs], { cwd: root, env: terraformEnvironment, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  const backendMetadata = JSON.parse(readStageBPrivateFileBytes({ filePath: path.join(terraformDataDir, "terraform.tfstate"), repositoryRoot: root, label: "Installation initialized Terraform backend metadata" }).bytes.toString("utf8"));
  assertInstallationInitializedBackendMetadata(backendMetadata?.backend);
  const workspace = String(exec("terraform", [`-chdir=${path.join(root, INSTALLATION.terraformRoot)}`, "workspace", "show"], { cwd: root, env: terraformEnvironment, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] })).trim();
  if (workspace !== "default") throw new Error("Installation requires the canonical default Terraform workspace.");
  const livePredecessor = discoverInstallationPredecessor({ run, expectedCallerArn: identity.Arn });
  if (livePredecessor.classification === "UNEXPECTED") throw new Error("Installation live predecessor is unexpected.");
  const plan = readStageBPrivateFileBytes({ filePath: planPath, repositoryRoot: root, label: "Installation saved Terraform plan" });
  if (plan.sha256 !== planBeforeAuthorization.sha256 || plan.sha256 !== preparation.savedPlanSha256) throw new Error("Installation saved plan changed after authorization.");
  const renderPath = path.join(path.dirname(planPath), `.${path.basename(planPath)}.${crypto.randomUUID()}.render.tfplan`);
  fs.writeFileSync(renderPath, plan.bytes, { flag: "wx", mode: 0o600 });
  let planJson;
  try {
    const rendered = exec("terraform", [`-chdir=${path.join(root, INSTALLATION.terraformRoot)}`, "show", "-json", renderPath], { cwd: root, env: terraformEnvironment, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    planJson = JSON.parse(rendered);
  } finally {
    fs.unlinkSync(renderPath);
  }
  const applySavedPlan = ({ planBytes }) => {
    const appliedPath = path.join(path.dirname(planPath), `.authorized-installation.${crypto.randomUUID()}.tfplan`);
    let staged = false;
    try {
      fs.writeFileSync(appliedPath, planBytes, { flag: "wx", mode: 0o600 });
      staged = true;
      exec("terraform", [`-chdir=${path.join(root, INSTALLATION.terraformRoot)}`, "apply", "-input=false", "-lock-timeout=60s", appliedPath], { cwd: root, env: terraformEnvironment, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    } finally {
      if (staged) fs.unlinkSync(appliedPath);
    }
  };
  const verifyInstalled = () => verifyInitialActivationPolicyReconciler({ run, expectedCallerArn: identity.Arn });
  const readState = () => { try { return Buffer.from(exec("terraform", [`-chdir=${path.join(root, INSTALLATION.terraformRoot)}`, "state", "pull"], { cwd: root, env: terraformEnvironment, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] })); } catch (error) { return classifyInstallationStatePullError(error); } };
  return executeInstallation({ sourceSha, preparation, authorization, planBytes: plan.bytes, planJson, executionRoleArn: INSTALLATION.executionRoleArn, livePredecessor: livePredecessor.classification, livePredecessorAddresses: livePredecessor.existingAddresses, applySavedPlan, verifyInstalled, readState, resultPath, now: deps.now || new Date() });
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) process.stdout.write(`${JSON.stringify(runInstallCli(), null, 2)}\n`);

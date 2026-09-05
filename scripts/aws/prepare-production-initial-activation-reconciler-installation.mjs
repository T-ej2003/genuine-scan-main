#!/usr/bin/env node
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createProductionAwsCommandRunner, createProductionAwsCredentialEnvironment, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, readStageBPrivateFileBytes, writeStageBPrivateFilesAtomic } from "./stage-b-artifact-contract.mjs";
import { INSTALLATION, assertInstallationInitializedBackendMetadata, assertInstallationPlan, assertInstallationStateResources, classifyInstallationStatePullError, createInstallationPreparation, stateIdentity } from "./production-initial-activation-reconciler-installation-contract.mjs";
import { INITIAL_ACTIVATION_RECONCILER, readPolicyEntities, verifyInitialActivationPolicyReconciler } from "./verify-production-initial-activation-policy-reconciler.mjs";
import { normalizeIamPolicyDocument } from "./iam-policy-document.mjs";
import { canonicalJson } from "./production-green-stage-b-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const required = (argv, name) => { const index = argv.indexOf(name); const value = index < 0 ? undefined : argv[index + 1]; if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const option = (argv, name) => { const index = argv.indexOf(name); return index < 0 ? undefined : argv[index + 1]; };
const runJson = (run, args) => JSON.parse(run([...args, "--output", "json", "--no-cli-pager"]));
const noSuchEntity = (error) => /\bNoSuchEntity(?:Exception)?\b/.test(`${error?.stderr || ""} ${error?.message || ""}`);

function readReservedPolicies(run) {
  const policies = [];
  const seenMarkers = new Set();
  let marker;
  for (;;) {
    const response = runJson(run, ["iam", "list-policies", "--scope", "Local", "--no-paginate", ...(marker ? ["--marker", marker] : [])]);
    if (!Array.isArray(response.Policies) || typeof response.IsTruncated !== "boolean") throw new Error("Initial-activation reconciler policy inventory is malformed.");
    policies.push(...response.Policies.filter((candidate) => candidate?.PolicyName === INITIAL_ACTIVATION_RECONCILER.policyName));
    if (!response.IsTruncated) break;
    if (typeof response.Marker !== "string" || !response.Marker || seenMarkers.has(response.Marker)) throw new Error("Initial-activation reconciler policy inventory pagination is invalid.");
    seenMarkers.add(response.Marker);
    marker = response.Marker;
  }
  return policies;
}

function readInitializedBackend(terraformDataDir) {
  const metadata = JSON.parse(readStageBPrivateFileBytes({ filePath: path.join(terraformDataDir, "terraform.tfstate"), repositoryRoot: root, label: "Installation initialized Terraform backend metadata" }).bytes.toString("utf8"));
  assertInstallationInitializedBackendMetadata(metadata?.backend);
  return metadata;
}

export function assertProtectedCheckout({ exec = execFileSync, sourceSha, repositoryRoot = root } = {}) {
  if (!/^[a-f0-9]{40}$/.test(sourceSha || "")) throw new Error("Protected source SHA is invalid.");
  const head = String(exec("git", ["rev-parse", "HEAD"], { cwd: repositoryRoot, encoding: "utf8" })).trim();
  const main = String(exec("git", ["rev-parse", "origin/main"], { cwd: repositoryRoot, encoding: "utf8" })).trim();
  const status = String(exec("git", ["status", "--porcelain", "--untracked-files=all"], { cwd: repositoryRoot, encoding: "utf8" }));
  if (head !== sourceSha || main !== sourceSha || status) throw new Error("Preparation requires the exact clean protected-main checkout.");
  return Object.freeze({ head, originMain: main });
}

export function discoverInstallationPredecessor({ run } = {}) {
  if (typeof run !== "function") throw new Error("An explicit administrator AWS runner is required.");
  const provider = runJson(run, ["iam", "get-open-id-connect-provider", "--open-id-connect-provider-arn", INITIAL_ACTIVATION_RECONCILER.oidcProviderArn]);
  if (provider?.Url !== "token.actions.githubusercontent.com" || !Array.isArray(provider.ClientIDList) || !provider.ClientIDList.some((clientId) => clientId === "sts.amazonaws.com")) throw new Error("GitHub Actions OIDC provider is not exact.");
  let role;
  let policy;
  try { role = runJson(run, ["iam", "get-role", "--role-name", INSTALLATION.roleArn.split("/").at(-1)]).Role; } catch (error) { if (!noSuchEntity(error)) throw error; }
  try { policy = runJson(run, ["iam", "get-policy", "--policy-arn", INSTALLATION.policyArn]).Policy; } catch (error) { if (!noSuchEntity(error)) throw error; }
  const reservedPolicies = readReservedPolicies(run);
  if (reservedPolicies.length !== (policy ? 1 : 0) || policy && reservedPolicies[0]?.Arn !== INSTALLATION.policyArn) return "UNEXPECTED";
  if (!role && !policy) return "ABSENT";
  const trust = JSON.parse(fs.readFileSync(path.join(root, `${INSTALLATION.terraformRoot}/trust-policy.json`), "utf8"));
  const roleExact = !role || (role.Arn === INSTALLATION.roleArn && role.MaxSessionDuration === 3600 && !Object.hasOwn(role, "PermissionsBoundary") && canonicalJson(normalizeIamPolicyDocument(role.AssumeRolePolicyDocument, "reconciler trust policy")) === canonicalJson(trust));
  let policyDocumentExact = true;
  if (policy) {
    if (!/^v[1-9][0-9]*$/.test(policy.DefaultVersionId || "")) policyDocumentExact = false;
    else {
      const version = runJson(run, ["iam", "get-policy-version", "--policy-arn", INSTALLATION.policyArn, "--version-id", policy.DefaultVersionId]).PolicyVersion;
      const expected = JSON.parse(fs.readFileSync(path.join(root, `${INSTALLATION.terraformRoot}/permissions-policy.json`), "utf8"));
      policyDocumentExact = canonicalJson(normalizeIamPolicyDocument(version?.Document, "reconciler permissions policy")) === canonicalJson(expected);
    }
  }
  const policyExact = !policy || (policy.Arn === INSTALLATION.policyArn && policy.PolicyName === "MSCQRProductionInitialActivationPolicyReconciler" && policy.PermissionsBoundaryUsageCount === 0 && policyDocumentExact);
  if (!roleExact || !policyExact) return "UNEXPECTED";
  if (!role || !policy) {
    if (role) {
      const attached = runJson(run, ["iam", "list-attached-role-policies", "--role-name", INSTALLATION.roleArn.split("/").at(-1)]).AttachedPolicies;
      const inline = runJson(run, ["iam", "list-role-policies", "--role-name", INSTALLATION.roleArn.split("/").at(-1)]).PolicyNames;
      if (!Array.isArray(attached) || attached.length !== 0 || !Array.isArray(inline) || inline.length !== 0) return "UNEXPECTED";
    }
    if (policy) {
      const entities = readPolicyEntities(run);
      if (entities.roles.length !== 0 || entities.users.length !== 0 || entities.groups.length !== 0) return "UNEXPECTED";
    }
    return "EXACT_PARTIAL";
  }
  try {
    verifyInitialActivationPolicyReconciler({ run });
    return "EXACT_COMPLETE";
  } catch {
    const attached = runJson(run, ["iam", "list-attached-role-policies", "--role-name", INSTALLATION.roleArn.split("/").at(-1)]).AttachedPolicies;
    const inline = runJson(run, ["iam", "list-role-policies", "--role-name", INSTALLATION.roleArn.split("/").at(-1)]).PolicyNames;
    const entities = readPolicyEntities(run);
    const safePartial = Array.isArray(attached) && (attached.length === 0 || attached.length === 1 && attached[0]?.PolicyArn === INSTALLATION.policyArn)
      && Array.isArray(inline) && inline.length === 0
      && entities.users.length === 0 && entities.groups.length === 0
      && entities.roles.every((candidate) => candidate?.RoleName === INSTALLATION.roleArn.split("/").at(-1))
      && (attached.length === 0 || entities.roles.length === 0);
    if (!safePartial) return "UNEXPECTED";
    return "EXACT_PARTIAL";
  }
}

function terraformPlan({ terraformDataDir, outputDir, profile, exec = execFileSync, parentEnvironment = process.env } = {}) {
  ensureStageBPrivateDirectory({ directory: terraformDataDir, repositoryRoot: root, create: true, label: "Installation Terraform data directory" });
  const env = { ...createProductionAwsCredentialEnvironment({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile, env: parentEnvironment }), TF_DATA_DIR: terraformDataDir };
  const backendArgs = [`-backend-config=bucket=${INSTALLATION.backend.bucket}`, `-backend-config=key=${INSTALLATION.backend.key}`, `-backend-config=region=${INSTALLATION.backend.region}`, `-backend-config=encrypt=${INSTALLATION.backend.encrypt}`, `-backend-config=use_lockfile=${INSTALLATION.backend.useLockfile}`];
  exec("terraform", [`-chdir=${path.join(root, INSTALLATION.terraformRoot)}`, "init", "-input=false", "-lock=false", ...backendArgs], { cwd: root, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  readInitializedBackend(terraformDataDir);
  const workspace = String(exec("terraform", [`-chdir=${path.join(root, INSTALLATION.terraformRoot)}`, "workspace", "show"], { cwd: root, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] })).trim();
  if (workspace !== "default") throw new Error("Installation requires the canonical default Terraform workspace.");
  const pullState = () => {
    try { return Buffer.from(exec("terraform", [`-chdir=${path.join(root, INSTALLATION.terraformRoot)}`, "state", "pull"], { cwd: root, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] })); }
    catch (error) { return classifyInstallationStatePullError(error); }
  };
  const stateBefore = pullState();
  const planPath = path.join(outputDir, "installation.tfplan");
  const planJsonPath = path.join(outputDir, "installation.plan.json");
  exec("terraform", [`-chdir=${path.join(root, INSTALLATION.terraformRoot)}`, "plan", "-input=false", "-lock=false", "-out", planPath], { cwd: root, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  const planBytes = readStageBPrivateFileBytes({ filePath: planPath, repositoryRoot: root, label: "Installation saved Terraform plan" }).bytes;
  const renderPath = path.join(outputDir, "installation-render.tfplan");
  fs.writeFileSync(renderPath, planBytes, { flag: "wx", mode: 0o600 });
  const rendered = exec("terraform", [`-chdir=${path.join(root, INSTALLATION.terraformRoot)}`, "show", "-json", renderPath], { cwd: root, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  fs.unlinkSync(renderPath);
  fs.writeFileSync(planJsonPath, rendered, { flag: "wx", mode: 0o600 });
  const stateAfter = pullState();
  if (JSON.stringify(stateIdentity(stateBefore)) !== JSON.stringify(stateIdentity(stateAfter))) throw new Error("Terraform state changed during read-only installation preparation.");
  return { planPath, planJsonPath, stateBytes: stateAfter };
}

function renderExactPlanJson({ planPath, planBytes, terraformDataDir, profile, exec = execFileSync, outputPath, parentEnvironment = process.env } = {}) {
  const directory = path.dirname(planPath);
  const renderPath = path.join(directory, `.${path.basename(planPath)}.render.tfplan`);
  const env = { ...createProductionAwsCredentialEnvironment({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile, env: parentEnvironment }), TF_DATA_DIR: terraformDataDir };
  fs.writeFileSync(renderPath, planBytes, { flag: "wx", mode: 0o600 });
  try {
    const rendered = exec("terraform", [`-chdir=${path.join(root, INSTALLATION.terraformRoot)}`, "show", "-json", renderPath], { cwd: root, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    fs.writeFileSync(outputPath, rendered, { flag: "wx", mode: 0o600 });
  } finally {
    fs.unlinkSync(renderPath);
  }
}

export function prepareInstallation({ sourceSha, planBytes, planJson, stateBytes, livePredecessor, preparedAt, outputPath, repositoryRoot = root } = {}) {
  const semantics = assertInstallationPlan(planJson);
  if (livePredecessor === "EXACT_PARTIAL") assertInstallationStateResources(stateBytes, { requiredAddresses: INSTALLATION.expectedAddresses.filter((address) => !semantics.changedAddresses.includes(address)) });
  const preparation = createInstallationPreparation({ sourceSha, state: stateIdentity(stateBytes), livePredecessor, planJson, planBytes, preparedAt });
  const output = assertStageBArtifactPath({ artifactPath: outputPath, repositoryRoot, label: "Installation preparation artifact", allowExisting: false });
  writeStageBPrivateFilesAtomic({ repositoryRoot, files: [{ filePath: output, bytes: Buffer.from(`${JSON.stringify(preparation, null, 2)}\n`), label: "Installation preparation artifact" }] });
  return preparation;
}

export function runPrepareCli(argv = process.argv.slice(2), deps = {}) {
  if (!argv.includes("--prepare")) throw new Error("Installation preparation requires --prepare.");
  const sourceSha = required(argv, "--source-sha");
  const profile = required(argv, "--admin-profile");
  const outputPath = path.resolve(required(argv, "--output"));
  assertProtectedCheckout({ sourceSha, repositoryRoot: root, exec: deps.exec || execFileSync });
  ensureStageBPrivateDirectory({ directory: path.dirname(outputPath), repositoryRoot: root, create: true, label: "Installation preparation directory" });
  const run = deps.run || createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile });
  const livePredecessor = discoverInstallationPredecessor({ run });
  if (livePredecessor === "UNEXPECTED") throw new Error("Live installation topology is unexpected.");
  const outputDir = path.dirname(outputPath);
  if (argv.includes("--plan-json")) throw new Error("Independent --plan-json input is not supported; plan JSON is always rendered from the saved plan.");
  const exec = deps.exec || execFileSync;
  const terraformDataDir = path.resolve(required(argv, "--terraform-data-dir"));
  const terraformEnvironment = { ...createProductionAwsCredentialEnvironment({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile, env: deps.env || process.env }), TF_DATA_DIR: terraformDataDir };
  const generated = argv.includes("--plan") ? { planPath: path.resolve(required(argv, "--plan")), planJsonPath: path.join(outputDir, "installation.plan.json") } : terraformPlan({ terraformDataDir, outputDir, profile, exec, parentEnvironment: deps.env || process.env });
  const plan = readStageBPrivateFileBytes({ filePath: generated.planPath, repositoryRoot: root, label: "Installation saved Terraform plan" });
  if (argv.includes("--plan")) {
    readInitializedBackend(terraformDataDir);
    const workspace = String(exec("terraform", [`-chdir=${path.join(root, INSTALLATION.terraformRoot)}`, "workspace", "show"], { cwd: root, env: terraformEnvironment, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] })).trim();
    if (workspace !== "default") throw new Error("Installation requires the canonical default Terraform workspace.");
    renderExactPlanJson({ planPath: generated.planPath, planBytes: plan.bytes, terraformDataDir, profile, exec, outputPath: generated.planJsonPath, parentEnvironment: deps.env || process.env });
  }
  const planJson = JSON.parse(readStageBPrivateFileBytes({ filePath: generated.planJsonPath, repositoryRoot: root, label: "Installation rendered Terraform plan" }).bytes.toString("utf8"));
  if (!argv.includes("--state-file") && !argv.includes("--state-absent")) throw new Error("Preparation must explicitly authenticate a state file or --state-absent.");
  const stateBytes = argv.includes("--state-file") ? readStageBPrivateFileBytes({ filePath: path.resolve(required(argv, "--state-file")), repositoryRoot: root, label: "Installation Terraform state" }).bytes : generated.stateBytes;
  if (!argv.includes("--state-file") && generated.stateBytes !== undefined) throw new Error("Preparation state is present; bind the authenticated state file instead of claiming absence.");
  if (!argv.includes("--state-file") && !(generated.stateBytes === undefined && !argv.includes("--plan"))) throw new Error("State absence must be proven by the canonical Terraform backend read.");
  const preparation = prepareInstallation({ sourceSha, planBytes: plan.bytes, planJson, stateBytes, livePredecessor, outputPath, repositoryRoot: root });
  return preparation;
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) process.stdout.write(`${JSON.stringify(runPrepareCli(), null, 2)}\n`);

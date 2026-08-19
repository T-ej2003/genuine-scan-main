#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { buildStageAStateIdentity, assertStageAStateIdentityBinding } from "./generate-production-green-stage-a-prerequisites.mjs";
import { STAGE_B } from "./production-green-stage-b-contract.mjs";
import { buildRecoveryAwsEnvironment, buildRecoveryTerraformEnvironment } from "./recover-stage-b-backend-task-definition.mjs";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, ensureStageBPrivateFile, writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";
import {
  ROOT_DROP_KEY_ADDRESS,
  ROOT_DROP_ALIAS_ADDRESS,
  ROOT_DROP_CENSUS_ACTOR_BINDINGS,
  assertStageATerraformBackendMetadata,
  buildRootDropAwsReadAdapter,
  collectRootDropCensus,
  createRootDropRecoveryRunner,
} from "./production-stage-a-root-drop-orphan-recovery.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
export const STAGE_A_REQUIRED_TERRAFORM_VARIABLE_KEYS = Object.freeze([
  "TF_VAR_aws_region",
  "TF_VAR_vpc_id",
  "TF_VAR_private_subnet_ids",
  "TF_VAR_runtime_security_group_ids",
  "TF_VAR_s3_prefix_list_id",
  "TF_VAR_vpc_dns_resolver_cidr",
  "TF_VAR_checker_principal_arns",
  "TF_VAR_release_role_arn",
  "TF_VAR_receipt_bucket_arn",
]);
const STAGE_A_FIXED_TERRAFORM_VARIABLES = Object.freeze({
  TF_VAR_aws_region: STAGE_B.region,
  TF_VAR_checker_principal_arns: `["arn:aws:iam::${STAGE_B.account}:role/mscqr-production-independent-checker"]`,
  TF_VAR_release_role_arn: `arn:aws:iam::${STAGE_B.account}:role/mscqr-production-release-deployer`,
  TF_VAR_receipt_bucket_arn: `arn:aws:s3:::mscqr-prod-euw2-artifacts-${STAGE_B.account}-${STAGE_B.region}-an`,
});
const assertStageATerraformVariables = (baseEnv = process.env) => {
  const allowed = new Set(STAGE_A_REQUIRED_TERRAFORM_VARIABLE_KEYS);
  const unexpected = Object.keys(baseEnv).filter((key) => key.startsWith("TF_VAR_") && !allowed.has(key));
  if (unexpected.length) throw new Error(`Stage-A recovery received unreviewed Terraform variables: ${unexpected.sort().join(", ")}`);
  for (const key of STAGE_A_REQUIRED_TERRAFORM_VARIABLE_KEYS) {
    if (typeof baseEnv[key] !== "string" || !baseEnv[key].trim()) throw new Error(`Stage-A recovery requires ${key} from the canonical production variable-input contract`);
  }
  for (const [key, expected] of Object.entries(STAGE_A_FIXED_TERRAFORM_VARIABLES)) if (baseEnv[key] !== expected) throw new Error(`${key} is outside the protected production Stage-A variable contract`);
  return true;
};
const option = (argv, name, required = true) => {
  const index = argv.indexOf(name);
  const value = index >= 0 ? argv[index + 1] : undefined;
  if (required && (!value || value.startsWith("--"))) throw new Error(`${name} is required`);
  return value;
};
const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8"));
const privatePath = (filePath, label) => ensureStageBPrivateFile({ filePath, repositoryRoot: root, label }).path;
const canonicalTerraformRoot = realpathSync(path.join(root, "infra/aws/terraform/production-green-stage-a"));
const assertCanonicalTerraformRoot = (requested) => {
  const resolved = realpathSync(path.resolve(requested || canonicalTerraformRoot));
  if (resolved !== canonicalTerraformRoot) throw new Error("Stage-A root-drop adoption requires the canonical production Stage-A Terraform root");
  return resolved;
};
const readCanonicalTerraformBackend = (terraformRoot) => {
  const dataDir = path.join(terraformRoot, ".terraform");
  const metadataPath = path.join(dataDir, "terraform.tfstate");
  if (lstatSync(dataDir).isSymbolicLink() || lstatSync(metadataPath).isSymbolicLink() || !lstatSync(metadataPath).isFile()) throw new Error("Stage-A root-drop adoption requires canonical initialized Terraform backend metadata");
  const metadata = JSON.parse(readFileSync(metadataPath, "utf8"));
  assertStageATerraformBackendMetadata(metadata);
  return metadata.backend || metadata;
};

export function validateRootDropPlanPaths({ planPath, repositoryRoot = root, reservedPaths = [] } = {}) {
  const repositoryRealpath = realpathSync(repositoryRoot);
  const reserved = new Set(reservedPaths.map((filePath) => realpathSync(filePath)));
  const validate = (filePath, label) => {
    const resolved = assertStageBArtifactPath({ artifactPath: filePath, repositoryRoot, label, allowExisting: false });
    const parent = path.dirname(resolved);
    ensureStageBPrivateDirectory({ directory: parent, repositoryRoot, create: false, label: `${label} parent directory` });
    const parentRealpath = realpathSync(parent);
    if (parentRealpath === repositoryRealpath || parentRealpath.startsWith(`${repositoryRealpath}${path.sep}`)) throw new Error(`${label} must be outside the repository.`);
    const canonical = path.join(parentRealpath, path.basename(resolved));
    if (reserved.has(canonical)) throw new Error(`${label} must not alias another recovery artifact.`);
    return canonical;
  };
  const plan = validate(planPath, "Stage-A adoption plan");
  const zeroDrift = validate(`${plan}.zero-drift`, "Stage-A zero-drift plan");
  if (plan === zeroDrift) throw new Error("Stage-A adoption plan and zero-drift plan must be distinct.");
  return { planPath: plan, zeroDriftPlanPath: zeroDrift };
}

function failedEvidence(argv) {
  const evidence = {
    sourceSha: option(argv, "--source-sha"),
    transitionId: option(argv, "--transition-id"),
    planSha256: option(argv, "--plan-sha256"),
    failedApplyWindow: { start: option(argv, "--failed-apply-start"), end: option(argv, "--failed-apply-end") },
  };
  for (const [key, flag] of [["creatorArn", "--creator-arn"], ["creationEventId", "--creation-event-id"]]) {
    const value = option(argv, flag, false);
    if (value !== undefined) evidence[key] = value;
  }
  return evidence;
}

export async function runCensus({ argv = process.argv.slice(2), run, execFile = execFileSync, write = (value) => process.stdout.write(value) } = {}) {
  const adminProfile = option(argv, "--admin-profile");
  const releaseProfile = option(argv, "--release-profile");
  if (adminProfile === releaseProfile) throw new Error("Stage-A root-drop census requires distinct administrator and release profiles");
  const suppliedRegion = option(argv, "--region", false);
  if (argv.includes("--region") && !suppliedRegion) throw new Error("Stage-A root-drop census: --region requires a value");
  const region = suppliedRegion || STAGE_B.region;
  if (region !== STAGE_B.region) throw new Error("Stage-A root-drop census: region is outside the protected production boundary");
  const statePath = privatePath(option(argv, "--stage-a-state"), "Stage-A state");
  const identityPath = privatePath(option(argv, "--stage-a-state-identity"), "Stage-A state identity");
  const outputPath = option(argv, "--output");
  const stateBytes = readFileSync(statePath);
  const state = JSON.parse(stateBytes);
  const stageAStateIdentity = readJson(identityPath);
  assertStageAStateIdentityBinding(buildStageAStateIdentity(state, { stateBytes }), stageAStateIdentity);
  const evidence = failedEvidence(argv);
  const env = buildRecoveryAwsEnvironment(releaseProfile);
  const adapter = buildRootDropAwsReadAdapter({ run: run || ((args) => execFile("aws", args, { cwd: root, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] })), profile: releaseProfile, discoveryProfile: adminProfile, provenanceProfile: adminProfile, actorBindings: ROOT_DROP_CENSUS_ACTOR_BINDINGS, region });
  const census = collectRootDropCensus({ adapter, terraformState: state, sourceSha: evidence.sourceSha, transitionId: evidence.transitionId, stageAStateIdentity, failedApplyEvidence: evidence });
  writeStageBPrivateFileAtomic({ filePath: outputPath, bytes: Buffer.from(`${JSON.stringify(census, null, 2)}\n`), repositoryRoot: root, label: "Stage-A root-drop census" });
  write(`${JSON.stringify({ status: census.status, candidateCount: census.candidateCount, output: outputPath }, null, 2)}\n`);
  return census;
}

export async function runAdoption({ argv = process.argv.slice(2), runTerraform, readRootDropCensus, readTerraformBackendMetadata = readCanonicalTerraformBackend, execFile = execFileSync, write = (value) => process.stdout.write(value) } = {}) {
  const censusPath = privatePath(option(argv, "--census"), "Stage-A root-drop census");
  const census = readJson(censusPath);
  const statePath = privatePath(option(argv, "--stage-a-state"), "Stage-A state");
  const identityPath = privatePath(option(argv, "--stage-a-state-identity"), "Stage-A state identity");
  const stateBytes = readFileSync(statePath);
  const stageAState = JSON.parse(stateBytes);
  const stageAStateIdentity = readJson(identityPath);
  assertStageAStateIdentityBinding(buildStageAStateIdentity(stageAState, { stateBytes }), stageAStateIdentity);
  const adminProfile = option(argv, "--admin-profile");
  const releaseProfile = option(argv, "--release-profile");
  if (adminProfile === releaseProfile) throw new Error("Stage-A root-drop adoption requires distinct administrator and release profiles");
  const suppliedRegion = option(argv, "--region", false);
  if (argv.includes("--region") && !suppliedRegion) throw new Error("Stage-A root-drop adoption: --region requires a value");
  const region = suppliedRegion || STAGE_B.region;
  if (region !== STAGE_B.region) throw new Error("Stage-A root-drop adoption: region is outside the protected production boundary");
  const terraformRoot = assertCanonicalTerraformRoot(option(argv, "--terraform-root", false));
  const planPath = option(argv, "--plan-path");
  const { planPath: validatedPlanPath, zeroDriftPlanPath } = validateRootDropPlanPaths({ planPath, reservedPaths: [censusPath, statePath, identityPath] });
  readTerraformBackendMetadata(terraformRoot);
  assertStageATerraformVariables();
  const env = buildRecoveryTerraformEnvironment(releaseProfile, process.env, { allowedTerraformVariableKeys: STAGE_A_REQUIRED_TERRAFORM_VARIABLE_KEYS });
  const tf = runTerraform
    ? (args) => runTerraform(args, env)
    : (args) => execFile("terraform", [`-chdir=${terraformRoot}`, ...args], { cwd: root, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  if (tf(["workspace", "show"]).trim() !== "default") throw new Error("Stage-A root-drop adoption requires the canonical default Terraform workspace");
  tf(["plan", "-input=false", "-lock=false", "-refresh=false", "-no-color"]);
  const freshCensus = readRootDropCensus
    ? await readRootDropCensus({ census, stageAState, stageAStateIdentity, profile: releaseProfile, adminProfile, releaseProfile })
    : collectRootDropCensus({
      adapter: buildRootDropAwsReadAdapter({ run: (args) => execFile("aws", args, { cwd: root, env: buildRecoveryAwsEnvironment(releaseProfile), encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }), profile: releaseProfile, discoveryProfile: adminProfile, provenanceProfile: adminProfile, actorBindings: ROOT_DROP_CENSUS_ACTOR_BINDINGS, region }),
      terraformState: stageAState,
      sourceSha: census.sourceSha,
      transitionId: census.transitionId,
      stageAStateIdentity,
      failedApplyEvidence: census.failedApplyEvidence,
  });
  const execute = argv.includes("--execute");
  const readStateSnapshot = async () => { const stateBytes = Buffer.from(tf(["state", "pull"])); return { state: JSON.parse(stateBytes), stateBytes }; };
  const readState = async () => (await readStateSnapshot()).state;
  const importKey = async ({ address, id }) => { tf(["import", "-input=false", "-lock=true", address, id]); return { outcome: "CONFIRMED_SUCCESS" }; };
  const refreshState = async () => readState();
  const createPlan = async ({ zeroDrift = false } = {}) => { const output = zeroDrift ? zeroDriftPlanPath : validatedPlanPath; tf(["plan", "-input=false", "-lock=true", "-out", output]); return output; };
  const readPlan = async (savedPath) => JSON.parse(tf(["show", "-json", savedPath]));
  const applyPlan = async (savedPath) => { if (!execute) throw new Error("alias apply requires explicit --execute"); tf(["apply", "-input=false", "-lock=true", savedPath]); return { outcome: "CONFIRMED_SUCCESS" }; };
  const runner = createRootDropRecoveryRunner({ execute, readState, readStateSnapshot, importKey, refreshState, createPlan, readPlan, applyPlan });
  const result = await runner({ census, freshCensus, terraformState: stageAState, stageAStateIdentity, sourceSha: census.sourceSha, transitionId: census.transitionId, planSha256: census.failedApplyEvidence?.planSha256 });
  write(`${JSON.stringify(result, null, 2)}\n`);
  return result;
}

export async function runCli(argv = process.argv.slice(2), dependencies = {}) {
  const mode = option(argv, "--mode");
  if (mode === "census") return runCensus({ argv, ...dependencies });
  if (mode === "adopt") return runAdoption({ argv, ...dependencies });
  throw new Error("--mode must be census or adopt");
}

if (import.meta.url === `file://${process.argv[1]}`) {
  runCli().catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
}

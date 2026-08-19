#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { existsSync, lstatSync, readFileSync, readdirSync, realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { buildStageAStateIdentity, assertStageAStateIdentityBinding, parseAuthenticatedStateBytes } from "./generate-production-green-stage-a-prerequisites.mjs";
import { STAGE_B } from "./production-green-stage-b-contract.mjs";
import { buildRecoveryAwsEnvironment, buildRecoveryTerraformEnvironment } from "./recover-stage-b-backend-task-definition.mjs";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, ensureStageBPrivateFile, writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";
import { readStageBProtectedMainCheckout } from "./stage-b-deployment-identity.mjs";
import {
  ROOT_DROP_KEY_ADDRESS,
  ROOT_DROP_ALIAS_ADDRESS,
  ROOT_DROP_CENSUS_ACTOR_BINDINGS,
  assertStageATerraformBackendMetadata,
  assertRootDropCensus,
  assertRootDropKeyIdentity,
  assertRootDropStateIdentity,
  buildRootDropAwsReadAdapter,
  collectRootDropCensus,
  rootDropStateCounts,
  assertAuthorizedRootDropRefreshTransition,
  createRootDropRecoveryRunner,
  assertRootDropAliasOnlyPlan,
  assertRootDropPreImportPlan,
  assertRootDropRefreshOnlyPlan,
  rootDropRecoverySha256,
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
export function assertNoAutoLoadedTerraformVariableFiles(terraformRoot) {
  const autoLoaded = readdirSync(terraformRoot).filter((name) => name === "terraform.tfvars" || name === "terraform.tfvars.json" || /.+\.auto\.tfvars(?:\.json)?$/.test(name));
  if (autoLoaded.length) throw new Error(`Stage-A recovery rejects auto-loaded Terraform variable files: ${autoLoaded.sort().join(", ")}`);
  return true;
}

const isExecutionRelevantTerraformPath = (value) => {
  const normalized = value.replace(/^"|"$/g, "");
  return /(?:^|\/)(?:terraform\.tfvars(?:\.json)?|[^/]+\.auto\.tfvars(?:\.json)?|override\.tf(?:\.json)?|[^/]+_override\.tf(?:\.json)?|[^/]+\.tf(?:\.json)?)$/.test(normalized);
};

export function assertRootDropExecutionSource({ sourceSha, repositoryRoot = root, terraformRoot = canonicalTerraformRoot, runGit = (args) => execFileSync("git", args, { cwd: repositoryRoot, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) } = {}) {
  const repositoryRealpath = realpathSync(repositoryRoot);
  const terraformRealpath = realpathSync(terraformRoot);
  if (path.relative(repositoryRealpath, terraformRealpath).startsWith(`..${path.sep}`)) throw new Error("Stage-A root-drop adoption Terraform root is outside the authenticated repository");
  const protectedCheckout = readStageBProtectedMainCheckout({ cwd: repositoryRealpath, fetchOriginMain: true, run: runGit });
  const currentHead = protectedCheckout.currentHead;
  const status = protectedCheckout.porcelainStatus;
  const topLevel = realpathSync(String(runGit(["rev-parse", "--show-toplevel"])).trim());
  if (topLevel !== repositoryRealpath) throw new Error("Stage-A root-drop adoption is not running from the authenticated repository root");
  if (currentHead !== sourceSha) throw new Error("Stage-A root-drop adoption checkout HEAD does not match the freshly fetched protected main");
  const relativeTerraformRoot = path.relative(repositoryRealpath, terraformRealpath);
  const ignoredStatus = String(runGit(["status", "--porcelain=v1", "--ignored=matching", "--untracked-files=all", "--", relativeTerraformRoot]));
  const ignoredRelevant = ignoredStatus.split("\n").filter((line) => line.startsWith("!!") && isExecutionRelevantTerraformPath(line.slice(3).trim()));
  if (ignoredRelevant.length) throw new Error(`Stage-A root-drop adoption has ignored Terraform configuration: ${ignoredRelevant.join(", ")}`);
  const trackedModes = String(runGit(["ls-files", "-s", "--", relativeTerraformRoot])).split("\n").filter(Boolean);
  if (trackedModes.some((line) => /^(?:120000|160000)\s/.test(line))) throw new Error("Stage-A root-drop adoption rejects symlinked or submodule Terraform configuration");
  return Object.freeze({ sourceSha, currentHead, repositoryRoot: repositoryRealpath, terraformRoot: terraformRealpath, clean: true });
}

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
  const preImport = validate(`${plan}.pre-import`, "Stage-A pre-import plan");
  if (new Set([plan, zeroDrift, preImport]).size !== 3) throw new Error("Stage-A recovery plan outputs must be distinct.");
  return { planPath: plan, zeroDriftPlanPath: zeroDrift, preImportPlanPath: preImport };
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
  const historicalStateIdentityPath = option(argv, "--failed-apply-state-identity", false);
  if (historicalStateIdentityPath) evidence.stageAStateIdentity = readJson(privatePath(historicalStateIdentityPath, "Failed-apply Stage-A state identity"));
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
  const state = parseAuthenticatedStateBytes(stateBytes);
  const stageAStateIdentity = readJson(identityPath);
  assertStageAStateIdentityBinding(buildStageAStateIdentity(state, { stateBytes }), stageAStateIdentity);
  const { keyCount, aliasCount } = rootDropStateCounts(state);
  const evidence = failedEvidence(argv);
  const env = buildRecoveryAwsEnvironment(releaseProfile);
  const adapter = buildRootDropAwsReadAdapter({ run: run || ((args) => execFile("aws", args, { cwd: root, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] })), profile: releaseProfile, discoveryProfile: adminProfile, provenanceProfile: adminProfile, actorBindings: ROOT_DROP_CENSUS_ACTOR_BINDINGS, region });
  const census = collectRootDropCensus({ adapter, terraformState: state, sourceSha: evidence.sourceSha, transitionId: evidence.transitionId, stageAStateIdentity, failedApplyEvidence: evidence, allowKeyOnly: keyCount === 1 && aliasCount === 0, allowMissingArn: keyCount === 1 && aliasCount === 0 });
  writeStageBPrivateFileAtomic({ filePath: outputPath, bytes: Buffer.from(`${JSON.stringify(census, null, 2)}\n`), repositoryRoot: root, label: "Stage-A root-drop census" });
  write(`${JSON.stringify({ status: census.status, candidateCount: census.candidateCount, output: outputPath }, null, 2)}\n`);
  return census;
}

export async function runAdoption(options = {}) {
  const refreshAccounting = { terraformRefreshOnlyApplies: 0, terraformStateWrites: 0 };
  try {
    return await runAdoptionInternal({ ...options, refreshAccounting });
  } catch (error) {
    if (refreshAccounting.terraformRefreshOnlyApplies || refreshAccounting.terraformStateWrites) {
      const value = error instanceof Error ? error : new Error(String(error));
      value.recoveryAccounting = { ...(value.recoveryAccounting || {}), ...refreshAccounting };
      throw value;
    }
    throw error;
  }
}

async function runAdoptionInternal({ argv = process.argv.slice(2), runTerraform, readRootDropCensus, readTerraformBackendMetadata = readCanonicalTerraformBackend, execFile = execFileSync, runGit, write = (value) => process.stdout.write(value), refreshAccounting } = {}) {
  const censusPath = privatePath(option(argv, "--census"), "Stage-A root-drop census");
  const census = readJson(censusPath);
  const statePath = privatePath(option(argv, "--stage-a-state"), "Stage-A state");
  const identityPath = privatePath(option(argv, "--stage-a-state-identity"), "Stage-A state identity");
  const stateBytes = readFileSync(statePath);
  const stageAState = parseAuthenticatedStateBytes(stateBytes);
  const stageAStateIdentity = readJson(identityPath);
  assertStageAStateIdentityBinding(buildStageAStateIdentity(stageAState, { stateBytes }), stageAStateIdentity);
  const legacyPolicyBound = census.status === "AUTHENTICATED_ORPHAN" && census.candidates?.[0]?.policyCompatibility === "LEGACY_BOUND_HISTORICAL";
  const stageARootDropCounts = (value) => ({
    keyCount: (value.resources || []).filter((resource) => resource?.type === "aws_kms_key" && resource?.name === "root_drop").flatMap((resource) => Array.isArray(resource.instances) ? resource.instances : []).length,
    aliasCount: (value.resources || []).filter((resource) => resource?.type === "aws_kms_alias" && resource?.name === "root_drop").flatMap((resource) => Array.isArray(resource.instances) ? resource.instances : []).length,
  });
  const censusIdentity = { stateIdentityVersion: census.stageAStateIdentityVersion, lineage: census.stageAStateLineage, serial: census.stageAStateSerial, stateSha256: census.stageAStateSha256 };
  const currentStateCounts = stageARootDropCounts(stageAState);
  if (legacyPolicyBound && currentStateCounts.keyCount === 1 && (currentStateCounts.aliasCount === 0 || currentStateCounts.aliasCount === 1)) assertRootDropCensus(census, { sourceSha: census.sourceSha, transitionId: census.transitionId, stageAStateIdentity: censusIdentity });
  else assertRootDropCensus(census, { sourceSha: census.sourceSha, transitionId: census.transitionId, stageAStateIdentity });
  const adminProfile = option(argv, "--admin-profile");
  const releaseProfile = option(argv, "--release-profile");
  if (adminProfile === releaseProfile) throw new Error("Stage-A root-drop adoption requires distinct administrator and release profiles");
  const suppliedRegion = option(argv, "--region", false);
  if (argv.includes("--region") && !suppliedRegion) throw new Error("Stage-A root-drop adoption: --region requires a value");
  const region = suppliedRegion || STAGE_B.region;
  if (region !== STAGE_B.region) throw new Error("Stage-A root-drop adoption: region is outside the protected production boundary");
  const terraformRoot = assertCanonicalTerraformRoot(option(argv, "--terraform-root", false));
  const executionSourceSha = legacyPolicyBound ? option(argv, "--execution-source-sha") : census.sourceSha;
  const planPath = option(argv, "--plan-path");
  const { planPath: validatedPlanPath, zeroDriftPlanPath, preImportPlanPath } = validateRootDropPlanPaths({ planPath, reservedPaths: [censusPath, statePath, identityPath] });
  assertNoAutoLoadedTerraformVariableFiles(terraformRoot);
  assertRootDropExecutionSource({ sourceSha: executionSourceSha, terraformRoot, runGit: runGit || ((args) => execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] })) });
  readTerraformBackendMetadata(terraformRoot);
  assertStageATerraformVariables();
  const env = buildRecoveryTerraformEnvironment(releaseProfile, process.env, { allowedTerraformVariableKeys: STAGE_A_REQUIRED_TERRAFORM_VARIABLE_KEYS });
  const tf = runTerraform
    ? (args) => runTerraform(args, env)
    : (args) => execFile("terraform", [`-chdir=${terraformRoot}`, ...args], { cwd: root, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  if (tf(["workspace", "show"]).trim() !== "default") throw new Error("Stage-A root-drop adoption requires the canonical default Terraform workspace");
  const readStateSnapshot = async () => { const stateBytes = Buffer.from(tf(["state", "pull"])); return { state: parseAuthenticatedStateBytes(stateBytes), stateBytes }; };
  const readState = async () => (await readStateSnapshot()).state;
  const execute = argv.includes("--execute");
  const importKey = async ({ address, id }) => { tf(["import", "-input=false", "-lock=true", address, id]); return { outcome: "CONFIRMED_SUCCESS" }; };
  const refreshState = async () => readState();
  const createPlan = async ({ zeroDrift = false } = {}) => { const output = zeroDrift ? zeroDriftPlanPath : validatedPlanPath; tf(["plan", "-input=false", "-lock=true", "-out", output]); return output; };
  const readPlan = async (savedPath) => JSON.parse(tf(["show", "-json", savedPath]));
  const applyPlan = async (savedPath) => { if (!execute) throw new Error("alias apply requires explicit --execute"); tf(["apply", "-input=false", "-lock=true", savedPath]); return { outcome: "CONFIRMED_SUCCESS" }; };
  const rootDropCounts = stageARootDropCounts;
  const initialSnapshot = await readStateSnapshot();
  const initialStateIdentity = buildStageAStateIdentity(initialSnapshot.state, { stateBytes: initialSnapshot.stateBytes });
  const initialCounts = rootDropCounts(initialSnapshot.state);
  if (census.status !== "AUTHENTICATED_ORPHAN" || !census.candidates?.[0]?.keyId) throw new Error("Stage-A root-drop adoption requires an authenticated orphan census");
  if (initialCounts.keyCount === 0 && initialCounts.aliasCount === 0) {
    assertStageAStateIdentityBinding(initialStateIdentity, stageAStateIdentity);
  } else if (initialCounts.keyCount === 1 && initialCounts.aliasCount === 0) {
    if (legacyPolicyBound) assertStageAStateIdentityBinding(initialStateIdentity, stageAStateIdentity);
    assertRootDropKeyIdentity(initialSnapshot.state, census.candidates[0].keyId, { allowMissingComputedIdentity: legacyPolicyBound });
  } else if (initialCounts.keyCount === 1 && initialCounts.aliasCount === 1) {
    assertRootDropStateIdentity(initialSnapshot.state, { keyId: census.candidates[0].keyId, requireCanonicalPolicy: true });
  } else {
    throw new Error("Stage-A root-drop adoption encountered an unsupported Terraform state topology");
  }
  let refreshedSnapshot = initialSnapshot;
  let currentStateIdentity = initialStateIdentity;
  let preImportPlanSha256;
  let preImportPlan;
  let refreshOnlyPlanSha256;
  if (initialCounts.aliasCount === 0) {
    if (legacyPolicyBound && initialCounts.keyCount === 1) {
      const keyId = census.candidates[0].keyId;
      const preIdentity = assertRootDropKeyIdentity(initialSnapshot.state, keyId, { allowMissingComputedIdentity: true });
      tf(["plan", "-refresh-only", "-input=false", "-lock=true", "-out", preImportPlanPath, "-no-color"]);
      refreshOnlyPlanSha256 = rootDropRecoverySha256(readFileSync(preImportPlanPath));
      preImportPlan = JSON.parse(tf(["show", "-json", preImportPlanPath]));
      if (rootDropRecoverySha256(readFileSync(preImportPlanPath)) !== refreshOnlyPlanSha256) throw new Error("Stage-A refresh-only plan changed while it was being classified");
      const refreshClassification = assertRootDropRefreshOnlyPlan(preImportPlan, { keyId, stateAlreadyConverged: preIdentity.computedIdentityComplete });
      if (!refreshClassification.stateConverged) {
        if (!execute) throw new Error("Stage-A historical 1/0 recovery requires --execute to persist the authenticated refresh-only state transition");
        if (rootDropRecoverySha256(readFileSync(preImportPlanPath)) !== refreshOnlyPlanSha256) throw new Error("Stage-A refresh-only plan changed immediately before state persistence");
        refreshAccounting.terraformRefreshOnlyApplies += 1;
        try {
          tf(["apply", "-input=false", "-lock=true", preImportPlanPath]);
          refreshAccounting.terraformStateWrites += 1;
        } catch (error) {
          let observed;
          try { observed = await readStateSnapshot(); } catch (readError) { error.mutationOutcome = "AMBIGUOUS"; error.recoveryAccounting = { unknownMutations: 1 }; throw error; }
          try {
            assertAuthorizedRootDropRefreshTransition({ beforeState: initialSnapshot.state, beforeStateBytes: initialSnapshot.stateBytes, afterState: observed.state, afterStateBytes: observed.stateBytes, keyId });
            refreshedSnapshot = observed;
            refreshAccounting.terraformStateWrites += 1;
          } catch {
            if (rootDropRecoverySha256(observed.stateBytes) === rootDropRecoverySha256(initialSnapshot.stateBytes)) {
              error.mutationOutcome = "DEFINITE_FAILURE";
            } else {
              error.mutationOutcome = "AMBIGUOUS";
              error.recoveryAccounting = { unknownMutations: 1 };
            }
            throw error;
          }
        }
        if (refreshedSnapshot === initialSnapshot) refreshedSnapshot = await readStateSnapshot();
      } else refreshedSnapshot = initialSnapshot;
      currentStateIdentity = buildStageAStateIdentity(refreshedSnapshot.state, { stateBytes: refreshedSnapshot.stateBytes });
      if (!refreshClassification.stateConverged) currentStateIdentity = assertAuthorizedRootDropRefreshTransition({ beforeState: initialSnapshot.state, beforeStateBytes: initialSnapshot.stateBytes, afterState: refreshedSnapshot.state, afterStateBytes: refreshedSnapshot.stateBytes, keyId });
      else assertRootDropKeyIdentity(refreshedSnapshot.state, keyId);
    } else {
      tf(["plan", "-input=false", "-lock=false", "-refresh=true", "-out", preImportPlanPath, "-no-color"]);
      preImportPlanSha256 = rootDropRecoverySha256(readFileSync(preImportPlanPath));
      preImportPlan = JSON.parse(tf(["show", "-json", preImportPlanPath]));
      if (rootDropRecoverySha256(readFileSync(preImportPlanPath)) !== preImportPlanSha256) throw new Error("Stage-A pre-import plan changed while it was being classified");
      refreshedSnapshot = await readStateSnapshot();
      currentStateIdentity = buildStageAStateIdentity(refreshedSnapshot.state, { stateBytes: refreshedSnapshot.stateBytes });
      assertStageAStateIdentityBinding(currentStateIdentity, initialStateIdentity);
    }
    const refreshedCounts = rootDropCounts(refreshedSnapshot.state);
    if (refreshedCounts.keyCount !== initialCounts.keyCount || refreshedCounts.aliasCount !== initialCounts.aliasCount) throw new Error("Stage-A refresh changed root-drop state before adoption");
    if (initialCounts.keyCount === 1) assertRootDropKeyIdentity(refreshedSnapshot.state, census.candidates[0].keyId);
  }
  const freshCensus = initialCounts.aliasCount === 1 ? undefined : readRootDropCensus
    ? await readRootDropCensus({ census, stageAState: refreshedSnapshot.state, stageAStateIdentity: currentStateIdentity, profile: releaseProfile, adminProfile, releaseProfile, allowKeyOnly: initialCounts.keyCount === 1, allowMissingArn: false })
    : collectRootDropCensus({
      adapter: buildRootDropAwsReadAdapter({ run: (args) => execFile("aws", args, { cwd: root, env: buildRecoveryAwsEnvironment(releaseProfile), encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }), profile: releaseProfile, discoveryProfile: adminProfile, provenanceProfile: adminProfile, actorBindings: ROOT_DROP_CENSUS_ACTOR_BINDINGS, region }),
      terraformState: refreshedSnapshot.state,
      sourceSha: census.sourceSha,
      transitionId: census.transitionId,
      stageAStateIdentity: currentStateIdentity,
      failedApplyEvidence: census.failedApplyEvidence,
      allowKeyOnly: initialCounts.keyCount === 1,
      allowMissingArn: false,
  });
  if (initialCounts.aliasCount === 0) {
    if (initialCounts.keyCount === 0) assertRootDropPreImportPlan(preImportPlan);
    else if (!legacyPolicyBound) assertRootDropAliasOnlyPlan(preImportPlan, { keyId: freshCensus?.candidates?.[0]?.keyId, policyCompatibility: freshCensus?.candidates?.[0]?.policyCompatibility });
  }
  const runner = createRootDropRecoveryRunner({ execute, readState, readStateSnapshot, importKey, refreshState, createPlan, readPlan, readPlanBytes: async (savedPath) => readFileSync(savedPath), applyPlan });
  const result = await runner({ census, freshCensus, terraformState: refreshedSnapshot.state, stageAStateIdentity: currentStateIdentity, sourceSha: census.sourceSha, transitionId: census.transitionId, planSha256: census.failedApplyEvidence?.planSha256 });
  const report = { ...result, preImportPlanSha256, terraformRefreshOnlyApplies: refreshAccounting.terraformRefreshOnlyApplies, terraformStateWrites: refreshAccounting.terraformStateWrites, ...(refreshOnlyPlanSha256 ? { refreshOnlyPlanSha256 } : {}) };
  write(`${JSON.stringify(report, null, 2)}\n`);
  return report;
}

export async function runCli(argv = process.argv.slice(2), dependencies = {}) {
  const mode = option(argv, "--mode");
  if (mode === "census") return runCensus({ argv, ...dependencies });
  if (mode === "adopt") return runAdoption({ argv, ...dependencies });
  throw new Error("--mode must be census or adopt");
}

const ZERO_RECOVERY_ACCOUNTING = Object.freeze({ terraformImports: 0, terraformApplies: 0, kmsWrites: 0, iamWrites: 0, unknownMutations: 0, unclassifiedMutations: 0 });
export function formatRootDropRecoveryFailure(error) {
  const value = error instanceof Error ? error : new Error(String(error));
  const result = { status: "FAILED", error: value.message, recoveryAccounting: { ...ZERO_RECOVERY_ACCOUNTING, ...(value.recoveryAccounting || {}) } };
  if (typeof value.mutationOutcome === "string") result.mutationOutcome = value.mutationOutcome;
  return `${JSON.stringify(result)}\n`;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  runCli().catch((error) => { process.stderr.write(formatRootDropRecoveryFailure(error)); process.exitCode = 1; });
}

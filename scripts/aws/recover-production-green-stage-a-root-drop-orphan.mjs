#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { buildStageAStateIdentity, assertStageAStateIdentityBinding } from "./generate-production-green-stage-a-prerequisites.mjs";
import { STAGE_B } from "./production-green-stage-b-contract.mjs";
import { buildRecoveryAwsEnvironment, buildRecoveryTerraformEnvironment } from "./recover-stage-b-backend-task-definition.mjs";
import { ensureStageBPrivateFile, writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";
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
  readTerraformBackendMetadata(terraformRoot);
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
  const planPath = option(argv, "--plan-path");
  const execute = argv.includes("--execute");
  const env = buildRecoveryTerraformEnvironment(releaseProfile);
  const tf = runTerraform || ((args) => execFile("terraform", [`-chdir=${terraformRoot}`, ...args], { cwd: root, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }));
  if (tf(["workspace", "show"]).trim() !== "default") throw new Error("Stage-A root-drop adoption requires the canonical default Terraform workspace");
  const readStateSnapshot = async () => { const stateBytes = Buffer.from(tf(["state", "pull"])); return { state: JSON.parse(stateBytes), stateBytes }; };
  const readState = async () => (await readStateSnapshot()).state;
  const importKey = async ({ address, id }) => { tf(["import", "-input=false", "-lock=true", address, id]); return { outcome: "CONFIRMED_SUCCESS" }; };
  const refreshState = async () => readState();
  const createPlan = async ({ zeroDrift = false } = {}) => { const output = zeroDrift ? `${planPath}.zero-drift` : planPath; tf(["plan", "-input=false", "-lock=true", "-out", output]); return output; };
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

#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { buildStageAStateIdentity, assertStageAStateIdentityBinding } from "./generate-production-green-stage-a-prerequisites.mjs";
import { STAGE_B } from "./production-green-stage-b-contract.mjs";
import { buildRecoveryAwsEnvironment } from "./recover-stage-b-backend-task-definition.mjs";
import { ensureStageBPrivateFile, writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";
import {
  ROOT_DROP_KEY_ADDRESS,
  ROOT_DROP_ALIAS_ADDRESS,
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

function failedEvidence(argv) {
  return {
    sourceSha: option(argv, "--source-sha"),
    transitionId: option(argv, "--transition-id"),
    planSha256: option(argv, "--plan-sha256"),
    creatorArn: option(argv, "--creator-arn", false),
    creationEventId: option(argv, "--creation-event-id", false),
    failedApplyWindow: { start: option(argv, "--failed-apply-start"), end: option(argv, "--failed-apply-end") },
  };
}

export async function runCensus({ argv = process.argv.slice(2), run, execFile = execFileSync, write = (value) => process.stdout.write(value) } = {}) {
  const profile = option(argv, "--profile");
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
  const env = buildRecoveryAwsEnvironment(profile);
  const adapter = buildRootDropAwsReadAdapter({ run: run || ((args) => execFile("aws", args, { cwd: root, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] })), profile, region });
  const census = collectRootDropCensus({ adapter, terraformState: state, sourceSha: evidence.sourceSha, transitionId: evidence.transitionId, stageAStateIdentity, failedApplyEvidence: evidence });
  writeStageBPrivateFileAtomic({ filePath: outputPath, bytes: Buffer.from(`${JSON.stringify(census, null, 2)}\n`), repositoryRoot: root, label: "Stage-A root-drop census" });
  write(`${JSON.stringify({ status: census.status, candidateCount: census.candidateCount, output: outputPath }, null, 2)}\n`);
  return census;
}

export async function runAdoption({ argv = process.argv.slice(2), runTerraform, readRootDropCensus, execFile = execFileSync, write = (value) => process.stdout.write(value) } = {}) {
  const censusPath = privatePath(option(argv, "--census"), "Stage-A root-drop census");
  const census = readJson(censusPath);
  const statePath = privatePath(option(argv, "--stage-a-state"), "Stage-A state");
  const identityPath = privatePath(option(argv, "--stage-a-state-identity"), "Stage-A state identity");
  const stateBytes = readFileSync(statePath);
  const stageAState = JSON.parse(stateBytes);
  const stageAStateIdentity = readJson(identityPath);
  assertStageAStateIdentityBinding(buildStageAStateIdentity(stageAState, { stateBytes }), stageAStateIdentity);
  const profile = option(argv, "--profile");
  const suppliedRegion = option(argv, "--region", false);
  if (argv.includes("--region") && !suppliedRegion) throw new Error("Stage-A root-drop adoption: --region requires a value");
  const region = suppliedRegion || STAGE_B.region;
  if (region !== STAGE_B.region) throw new Error("Stage-A root-drop adoption: region is outside the protected production boundary");
  const freshCensus = readRootDropCensus
    ? await readRootDropCensus({ census, stageAState, stageAStateIdentity, profile })
    : collectRootDropCensus({
      adapter: buildRootDropAwsReadAdapter({ run: (args) => execFile("aws", args, { cwd: root, env: buildRecoveryAwsEnvironment(profile), encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }), profile, region }),
      terraformState: stageAState,
      sourceSha: census.sourceSha,
      transitionId: census.transitionId,
      stageAStateIdentity,
      failedApplyEvidence: census.failedApplyEvidence,
    });
  const terraformRoot = option(argv, "--terraform-root");
  const planPath = option(argv, "--plan-path");
  const execute = argv.includes("--execute");
  const env = buildRecoveryAwsEnvironment(profile);
  const tf = runTerraform || ((args) => execFile("terraform", [`-chdir=${terraformRoot}`, ...args], { cwd: root, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }));
  const readState = async () => JSON.parse(tf(["state", "pull"]));
  const importKey = async ({ address, id }) => { tf(["import", "-input=false", "-lock=true", address, id]); return { outcome: "CONFIRMED_SUCCESS" }; };
  const refreshState = async () => readState();
  const createPlan = async ({ zeroDrift = false } = {}) => { const output = zeroDrift ? `${planPath}.zero-drift` : planPath; tf(["plan", "-input=false", "-lock=true", "-out", output]); return output; };
  const readPlan = async (savedPath) => JSON.parse(tf(["show", "-json", savedPath]));
  const applyPlan = async (savedPath) => { if (!execute) throw new Error("alias apply requires explicit --execute"); tf(["apply", "-input=false", "-lock=true", savedPath]); return { outcome: "CONFIRMED_SUCCESS" }; };
  const runner = createRootDropRecoveryRunner({ execute, readState, importKey, refreshState, createPlan, readPlan, applyPlan });
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

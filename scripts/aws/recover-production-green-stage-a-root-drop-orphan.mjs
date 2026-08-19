#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { buildStageAStateIdentity, assertStageAStateIdentityBinding } from "./generate-production-green-stage-a-prerequisites.mjs";
import { ensureStageBPrivateFile, writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";
import {
  ROOT_DROP_KEY_ADDRESS,
  ROOT_DROP_ALIAS_ADDRESS,
  authenticateRootDropOrphan,
  buildRootDropAwsReadAdapter,
  buildRootDropCensus,
  createRootDropRecoveryRunner,
  rootDropTagsFromAws,
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

export async function runCensus({ argv = process.argv.slice(2), run, write = (value) => process.stdout.write(value) } = {}) {
  const profile = option(argv, "--profile");
  const region = option(argv, "--region", false) || "eu-west-2";
  const statePath = privatePath(option(argv, "--stage-a-state"), "Stage-A state");
  const identityPath = privatePath(option(argv, "--stage-a-state-identity"), "Stage-A state identity");
  const outputPath = option(argv, "--output");
  const stateBytes = readFileSync(statePath);
  const state = JSON.parse(stateBytes);
  const stageAStateIdentity = readJson(identityPath);
  assertStageAStateIdentityBinding(buildStageAStateIdentity(state, { stateBytes }), stageAStateIdentity);
  const evidence = failedEvidence(argv);
  const adapter = buildRootDropAwsReadAdapter({ run: run || ((args) => execFileSync("aws", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] })), profile, region });
  const candidates = [];
  for (const listed of adapter.listKeys()) {
    const metadata = adapter.describeKey(listed.KeyId);
    const events = adapter.lookupCreateKeyEvents(metadata.Arn).map((entry) => {
      try { return JSON.parse(entry.CloudTrailEvent); } catch { return entry; }
    });
    const relevant = events.filter((event) => event.eventName === "CreateKey" && event.eventSource === "kms.amazonaws.com" && event.awsRegion === region && Date.parse(event.eventTime) >= Date.parse(evidence.failedApplyWindow.start) && Date.parse(event.eventTime) <= Date.parse(evidence.failedApplyWindow.end));
    if (relevant.length === 0) continue;
    candidates.push({
      keyId: metadata.KeyId,
      arn: metadata.Arn,
      metadata,
      tags: rootDropTagsFromAws(adapter.listTags(metadata.KeyId)),
      policy: adapter.getPolicy(metadata.KeyId),
      publicKey: adapter.getPublicKey(metadata.KeyId),
      aliases: adapter.listAliases(metadata.KeyId),
      creationEvents: relevant,
    });
  }
  const authenticatedCandidates = [];
  for (const candidate of candidates) {
    try { authenticatedCandidates.push({ ...candidate, ...authenticateRootDropOrphan({ candidate, terraformState: state, sourceSha: evidence.sourceSha, transitionId: evidence.transitionId, failedApplyEvidence: evidence }) }); }
    catch (error) { authenticatedCandidates.push({ keyId: candidate.keyId, arn: candidate.arn, authenticated: false, reason: error.message }); }
  }
  const census = buildRootDropCensus({ sourceSha: evidence.sourceSha, transitionId: evidence.transitionId, stageAStateIdentity, candidates: authenticatedCandidates, failedApplyEvidence: authenticatedCandidates.length === 1 && authenticatedCandidates[0].authenticated ? evidence : undefined });
  writeStageBPrivateFileAtomic({ filePath: outputPath, bytes: Buffer.from(`${JSON.stringify(census, null, 2)}\n`), repositoryRoot: root, label: "Stage-A root-drop census" });
  write(`${JSON.stringify({ status: census.status, candidateCount: census.candidateCount, output: outputPath }, null, 2)}\n`);
  return census;
}

export async function runAdoption({ argv = process.argv.slice(2), runTerraform, write = (value) => process.stdout.write(value) } = {}) {
  const censusPath = privatePath(option(argv, "--census"), "Stage-A root-drop census");
  const census = readJson(censusPath);
  const statePath = privatePath(option(argv, "--stage-a-state"), "Stage-A state");
  const identityPath = privatePath(option(argv, "--stage-a-state-identity"), "Stage-A state identity");
  const stateBytes = readFileSync(statePath);
  const stageAState = JSON.parse(stateBytes);
  const stageAStateIdentity = readJson(identityPath);
  assertStageAStateIdentityBinding(buildStageAStateIdentity(stageAState, { stateBytes }), stageAStateIdentity);
  const terraformRoot = option(argv, "--terraform-root");
  const planPath = option(argv, "--plan-path");
  const execute = argv.includes("--execute");
  const tf = runTerraform || ((args) => execFileSync("terraform", [`-chdir=${terraformRoot}`, ...args], { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }));
  const readState = async () => JSON.parse(tf(["state", "pull"]));
  const importKey = async ({ address, id }) => { tf(["import", "-input=false", "-lock=true", address, id]); return { outcome: "CONFIRMED_SUCCESS" }; };
  const refreshState = async () => readState();
  const createPlan = async ({ zeroDrift = false } = {}) => { const output = zeroDrift ? `${planPath}.zero-drift` : planPath; tf(["plan", "-input=false", "-lock=true", "-out", output]); return output; };
  const readPlan = async (savedPath) => JSON.parse(tf(["show", "-json", savedPath]));
  const applyPlan = async (savedPath) => { if (!execute) throw new Error("alias apply requires explicit --execute"); tf(["apply", "-input=false", "-lock=true", savedPath]); return { outcome: "CONFIRMED_SUCCESS" }; };
  const runner = createRootDropRecoveryRunner({ execute, readState, importKey, refreshState, createPlan, readPlan, applyPlan });
  const result = await runner({ census, terraformState: stageAState, stageAStateIdentity, sourceSha: census.sourceSha, transitionId: census.transitionId, planSha256: census.failedApplyEvidence?.planSha256 });
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

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { makeCanonicalImageAuthorization } from "./fixtures/canonical-image-authorization.mjs";
import { buildRecoveryAwsEnvironment, collectCanonicalBackendRecoveryCensus, deriveCanonicalRecoveryProvenance, runCanonicalRecoveryCli } from "../aws/recover-stage-b-backend-task-definition.mjs";
import { STAGE_B_TERRAFORM_BACKEND_CONFIG } from "../aws/stage-b-terraform-backend-contract.mjs";
import {
  STAGE_B_BACKEND_RECOVERY,
  assertBackendRecoveryPreconditions,
  assertCanonicalRecoveryDescendantResume,
  assertCanonicalRecoverySourceBinding,
  assertCanonicalBackendRecoveryCensus,
  assertCanonicalBackendRecoveryReadback,
  buildCanonicalRecoveryJournal,
  buildCanonicalBackendRecoveryTaskDefinition,
  canonicalRecoveryIncidentIdentity,
  canonicalSha256,
  reconcileCanonicalBackendState,
  recoveryEvidence,
  runCanonicalBackendRecovery,
  normalizeTerraformRecoveryCheckpointState,
  stateSnapshotSha256,
  taskDefinitionFingerprint,
} from "../aws/stage-b-task-definition-recovery-contract.mjs";

const sourceSha = "45c5a38c7e3594793fafe1f051f1f381937ba0d4";
const imageAuthorizationFixture = makeCanonicalImageAuthorization({ sourceSha, imageReleaseSha: "25394d30c189583384c9bba62604bf968dc9e0b2" });
const imageAuthorization = imageAuthorizationFixture.authorization;
const imageReleaseSha = imageAuthorization.imageReleaseSha;
const image = `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${imageAuthorization.backendDigest}`;
const bindings = {
  toolingSha: sourceSha,
  toolingTreeSha256: "a".repeat(64),
  sourceSha,
  backendImage: image,
  imageReleaseSha,
  imageAuthorization,
  imageAuthorizationValidation: { now: imageAuthorizationFixture.now, verifyImageEvidence: imageAuthorizationFixture.verifyImageEvidence },
  sourceContractSha256: "b".repeat(64),
  migrationSetDigest: "c".repeat(64),
  packageChecksumSha256: "d".repeat(64),
  receiptBucket: "arn:aws:s3:::mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an",
  executorLogGroup: "/ecs/stage-b-executor",
  canaryLogGroup: "/ecs/mscqr-production/rls-green-canary",
  backendLogGroup: "/ecs/mscqr-production/rls-green-backend",
  workerLogGroup: "/ecs/mscqr-production/rls-green-worker",
};
const protectedCheckout = { mode: "production", toolingSha: sourceSha, currentHead: sourceSha, originMainHead: sourceSha, isAncestor: true, porcelainStatus: "", derivedProvenance: { toolingTreeSha256: "a".repeat(64), sourceContractSha256: "b".repeat(64) }, repositoryState: { remoteDefaultBranch: "main", shallow: false, mergeInProgress: false, rebaseInProgress: false, cherryPickInProgress: false } };
const deriveProvenance = ({ protectedCheckout: checkout }) => checkout.derivedProvenance;

const originalIncidentSha = "3d5eeefc34d69820e00bef072da3c4396689491f";
const executorSha = "eec7724ea16cd5051cd709fbd729fa7bc1c3786b";
const originalIncidentTree = "0df4855040c73f840af70c7c77aa57d62e8af6e11d580a620561e215a973a81e";
const executorTree = "e4a27b104d38173b000861b6ab79eee97cc69362e83f22a458b94bc58ba08660";
const crossImageAuthorizationFixture = makeCanonicalImageAuthorization({ sourceSha: originalIncidentSha, imageReleaseSha: "29bf92a14d5e832575009bd76b16886feff62cbd" });
const crossImageAuthorization = crossImageAuthorizationFixture.authorization;
const crossImage = `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${crossImageAuthorization.backendDigest}`;
const crossBindings = { ...bindings, sourceSha: originalIncidentSha, toolingSha: originalIncidentSha, toolingTreeSha256: originalIncidentTree, imageReleaseSha: crossImageAuthorization.imageReleaseSha, backendImage: crossImage, imageAuthorization: crossImageAuthorization };
const crossProtectedCheckout = { ...protectedCheckout, toolingSha: executorSha, currentHead: executorSha, originMainHead: executorSha, derivedProvenance: { toolingTreeSha256: executorTree, sourceContractSha256: bindings.sourceContractSha256 } };
const crossProvenance = ({ sourceSha: value }) => value === originalIncidentSha
  ? { toolingTreeSha256: originalIncidentTree, sourceContractSha256: bindings.sourceContractSha256 }
  : { toolingTreeSha256: executorTree, sourceContractSha256: bindings.sourceContractSha256 };
const crossReuse = ({ imageReleaseSha: release, toolingSha: tooling }) => ({ schemaVersion: 1, imageReleaseSha: release, toolingSha: tooling, toolingInputTreeSha256: executorTree, comparisonBaseSha: release, comparisonHeadIdentity: "tooling-input-tree-sha256", comparisonHeadSha256: executorTree, classificationRulesVersion: "stage-b-image-reuse-v2", imageReuseCompatible: true, imageBuildInputsChanged: false, imageAffectingFiles: [], classifiedChangedFiles: [{ file: "scripts/aws/stage-b-task-definition-recovery-contract.mjs", category: "toolingOnly", imageAffecting: false }] });
const journalIdentity = { imageReleaseSha, imageAuthorizationSha256: imageAuthorization.evidenceSha256 };
const journalAdapter = (initial) => { let value = initial ? structuredClone(initial) : null; return { read: () => value && structuredClone(value), write: (next) => { value = structuredClone(next); } }; };
const state = (arn = STAGE_B_BACKEND_RECOVERY.predecessorArn, serial = STAGE_B_BACKEND_RECOVERY.serial) => ({
  version: 4,
  terraform_version: "1.9.8",
  serial,
  lineage: STAGE_B_BACKEND_RECOVERY.lineage,
  resources: [{ mode: "managed", type: "aws_ecs_task_definition", name: "candidate", instances: [{ index_key: "backend", schema_version: 1, attributes: { id: arn, arn, family: STAGE_B_BACKEND_RECOVERY.family } }] }],
});

const checkpointBeforeState = () => ({
  ...state(),
  terraform_version: "1.15.7",
  check_results: [
    { object_kind: "check", config_addr: "check.release_bindings", status: "pass", objects: [{ object_addr: "check.release_bindings", status: "pass" }] },
    { object_kind: "var", config_addr: "var.retained_candidate_task_definitions", status: "pass", objects: [{ object_addr: "var.retained_candidate_task_definitions", status: "pass" }] },
    { object_kind: "check", config_addr: "check.production_only", status: "pass", objects: [{ object_addr: "check.production_only", status: "pass" }] },
  ],
  resources: [
    ...state().resources,
    { mode: "managed", type: "aws_cloudwatch_log_group", name: "stage_b", provider: 'provider["registry.terraform.io/hashicorp/aws"]', instances: [{ schema_version: 0, attributes: { id: "/ecs/mscqr-production/rls-green-backend", name: "/ecs/mscqr-production/rls-green-backend" } }] },
    { mode: "managed", type: "aws_dynamodb_table", name: "replay", provider: 'provider["registry.terraform.io/hashicorp/aws"]', instances: [{ schema_version: 0, attributes: { id: "mscqr-production-rls-stage-b-replay", name: "mscqr-production-rls-stage-b-replay" } }] },
  ],
});

const checkpointAfterState = () => {
  const value = structuredClone(checkpointBeforeState());
  value.serial = 94;
  value.terraform_version = "1.15.8";
  value.check_results.reverse();
  value.resources = value.resources.filter((resource) => !(resource.type === "aws_ecs_task_definition" && resource.name === "candidate"));
  return value;
};

const checkpointImportedState = (arn) => {
  const value = checkpointAfterState();
  value.serial = 95;
  value.resources.unshift({ mode: "managed", type: "aws_ecs_task_definition", name: "candidate", instances: [{ index_key: "backend", schema_version: 1, attributes: { id: arn, arn, family: STAGE_B_BACKEND_RECOVERY.family } }] });
  return value;
};

const journalArgs = (current, payload, newestHistoricalArn = STAGE_B_BACKEND_RECOVERY.historicalRevisionArns.at(-1)) => ({
  sourceSha, toolingTreeSha256: bindings.toolingTreeSha256, sourceContractSha256: bindings.sourceContractSha256, imageReleaseSha, imageAuthorizationSha256: imageAuthorization.evidenceSha256,
  fingerprint: payload.fingerprint, imageDigest: image, newestHistoricalArn,
  incidentIdentity: canonicalRecoveryIncidentIdentity({ sourceSha, toolingTreeSha256: bindings.toolingTreeSha256, sourceContractSha256: bindings.sourceContractSha256, imageReleaseSha, imageDigest: imageAuthorization.backendDigest, imageAuthorizationSha256: imageAuthorization.evidenceSha256, stateLineage: current.lineage, stateSerial: current.serial, predecessorArn: STAGE_B_BACKEND_RECOVERY.predecessorArn, newestHistoricalArn, fingerprint: payload.fingerprint }),
});

function replacementPayload(arn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:9", options = {}) {
  const payload = buildCanonicalBackendRecoveryTaskDefinition(bindings);
  const taskDefinition = { ...structuredClone(payload.taskDefinition), taskDefinitionArn: arn, family: options.family || payload.taskDefinition.family, status: options.status || "ACTIVE", revision: Number(arn.split(":").at(-1)) };
  if (options.mutate) options.mutate(taskDefinition);
  return { taskDefinition, tags: options.tags || structuredClone(payload.tags), fingerprint: taskDefinitionFingerprint(payload.taskDefinition, payload.tags) };
}

function crossReplacementPayload(arn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:9") {
  const payload = buildCanonicalBackendRecoveryTaskDefinition(crossBindings);
  const taskDefinition = { ...structuredClone(payload.taskDefinition), taskDefinitionArn: arn, family: payload.taskDefinition.family, status: "ACTIVE", revision: Number(arn.split(":").at(-1)) };
  return { taskDefinition, tags: structuredClone(payload.tags), fingerprint: taskDefinitionFingerprint(payload.taskDefinition, payload.tags) };
}

function crossResumeJournal() {
  const current = state();
  const payload = crossReplacementPayload();
  const journal = buildCanonicalRecoveryJournal(current, {
    sourceSha: originalIncidentSha,
    toolingTreeSha256: originalIncidentTree,
    sourceContractSha256: crossBindings.sourceContractSha256,
    imageReleaseSha: crossBindings.imageReleaseSha,
    imageAuthorizationSha256: crossImageAuthorization.evidenceSha256,
    fingerprint: payload.fingerprint,
    imageDigest: crossBindings.backendImage,
    newestHistoricalArn: STAGE_B_BACKEND_RECOVERY.newestHistoricalArn,
    incidentIdentity: canonicalRecoveryIncidentIdentity({ sourceSha: originalIncidentSha, toolingTreeSha256: originalIncidentTree, sourceContractSha256: crossBindings.sourceContractSha256, imageReleaseSha: crossBindings.imageReleaseSha, imageDigest: crossImageAuthorization.backendDigest, imageAuthorizationSha256: crossImageAuthorization.evidenceSha256, stateLineage: current.lineage, stateSerial: current.serial, predecessorArn: STAGE_B_BACKEND_RECOVERY.predecessorArn, newestHistoricalArn: STAGE_B_BACKEND_RECOVERY.newestHistoricalArn, fingerprint: payload.fingerprint }),
  });
  return { ...journal, phase: "STATE_RECONCILING_PRE_REMOVE", replacementArn: payload.taskDefinition.taskDefinitionArn, replacementFingerprint: payload.fingerprint, registrationCalls: 1, registrationMayHaveOccurred: true };
}

function cliPostRemoveState() {
  const value = structuredClone(state());
  value.serial = 94;
  value.terraform_version = "1.15.8";
  value.check_results = [];
  value.resources = [];
  return value;
}

function createCliCrossDescendantFixture({ journalMutate, bindingsMutate, authorizationMutate, protectedCheckout = crossProtectedCheckout, deriveImageReuse } = {}) {
  const originalProvenance = deriveCanonicalRecoveryProvenance({ sourceSha: originalIncidentSha });
  const incidentBindings = { ...crossBindings, toolingTreeSha256: originalProvenance.toolingTreeSha256, sourceContractSha256: originalProvenance.sourceContractSha256 };
  bindingsMutate?.(incidentBindings);
  const authorization = structuredClone(crossImageAuthorization);
  authorizationMutate?.(authorization);
  incidentBindings.imageAuthorization = authorization;
  const predecessor = { ...state(), terraform_version: "1.15.7", check_results: [] };
  const payload = buildCanonicalBackendRecoveryTaskDefinition(incidentBindings);
  const replacementArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:9";
  const replacement = { taskDefinition: { ...structuredClone(payload.taskDefinition), taskDefinitionArn: replacementArn, family: payload.taskDefinition.family, status: "ACTIVE", revision: 9 }, tags: structuredClone(payload.tags), fingerprint: taskDefinitionFingerprint(payload.taskDefinition, payload.tags) };
  const journal = buildCanonicalRecoveryJournal(predecessor, {
    sourceSha: originalIncidentSha,
    toolingTreeSha256: incidentBindings.toolingTreeSha256,
    sourceContractSha256: incidentBindings.sourceContractSha256,
    imageReleaseSha: incidentBindings.imageReleaseSha,
    imageAuthorizationSha256: authorization.evidenceSha256,
    fingerprint: replacement.fingerprint,
    imageDigest: incidentBindings.backendImage,
    newestHistoricalArn: STAGE_B_BACKEND_RECOVERY.newestHistoricalArn,
    incidentIdentity: canonicalRecoveryIncidentIdentity({ sourceSha: originalIncidentSha, toolingTreeSha256: incidentBindings.toolingTreeSha256, sourceContractSha256: incidentBindings.sourceContractSha256, imageReleaseSha: incidentBindings.imageReleaseSha, imageDigest: crossImageAuthorization.backendDigest, imageAuthorizationSha256: authorization.evidenceSha256, stateLineage: predecessor.lineage, stateSerial: predecessor.serial, predecessorArn: STAGE_B_BACKEND_RECOVERY.predecessorArn, newestHistoricalArn: STAGE_B_BACKEND_RECOVERY.newestHistoricalArn, fingerprint: replacement.fingerprint }),
  });
  journal.phase = "STATE_RECONCILING_PRE_REMOVE";
  journal.replacementArn = replacementArn;
  journal.replacementFingerprint = replacement.fingerprint;
  journal.registrationCalls = 1;
  journal.registrationMayHaveOccurred = true;
  journal.stateBeforeSha256 = canonicalSha256(predecessor);
  journal.stateAfterRemoveSha256 = canonicalSha256(cliPostRemoveState());
  delete journal.checkpointHashDomain;
  journalMutate?.(journal);
  const directory = mkdtempSync(path.join("/tmp", "mscqr-recovery-cli-cross-"));
  const terraformDataDir = path.join(directory, "terraform-data");
  mkdirSync(terraformDataDir, { recursive: true, mode: 0o700 });
  writeFileSync(path.join(terraformDataDir, "terraform.tfstate"), JSON.stringify({ backend: { type: "s3", hash: 1, config: STAGE_B_TERRAFORM_BACKEND_CONFIG } }), { mode: 0o600 });
  const bindingsPath = path.join(directory, "bindings.json");
  const imageAuthorizationPath = path.join(directory, "image-authorization.json");
  const evidencePath = path.join(directory, "evidence.json");
  const journalPath = path.join(directory, "recovery.json");
  const stateBeforePath = path.join(directory, "state-before.json");
  writeFileSync(bindingsPath, JSON.stringify(incidentBindings), { mode: 0o600 });
  writeFileSync(imageAuthorizationPath, JSON.stringify(authorization), { mode: 0o600 });
  writeFileSync(journalPath, `${JSON.stringify(journal, null, 2)}\n`, { mode: 0o600 });
  writeFileSync(stateBeforePath, JSON.stringify(predecessor), { mode: 0o600 });
  let current = cliPostRemoveState();
  const calls = [];
  const exec = (command, args) => {
    calls.push({ command, args: [...args] });
    if (command === "terraform" && args.includes("workspace") && args.includes("show")) return "default\n";
    if (command === "terraform" && args.includes("state") && args.includes("pull")) return JSON.stringify(current);
    if (command === "terraform" && args.includes("import")) { current = state(replacementArn, 95); return ""; }
    if (command === "aws" && args.includes("register-task-definition")) throw new Error("unexpected ECS registration");
    if (command === "aws" && args.includes("list-task-definitions")) return JSON.stringify({ taskDefinitionArns: [replacementArn, STAGE_B_BACKEND_RECOVERY.newestHistoricalArn] });
    if (command === "aws" && args.includes("describe-task-definition")) {
      const arn = args[args.indexOf("--task-definition") + 1];
      return JSON.stringify(arn === replacementArn ? replacement : historicalPayload(STAGE_B_BACKEND_RECOVERY.newestHistoricalArn));
    }
    throw new Error(`unexpected CLI adapter call: ${command} ${args.join(" ")}`);
  };
  const argv = ["--execute", "--source-sha", executorSha, "--bindings", bindingsPath, "--image-authorization", imageAuthorizationPath,
    "--terraform-root", path.resolve("infra/aws/terraform/production-green-stage-b"), "--evidence-out", evidencePath, "--recovery-state", journalPath,
    "--state-before", stateBeforePath, "--aws-profile", "test"];
  return {
    argv,
    baseEnv: { ...process.env, TF_DATA_DIR: terraformDataDir, TF_WORKSPACE: "default" },
    protectedCheckout,
    authorizationFixture: crossImageAuthorizationFixture,
    exec,
    deriveImageReuse,
    calls,
    journalPath,
    evidencePath,
    cleanup: () => rmSync(directory, { recursive: true, force: true }),
  };
}

const historicalPayload = (arn = STAGE_B_BACKEND_RECOVERY.historicalRevisionArns.at(-1)) => replacementPayload(arn, { mutate: (value) => { value.containerDefinitions[0].image = `${image.slice(0, -64)}${"e".repeat(64)}`; } });
const censusFor = (payload) => ({ complete: true, revisions: [{ arn: payload.taskDefinition.taskDefinitionArn, readback: payload }, { arn: STAGE_B_BACKEND_RECOVERY.historicalRevisionArns.at(-1), readback: historicalPayload() }] });

function awsNormalizedReadback(arn) {
  const payload = replacementPayload(arn);
  const container = payload.taskDefinition.containerDefinitions[0];
  payload.taskDefinition.placementConstraints = [];
  payload.taskDefinition.volumes[0].host = {};
  container.cpu = 0;
  container.volumesFrom = [];
  container.systemControls = [];
  payload.tags.reverse();
  return payload;
}

test("recovery preconditions are exact and source-bound", () => {
  assert.deepEqual(assertBackendRecoveryPreconditions({ state: state(), sourceSha }), {
    address: STAGE_B_BACKEND_RECOVERY.address,
    family: STAGE_B_BACKEND_RECOVERY.family,
    predecessorArn: STAGE_B_BACKEND_RECOVERY.predecessorArn,
    sourceSha,
    lineage: STAGE_B_BACKEND_RECOVERY.lineage,
    serial: 93,
    newestHistoricalArn: STAGE_B_BACKEND_RECOVERY.newestHistoricalArn,
  });
  for (const mutate of [
    (value) => value.resources[0].instances[0].attributes.arn = STAGE_B_BACKEND_RECOVERY.historicalRevisionArns[0],
    (value) => value.serial = 94,
    (value) => value.lineage = "0".repeat(36),
    (value) => value.resources.push(structuredClone(value.resources[0])),
  ]) assert.throws(() => assertBackendRecoveryPreconditions({ state: (() => { const value = state(); mutate(value); return value; })(), sourceSha }));
  assert.throws(() => assertBackendRecoveryPreconditions({ state: state(), sourceSha: "0".repeat(40), expectedNewestArn: STAGE_B_BACKEND_RECOVERY.historicalRevisionArns[0] }));
});

test("canonical source rendering produces the exact immutable replacement fingerprint", () => {
  const payload = buildCanonicalBackendRecoveryTaskDefinition(bindings);
  assert.equal(payload.taskDefinition.family, STAGE_B_BACKEND_RECOVERY.family);
  assert.equal(payload.taskDefinition.containerDefinitions[0].image, image);
  assert.equal(payload.taskDefinition.containerDefinitions[0].environment.find(({ name }) => name === "RELEASE_GIT_SHA").value, imageReleaseSha);
  assert.equal(payload.tags.find(({ key }) => key === "MSCQRExecTarget").value, "production-backend");
  assert.match(taskDefinitionFingerprint(payload.taskDefinition, payload.tags), /^[a-f0-9]{64}$/);
});

test("recovery separates tooling provenance from image/task-definition provenance", () => {
  assert.doesNotThrow(() => assertCanonicalRecoverySourceBinding({ sourceSha, bindings, protectedCheckout, deriveProvenance }));
  assert.notEqual(bindings.toolingSha, bindings.imageReleaseSha);
  assert.throws(() => assertCanonicalRecoverySourceBinding({ sourceSha, bindings: { ...bindings, imageReleaseSha: sourceSha }, protectedCheckout }), /image-release identity/);
  assert.throws(() => assertCanonicalRecoverySourceBinding({ sourceSha, bindings: { ...bindings, backendImage: `${image.slice(0, -64)}${"e".repeat(64)}` }, protectedCheckout }), /backend image/);
});

test("protected eec7724 resumes the original 3d5eeef incident without rebinding or registering", async () => {
  const replacementArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:9";
  const replacement = crossReplacementPayload(replacementArn);
  const historical = historicalPayload();
  let current = { ...state(), serial: 94, resources: [] };
  let registrations = 0;
  let imports = 0;
  const journal = journalAdapter(crossResumeJournal());
  const result = await runCanonicalBackendRecovery({
    bindings: crossBindings,
    sourceSha: executorSha,
    protectedCheckout: crossProtectedCheckout,
    imageAuthorization: crossImageAuthorization,
    imageAuthorizationValidation: { now: crossImageAuthorizationFixture.now, verifyImageEvidence: crossImageAuthorizationFixture.verifyImageEvidence },
    deriveProvenance: crossProvenance,
    proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === originalIncidentSha && descendantSha === executorSha,
    deriveImageReuse: crossReuse,
    journal,
    readState: async () => structuredClone(current),
    census: async () => ({ complete: true, revisions: [{ arn: replacementArn, readback: replacement }, { arn: STAGE_B_BACKEND_RECOVERY.newestHistoricalArn, readback: historical }] }),
    describe: async () => replacement,
    register: async () => { registrations += 1; throw new Error("cross-descendant resume must not register"); },
    removeState: async () => { throw new Error("cross-descendant resume must not repeat state rm"); },
    importState: async ({ arn }) => { imports += 1; current = state(arn, 95); },
  });
  assert.equal(registrations, 0);
  assert.equal(imports, 1);
  assert.equal(result.registration.arn, replacementArn);
  assert.equal(result.reconciliation.importCalls, 1);
  assert.equal(result.reconciliation.removeCalls, 0);
  assert.equal(result.evidence.sourceSha, originalIncidentSha);
  assert.equal(result.evidence.incidentIdentity, journal.read().incidentIdentity);
  assert.equal(result.evidence.resumeExecutorToolingSha, executorSha);
  assert.equal(journal.read().sourceSha, originalIncidentSha);
  assert.equal(journal.read().registrationCalls, 1);
});

test("cross-descendant resume rejects identity, ancestry, checkout, authorization, and image-reuse drift", () => {
  const base = { sourceSha: executorSha, bindings: crossBindings, protectedCheckout: crossProtectedCheckout, journalState: crossResumeJournal(), imageAuthorization: crossImageAuthorization, imageAuthorizationValidation: { now: crossImageAuthorizationFixture.now, verifyImageEvidence: crossImageAuthorizationFixture.verifyImageEvidence }, deriveProvenance: crossProvenance, proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === originalIncidentSha && descendantSha === executorSha, deriveImageReuse: crossReuse };
  const cases = [
    ["unrelated commit", { proveDescendant: () => false }],
    ["source ancestor rather than descendant", { proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === executorSha && descendantSha === originalIncidentSha }],
    ["dirty checkout", { protectedCheckout: { ...crossProtectedCheckout, porcelainStatus: " M scripts/aws/example.mjs" } }],
    ["non-origin checkout", { protectedCheckout: { ...crossProtectedCheckout, originMainHead: "f".repeat(40) } }],
    ["image-affecting descendant", { deriveImageReuse: () => ({ ...crossReuse({ imageReleaseSha: crossBindings.imageReleaseSha, toolingSha: executorSha }), imageAffectingFiles: ["backend/src/runtime.mjs"], classifiedChangedFiles: [{ file: "backend/src/runtime.mjs", category: "runtimeApplicationSource", imageAffecting: true }] }) }],
    ["changed image digest", { journalState: { ...crossResumeJournal(), authorizedBackendImageDigest: `sha256:${"e".repeat(64)}` } }],
    ["changed image authorization", { journalState: { ...crossResumeJournal(), imageAuthorizationSha256: "f".repeat(64) } }],
    ["changed incident identity", { journalState: { ...crossResumeJournal(), incidentIdentity: "f".repeat(64) } }],
    ["unknown checkpoint domain", { journalState: { ...crossResumeJournal(), checkpointHashDomain: "unreviewed" } }],
  ];
  for (const [label, overrides] of cases) assert.throws(() => assertCanonicalRecoveryDescendantResume({ ...base, ...overrides }), label);
});

test("cross-descendant resume rejects canonical revision, census, budget, and Terraform drift before import", async () => {
  const replacementArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:9";
  const replacement = crossReplacementPayload(replacementArn);
  const historical = historicalPayload();
  const cases = [
    ["missing :9", { census: [{ arn: STAGE_B_BACKEND_RECOVERY.newestHistoricalArn, readback: historical }] }],
    [":8 anchor mismatch", { census: [{ arn: replacementArn, readback: replacement }, { arn: STAGE_B_BACKEND_RECOVERY.historicalRevisionArns[1], readback: historical }] }],
    ["unexpected :10", { census: [{ arn: `${replacementArn.slice(0, -1)}10`, readback: crossReplacementPayload(`${replacementArn.slice(0, -1)}10`) }, { arn: replacementArn, readback: replacement }, { arn: STAGE_B_BACKEND_RECOVERY.newestHistoricalArn, readback: historical }] }],
    [":9 fingerprint drift", { census: [{ arn: replacementArn, readback: crossReplacementPayload(replacementArn), mutate: (value) => { value.taskDefinition.containerDefinitions[0].image = `${crossImage.slice(0, -64)}${"e".repeat(64)}`; } }, { arn: STAGE_B_BACKEND_RECOVERY.newestHistoricalArn, readback: historical }] }],
    ["registration budget", { journal: { registrationCalls: 0, registrationMayHaveOccurred: false } }],
    ["lineage drift", { state: { ...state(), serial: 94, lineage: "0".repeat(36), resources: [] } }],
    ["candidate present", { state: state(STAGE_B_BACKEND_RECOVERY.predecessorArn, 94) }],
  ];
  for (const [label, options] of cases) {
    let current = options.state || { ...state(), serial: 94, resources: [] };
    let registrations = 0;
    let imports = 0;
    const journal = crossResumeJournal();
    if (options.journal) Object.assign(journal, options.journal);
    const revisions = options.census || [{ arn: replacementArn, readback: replacement }, { arn: STAGE_B_BACKEND_RECOVERY.newestHistoricalArn, readback: historical }];
    await assert.rejects(() => runCanonicalBackendRecovery({ bindings: crossBindings, sourceSha: executorSha, protectedCheckout: crossProtectedCheckout, imageAuthorization: crossImageAuthorization, imageAuthorizationValidation: { now: crossImageAuthorizationFixture.now, verifyImageEvidence: crossImageAuthorizationFixture.verifyImageEvidence }, deriveProvenance: crossProvenance, proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === originalIncidentSha && descendantSha === executorSha, deriveImageReuse: crossReuse, journal: journalAdapter(journal), readState: async () => structuredClone(current), census: async () => ({ complete: true, revisions: revisions.map(({ mutate, ...entry }) => { const value = structuredClone(entry); mutate?.(value.readback); return value; }) }), describe: async () => replacement, register: async () => { registrations += 1; }, removeState: async () => {}, importState: async ({ arn }) => { imports += 1; current = state(arn, 95); } }), label);
    assert.equal(registrations, 0, label);
    assert.equal(imports, 0, label);
  }
});

test("production CLI reaches cross-descendant reconciliation without exact-source preflight or registration", async () => {
  const fixture = createCliCrossDescendantFixture();
  try {
    const result = await runCanonicalRecoveryCli(fixture.argv, {
      baseEnv: fixture.baseEnv,
      exec: fixture.exec,
      readProtectedCheckout: () => fixture.protectedCheckout,
      verifyImageEvidence: fixture.authorizationFixture.verifyImageEvidence,
      deriveImageReuse: fixture.deriveImageReuse,
    });
    assert.equal(result.registration.registrationCalls, 0);
    assert.equal(result.reconciliation.importCalls, 1);
    assert.equal(result.reconciliation.removeCalls, 0);
    assert.equal(fixture.calls.filter(({ command, args }) => command === "aws" && args.includes("register-task-definition")).length, 0);
    assert.equal(fixture.calls.filter(({ command, args }) => command === "terraform" && args.includes("import")).length, 1);
    assert.equal(result.evidence.sourceSha, originalIncidentSha);
    assert.equal(result.evidence.resumeExecutorToolingSha, executorSha);
  } finally {
    fixture.cleanup();
  }
});

test("production CLI rejects forged descendant resume inputs before any adapter mutation", async () => {
  const cases = [
    ["forged journal source", { journalMutate: (journal) => { journal.sourceSha = "f".repeat(40); } }],
    ["dirty executor", { protectedCheckout: { ...crossProtectedCheckout, porcelainStatus: " M scripts/aws/example.mjs" } }],
    ["invalid image authorization", { authorizationMutate: (authorization) => { authorization.valid = false; } }],
    ["bindings not matching original incident", { bindingsMutate: (value) => { value.sourceSha = executorSha; } }],
    ["image-affecting descendant delta", { deriveImageReuse: () => ({ ...crossReuse({ imageReleaseSha: crossBindings.imageReleaseSha, toolingSha: executorSha }), imageAffectingFiles: ["backend/src/runtime.mjs"], classifiedChangedFiles: [{ file: "backend/src/runtime.mjs", category: "runtimeApplicationSource", imageAffecting: true }] }) }],
    ["unregistered early phase", { journalMutate: (journal) => { journal.phase = "DISCOVERY"; } }],
  ];
  for (const [label, options] of cases) {
    const fixture = createCliCrossDescendantFixture(options);
    try {
      await assert.rejects(() => runCanonicalRecoveryCli(fixture.argv, {
        baseEnv: fixture.baseEnv,
        exec: fixture.exec,
        readProtectedCheckout: () => fixture.protectedCheckout,
        verifyImageEvidence: fixture.authorizationFixture.verifyImageEvidence,
        deriveImageReuse: fixture.deriveImageReuse,
      }), label);
      assert.equal(fixture.calls.some(({ command, args }) => (command === "aws" && args.includes("register-task-definition")) || (command === "terraform" && args.includes("state") && (args.includes("rm") || args.includes("import")))), false, label);
    } finally {
      fixture.cleanup();
    }
  }
});

test("completed cross-descendant recovery is terminal and leaves journal/evidence bytes unchanged", async () => {
  const fixture = createCliCrossDescendantFixture({ journalMutate: (journal) => { journal.phase = "COMPLETED"; } });
  try {
    const journal = JSON.parse(readFileSync(fixture.journalPath, "utf8"));
    const evidence = recoveryEvidence({
      sourceSha: journal.sourceSha,
      toolingTreeSha256: journal.toolingTreeSha256,
      sourceContractSha256: journal.sourceContractSha256,
      imageReleaseSha: journal.imageReleaseSha,
      imageAuthorizationSha256: journal.imageAuthorizationSha256,
      state: state(),
      stateBinding: journal,
      replacement: { arn: journal.replacementArn, fingerprint: journal.replacementFingerprint, protectedSourceFingerprint: journal.protectedSourceFingerprint },
      imageDigest: journal.imageDigest,
      newestHistoricalArn: journal.newestHistoricalArn,
      incidentIdentity: journal.incidentIdentity,
    });
    journal.evidenceSha256 = evidence.evidenceSha256;
    writeFileSync(fixture.journalPath, `${JSON.stringify(journal, null, 2)}\n`, { mode: 0o600 });
    writeFileSync(fixture.evidencePath, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
    const journalBefore = readFileSync(fixture.journalPath);
    const evidenceBefore = readFileSync(fixture.evidencePath);
    await assert.rejects(() => runCanonicalRecoveryCli(fixture.argv, {
      baseEnv: fixture.baseEnv,
      exec: fixture.exec,
      readProtectedCheckout: () => fixture.protectedCheckout,
      verifyImageEvidence: fixture.authorizationFixture.verifyImageEvidence,
      deriveImageReuse: fixture.deriveImageReuse,
    }), /terminal/);
    assert.deepEqual(readFileSync(fixture.journalPath), journalBefore);
    assert.deepEqual(readFileSync(fixture.evidencePath), evidenceBefore);
    assert.equal(fixture.calls.some(({ command, args }) => (command === "aws" && args.includes("register-task-definition")) || (command === "terraform" && args.includes("state") && (args.includes("rm") || args.includes("import")))), false);
  } finally {
    fixture.cleanup();
  }
});

test("cross-descendant reconciliation phases remain resumable while completion stays terminal", () => {
  for (const phase of ["STATE_RECONCILING_PRE_REMOVE", "STATE_RECONCILING_POST_REMOVE", "STATE_RECONCILED"]) {
    assert.doesNotThrow(() => assertCanonicalRecoveryDescendantResume({ sourceSha: executorSha, bindings: crossBindings, protectedCheckout: crossProtectedCheckout, journalState: { ...crossResumeJournal(), phase }, imageAuthorization: crossImageAuthorization, imageAuthorizationValidation: { now: crossImageAuthorizationFixture.now, verifyImageEvidence: crossImageAuthorizationFixture.verifyImageEvidence }, deriveProvenance: crossProvenance, proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === originalIncidentSha && descendantSha === executorSha, deriveImageReuse: crossReuse }));
  }
});

test("exact-source completed recovery preserves the existing terminal path without registration", async () => {
  const replacementArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:9";
  const payload = replacementPayload(replacementArn);
  const journal = buildCanonicalRecoveryJournal(state(), journalArgs(state(), payload));
  Object.assign(journal, { phase: "COMPLETED", replacementArn, replacementFingerprint: payload.fingerprint, registrationCalls: 1, registrationMayHaveOccurred: true });
  let registrations = 0;
  const result = await runCanonicalBackendRecovery({ bindings, sourceSha, protectedCheckout, journal: journalAdapter(journal), readState: async () => state(replacementArn, 95), census: async () => censusFor(payload), describe: async () => payload, register: async () => { registrations += 1; }, removeState: async () => { throw new Error("completed recovery must not remove state"); }, importState: async () => { throw new Error("completed recovery must not import state"); } });
  assert.equal(registrations, 0);
  assert.equal(result.registration.registrationCalls, 0);
  assert.equal(result.reconciliation.importCalls, 0);
});

test("recovery derives the two source identities through the authoritative implementations", () => {
  const currentSha = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  const derived = deriveCanonicalRecoveryProvenance({ sourceSha: currentSha });
  assert.match(derived.toolingTreeSha256, /^[a-f0-9]{64}$/);
  assert.match(derived.sourceContractSha256, /^[a-f0-9]{64}$/);
});

test("Terraform 1.15.7 to 1.15.8 state-rm checkpoint normalizes only reviewed metadata", () => {
  const before = checkpointBeforeState();
  const after = checkpointAfterState();
  const expectedAfter = { ...structuredClone(before), serial: 94, resources: before.resources.filter((resource) => !(resource.type === "aws_ecs_task_definition" && resource.name === "candidate")) };
  assert.equal(stateSnapshotSha256(expectedAfter), stateSnapshotSha256(after));
  assert.equal(normalizeTerraformRecoveryCheckpointState(before).terraform_version, "<terraform-generated-version>");
  assert.deepEqual(normalizeTerraformRecoveryCheckpointState(before).check_results, normalizeTerraformRecoveryCheckpointState(after).check_results);

  const rejected = [
    (value) => { value.lineage = "0".repeat(36); },
    (value) => { value.resources[0].instances[0].attributes.name = "/ecs/changed"; },
    (value) => { value.resources = value.resources.slice(0, 1); },
    (value) => { value.resources[0].provider = 'provider["registry.terraform.io/hashicorp/random"]'; },
    (value) => { value.resources.unshift({ mode: "managed", type: "aws_ecs_task_definition", name: "candidate", instances: [{ index_key: "backend", schema_version: 1, attributes: { id: STAGE_B_BACKEND_RECOVERY.predecessorArn, arn: STAGE_B_BACKEND_RECOVERY.predecessorArn, family: STAGE_B_BACKEND_RECOVERY.family } }] }); },
    (value) => { value.unreviewed_checkpoint_field = true; },
  ];
  for (const mutate of rejected) {
    const changed = structuredClone(after);
    mutate(changed);
    assert.notEqual(stateSnapshotSha256(expectedAfter), stateSnapshotSha256(changed));
  }
  const malformedVersion = structuredClone(after);
  malformedVersion.terraform_version = "not-a-version";
  assert.throws(() => stateSnapshotSha256(malformedVersion), /version is malformed/);
  const unreviewedVersion = structuredClone(after);
  unreviewedVersion.terraform_version = "1.15.9";
  assert.notEqual(stateSnapshotSha256(expectedAfter), stateSnapshotSha256(unreviewedVersion));
  const malformedChecks = structuredClone(after);
  malformedChecks.check_results = { status: "pass" };
  assert.throws(() => stateSnapshotSha256(malformedChecks), /check results are malformed/);
});

test("AWS ECS readback projections preserve the exact protected semantic fingerprint", () => {
  const source = replacementPayload();
  const readback = awsNormalizedReadback(source.taskDefinition.taskDefinitionArn);
  assert.equal(taskDefinitionFingerprint(readback.taskDefinition, readback.tags), source.fingerprint);
  assert.doesNotThrow(() => assertCanonicalBackendRecoveryReadback({ readback, expectedArn: source.taskDefinition.taskDefinitionArn, expectedFingerprint: source.fingerprint }));
});

test("task-definition fingerprint normalization remains field-specific and fail-closed", () => {
  const source = replacementPayload();
  const mutations = [
    (value) => { value.containerDefinitions[0].cpu = 1; },
    (value) => { value.containerDefinitions[0].volumesFrom = [{ sourceContainer: "other", readOnly: true }]; },
    (value) => { value.containerDefinitions[0].systemControls = [{ namespace: "net.ipv4.ip_forward", value: "1" }]; },
    (value) => { value.containerDefinitions[0].image = `${image.slice(0, -64)}${"e".repeat(64)}`; },
    (value) => { value.containerDefinitions[0].secrets[0].valueFrom += "-other"; },
    (value) => { value.containerDefinitions[0].environment[0].value = "other"; },
    (value) => { value.containerDefinitions[0].mountPoints[0].containerPath = "/other"; },
    (value) => { value.containerDefinitions[0].logConfiguration.options["awslogs-group"] = "/ecs/other"; },
    (value) => { value.executionRoleArn = "arn:aws:iam::368992683803:role/other"; },
    (value) => { value.taskRoleArn = "arn:aws:iam::368992683803:role/other"; },
    (value) => { value.firelensConfiguration = {}; },
  ];
  for (const mutate of mutations) {
    const changed = structuredClone(source.taskDefinition);
    mutate(changed);
    assert.notEqual(taskDefinitionFingerprint(changed, source.tags), source.fingerprint);
  }
  const changedTag = structuredClone(source.tags);
  changedTag[0].value = "other";
  assert.notEqual(taskDefinitionFingerprint(source.taskDefinition, changedTag), source.fingerprint);
  const hostVolume = structuredClone(source.taskDefinition);
  hostVolume.volumes[0].host = { sourcePath: "/host" };
  assert.throws(() => taskDefinitionFingerprint(hostVolume, source.tags), /unreviewed provider field/);
});

test("replacement readback rejects historical, inactive, wrong-family, stale, and malformed revisions", () => {
  const exactPayload = replacementPayload();
  assert.doesNotThrow(() => assertCanonicalBackendRecoveryReadback({ readback: exactPayload, expectedArn: exactPayload.taskDefinition.taskDefinitionArn, expectedFingerprint: exactPayload.fingerprint }));
  const cases = [
    () => ({ readback: replacementPayload(STAGE_B_BACKEND_RECOVERY.historicalRevisionArns[0]), expectedArn: STAGE_B_BACKEND_RECOVERY.historicalRevisionArns[0] }),
    () => ({ readback: replacementPayload(undefined, { status: "INACTIVE" }), expectedArn: exactPayload.taskDefinition.taskDefinitionArn }),
    () => ({ readback: replacementPayload(undefined, { family: "wrong-family" }), expectedArn: exactPayload.taskDefinition.taskDefinitionArn }),
    () => ({ readback: replacementPayload(undefined, { mutate: (value) => { value.containerDefinitions[0].image = `${image.slice(0, -64)}${"e".repeat(64)}`; } }), expectedArn: exactPayload.taskDefinition.taskDefinitionArn }),
    () => ({ readback: replacementPayload(undefined, { mutate: (value) => { value.containerDefinitions[0].portMappings[0].containerPort = 443; } }), expectedArn: exactPayload.taskDefinition.taskDefinitionArn }),
    () => ({ readback: replacementPayload(undefined, { mutate: (value) => { value.taskRoleArn = "arn:aws:iam::368992683803:role/unreviewed"; } }), expectedArn: exactPayload.taskDefinition.taskDefinitionArn }),
    () => ({ readback: replacementPayload(undefined, { tags: [{ key: "MSCQRExecTarget", value: "wrong" }] }), expectedArn: exactPayload.taskDefinition.taskDefinitionArn }),
    () => ({ readback: replacementPayload(undefined, { mutate: (value) => { value.containerDefinitions[0].environment.find(({ name }) => name === "RELEASE_GIT_SHA").value = "0".repeat(40); } }), expectedArn: exactPayload.taskDefinition.taskDefinitionArn }),
  ];
  for (const makeCase of cases) { const value = makeCase(); assert.throws(() => assertCanonicalBackendRecoveryReadback({ ...value, expectedFingerprint: exactPayload.fingerprint })); }
  assert.throws(() => assertCanonicalBackendRecoveryReadback({ readback: exactPayload, expectedArn: STAGE_B_BACKEND_RECOVERY.historicalRevisionArns[1], expectedFingerprint: exactPayload.fingerprint }));
});

test("state reconciliation is exact, minimal, and rejects historical adoption", async () => {
  const replacementArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:9";
  let current = state();
  let removes = 0;
  let imports = 0;
  const payload = replacementPayload(replacementArn);
  const journal = buildCanonicalRecoveryJournal(current, journalArgs(current, payload));
  journal.replacementArn = replacementArn;
  journal.phase = "REGISTERED";
  const result = await reconcileCanonicalBackendState({
    sourceSha,
    replacementArn,
    readState: async () => structuredClone(current),
    journal: journalAdapter(journal),
    removeState: async ({ address, expectedArn }) => { removes += 1; assert.equal(address, STAGE_B_BACKEND_RECOVERY.address); assert.equal(expectedArn, STAGE_B_BACKEND_RECOVERY.predecessorArn); current = { ...current, serial: 94, resources: [] }; },
    importState: async ({ address, arn }) => { imports += 1; assert.equal(address, STAGE_B_BACKEND_RECOVERY.address); assert.equal(arn, replacementArn); current = state(replacementArn, 95); },
  });
  assert.equal(removes, 1);
  assert.equal(imports, 1);
  assert.deepEqual(result, { stateLineageBefore: STAGE_B_BACKEND_RECOVERY.lineage, stateLineageAfter: STAGE_B_BACKEND_RECOVERY.lineage, stateSerialBefore: 93, stateSerialAfter: 95, stateBackendCandidate: replacementArn, liveBackendCandidate: replacementArn, stateLivePredecessorMatch: true, removeCalls: 1, importCalls: 1 });
  await assert.rejects(() => reconcileCanonicalBackendState({ sourceSha, replacementArn: STAGE_B_BACKEND_RECOVERY.historicalRevisionArns[1], readState: async () => state(), removeState: async () => { throw new Error("must not mutate"); }, importState: async () => { throw new Error("must not mutate"); } }));
});

test("end-to-end recovery orchestration registers once, then reconciles only Terraform state", async () => {
  const replacementArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:9";
  const payload = replacementPayload(replacementArn);
  const historical = replacementPayload("arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:8", { mutate: (value) => { value.containerDefinitions[0].image = `${image.slice(0, -64)}${"e".repeat(64)}`; } });
  let current = state();
  const calls = [];
  const journal = journalAdapter();
  const result = await runCanonicalBackendRecovery({
    bindings,
    sourceSha,
    protectedCheckout,
    readState: async () => structuredClone(current),
    journal,
    census: async () => calls.includes("register") ? censusFor(payload) : { complete: true, revisions: [{ arn: historical.taskDefinition.taskDefinitionArn, readback: historical }] },
    register: async () => { calls.push("register"); return { taskDefinition: { taskDefinitionArn: replacementArn } }; },
    describe: async () => payload,
    removeState: async () => { calls.push("remove"); current = { ...current, serial: 94, resources: [] }; },
    importState: async () => { calls.push("import"); current = state(replacementArn, 95); },
  });
  assert.deepEqual(calls, ["register", "remove", "import"]);
  assert.equal(result.registration.registrationCalls, 1);
  assert.equal(result.reconciliation.stateBackendCandidate, replacementArn);
  assert.equal(result.evidence.replacementArn, replacementArn);
});

test("source identity and evidence destination failures happen before mutation adapters", async () => {
  const directory = `/tmp/mscqr-recovery-test-${process.pid}`;
  const { mkdirSync, rmSync, writeFileSync } = await import("node:fs");
  rmSync(directory, { recursive: true, force: true });
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const bindingsPath = `${directory}/bindings.json`;
  const imageAuthorizationPath = `${directory}/image-authorization.json`;
  const evidencePath = `${directory}/evidence.json`;
  writeFileSync(bindingsPath, JSON.stringify(bindings), { mode: 0o600 });
  writeFileSync(imageAuthorizationPath, JSON.stringify(imageAuthorization), { mode: 0o600 });
  writeFileSync(evidencePath, "occupied\n", { mode: 0o600 });
  const calls = [];
  const exec = (command) => { calls.push(command); throw new Error("mutation adapter must not run"); };
  const terraformRoot = path.resolve("infra/aws/terraform/production-green-stage-b");
  const cliArgs = (output) => ["--execute", "--source-sha", sourceSha, "--bindings", bindingsPath, "--image-authorization", imageAuthorizationPath, "--terraform-root", terraformRoot, "--evidence-out", output, "--aws-profile", "test"];
  await assert.rejects(() => runCanonicalRecoveryCli(cliArgs(evidencePath), { exec, readProtectedCheckout: () => protectedCheckout }), /occupied/);
  assert.deepEqual(calls, []);
  await assert.rejects(() => runCanonicalRecoveryCli(cliArgs(`${directory}/other.json`).map((value, index) => index === 2 ? "0".repeat(40) : value), { exec, readProtectedCheckout: () => protectedCheckout }), /exact clean protected-main/);
  assert.deepEqual(calls, []);
  await assert.rejects(() => runCanonicalRecoveryCli(cliArgs(`${directory}/dirty.json`), { exec, readProtectedCheckout: () => ({ ...protectedCheckout, porcelainStatus: " M scripts/aws/example.mjs" }) }), /clean protected-main/);
  assert.deepEqual(calls, []);
  await assert.rejects(() => runCanonicalRecoveryCli(cliArgs(`${directory}/different-head.json`), { exec, readProtectedCheckout: () => ({ ...protectedCheckout, currentHead: "f".repeat(40) }) }), /exact clean protected-main/);
  assert.deepEqual(calls, []);
  writeFileSync(bindingsPath, JSON.stringify({ ...bindings, imageReleaseSha: "0".repeat(40) }), { mode: 0o600 });
  await assert.rejects(() => runCanonicalRecoveryCli(cliArgs(`${directory}/binding-mismatch.json`), { exec, readProtectedCheckout: () => protectedCheckout }), /image-release identity/);
  assert.deepEqual(calls, []);
  writeFileSync(`${directory}/not-a-directory`, "x\n", { mode: 0o600 });
  await assert.rejects(() => runCanonicalRecoveryCli(cliArgs(`${directory}/not-a-directory/evidence.json`), { exec, readProtectedCheckout: () => protectedCheckout }), /directory/);
  assert.deepEqual(calls, []);
  rmSync(directory, { recursive: true, force: true });
});

test("retry after remote registration resumes the exact newest canonical revision without registering", async () => {
  const replacementArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:9";
  const payload = replacementPayload(replacementArn);
  let current = state();
  let newestValue = STAGE_B_BACKEND_RECOVERY.newestHistoricalArn;
  let registrationCalls = 0;
  const journal = journalAdapter();
  const common = { bindings, sourceSha, protectedCheckout, readState: async () => structuredClone(current), journal,
    census: async () => newestValue === replacementArn ? censusFor(payload) : ({ complete: true, revisions: [{ arn: STAGE_B_BACKEND_RECOVERY.newestHistoricalArn, readback: replacementPayload(STAGE_B_BACKEND_RECOVERY.newestHistoricalArn, { mutate: (value) => { value.containerDefinitions[0].image = `${image.slice(0, -64)}${"e".repeat(64)}`; } }) }] }), describe: async () => payload,
    removeState: async () => { current = { ...current, serial: 94, resources: [] }; },
    importState: async () => { current = state(replacementArn, 95); } };
  await assert.rejects(() => runCanonicalBackendRecovery({ ...common, register: async () => { registrationCalls += 1; newestValue = replacementArn; throw new Error("response lost"); } }), /response lost/);
  const result = await runCanonicalBackendRecovery({ ...common, register: async () => { registrationCalls += 1; throw new Error("must not register on retry"); } });
  assert.equal(registrationCalls, 1);
  assert.equal(result.registration.registrationCalls, 0);
  assert.equal(result.reconciliation.stateBackendCandidate, replacementArn);
});

test("REGISTERED fingerprint-blocked journal resumes existing AWS-normalized revision without registering", async () => {
  const replacementArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:9";
  const readback = awsNormalizedReadback(replacementArn);
  let current = state(); let registrations = 0;
  const initial = buildCanonicalRecoveryJournal(current, journalArgs(current, readback));
  const journal = journalAdapter({ ...initial, phase: "REGISTERED", replacementArn, registrationCalls: 1, registrationMayHaveOccurred: true });
  const result = await runCanonicalBackendRecovery({ bindings, sourceSha, protectedCheckout, journal,
    readState: async () => structuredClone(current), census: async () => censusFor(readback), describe: async () => readback,
    register: async () => { registrations += 1; throw new Error("must not register on resume"); },
    removeState: async () => { current = { ...current, serial: 94, resources: [] }; },
    importState: async () => { current = state(replacementArn, 95); },
  });
  assert.equal(registrations, 0);
  assert.equal(result.registration.registrationCalls, 0);
  assert.equal(result.reconciliation.stateBackendCandidate, replacementArn);
});

test("captured revision :8 with legacy RELEASE_GIT_SHA is historical and triggers one fresh registration", async () => {
  const replacementArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:8";
  const invalid = replacementPayload(replacementArn, { mutate: (value) => {
    value.containerDefinitions[0].environment.find(({ name }) => name === "RELEASE_GIT_SHA").value = "f6bd6e45033fd9adde9f55889ffd00957b063d35";
  } });
  const expected = replacementPayload(replacementArn);
  assert.notEqual(taskDefinitionFingerprint(invalid.taskDefinition, invalid.tags), expected.fingerprint);
  assert.throws(() => assertCanonicalBackendRecoveryReadback({ readback: invalid, expectedArn: replacementArn, expectedFingerprint: expected.fingerprint }), /historical/);
  let registrations = 0; let current = state();
  const newArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:9";
  const payload = replacementPayload(newArn);
  const result = await runCanonicalBackendRecovery({ bindings, sourceSha, protectedCheckout, journal: journalAdapter(),
    readState: async () => structuredClone(current), census: async () => registrations ? censusFor(payload) : ({ complete: true, revisions: [{ arn: replacementArn, readback: invalid }] }), describe: async () => payload,
    register: async () => { registrations += 1; return { taskDefinition: { taskDefinitionArn: newArn } }; },
    removeState: async () => { current = { ...current, serial: 94, resources: [] }; }, importState: async () => { current = state(newArn, 95); },
  });
  assert.equal(registrations, 1);
  assert.equal(result.registration.arn, newArn);
});

test("recovery authorization uses the selected profile environment and rejects ambient credentials", async () => {
  const { mkdtempSync, rmSync, writeFileSync } = await import("node:fs");
  const directory = mkdtempSync(path.join("/tmp", "mscqr-recovery-profile-"));
  const bindingsPath = path.join(directory, "bindings.json");
  const imageAuthorizationPath = path.join(directory, "image-authorization.json");
  const evidencePath = path.join(directory, "evidence.json");
  writeFileSync(bindingsPath, JSON.stringify(bindings), { mode: 0o600 });
  writeFileSync(imageAuthorizationPath, JSON.stringify(imageAuthorization), { mode: 0o600 });
  const cliArgs = ["--execute", "--source-sha", sourceSha, "--bindings", bindingsPath, "--image-authorization", imageAuthorizationPath,
    "--terraform-root", path.resolve("infra/aws/terraform/production-green-stage-b"), "--evidence-out", evidencePath, "--aws-profile", "selected-recovery-profile"];
  const observed = [];
  const calls = [];
  const ambient = { ...process.env, AWS_PROFILE: "ambient-profile", AWS_ACCESS_KEY_ID: "ambient-key", AWS_SECRET_ACCESS_KEY: "ambient-secret", AWS_SESSION_TOKEN: "ambient-token", AWS_SECURITY_TOKEN: "ambient-security-token" };
  try {
    await assert.rejects(() => runCanonicalRecoveryCli(cliArgs, {
      baseEnv: ambient,
      readProtectedCheckout: () => protectedCheckout,
      verifyImageEvidence: ({ env }) => { observed.push(env); throw new Error("signature verification failed"); },
      exec: (...args) => { calls.push(args); throw new Error("mutation adapter must not run"); },
    }), /signature verification failed/);
    assert.equal(observed.length, 1);
    assert.equal(observed[0].AWS_PROFILE, "selected-recovery-profile");
    assert.equal(observed[0].AWS_REGION, "eu-west-2");
    for (const key of ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN"]) assert.equal(observed[0][key], undefined);
    assert.deepEqual(calls, []);
    assert.deepEqual(buildRecoveryAwsEnvironment("selected-recovery-profile", ambient), observed[0]);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("schema-v4 journal tooling SHA is mandatory and source-bound on resume", async () => {
  const replacementArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:9";
  const payload = replacementPayload(replacementArn);
  for (const toolingSha of [undefined, "f6bd6e45033fd9adde9f55889ffd00957b063d35", "0".repeat(40)]) {
    const initial = buildCanonicalRecoveryJournal(state(), journalArgs(state(), payload));
    if (toolingSha === undefined) delete initial.toolingSha;
    else initial.toolingSha = toolingSha;
    const journal = journalAdapter({ ...initial, phase: "REGISTERED", replacementArn, registrationCalls: 1, registrationMayHaveOccurred: true });
    let registrations = 0;
    await assert.rejects(() => runCanonicalBackendRecovery({ bindings, sourceSha, protectedCheckout, journal,
      readState: async () => state(), census: async () => censusFor(payload), describe: async () => payload,
      register: async () => { registrations += 1; }, removeState: async () => {}, importState: async () => {},
    }), /Canonical recovery journal does not match/);
    assert.equal(registrations, 0);
  }
});

test("discovery failure records no registration attempt and legacy false registration journals fail closed", async () => {
  let current = state();
  const journal = journalAdapter();
  let registrations = 0;
  await assert.rejects(() => runCanonicalBackendRecovery({ bindings, sourceSha, protectedCheckout, journal,
    readState: async () => structuredClone(current), census: async () => { throw new Error("ListTaskDefinitions denied"); },
    register: async () => { registrations += 1; }, describe: async () => {}, removeState: async () => {}, importState: async () => {},
  }), /ListTaskDefinitions denied/);
  assert.equal(journal.read(), null);
  assert.equal(registrations, 0);
  journal.write({ ...journal.read(), schemaVersion: 1, phase: "REGISTERING", registrationCalls: 1 });
  await assert.rejects(() => runCanonicalBackendRecovery({ bindings, sourceSha, protectedCheckout, journal,
    readState: async () => structuredClone(current), census: async () => ({ complete: true, revisions: [{ arn: STAGE_B_BACKEND_RECOVERY.newestHistoricalArn, readback: replacementPayload(STAGE_B_BACKEND_RECOVERY.newestHistoricalArn, { mutate: (value) => { value.containerDefinitions[0].image = `${image.slice(0, -64)}${"e".repeat(64)}`; } }) }] }),
    register: async () => { registrations += 1; }, describe: async () => {}, removeState: async () => {}, importState: async () => {},
  }), /Legacy recovery journal/);
  assert.equal(registrations, 0);
});

test("a sent registration that loses its response is marked ambiguous and never retried against historical newest", async () => {
  const journal = journalAdapter();
  let registrations = 0;
  await assert.rejects(() => runCanonicalBackendRecovery({ bindings, sourceSha, protectedCheckout, journal,
    readState: async () => state(), census: async () => ({ complete: true, revisions: [{ arn: STAGE_B_BACKEND_RECOVERY.newestHistoricalArn, readback: replacementPayload(STAGE_B_BACKEND_RECOVERY.newestHistoricalArn, { mutate: (value) => { value.containerDefinitions[0].image = `${image.slice(0, -64)}${"e".repeat(64)}`; } }) }] }),
    register: async () => { registrations += 1; throw new Error("response lost"); }, describe: async () => {}, removeState: async () => {}, importState: async () => {},
  }), /response lost/);
  assert.equal(journal.read().registrationCalls, 1);
  assert.equal(journal.read().registrationMayHaveOccurred, true);
  await assert.rejects(() => runCanonicalBackendRecovery({ bindings, sourceSha, protectedCheckout, journal,
    readState: async () => state(), census: async () => ({ complete: true, revisions: [{ arn: STAGE_B_BACKEND_RECOVERY.newestHistoricalArn, readback: replacementPayload(STAGE_B_BACKEND_RECOVERY.newestHistoricalArn, { mutate: (value) => { value.containerDefinitions[0].image = `${image.slice(0, -64)}${"e".repeat(64)}`; } }) }] }),
    register: async () => { registrations += 1; }, describe: async () => {}, removeState: async () => {}, importState: async () => {},
  }), /cannot prove a prior registration/);
  assert.equal(registrations, 1);
});

test("interrupted state removal resumes with import only", async () => {
  const replacementArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:9";
  const payload = replacementPayload(replacementArn);
  let current = state();
  let removes = 0;
  let imports = 0;
  const journal = journalAdapter();
  const common = { bindings, sourceSha, protectedCheckout, readState: async () => structuredClone(current), journal,
    census: async () => censusFor(payload), describe: async () => payload,
    register: async () => { throw new Error("must not register while resuming"); },
    removeState: async () => { removes += 1; current = { ...current, serial: 94, resources: [] }; },
    importState: async () => { imports += 1; current = state(replacementArn, 95); } };
  let firstImport = true;
  await assert.rejects(() => runCanonicalBackendRecovery({ ...common, removeState: async () => { removes += 1; current = { ...current, serial: 94, resources: [] }; }, importState: async () => { imports += 1; if (firstImport) { firstImport = false; throw new Error("interrupted after state rm"); } current = state(replacementArn, 95); } }), /interrupted/);
  const result = await runCanonicalBackendRecovery(common);
  assert.equal(removes, 1);
  assert.equal(imports, 2);
  assert.equal(result.reconciliation.removeCalls, 0);
  assert.equal(result.reconciliation.importCalls, 1);
});

test("pre-remove checkpoint resumes when state removal never mutates state", async () => {
  const replacementArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:9";
  const payload = replacementPayload(replacementArn);
  let current = state(); let registrations = 0; let removes = 0; let imports = 0;
  const journal = journalAdapter();
  const historical = replacementPayload(STAGE_B_BACKEND_RECOVERY.historicalRevisionArns.at(-1), { mutate: (value) => { value.containerDefinitions[0].image = `${image.slice(0, -64)}${"e".repeat(64)}`; } });
  const common = { bindings, sourceSha, protectedCheckout, journal, readState: async () => structuredClone(current), census: async () => registrations ? censusFor(payload) : { complete: true, revisions: [{ arn: historical.taskDefinition.taskDefinitionArn, readback: historical }] }, describe: async () => payload,
    register: async () => { registrations += 1; return { taskDefinition: { taskDefinitionArn: replacementArn } }; },
    importState: async () => { imports += 1; current = state(replacementArn, 95); } };
  await assert.rejects(() => runCanonicalBackendRecovery({ ...common, removeState: async () => { removes += 1; throw new Error("lock timeout"); } }), /lock timeout/);
  assert.equal(journal.read().phase, "STATE_RECONCILING_PRE_REMOVE");
  assert.equal(current.serial, 93);
  const resumed = await runCanonicalBackendRecovery({ ...common, register: async () => { throw new Error("must not register again"); }, removeState: async () => { removes += 1; current = { ...current, serial: 94, resources: [] }; } });
  assert.equal(registrations, 1);
  assert.equal(removes, 2);
  assert.equal(imports, 1);
  assert.equal(resumed.reconciliation.stateBackendCandidate, replacementArn);
});

test("persisted pre-remove journal resumes when the process dies before state removal starts", async () => {
  const replacementArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:9";
  const payload = replacementPayload(replacementArn);
  let current = state(); let removes = 0; let imports = 0;
  const initial = buildCanonicalRecoveryJournal(current, journalArgs(current, payload));
  const journal = journalAdapter({ ...initial, phase: "STATE_RECONCILING_PRE_REMOVE", replacementArn, replacementFingerprint: payload.fingerprint, registrationCalls: 1, registrationMayHaveOccurred: true });
  const resumed = await runCanonicalBackendRecovery({ bindings, sourceSha, protectedCheckout, journal,
    readState: async () => structuredClone(current), census: async () => censusFor(payload), describe: async () => payload,
    register: async () => { throw new Error("must not register again"); },
    removeState: async () => { removes += 1; current = { ...current, serial: 94, resources: [] }; },
    importState: async () => { imports += 1; current = state(replacementArn, 95); },
  });
  assert.equal(removes, 1);
  assert.equal(imports, 1);
  assert.equal(resumed.reconciliation.stateBackendCandidate, replacementArn);
});

test("legacy schema-v4 journal resumes the existing :9 after state rm using the exact pre-removal snapshot", async () => {
  const replacementArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:9";
  const payload = replacementPayload(replacementArn);
  const preRemoval = checkpointBeforeState();
  const postRemoval = checkpointAfterState();
  const imported = checkpointImportedState(replacementArn);
  const initial = buildCanonicalRecoveryJournal(preRemoval, journalArgs(preRemoval, payload));
  const journal = journalAdapter({ ...initial, phase: "STATE_RECONCILING_PRE_REMOVE", replacementArn, replacementFingerprint: payload.fingerprint, registrationCalls: 1, registrationMayHaveOccurred: true });
  const legacy = journal.read();
  delete legacy.checkpointHashDomain;
  legacy.stateBeforeSha256 = canonicalSha256(preRemoval);
  legacy.stateAfterRemoveSha256 = canonicalSha256({ ...preRemoval, serial: 94, resources: preRemoval.resources.filter((resource) => !(resource.type === "aws_ecs_task_definition" && resource.name === "candidate")) });
  journal.write(legacy);
  let current = postRemoval;
  let registrations = 0;
  let imports = 0;
  const result = await runCanonicalBackendRecovery({ bindings, sourceSha, protectedCheckout, journal,
    stateBefore: preRemoval, readState: async () => structuredClone(current), census: async () => censusFor(payload), describe: async () => payload,
    register: async () => { registrations += 1; throw new Error("must not register existing :9"); },
    removeState: async () => { throw new Error("must not remove after state rm checkpoint"); },
    importState: async () => { imports += 1; current = imported; },
  });
  assert.equal(registrations, 0);
  assert.equal(imports, 1);
  assert.equal(result.reconciliation.stateSerialAfter, 95);

  const wrongSnapshot = structuredClone(preRemoval);
  wrongSnapshot.resources[1].instances[0].attributes.name = "/ecs/changed";
  await assert.rejects(() => runCanonicalBackendRecovery({ bindings, sourceSha, protectedCheckout, journal: journalAdapter(legacy), stateBefore: wrongSnapshot,
    readState: async () => structuredClone(postRemoval), census: async () => censusFor(payload), describe: async () => payload,
    register: async () => { throw new Error("must not register"); }, removeState: async () => { throw new Error("must not remove"); }, importState: async () => { throw new Error("must not import"); },
  }), /pre-removal state snapshot/);
});

test("legacy post-remove checkpoint accepts only the reviewed semantic metadata transition", async () => {
  const replacementArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:9";
  const payload = replacementPayload(replacementArn);
  const journalState = checkpointBeforeState();
  const executorSnapshot = structuredClone(journalState);
  executorSnapshot.terraform_version = "1.15.8";
  executorSnapshot.check_results.reverse();
  const expectedRemoved = { ...journalState, serial: 94, resources: journalState.resources.filter((resource) => !(resource.type === "aws_ecs_task_definition" && resource.name === "candidate")) };
  let current = { ...executorSnapshot, serial: 94, resources: executorSnapshot.resources.filter((resource) => !(resource.type === "aws_ecs_task_definition" && resource.name === "candidate")) };
  const initial = buildCanonicalRecoveryJournal(journalState, journalArgs(journalState, payload));
  const legacy = { ...initial, phase: "STATE_RECONCILING_PRE_REMOVE", replacementArn, replacementFingerprint: payload.fingerprint, registrationCalls: 1, registrationMayHaveOccurred: true,
    stateBeforeSha256: canonicalSha256(journalState), stateAfterRemoveSha256: canonicalSha256(expectedRemoved) };
  delete legacy.checkpointHashDomain;
  let imports = 0;
  await assert.doesNotReject(() => runCanonicalBackendRecovery({ bindings, sourceSha, protectedCheckout, journal: journalAdapter(legacy), stateBefore: executorSnapshot,
    readState: async () => structuredClone(current), census: async () => censusFor(payload), describe: async () => payload,
    register: async () => { throw new Error("must not register"); }, removeState: async () => { throw new Error("must not remove"); },
    importState: async ({ arn }) => { imports += 1; current = checkpointImportedState(arn); },
  }));
  assert.equal(imports, 1);

  for (const mutate of [
    (value) => { value.resources[1].instances[0].attributes.name = "/ecs/changed"; },
    (value) => { value.resources.push({ mode: "managed", type: "aws_s3_bucket", name: "unexpected", instances: [] }); },
    (value) => { value.lineage = "0".repeat(36); },
    (value) => { value.resources[0].provider = 'provider["registry.terraform.io/hashicorp/random"]'; },
    (value) => { value.terraform_version = "1.15.9"; },
  ]) {
    const changed = structuredClone(current);
    mutate(changed);
    await assert.rejects(() => runCanonicalBackendRecovery({ bindings, sourceSha, protectedCheckout, journal: journalAdapter(legacy), stateBefore: executorSnapshot,
      readState: async () => changed, census: async () => censusFor(payload), describe: async () => payload,
      register: async () => { throw new Error("must not register"); }, removeState: async () => {}, importState: async () => {},
    }), /checkpoint|lineage|pre-removal/);
  }

  const forged = { ...legacy, stateBeforeSha256: "f".repeat(64), stateAfterRemoveSha256: canonicalSha256({ ...executorSnapshot, serial: 94, resources: executorSnapshot.resources.filter((resource) => !(resource.type === "aws_ecs_task_definition" && resource.name === "candidate")) }) };
  await assert.rejects(() => runCanonicalBackendRecovery({ bindings, sourceSha, protectedCheckout, journal: journalAdapter(forged), stateBefore: executorSnapshot,
    readState: async () => structuredClone(current), census: async () => censusFor(payload), describe: async () => payload,
    register: async () => { throw new Error("must not register"); }, removeState: async () => {}, importState: async () => {},
  }), /hash evidence is inconsistent|pre-removal/);
});

test("legacy DISCOVERY and PREPARED journals resume with raw state hashes and reject state drift", async () => {
  const replacementArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:9";
  const payload = replacementPayload(replacementArn);
  const preRemoval = checkpointBeforeState();
  for (const phase of ["DISCOVERY", "PREPARED"]) {
    const initial = buildCanonicalRecoveryJournal(preRemoval, journalArgs(preRemoval, payload));
    const legacy = { ...initial, phase, stateBeforeSha256: canonicalSha256(preRemoval) };
    delete legacy.checkpointHashDomain;
    const legacyRemoved = { ...preRemoval, serial: 94, resources: preRemoval.resources.filter((resource) => !(resource.type === "aws_ecs_task_definition" && resource.name === "candidate")) };
    legacy.stateAfterRemoveSha256 = canonicalSha256(legacyRemoved);
    let current = structuredClone(preRemoval);
    let registrations = 0;
    const result = await runCanonicalBackendRecovery({ bindings, sourceSha, protectedCheckout, journal: journalAdapter(legacy),
      readState: async () => structuredClone(current), census: async () => censusFor(payload), describe: async () => payload,
      register: async () => { registrations += 1; throw new Error("must not register"); },
      removeState: async () => { current = legacyRemoved; }, importState: async () => { current = checkpointImportedState(replacementArn); },
    });
    assert.equal(registrations, 0);
    assert.equal(result.registration.resumed, true);

    for (const mutate of [
      (value) => { value.resources[1].instances[0].attributes.name = "/ecs/changed"; },
      (value) => { value.lineage = "0".repeat(36); },
      (value) => { value.resources[1].provider = 'provider["registry.terraform.io/hashicorp/random"]'; },
    ]) {
      const changed = structuredClone(preRemoval);
      mutate(changed);
      let changedRegistrations = 0;
      await assert.rejects(() => runCanonicalBackendRecovery({ bindings, sourceSha, protectedCheckout, journal: journalAdapter(legacy),
        readState: async () => changed, census: async () => censusFor(payload), describe: async () => payload,
        register: async () => { changedRegistrations += 1; }, removeState: async () => {}, importState: async () => {},
      }), /state changed before|lineage changed/);
      assert.equal(changedRegistrations, 0);
    }
  }
});

test("new checkpoint hash domain uses normalized hashes without a legacy fallback", async () => {
  const replacementArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:9";
  const payload = replacementPayload(replacementArn);
  const preRemoval = checkpointBeforeState();
  const normalizedState = structuredClone(preRemoval);
  normalizedState.terraform_version = "1.15.8";
  normalizedState.check_results.reverse();
  const initial = buildCanonicalRecoveryJournal(preRemoval, journalArgs(preRemoval, payload));
  const valid = { ...initial, phase: "PREPARED" };
  let current = normalizedState;
  await assert.doesNotReject(() => runCanonicalBackendRecovery({ bindings, sourceSha, protectedCheckout, journal: journalAdapter(valid),
    readState: async () => structuredClone(current), census: async () => censusFor(payload), describe: async () => payload,
    register: async () => { throw new Error("must not register"); }, removeState: async () => { current = checkpointAfterState(); }, importState: async () => { current = checkpointImportedState(replacementArn); },
  }));

  const rawHashTrap = { ...initial, phase: "PREPARED", stateBeforeSha256: canonicalSha256(normalizedState) };
  await assert.rejects(() => runCanonicalBackendRecovery({ bindings, sourceSha, protectedCheckout, journal: journalAdapter(rawHashTrap),
    readState: async () => structuredClone(normalizedState), census: async () => censusFor(payload), describe: async () => payload,
    register: async () => { throw new Error("must not register"); }, removeState: async () => {}, importState: async () => {},
  }), /state changed before/);
});

test("post-remove readback resumes import when process dies before the post-remove journal write", async () => {
  const replacementArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:9";
  const payload = replacementPayload(replacementArn);
  let current = state(); let reads = 0; let imports = 0;
  const journal = journalAdapter();
  const common = { bindings, sourceSha, protectedCheckout, journal, census: async () => censusFor(payload), describe: async () => payload,
    register: async () => ({ taskDefinition: { taskDefinitionArn: replacementArn } }),
    removeState: async () => { current = { ...current, serial: 94, resources: [] }; },
    importState: async () => { imports += 1; current = state(replacementArn, 95); } };
  await assert.rejects(() => runCanonicalBackendRecovery({ ...common, readState: async () => { reads += 1; if (reads === 3) throw new Error("process died after rm"); return structuredClone(current); } }), /process died/);
  assert.equal(journal.read().phase, "STATE_RECONCILING_PRE_REMOVE");
  const resumed = await runCanonicalBackendRecovery({ ...common, readState: async () => structuredClone(current), register: async () => { throw new Error("must not register again"); } });
  assert.equal(imports, 1);
  assert.equal(resumed.reconciliation.removeCalls, 0);
});

test("interrupted import resumes without registration or second state mutation", async () => {
  const replacementArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:9";
  const payload = replacementPayload(replacementArn);
  let current = state();
  let removes = 0;
  let imports = 0;
  let readCount = 0;
  const journal = journalAdapter();
  const result = await runCanonicalBackendRecovery({ bindings, sourceSha, protectedCheckout, journal,
    readState: async () => { readCount += 1; if (readCount === 4) throw new Error("interrupted after import"); return structuredClone(current); },
    census: async () => censusFor(payload), describe: async () => payload,
    register: async () => ({ taskDefinition: { taskDefinitionArn: replacementArn } }),
    removeState: async () => { removes += 1; current = { ...current, serial: 94, resources: [] }; },
    importState: async () => { imports += 1; current = state(replacementArn, 95); },
  }).catch((error) => { assert.match(error.message, /interrupted/); return null; });
  assert.equal(result, null);
  const resumed = await runCanonicalBackendRecovery({ bindings, sourceSha, protectedCheckout, journal,
    readState: async () => structuredClone(current), census: async () => censusFor(payload), describe: async () => payload,
    register: async () => { throw new Error("must not register on imported resume"); },
    removeState: async () => { removes += 1; }, importState: async () => { imports += 1; } });
  assert.equal(removes, 1);
  assert.equal(imports, 1);
  assert.equal(resumed.reconciliation.removeCalls, 0);
  assert.equal(resumed.reconciliation.importCalls, 0);
});

test("historical mismatch authorizes one fresh registration while an unexpected newer revision blocks", async () => {
  const replacementArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:9";
  const payload = replacementPayload(replacementArn);
  const historical = historicalPayload();
  let current = state(); let registrations = 0; let registered = false;
  await runCanonicalBackendRecovery({ bindings, sourceSha, protectedCheckout, journal: journalAdapter(), readState: async () => structuredClone(current),
    census: async () => registered ? censusFor(payload) : { complete: true, revisions: [{ arn: historical.taskDefinition.taskDefinitionArn, readback: historical }] },
    describe: async () => payload,
    register: async () => { registrations += 1; registered = true; return { taskDefinition: { taskDefinitionArn: replacementArn } }; },
    removeState: async () => { current = { ...current, serial: 94, resources: [] }; }, importState: async () => { current = state(replacementArn, 95); } });
  assert.equal(registrations, 1);
  const newer = replacementPayload(replacementArn, { mutate: (value) => { value.containerDefinitions[0].image = `${image.slice(0, -64)}${"e".repeat(64)}`; } });
  let blockedRegistrations = 0; let blockedRemoves = 0;
  await assert.rejects(() => runCanonicalBackendRecovery({ bindings, sourceSha, protectedCheckout, journal: journalAdapter(), readState: async () => state(),
    census: async () => ({ complete: true, revisions: [{ arn: replacementArn, readback: newer }, { arn: historical.taskDefinition.taskDefinitionArn, readback: historical }] }),
    register: async () => { blockedRegistrations += 1; }, describe: async () => newer, removeState: async () => { blockedRemoves += 1; }, importState: async () => {} }), /unreviewed newer/);
  assert.equal(blockedRegistrations, 0);
  assert.equal(blockedRemoves, 0);
});

test("fresh recovery requires the exact configured :8 historical anchor", async () => {
  const payload = replacementPayload();
  for (const activeHistorical of [
    [STAGE_B_BACKEND_RECOVERY.historicalRevisionArns[1]],
    [STAGE_B_BACKEND_RECOVERY.historicalRevisionArns[0]],
    STAGE_B_BACKEND_RECOVERY.historicalRevisionArns.slice(0, 2),
  ]) {
    let registrations = 0;
    await assert.rejects(() => runCanonicalBackendRecovery({ bindings, sourceSha, protectedCheckout, journal: journalAdapter(),
      readState: async () => state(), census: async () => ({ complete: true, revisions: activeHistorical.map((arn) => ({ arn, readback: historicalPayload(arn) })) }), describe: async () => payload,
      register: async () => { registrations += 1; }, removeState: async () => {}, importState: async () => {},
    }), /exact reviewed newest historical/);
    assert.equal(registrations, 0);
  }
});

test("census decisions require the explicit completeness envelope", () => {
  const payload = replacementPayload();
  const valid = censusFor(payload);
  assert.doesNotThrow(() => assertCanonicalBackendRecoveryCensus({ census: valid }));
  for (const census of [valid.revisions, { complete: false, revisions: valid.revisions }, { revisions: valid.revisions }, { complete: true }, { complete: true, revisions: "invalid" }]) {
    assert.throws(() => assertCanonicalBackendRecoveryCensus({ census }), /complete ACTIVE backend revision census/);
  }
});

test("pagination must complete before the recovery census is authorized", async () => {
  const payload = replacementPayload();
  const pages = new Map([[undefined, { taskDefinitionArns: [payload.taskDefinition.taskDefinitionArn], nextToken: "page-2" }], ["page-2", { taskDefinitionArns: [STAGE_B_BACKEND_RECOVERY.newestHistoricalArn] }]]);
  const census = await collectCanonicalBackendRecoveryCensus({ list: async (token) => pages.get(token), describe: async (arn) => arn === payload.taskDefinition.taskDefinitionArn ? payload : historicalPayload(arn) });
  assert.equal(census.complete, true);
  assert.equal(census.revisions.length, 2);
  await assert.rejects(() => collectCanonicalBackendRecoveryCensus({ list: async () => ({ taskDefinitionArns: [], nextToken: "same" }), describe: async () => payload }), /repeated a token/);
  await assert.rejects(() => collectCanonicalBackendRecoveryCensus({ list: async () => { throw new Error("ListTaskDefinitions denied"); }, describe: async () => payload }), /ListTaskDefinitions denied/);
});

test("unverified source provenance blocks before registration", async () => {
  const payload = replacementPayload();
  for (const changedBindings of [
    { ...bindings, toolingTreeSha256: "c".repeat(64) },
    { ...bindings, toolingTreeSha256: "d".repeat(64) },
    { ...bindings, sourceContractSha256: "e".repeat(64) },
    { ...bindings, sourceContractSha256: "f".repeat(64) },
  ]) {
    let registrations = 0;
    await assert.rejects(() => runCanonicalBackendRecovery({ bindings: changedBindings, sourceSha, protectedCheckout, journal: journalAdapter(),
      readState: async () => state(), census: async () => ({ complete: true, revisions: [{ arn: STAGE_B_BACKEND_RECOVERY.newestHistoricalArn, readback: historicalPayload() }] }), describe: async () => payload,
      register: async () => { registrations += 1; }, removeState: async () => {}, importState: async () => {},
    }), /source provenance/);
    assert.equal(registrations, 0);
  }
});

test("fresh incident identity is complete and every journal binding mismatch blocks before registration", async () => {
  const replacementArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:9";
  const payload = replacementPayload(replacementArn);
  const initial = buildCanonicalRecoveryJournal(state(), journalArgs(state(), payload));
  const mismatches = {
    toolingTreeSha256: "c".repeat(64),
    sourceContractSha256: "d".repeat(64),
    imageReleaseSha: "0".repeat(40),
    imageDigest: `${image.slice(0, -64)}${"e".repeat(64)}`,
    authorizedBackendImageDigest: `sha256:${"e".repeat(64)}`,
    imageAuthorizationSha256: "e".repeat(64),
    stateLineage: "0".repeat(36),
    stateSerial: 94,
    predecessorSerial: 94,
    predecessorArn: STAGE_B_BACKEND_RECOVERY.historicalRevisionArns[0],
    newestHistoricalArn: STAGE_B_BACKEND_RECOVERY.historicalRevisionArns[1],
    checkpointHashDomain: "unreviewed-checkpoint-domain",
    incidentIdentity: "f".repeat(64),
  };
  for (const [field, value] of Object.entries(mismatches)) {
    const journal = journalAdapter({ ...initial, phase: "REGISTERED", replacementArn, registrationCalls: 1, registrationMayHaveOccurred: true, [field]: value });
    let registrations = 0;
    await assert.rejects(() => runCanonicalBackendRecovery({ bindings, sourceSha, protectedCheckout, journal,
      readState: async () => state(), census: async () => censusFor(payload), describe: async () => payload,
      register: async () => { registrations += 1; }, removeState: async () => {}, importState: async () => {},
    }), /journal|incident|lineage|replacement/);
    assert.equal(registrations, 0, field);
  }
  assert.deepEqual(Object.keys(initial).filter((key) => ["toolingTreeSha256", "sourceContractSha256", "imageReleaseSha", "authorizedBackendImageDigest", "imageAuthorizationSha256", "stateLineage", "stateSerial", "predecessorSerial", "predecessorArn", "newestHistoricalArn", "protectedSourceFingerprint", "incidentIdentity"].includes(key)).sort(), ["authorizedBackendImageDigest", "imageAuthorizationSha256", "imageReleaseSha", "incidentIdentity", "newestHistoricalArn", "predecessorArn", "predecessorSerial", "protectedSourceFingerprint", "sourceContractSha256", "stateLineage", "stateSerial", "toolingTreeSha256"].sort());
});

test("source SHA and tooling SHA mismatches block before any recovery mutation", async () => {
  const payload = replacementPayload();
  for (const changedBindings of [{ ...bindings, toolingSha: "0".repeat(40) }, { ...bindings, sourceSha: "0".repeat(40) }]) {
    let registrations = 0;
    await assert.rejects(() => runCanonicalBackendRecovery({ bindings: changedBindings, sourceSha, protectedCheckout, journal: journalAdapter(),
      readState: async () => state(), census: async () => ({ complete: true, revisions: [{ arn: STAGE_B_BACKEND_RECOVERY.newestHistoricalArn, readback: historicalPayload() }] }), describe: async () => payload,
      register: async () => { registrations += 1; }, removeState: async () => {}, importState: async () => {},
    }), /source|tooling|image/);
    assert.equal(registrations, 0);
  }
});

test("an existing current-source revision is adopted with zero registration", async () => {
  const replacementArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:9";
  const payload = replacementPayload(replacementArn);
  let current = state(); let registrations = 0;
  const result = await runCanonicalBackendRecovery({ bindings, sourceSha, protectedCheckout, journal: journalAdapter(),
    readState: async () => structuredClone(current), census: async () => censusFor(payload), describe: async () => payload,
    register: async () => { registrations += 1; }, removeState: async () => { current = { ...current, serial: 94, resources: [] }; }, importState: async () => { current = state(replacementArn, 95); },
  });
  assert.equal(registrations, 0);
  assert.equal(result.registration.registrationCalls, 0);
});

test("post-registration image and RELEASE_GIT_SHA mismatches are fail-closed and never retried", async () => {
  const replacementArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:9";
  for (const mutate of [
    (value) => { value.containerDefinitions[0].image = `${image.slice(0, -64)}${"e".repeat(64)}`; },
    (value) => { value.containerDefinitions[0].environment.find(({ name }) => name === "RELEASE_GIT_SHA").value = "0".repeat(40); },
  ]) {
    const invalid = replacementPayload(replacementArn, { mutate });
    let current = state(); let registrations = 0; let attempted = false;
    const journal = journalAdapter();
    await assert.rejects(() => runCanonicalBackendRecovery({ bindings, sourceSha, protectedCheckout, journal,
      readState: async () => structuredClone(current), census: async () => attempted ? censusFor(invalid) : ({ complete: true, revisions: [{ arn: STAGE_B_BACKEND_RECOVERY.newestHistoricalArn, readback: historicalPayload() }] }),
      describe: async () => invalid, register: async () => { registrations += 1; attempted = true; return { taskDefinition: { taskDefinitionArn: replacementArn } }; },
      removeState: async () => {}, importState: async () => {},
    }), /fingerprint/);
    assert.equal(registrations, 1);
    assert.equal(journal.read().replacementArn, replacementArn);
    await assert.rejects(() => runCanonicalBackendRecovery({ bindings, sourceSha, protectedCheckout, journal,
      readState: async () => structuredClone(current), census: async () => censusFor(invalid), describe: async () => invalid,
      register: async () => { registrations += 1; }, removeState: async () => {}, importState: async () => {},
    }), /unreviewed newer/);
    assert.equal(registrations, 1);
  }
});

test("a crash after a successful registration resumes from the persisted returned ARN", async () => {
  const replacementArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:9";
  const payload = replacementPayload(replacementArn);
  const journal = journalAdapter(); let registrations = 0; let current = state();
  await assert.rejects(() => runCanonicalBackendRecovery({ bindings, sourceSha, protectedCheckout, journal,
    readState: async () => structuredClone(current), census: async () => ({ complete: true, revisions: [{ arn: STAGE_B_BACKEND_RECOVERY.newestHistoricalArn, readback: historicalPayload() }] }),
    describe: async () => { throw new Error("process interrupted after returned ARN"); }, register: async () => { registrations += 1; return { taskDefinition: { taskDefinitionArn: replacementArn } }; },
    removeState: async () => {}, importState: async () => {},
  }), /process interrupted/);
  assert.equal(journal.read().phase, "REGISTERED");
  assert.equal(journal.read().replacementArn, replacementArn);
  let reconciled = false;
  const result = await runCanonicalBackendRecovery({ bindings, sourceSha, protectedCheckout, journal,
    readState: async () => structuredClone(current), census: async () => censusFor(payload), describe: async () => payload,
    register: async () => { registrations += 1; }, removeState: async () => { current = { ...current, serial: 94, resources: [] }; }, importState: async () => { reconciled = true; current = state(replacementArn, 95); },
  });
  assert.equal(registrations, 1);
  assert.equal(reconciled, true);
  assert.equal(result.registration.registrationCalls, 0);
});

test("schema-1 and schema-3 journals remain historical evidence and registration count above one is impossible", async () => {
  const payload = replacementPayload();
  for (const schemaVersion of [1, 3]) {
    const journal = journalAdapter({ schemaVersion, phase: "REGISTERING", registrationCalls: 1, registrationMayHaveOccurred: true });
    let registrations = 0;
    await assert.rejects(() => runCanonicalBackendRecovery({ bindings, sourceSha, protectedCheckout, journal,
      readState: async () => state(), census: async () => censusFor(payload), register: async () => { registrations += 1; }, describe: async () => payload, removeState: async () => {}, importState: async () => {},
    }), /Legacy recovery journal/);
    assert.equal(registrations, 0);
  }
  const journal = journalAdapter({ ...buildCanonicalRecoveryJournal(state(), journalArgs(state(), payload)), phase: "REGISTERING", registrationCalls: 2, registrationMayHaveOccurred: true });
  await assert.rejects(() => runCanonicalBackendRecovery({ bindings, sourceSha, protectedCheckout, journal,
    readState: async () => state(), census: async () => ({ complete: true, revisions: [{ arn: STAGE_B_BACKEND_RECOVERY.newestHistoricalArn, readback: historicalPayload() }] }), register: async () => { throw new Error("must not register"); }, describe: async () => payload, removeState: async () => {}, importState: async () => {},
  }), /journal/);
});

test("recovery evidence is deterministic and binds source, image, predecessor, replacement, and state", () => {
  const payload = replacementPayload();
  const evidence = recoveryEvidence({ ...journalArgs(state(), payload), state: state(), replacement: { arn: payload.taskDefinition.taskDefinitionArn, fingerprint: payload.fingerprint, protectedSourceFingerprint: payload.fingerprint }, registrationEvent: { eventId: "reviewed-test-event" } });
  const { evidenceSha256, ...evidenceBody } = evidence;
  assert.equal(evidenceSha256, canonicalSha256(evidenceBody));
  assert.equal(evidence.predecessorArn, STAGE_B_BACKEND_RECOVERY.predecessorArn);
  assert.throws(() => recoveryEvidence({ ...journalArgs(state(), payload), state: state(), replacement: { arn: STAGE_B_BACKEND_RECOVERY.historicalRevisionArns[1], fingerprint: payload.fingerprint, protectedSourceFingerprint: payload.fingerprint } }));
});

test("generic deployment script cannot register Stage-B managed families", () => {
  const script = readFileSync("scripts/aws/deploy-ecs-service.sh", "utf8");
  assert.match(script, /reject_generic_stage_b_registration/);
  assert.match(script, /mscqr-production-rls-green-backend-candidate/);
  assert.match(script, /mscqr-production-full-rls-green-\*/);
  assert.match(script, /if \[\[ -z \"\$EXISTING_TASK_DEFINITION_ARN\" \]\]/);
});

test("recovery CLI requires explicit execution and hard-codes only the reviewed state operations", async () => {
  await assert.rejects(() => runCanonicalRecoveryCli(["--source-sha", sourceSha]), /--execute/);
  const script = readFileSync("scripts/aws/recover-stage-b-backend-task-definition.mjs", "utf8");
  assert.match(script, /--profile/);
  assert.match(script, /state\", \"rm/);
  assert.match(script, /import\", \"-lock-timeout=60s/);
  assert.match(script, /--state-before/);
  assert.match(script, /No ACTIVE backend candidate revisions/);
});

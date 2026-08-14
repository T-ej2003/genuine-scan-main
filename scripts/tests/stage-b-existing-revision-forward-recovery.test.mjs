import assert from "node:assert/strict";
import fs, { readFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import test from "node:test";
import { makeCanonicalImageAuthorization } from "./fixtures/canonical-image-authorization.mjs";
import {
  STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY as CONTRACT,
  assertForwardCensus,
  assertForwardDescendantResume,
  assertForwardRevisionReadback,
  assertForwardSourceBinding,
  assertForwardStateAfterImport,
  assertForwardStateBeforeImport,
  canonicalForwardRecoveryIncidentIdentity,
  runExistingRevisionForwardRecovery,
} from "../aws/stage-b-existing-revision-forward-recovery-contract.mjs";
import { assertForwardRecoveryTerraformBackend, buildForwardRecoveryTerraformEnvironment, preflightForwardRecoveryOutputs } from "../aws/forward-recover-stage-b-existing-revision.mjs";
import { STAGE_B_TERRAFORM_BACKEND_CONFIG } from "../aws/stage-b-terraform-backend-contract.mjs";
import { buildCanonicalBackendRecoveryTaskDefinition, canonicalSha256, stateSnapshotSha256, taskDefinitionFingerprint } from "../aws/stage-b-task-definition-recovery-contract.mjs";

const sourceSha = "45c5a38c7e3594793fafe1f051f1f381937ba0d4";
const imageReleaseSha = "25394d30c189583384c9bba62604bf968dc9e0b2";
const imageFixture = makeCanonicalImageAuthorization({ sourceSha, imageReleaseSha });
const imageAuthorization = imageFixture.authorization;
const backendImage = `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${imageAuthorization.backendDigest}`;
const bindings = {
  toolingSha: sourceSha,
  sourceSha,
  toolingTreeSha256: "a".repeat(64),
  sourceContractSha256: "b".repeat(64),
  imageReleaseSha,
  backendImage,
  imageAuthorization,
  migrationSetDigest: "c".repeat(64),
  packageChecksumSha256: "d".repeat(64),
  receiptBucket: "arn:aws:s3:::mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an",
  executorLogGroup: "/ecs/stage-b-executor",
  canaryLogGroup: "/ecs/mscqr-production/rls-green-canary",
  backendLogGroup: "/ecs/mscqr-production/rls-green-backend",
  workerLogGroup: "/ecs/mscqr-production/rls-green-worker",
};
const protectedCheckout = { currentHead: sourceSha, originMainHead: sourceSha, toolingSha: sourceSha, porcelainStatus: "" };
const deriveProvenance = () => ({ toolingTreeSha256: bindings.toolingTreeSha256, sourceContractSha256: bindings.sourceContractSha256 });
const deriveImageReuse = ({ imageReleaseSha: release, toolingSha }) => ({
  schemaVersion: 2, imageReleaseSha: release, toolingSha, toolingInputTreeSha256: bindings.toolingTreeSha256,
  comparisonBaseSha: release, comparisonHeadIdentity: "tooling-input-tree-sha256", comparisonHeadSha256: bindings.toolingTreeSha256,
  classificationRulesVersion: "stage-b-image-reuse-v2", imageReuseCompatible: true, imageBuildInputsChanged: false,
  classifiedChangedFiles: [], imageAffectingFiles: [], reportMatchesRecomputedDiff: true,
});

const emptyState = (serial = CONTRACT.startSerial) => ({
  version: 4, terraform_version: "1.15.8", serial, lineage: CONTRACT.lineage,
  resources: [{ mode: "managed", type: "aws_ecs_task_definition", name: "candidate", instances: [] }],
});
const arn = CONTRACT.existingRevisionArn;
const taskPayload = buildCanonicalBackendRecoveryTaskDefinition(bindings);
const fingerprint = taskDefinitionFingerprint(taskPayload.taskDefinition, taskPayload.tags);
const readback = { taskDefinition: { ...structuredClone(taskPayload.taskDefinition), taskDefinitionArn: arn, family: CONTRACT.family, status: "ACTIVE", revision: 9 }, tags: structuredClone(taskPayload.tags) };
const census = { complete: true, revisions: [{ arn, readback }] };
const journalAdapter = (initial) => { let value = initial && structuredClone(initial); return { read: () => value && structuredClone(value), write: (next) => { value = structuredClone(next); } }; };
const expectedIdentity = () => canonicalForwardRecoveryIncidentIdentity({
  sourceSha, toolingTreeSha256: bindings.toolingTreeSha256, sourceContractSha256: bindings.sourceContractSha256,
  imageReleaseSha, authorizedBackendDigest: imageAuthorization.backendDigest, imageAuthorizationSha256: imageAuthorization.evidenceSha256,
  stateLineage: CONTRACT.lineage, stateSerial: CONTRACT.startSerial, stateBeforeSha256: stateSnapshotSha256(emptyState()), existingRevisionArn: arn,
  censusSha256: canonicalSha256([{ arn, revision: 9, readback }]), fingerprint,
});

function importedState() {
  const state = emptyState(95);
  state.resources[0].instances = [{ index_key: "backend", schema_version: 1, attributes: { id: arn, arn, family: CONTRACT.family } }];
  return state;
}

function common(overrides = {}) {
  let current = structuredClone(emptyState());
  let imports = 0;
  let registrations = 0;
  const journal = journalAdapter();
  const evidenceStore = { value: null };
  const evidence = { read: () => evidenceStore.value && structuredClone(evidenceStore.value), write: (value) => { evidenceStore.value = structuredClone(value); } };
  return {
    bindings, sourceSha, protectedCheckout, imageAuthorization,
    imageAuthorizationValidation: { now: imageFixture.now, verifyImageEvidence: imageFixture.verifyImageEvidence },
    deriveProvenance, deriveImageReuse, journal, evidence,
    readState: async () => structuredClone(current),
    census: async () => structuredClone(census),
    describe: async () => structuredClone(readback),
    importState: async ({ address, arn: requestedArn }) => { assert.equal(address, CONTRACT.address); assert.equal(requestedArn, arn); imports += 1; current = importedState(); },
    register: async () => { registrations += 1; },
    get counts() { return { imports, registrations }; },
    ...overrides,
  };
}

test("adopts exact :9 with one import and zero registration capability", async () => {
  const run = common();
  const result = await runExistingRevisionForwardRecovery(run);
  assert.equal(result.imported, true);
  assert.deepEqual(run.counts, { imports: 1, registrations: 0 });
  assert.equal(result.state.serial, 95);
});

test("completed forward incident replays idempotently without import or registration", async () => {
  const run = common();
  const first = await runExistingRevisionForwardRecovery(run);
  const journalBytes = JSON.stringify(run.journal.read());
  const replay = common({ journal: run.journal, evidence: run.evidence, readState: async () => importedState() });
  const result = await runExistingRevisionForwardRecovery(replay);
  assert.equal(result.imported, false);
  assert.deepEqual(replay.counts, { imports: 0, registrations: 0 });
  assert.equal(JSON.stringify(run.journal.read()), journalBytes);
});

test("completed replay rejects corrupted or replaced evidence without mutation", async () => {
  const run = common();
  const first = await runExistingRevisionForwardRecovery(run);
  const journalBytes = JSON.stringify(run.journal.read());
  for (const completedEvidence of [{ ...first.evidence, evidenceSha256: "f".repeat(64) }, { foreign: true }]) {
    const evidence = { read: () => structuredClone(completedEvidence), write: () => { throw new Error("evidence rewrite"); } };
    const replay = common({ journal: run.journal, evidence, readState: async () => importedState() });
    await assert.rejects(() => runExistingRevisionForwardRecovery(replay), /evidence/);
    assert.equal(JSON.stringify(run.journal.read()), journalBytes);
    assert.deepEqual(replay.counts, { imports: 0, registrations: 0 });
  }
});

test("zero-registration mode rejects every newer or mismatched census", () => {
  assert.throws(() => assertForwardCensus({ census: { complete: true, revisions: [{ arn: `${arn.slice(0, -1)}10`, readback: { taskDefinition: { ...readback.taskDefinition, taskDefinitionArn: `${arn.slice(0, -1)}10`, revision: 10 }, tags: readback.tags } }, { arn, readback }] } }), /newest/);
  assert.throws(() => assertForwardCensus({ census: { complete: false, revisions: [readback] } }), /complete/);
  assert.throws(() => assertForwardCensus({ census: [readback] }), /complete/);
});

test("zero-registration mode rejects wrong family, image, fingerprint, and incomplete readback", () => {
  assert.throws(() => assertForwardRevisionReadback({ readback: { taskDefinition: { ...readback.taskDefinition, family: "wrong" }, tags: readback.tags }, expectedFingerprint: fingerprint, imageReleaseSha, backendImage }), /fingerprint/);
  assert.throws(() => assertForwardRevisionReadback({ readback: { taskDefinition: { ...readback.taskDefinition, containerDefinitions: [{ ...readback.taskDefinition.containerDefinitions[0], image: `${backendImage.slice(0, -1)}0` }] }, tags: readback.tags }, expectedFingerprint: fingerprint, imageReleaseSha, backendImage }), /fingerprint|image/);
  assert.throws(() => assertForwardRevisionReadback({ readback: { taskDefinition: { ...readback.taskDefinition, taskDefinitionArn: `${arn.slice(0, -1)}8`, revision: 8 }, tags: readback.tags }, expectedFingerprint: fingerprint, imageReleaseSha, backendImage }), /fingerprint/);
});

test("state guard rejects lineage, serial, candidate, and unrelated drift", () => {
  assertForwardStateBeforeImport(emptyState());
  assert.throws(() => assertForwardStateBeforeImport({ ...emptyState(), lineage: "00000000-0000-0000-0000-000000000000" }), /lineage/);
  assert.throws(() => assertForwardStateBeforeImport(emptyState(95)), /lineage|serial/);
  const present = emptyState();
  present.resources[0].instances = [{ index_key: "backend", attributes: { id: arn, arn } }];
  assert.throws(() => assertForwardStateBeforeImport(present), /absent/);
  const before = emptyState();
  const after = importedState();
  after.resources.push({ mode: "managed", type: "aws_s3_bucket", name: "unrelated", instances: [] });
  assert.throws(() => assertForwardStateAfterImport(before, after), /outside/);
  assert.throws(() => assertForwardStateAfterImport(before, { ...after, lineage: "00000000-0000-0000-0000-000000000000" }), /lineage/);
});

test("post-import comparison reuses the reviewed Terraform checkpoint normalizer", () => {
  const before = emptyState();
  before.terraform_version = "1.15.7";
  before.check_results = [{ object: "z" }, { object: "a" }];
  const after = importedState();
  after.check_results = [{ object: "a" }, { object: "z" }];
  assert.doesNotThrow(() => assertForwardStateAfterImport(before, after));
  const changed = structuredClone(after);
  changed.resources.push({ mode: "managed", type: "aws_s3_bucket", name: "drift", instances: [] });
  assert.throws(() => assertForwardStateAfterImport(before, changed), /outside/);
  const providerChanged = structuredClone(after);
  providerChanged.provider = [{ name: "changed" }];
  assert.throws(() => assertForwardStateAfterImport(before, providerChanged), /outside/);
  const allowlistChanged = structuredClone(after);
  allowlistChanged.format_version = 5;
  assert.throws(() => assertForwardStateAfterImport(before, allowlistChanged), /outside/);
});

test("importing replay finalizes an already successful import without a second import", async () => {
  for (const boundary of ["AFTER_IMPORT", "AFTER_POST_IMPORT_VERIFICATION", "AFTER_EVIDENCE_PERSISTED"]) {
    const run = common({ interruptAt: (phase) => { if (phase === boundary) throw new Error(`interrupted at ${boundary}`); } });
    await assert.rejects(() => runExistingRevisionForwardRecovery(run), /interrupted/);
    assert.equal(run.journal.read().phase, "IMPORTING");
    const replay = common({ journal: run.journal, evidence: run.evidence, readState: async () => importedState() });
    const result = await runExistingRevisionForwardRecovery(replay);
    assert.equal(result.imported, false);
    assert.deepEqual(replay.counts, { imports: 0, registrations: 0 });
    assert.equal(run.journal.read().phase, "COMPLETED");
  }
  const completed = common();
  await runExistingRevisionForwardRecovery(completed);
  const journalBytes = JSON.stringify(completed.journal.read());
  const evidenceBytes = JSON.stringify(completed.evidence.read());
  const replay = common({ journal: completed.journal, evidence: completed.evidence, readState: async () => importedState() });
  await runExistingRevisionForwardRecovery(replay);
  assert.equal(JSON.stringify(completed.journal.read()), journalBytes);
  assert.equal(JSON.stringify(completed.evidence.read()), evidenceBytes);
  assert.deepEqual(replay.counts, { imports: 0, registrations: 0 });
});

test("forged or legacy evidence cannot authorize the forward mode", async () => {
  const run = common({ journal: journalAdapter({ schemaVersion: 4, kind: "STAGE_B_CANONICAL_BACKEND_TASK_DEFINITION_RECOVERY", phase: "COMPLETED", registrationCalls: 1 }) });
  await assert.rejects(() => runExistingRevisionForwardRecovery(run), /zero-registration incident/);
  const forged = common({ imageAuthorization: { ...imageAuthorization, evidenceSha256: "f".repeat(64) } });
  await assert.rejects(() => runExistingRevisionForwardRecovery(forged));
});

test("ambiguous import journal blocks retry and cannot reach registration", async () => {
  const run = common();
  const first = await runExistingRevisionForwardRecovery(run);
  const journal = run.journal.read();
  journal.phase = "IMPORTING";
  journal.stateAfterImportSha256 = undefined;
  run.journal.write(journal);
  const retry = common({ journal: run.journal, readState: async () => emptyState() });
  await assert.rejects(() => runExistingRevisionForwardRecovery(retry), /ambiguous|missing|lineage|serial/);
  assert.equal(retry.counts.registrations, 0);
  assert.ok(first.evidence);
});

test("incident identity is bound to the exact current state and :9", () => {
  assert.equal(typeof expectedIdentity(), "string");
  assert.throws(() => canonicalForwardRecoveryIncidentIdentity({ sourceSha, toolingTreeSha256: bindings.toolingTreeSha256, sourceContractSha256: bindings.sourceContractSha256, imageReleaseSha, authorizedBackendDigest: imageAuthorization.backendDigest, imageAuthorizationSha256: imageAuthorization.evidenceSha256, stateLineage: CONTRACT.lineage, stateSerial: 93, stateBeforeSha256: canonicalSha256(emptyState()), existingRevisionArn: arn, censusSha256: "c".repeat(64), fingerprint }), /incomplete/);
});

test("forward CLI source contains only the reviewed import mutation", () => {
  const source = readFileSync(new URL("../aws/forward-recover-stage-b-existing-revision.mjs", import.meta.url), "utf8");
  for (const forbidden of ["register-task-definition", "deregister-task-definition", "update-service", '"apply"', '"state", "rm"', '"state", "push"']) assert.equal(source.includes(forbidden), false, `forward CLI must not contain ${forbidden}`);
  assert.match(source, /"import", "-lock-timeout=60s"/);
});

test("source, image, authorization, and provenance mismatches fail before import", async () => {
  for (const mutate of [
    (value) => { value.bindings = { ...bindings, sourceSha: "f".repeat(40), toolingSha: "f".repeat(40) }; },
    (value) => { value.bindings = { ...bindings, backendImage: `${backendImage.slice(0, -1)}0` }; },
    (value) => { value.imageAuthorization = { ...imageAuthorization, evidenceSha256: "f".repeat(64) }; },
    (value) => { value.deriveProvenance = () => ({ toolingTreeSha256: "f".repeat(64), sourceContractSha256: bindings.sourceContractSha256 }); },
  ]) {
    const run = common();
    mutate(run);
    await assert.rejects(() => runExistingRevisionForwardRecovery(run));
    assert.deepEqual(run.counts, { imports: 0, registrations: 0 });
  }
});

test("two-SHA authorization requires an authenticated ancestor and image-safe reuse", () => {
  const authorizationSourceSha = execFileSync("git", ["rev-parse", "HEAD~1"], { encoding: "utf8" }).trim();
  const executorSha = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  const fixture = makeCanonicalImageAuthorization({ sourceSha: authorizationSourceSha, imageReleaseSha: authorizationSourceSha });
  const currentBindings = { ...bindings, sourceSha: executorSha, toolingSha: executorSha, imageAuthorization: fixture.authorization };
  currentBindings.imageReleaseSha = authorizationSourceSha;
  currentBindings.backendImage = `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${fixture.authorization.backendDigest}`;
  const currentCheckout = { currentHead: executorSha, originMainHead: executorSha, toolingSha: executorSha, porcelainStatus: "" };
  const reuse = ({ imageReleaseSha: release, toolingSha }) => ({ ...deriveImageReuse({ imageReleaseSha: release, toolingSha }), imageReleaseSha: release, toolingSha });
  assertForwardSourceBinding({ sourceSha: executorSha, bindings: currentBindings, protectedCheckout: currentCheckout, imageAuthorization: fixture.authorization, imageAuthorizationValidation: { now: fixture.now, verifyImageEvidence: fixture.verifyImageEvidence }, deriveProvenance: () => ({ toolingTreeSha256: bindings.toolingTreeSha256, sourceContractSha256: bindings.sourceContractSha256 }), deriveImageReuse: reuse, proveDescendant: () => true });
  assert.throws(() => assertForwardSourceBinding({ sourceSha: executorSha, bindings: currentBindings, protectedCheckout: currentCheckout, imageAuthorization: fixture.authorization, imageAuthorizationValidation: { now: fixture.now, verifyImageEvidence: fixture.verifyImageEvidence }, deriveProvenance, deriveImageReuse: reuse, proveDescendant: () => false }), /ancestor/);
  assert.throws(() => assertForwardSourceBinding({ sourceSha: executorSha, bindings: { ...currentBindings, imageReleaseSha: "8".repeat(40) }, protectedCheckout: currentCheckout, imageAuthorization: fixture.authorization, imageAuthorizationValidation: { now: fixture.now, verifyImageEvidence: fixture.verifyImageEvidence }, deriveProvenance, deriveImageReuse: reuse, proveDescendant: () => true }), /image authorization/);
  assert.throws(() => assertForwardSourceBinding({ sourceSha: executorSha, bindings: currentBindings, protectedCheckout: currentCheckout, imageAuthorization: fixture.authorization, imageAuthorizationValidation: { now: fixture.now, verifyImageEvidence: fixture.verifyImageEvidence }, deriveProvenance, deriveImageReuse: () => ({ ...reuse({ imageReleaseSha: authorizationSourceSha, toolingSha: executorSha }), imageAffectingFiles: ["backend/src/app.ts"], imageReuseCompatible: false, imageBuildInputsChanged: true }), proveDescendant: () => true }), /reuse/);
});

function backendMetadata(overrides = {}) {
  return { backend: { type: "s3", hash: 1, config: { ...STAGE_B_TERRAFORM_BACKEND_CONFIG, ...overrides } } };
}

function privateBackendDirectory(overrides) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-forward-backend-"));
  fs.chmodSync(directory, 0o700);
  fs.writeFileSync(path.join(directory, "terraform.tfstate"), JSON.stringify(backendMetadata(overrides)), { mode: 0o600 });
  return directory;
}

test("forward CLI backend gate rejects stale TF_DATA_DIR, copied backend, wrong key, and workspace", () => {
  const dataDir = privateBackendDirectory();
  const otherDir = privateBackendDirectory();
  assert.throws(() => buildForwardRecoveryTerraformEnvironment(dataDir, { TF_DATA_DIR: otherDir, TF_WORKSPACE: "default" }), /stale/);
  assert.doesNotThrow(() => assertForwardRecoveryTerraformBackend({ env: buildForwardRecoveryTerraformEnvironment(dataDir, {}), repositoryRoot: process.cwd(), runTerraform: () => "default\n" }));
  for (const overrides of [{ bucket: "local-copy" }, { key: "wrong.tfstate" }]) {
    const wrong = privateBackendDirectory(overrides);
    assert.throws(() => assertForwardRecoveryTerraformBackend({ env: buildForwardRecoveryTerraformEnvironment(wrong, {}), repositoryRoot: process.cwd(), runTerraform: () => "default\n" }), /outside/);
  }
  assert.throws(() => buildForwardRecoveryTerraformEnvironment(dataDir, { TF_WORKSPACE: "staging" }), /workspace/);
  assert.throws(() => assertForwardRecoveryTerraformBackend({ env: buildForwardRecoveryTerraformEnvironment(dataDir, {}), repositoryRoot: process.cwd(), runTerraform: () => "staging\n" }), /workspace/);
});

test("forward recovery revalidates the remote state immediately before import", async () => {
  let reads = 0;
  const run = common({ readState: async () => { reads += 1; return reads === 1 ? emptyState() : { ...emptyState(), resources: [...emptyState().resources, { mode: "managed", type: "aws_s3_bucket", name: "drift", instances: [] }] }; } });
  await assert.rejects(() => runExistingRevisionForwardRecovery(run), /changed before/);
  assert.equal(run.counts.imports, 0);
});

test("importing forward recovery resumes through a protected descendant executor without a second import", async () => {
  const first = common();
  await runExistingRevisionForwardRecovery(first);
  const oldJournal = first.journal.read();
  const importingJournal = { ...oldJournal, phase: "IMPORTING", stateAfterImportSha256: undefined, evidenceSha256: undefined, importMayHaveOccurred: true };
  delete importingJournal.stateAfterImportSha256;
  delete importingJournal.evidenceSha256;
  const executorSha = "e".repeat(40);
  const executorTree = "f".repeat(64);
  const replay = common({
    sourceSha: executorSha,
    protectedCheckout: { currentHead: executorSha, originMainHead: executorSha, toolingSha: executorSha, porcelainStatus: "" },
    journal: journalAdapter(importingJournal),
    evidence: first.evidence,
    readState: async () => importedState(),
    deriveProvenance: ({ sourceSha: value }) => value === sourceSha ? deriveProvenance() : { toolingTreeSha256: executorTree, sourceContractSha256: bindings.sourceContractSha256 },
    deriveImageReuse: ({ imageReleaseSha: release, toolingSha }) => ({ ...deriveImageReuse({ imageReleaseSha: release, toolingSha }), toolingSha, imageReleaseSha: release, toolingInputTreeSha256: executorTree, comparisonHeadSha256: executorTree }),
    proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === sourceSha && descendantSha === executorSha,
  });
  const result = await runExistingRevisionForwardRecovery(replay);
  assert.equal(result.imported, false);
  assert.deepEqual(replay.counts, { imports: 0, registrations: 0 });
  assert.equal(replay.journal.read().sourceSha, sourceSha);
  assert.equal(replay.journal.read().phase, "COMPLETED");
});

test("forward CLI preflights all artifact paths before any import boundary", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-forward-artifacts-"));
  fs.chmodSync(directory, 0o700);
  const paths = { evidencePath: path.join(directory, "evidence.json"), journalPath: path.join(directory, "journal.json"), bindingsPath: path.join(directory, "bindings.json"), imageAuthorizationPath: path.join(directory, "authorization.json") };
  for (const filePath of [paths.bindingsPath, paths.imageAuthorizationPath]) fs.writeFileSync(filePath, "{}", { mode: 0o600 });
  assert.doesNotThrow(() => preflightForwardRecoveryOutputs(paths));
  assert.throws(() => preflightForwardRecoveryOutputs({ ...paths, evidencePath: paths.bindingsPath }), /distinct/);
  fs.writeFileSync(paths.evidencePath, "{}", { mode: 0o600 });
  fs.writeFileSync(paths.journalPath, JSON.stringify({ phase: "PREPARED" }), { mode: 0o600 });
  assert.throws(() => preflightForwardRecoveryOutputs(paths), /completed deterministic/);
  fs.writeFileSync(paths.journalPath, JSON.stringify({ phase: "IMPORTING" }), { mode: 0o600 });
  assert.doesNotThrow(() => preflightForwardRecoveryOutputs(paths));
  fs.chmodSync(directory, 0o755);
  assert.throws(() => preflightForwardRecoveryOutputs(paths), /private/);
});

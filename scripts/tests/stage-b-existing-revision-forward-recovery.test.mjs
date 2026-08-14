import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { makeCanonicalImageAuthorization } from "./fixtures/canonical-image-authorization.mjs";
import {
  STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY as CONTRACT,
  assertForwardCensus,
  assertForwardRevisionReadback,
  assertForwardStateAfterImport,
  assertForwardStateBeforeImport,
  canonicalForwardRecoveryIncidentIdentity,
  runExistingRevisionForwardRecovery,
} from "../aws/stage-b-existing-revision-forward-recovery-contract.mjs";
import { buildCanonicalBackendRecoveryTaskDefinition, canonicalSha256, taskDefinitionFingerprint } from "../aws/stage-b-task-definition-recovery-contract.mjs";

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
  stateLineage: CONTRACT.lineage, stateSerial: CONTRACT.startSerial, stateBeforeSha256: canonicalSha256(emptyState()), existingRevisionArn: arn,
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
  return {
    bindings, sourceSha, protectedCheckout, imageAuthorization,
    imageAuthorizationValidation: { now: imageFixture.now, verifyImageEvidence: imageFixture.verifyImageEvidence },
    deriveProvenance, deriveImageReuse, journal,
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
  await runExistingRevisionForwardRecovery(run);
  const journalBytes = JSON.stringify(run.journal.read());
  const replay = common({ journal: run.journal, readState: async () => importedState() });
  const result = await runExistingRevisionForwardRecovery(replay);
  assert.equal(result.imported, false);
  assert.deepEqual(replay.counts, { imports: 0, registrations: 0 });
  assert.equal(JSON.stringify(run.journal.read()), journalBytes);
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
  await assert.rejects(() => runExistingRevisionForwardRecovery(retry), /ambiguous|missing/);
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

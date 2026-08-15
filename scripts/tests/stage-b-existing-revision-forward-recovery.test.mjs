import assert from "node:assert/strict";
import fs, { readFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import test from "node:test";
import { makeCanonicalImageAuthorization } from "./fixtures/canonical-image-authorization.mjs";
import {
  STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY as CONTRACT,
  STAGE_B_AMBIGUOUS_IMPORT_SUPERSESSION,
  assertForwardCensus,
  assertAmbiguousImportSupersessionAuthority,
  assertForwardImportRetryState,
  assertForwardRevisionReadback,
  assertForwardSourceBinding,
  assertForwardStateAfterImport,
  assertForwardStateBeforeImport,
  canonicalForwardRecoveryIncidentIdentity,
  journalSha256,
  runAmbiguousImportSupersession,
  runExistingRevisionForwardRecovery,
} from "../aws/stage-b-existing-revision-forward-recovery-contract.mjs";
import { assertForwardRecoveryTerraformBackend, assertForwardRecoveryTfvarsBinding, buildForwardRecoveryTerraformEnvironment, buildForwardRecoveryTerraformImportArgs, classifyForwardRecoveryResult, preflightForwardRecoveryOutputs, runForwardRecoveryCli } from "../aws/forward-recover-stage-b-existing-revision.mjs";
import { STAGE_B_TERRAFORM_BACKEND_CONFIG } from "../aws/stage-b-terraform-backend-contract.mjs";
import { buildCanonicalBackendRecoveryTaskDefinition, canonicalSha256, stateSnapshotSha256, taskDefinitionFingerprint } from "../aws/stage-b-task-definition-recovery-contract.mjs";

const sourceSha = "45c5a38c7e3594793fafe1f051f1f381937ba0d4";
const imageReleaseSha = "25394d30c189583384c9bba62604bf968dc9e0b2";
const imageFixture = makeCanonicalImageAuthorization({ sourceSha, imageReleaseSha });
const imageAuthorization = imageFixture.authorization;
const authorizationSourceSha = imageReleaseSha;
const twoShaImageFixture = makeCanonicalImageAuthorization({ sourceSha: authorizationSourceSha, imageReleaseSha });
const twoShaImageAuthorization = twoShaImageFixture.authorization;
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
  imageReleaseSha, authorizedBackendDigest: imageAuthorization.backendDigest, imageAuthorizationSha256: imageAuthorization.evidenceSha256, imageAuthorizationSourceSha: imageAuthorization.sourceSha,
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

function ambiguousOldJournal() {
  const oldSourceSha = "6".repeat(40);
  const censusSha256 = canonicalSha256([{ arn, revision: 9, readback }]);
  const fields = {
    sourceSha: oldSourceSha, toolingTreeSha256: bindings.toolingTreeSha256, sourceContractSha256: bindings.sourceContractSha256,
    imageReleaseSha, authorizedBackendDigest: imageAuthorization.backendDigest, imageAuthorizationSha256: imageAuthorization.evidenceSha256,
    imageAuthorizationSourceSha: imageAuthorization.sourceSha, stateLineage: CONTRACT.lineage, stateSerial: CONTRACT.startSerial,
    stateBeforeSha256: stateSnapshotSha256(emptyState()), existingRevisionArn: arn, censusSha256, fingerprint,
  };
  return {
    schemaVersion: CONTRACT.schemaVersion, kind: CONTRACT.kind, mode: CONTRACT.mode, phase: "IMPORTING",
    ...fields, incidentIdentity: canonicalForwardRecoveryIncidentIdentity(fields), registrationCalls: 0, registrationCapability: "NONE",
    importCalls: 1, importMayHaveOccurred: true,
  };
}

function ambiguousCommon(overrides = {}) {
  const run = common(overrides);
  run.oldJournal = ambiguousOldJournal();
  run.oldJournalBytes = Buffer.from(JSON.stringify(run.oldJournal));
  run.oldJournalSha256 = journalSha256(run.oldJournalBytes);
  return run;
}

test("ambiguous import supersession authorizes the exact current state and one zero-registration import", async () => {
  const run = ambiguousCommon({ proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === "6".repeat(40) && descendantSha === sourceSha });
  const result = await runAmbiguousImportSupersession(run);
  assert.equal(result.imported, true);
  assert.deepEqual(run.counts, { imports: 1, registrations: 0 });
  assert.equal(run.journal.read().mode, STAGE_B_AMBIGUOUS_IMPORT_SUPERSESSION.mode);
  assert.equal(run.journal.read().supersedesIncidentIdentity, run.oldJournal.incidentIdentity);
  assert.equal(run.journal.read().supersessionReason, STAGE_B_AMBIGUOUS_IMPORT_SUPERSESSION.supersessionReason);
});

test("legacy ambiguous IMPORTING journal is immutable and cannot complete or retry", async () => {
  const old = ambiguousOldJournal();
  const run = common({ journal: journalAdapter(old), readState: async () => importedState() });
  const before = JSON.stringify(run.journal.read());
  await assert.rejects(() => runExistingRevisionForwardRecovery(run), /permanently non-resumable|supersession/);
  assert.equal(JSON.stringify(run.journal.read()), before);
  assert.deepEqual(run.counts, { imports: 0, registrations: 0 });
});

test("ambiguous import supersession replay is terminal and cannot import again", async () => {
  const first = ambiguousCommon({ proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === "6".repeat(40) && descendantSha === sourceSha });
  await runAmbiguousImportSupersession(first);
  const replay = ambiguousCommon({ journal: first.journal, evidence: first.evidence, readState: async () => importedState(), proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === "6".repeat(40) && descendantSha === sourceSha });
  const result = await runAmbiguousImportSupersession(replay);
  assert.equal(result.imported, false);
  assert.deepEqual(replay.counts, { imports: 0, registrations: 0 });
});

test("ambiguous supersession crash after import finalizes the existing :9 without a second import", async () => {
  const first = ambiguousCommon({ proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === "6".repeat(40) && descendantSha === sourceSha, interruptAt: (phase) => { if (phase === "AFTER_IMPORT") throw new Error("interrupted"); } });
  await assert.rejects(() => runAmbiguousImportSupersession(first), /interrupted/);
  assert.equal(first.journal.read().phase, "IMPORTING");
  const replay = ambiguousCommon({ journal: first.journal, evidence: first.evidence, readState: async () => importedState(), proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === "6".repeat(40) && descendantSha === sourceSha });
  const result = await runAmbiguousImportSupersession(replay);
  assert.equal(result.imported, false);
  assert.deepEqual(replay.counts, { imports: 0, registrations: 0 });
  assert.equal(replay.journal.read().phase, "COMPLETED");
});

test("ambiguous supersession rejects altered historical journal, current drift, and newer revisions", () => {
  const old = ambiguousOldJournal();
  const oldBytes = Buffer.from(JSON.stringify(old));
  const base = { state: emptyState(), census, readback, fingerprint, sourceSha, bindings, protectedCheckout, imageAuthorization, imageAuthorizationValidation: imageFixture, deriveProvenance, deriveImageReuse, oldJournalBytes: oldBytes, proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === "6".repeat(40) && descendantSha === sourceSha };
  assert.throws(() => assertAmbiguousImportSupersessionAuthority({ ...base, oldJournal: { ...old, incidentIdentity: "f".repeat(64) }, oldJournalSha256: journalSha256(oldBytes) }), /identity/);
  assert.throws(() => assertAmbiguousImportSupersessionAuthority({ ...base, oldJournal: old, oldJournalSha256: journalSha256(oldBytes), state: emptyState(95) }), /serial|lineage/);
  assert.throws(() => assertAmbiguousImportSupersessionAuthority({ ...base, oldJournal: old, oldJournalSha256: journalSha256(oldBytes), census: { complete: true, revisions: [{ arn: `${arn.slice(0, -1)}10`, readback: { ...readback, taskDefinition: { ...readback.taskDefinition, taskDefinitionArn: `${arn.slice(0, -1)}10`, revision: 10 } } }, ...census.revisions] } }), /newest|canonical/);
});

test("ambiguous supersession rejects changed :9 and never exposes mutation capabilities", async () => {
  const run = ambiguousCommon({
    proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === "6".repeat(40) && descendantSha === sourceSha,
    describe: async () => ({ ...readback, taskDefinition: { ...readback.taskDefinition, revision: 10 } }),
  });
  await assert.rejects(() => runAmbiguousImportSupersession(run), /fingerprint|canonical/);
  assert.deepEqual(run.counts, { imports: 0, registrations: 0 });
  assert.equal(typeof run.register, "function");
  assert.equal(STAGE_B_AMBIGUOUS_IMPORT_SUPERSESSION.existingRevisionArn.endsWith(":9"), true);
});

test("adopts exact :9 with one import and zero registration capability", async () => {
  const run = common();
  const result = await runExistingRevisionForwardRecovery(run);
  assert.equal(result.imported, true);
  assert.deepEqual(run.counts, { imports: 1, registrations: 0 });
  assert.equal(result.state.serial, 95);
  assert.equal(classifyForwardRecoveryResult(result).status, "imported");
});

test("completed forward incident replays idempotently without import or registration", async () => {
  const run = common();
  const first = await runExistingRevisionForwardRecovery(run);
  const journalBytes = JSON.stringify(run.journal.read());
  const replay = common({ journal: run.journal, evidence: run.evidence, readState: async () => importedState() });
  const result = await runExistingRevisionForwardRecovery(replay);
  assert.equal(result.imported, false);
  assert.deepEqual(replay.counts, { imports: 0, registrations: 0 });
  assert.equal(classifyForwardRecoveryResult(result).status, "already-reconciled");
  assert.equal(JSON.stringify(run.journal.read()), journalBytes);
});

test("completed descendant replay is terminal without current-HEAD image freshness", async () => {
  const first = common();
  await runExistingRevisionForwardRecovery(first);
  const journalBytes = JSON.stringify(first.journal.read());
  const executorSha = "e".repeat(40);
  const replay = common({
    sourceSha: executorSha,
    protectedCheckout: { currentHead: executorSha, originMainHead: executorSha, toolingSha: executorSha, porcelainStatus: "" },
    journal: first.journal,
    evidence: first.evidence,
    readState: async () => importedState(),
    imageAuthorizationValidation: { verifyImageEvidence: () => { throw new Error("completed replay must not revalidate expiring image evidence"); } },
    deriveProvenance: () => { throw new Error("completed replay must not derive current executor provenance"); },
    deriveImageReuse: () => { throw new Error("completed replay must not re-prove image reuse"); },
    proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === sourceSha && descendantSha === executorSha,
  });
  const result = await runExistingRevisionForwardRecovery(replay);
  assert.equal(result.imported, false);
  assert.deepEqual(replay.counts, { imports: 0, registrations: 0 });
  assert.equal(JSON.stringify(first.journal.read()), journalBytes);
});

test("tfvars authorization is required only when an import can be reached", async () => {
  let gates = 0;
  const fresh = common({ validateImportBindings: () => { gates += 1; } });
  await runExistingRevisionForwardRecovery(fresh);
  assert.equal(gates, 2);

  const completedReplay = common({
    journal: fresh.journal,
    evidence: fresh.evidence,
    readState: async () => importedState(),
    validateImportBindings: () => { throw new Error("terminal replay must not require tfvars"); },
  });
  await runExistingRevisionForwardRecovery(completedReplay);
  assert.deepEqual(completedReplay.counts, { imports: 0, registrations: 0 });

  const importing = await importingRun();
  const consumedReplay = common({
    journal: importing.journal,
    evidence: importing.evidence,
    readState: async () => importedState(),
    validateImportBindings: () => { throw new Error("consumed replay must not require tfvars"); },
  });
  await runExistingRevisionForwardRecovery(consumedReplay);
  assert.deepEqual(consumedReplay.counts, { imports: 0, registrations: 0 });
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

test("Terraform 1.15.8 import effects accept only authenticated outputs, checks, and lifecycle metadata", () => {
  const expectedBoundImages = {
    backend: "368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:" + "1".repeat(64),
    worker: "368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-worker@sha256:" + "2".repeat(64),
    executor: "368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:" + "3".repeat(64),
    canary: "368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:" + "4".repeat(64),
    read_only_canary: "368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:" + "4".repeat(64),
  };
  const makeState = (imported = false) => {
    const value = emptyState(imported ? 95 : 94);
    value.check_results = [{ object_kind: "check", config_addr: "check.release_bindings", status: "pass", objects: [{ object_addr: "check.release_bindings", status: "pass" }] }];
    value.outputs = {
      bound_images: { value: imported ? expectedBoundImages : Object.fromEntries(Object.entries(expectedBoundImages).map(([key]) => [key, `old-${key}`])) },
      task_definition_arns: { value: { backend: imported ? arn : `${arn.slice(0, -1)}5`, worker: "worker-arn" } },
      stable: { value: "unchanged" },
    };
    value.resources.push({ mode: "managed", type: "aws_cloudwatch_log_group", name: "stage_b", instances: ["backend", "canary", "read_only_canary", "worker"].map((index_key) => ({ index_key, attributes: { name: `/ecs/${index_key}` }, ...(imported ? { create_before_destroy: true } : {}) })) });
    if (imported) value.resources[0].instances = [{ index_key: "backend", schema_version: 1, attributes: { id: arn, arn, family: CONTRACT.family } }];
    return value;
  };
  const before = makeState();
  const after = makeState(true);
  after.check_results = null;
  assert.doesNotThrow(() => assertForwardStateAfterImport(before, after, { expectedBoundImages }));

  const wrongImage = structuredClone(after);
  wrongImage.outputs.bound_images.value.backend = "368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:" + "f".repeat(64);
  assert.throws(() => assertForwardStateAfterImport(before, wrongImage, { expectedBoundImages }), /bound_images/);
  const failedCheck = structuredClone(after);
  failedCheck.check_results = [{ status: "fail" }];
  assert.throws(() => assertForwardStateAfterImport(before, failedCheck, { expectedBoundImages }), /reviewed import effects|check-results/);
  const unrelatedOutput = structuredClone(after);
  unrelatedOutput.outputs.stable.value = "changed";
  assert.throws(() => assertForwardStateAfterImport(before, unrelatedOutput, { expectedBoundImages }), /reviewed import effects/);
  const unrelatedResource = structuredClone(after);
  unrelatedResource.resources.find(({ type }) => type === "aws_cloudwatch_log_group").instances[0].attributes.name = "/ecs/changed";
  assert.throws(() => assertForwardStateAfterImport(before, unrelatedResource, { expectedBoundImages }), /reviewed import effects/);
  const unrelatedLifecycle = structuredClone(after);
  unrelatedLifecycle.resources.push({ mode: "managed", type: "aws_s3_bucket", name: "drift", instances: [{ create_before_destroy: true }] });
  assert.throws(() => assertForwardStateAfterImport(before, unrelatedLifecycle, { expectedBoundImages }), /reviewed import effects/);
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

test("forward import command binds the canonical tfvars and lock timeout", () => {
  assert.deepEqual(buildForwardRecoveryTerraformImportArgs({ tfvarsPath: "/private/tmp/stage-b/production.tfvars", address: CONTRACT.address, arn }), [
    `-chdir=${path.resolve("infra/aws/terraform/production-green-stage-b")}`, "import", "-lock-timeout=60s", "-var-file=/private/tmp/stage-b/production.tfvars", CONTRACT.address, arn,
  ]);
  assert.throws(() => buildForwardRecoveryTerraformImportArgs({ tfvarsPath: "production.tfvars", address: CONTRACT.address, arn }), /absolute/);
  assert.throws(() => buildForwardRecoveryTerraformImportArgs({ tfvarsPath: "/private/tmp/stage-b/production.tfvars", address: CONTRACT.address, arn: `${arn.slice(0, -1)}8` }), /unreviewed/);
});

test("forward tfvars preflight binds the canonical release report and authorized backend", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-forward-tfvars-"));
  const tfvarsPath = path.join(directory, "production.tfvars");
  const bindingReportPath = path.join(directory, "binding.json");
  const releasePreflightPath = path.join(directory, "release-preflight.json");
  for (const filePath of [tfvarsPath, bindingReportPath, releasePreflightPath]) fs.writeFileSync(filePath, "{}\n", { mode: 0o600 });
  const backendDigest = imageAuthorization.backendDigest;
  const bindingsForPreflight = { ...bindings, sourceContractSha256: bindings.sourceContractSha256 };
  const report = { tfvarsSha256: "a".repeat(64), imageEvidenceCanonicalSha256: imageAuthorization.imageEvidenceSha256, sourceContractSha256: bindingsForPreflight.sourceContractSha256, images: { backend: { imageReference: bindingsForPreflight.backendImage, digest: backendDigest } } };
  fs.writeFileSync(releasePreflightPath, `${JSON.stringify({ status: "ready-for-plan", tfvarsSha256: report.tfvarsSha256 })}\n`, { mode: 0o600 });
  const calls = [];
  assertForwardRecoveryTfvarsBinding({
    tfvarsPath, bindingReportPath, bindingReportSha256: "b".repeat(64), releasePreflightPath, sourceSha,
    bindings: bindingsForPreflight, imageAuthorization,
    validateTfvarsBinding: (value) => { calls.push(value); return report; },
  });
  assert.equal(calls[0].expectedToolingSha, sourceSha);
  assert.equal(calls[0].expectedToolingTreeSha256, bindings.toolingTreeSha256);
  assert.equal(calls[0].expectedImageReleaseSha, imageReleaseSha);
  assert.equal(calls[0].expectedImageEvidenceSha256, imageAuthorization.imageEvidenceSha256);
  assert.notEqual(imageAuthorization.imageEvidenceSha256, imageAuthorization.imageEvidence.canonicalArtifactSha256);
  assert.throws(() => assertForwardRecoveryTfvarsBinding({
    tfvarsPath, bindingReportPath, bindingReportSha256: "b".repeat(64), releasePreflightPath, sourceSha,
    bindings: bindingsForPreflight, imageAuthorization: { ...imageAuthorization, imageEvidenceSha256: "f".repeat(64) },
    validateTfvarsBinding: () => report,
  }), /source, or authorized backend image/);
  assert.throws(() => assertForwardRecoveryTfvarsBinding({
    tfvarsPath, bindingReportPath, bindingReportSha256: "b".repeat(64), releasePreflightPath, sourceSha,
    bindings: bindingsForPreflight, imageAuthorization: { ...imageAuthorization, imageEvidenceSha256: undefined },
    validateTfvarsBinding: () => report,
  }), /canonical image-evidence binding/);
  assert.throws(() => assertForwardRecoveryTfvarsBinding({
    tfvarsPath, bindingReportPath, bindingReportSha256: "b".repeat(64), releasePreflightPath, sourceSha,
    bindings: bindingsForPreflight, imageAuthorization,
    validateTfvarsBinding: () => ({ ...report, imageEvidenceCanonicalSha256: imageAuthorization.imageEvidence.canonicalArtifactSha256 }),
  }), /source, or authorized backend image/);
  assert.throws(() => assertForwardRecoveryTfvarsBinding({
    tfvarsPath, bindingReportPath, bindingReportSha256: "b".repeat(64), releasePreflightPath, sourceSha,
    bindings: bindingsForPreflight, imageAuthorization,
    validateTfvarsBinding: () => ({ ...report, tfvarsSha256: "c".repeat(64) }),
  }), /preflight/);
  assert.throws(() => assertForwardRecoveryTfvarsBinding({
    tfvarsPath, bindingReportPath, bindingReportSha256: "b".repeat(64), releasePreflightPath, sourceSha,
    bindings: bindingsForPreflight, imageAuthorization,
    validateTfvarsBinding: () => ({ ...report, images: { backend: { imageReference: bindingsForPreflight.backendImage, digest: "sha256:" + "f".repeat(64) } } }),
  }), /authorized backend/);
});

test("mutation-boundary tfvars revalidation blocks a changed binding before import", async () => {
  let validations = 0;
  const run = common({
    validateImportBindings: () => {
      validations += 1;
      if (validations === 2) throw new Error("tfvars modified after initial validation");
    },
  });
  await assert.rejects(() => runExistingRevisionForwardRecovery(run), /tfvars modified/);
  assert.equal(validations, 2);
  assert.deepEqual(run.counts, { imports: 0, registrations: 0 });
  assert.equal(run.journal.read().phase, "PREPARED");
});

test("IMPORTING replay permits exactly one bounded retry only from the authenticated pre-import state", async () => {
  let state = emptyState();
  let attempts = 0;
  let gates = 0;
  const run = common({
    validateImportBindings: () => { gates += 1; },
    readState: async () => structuredClone(state),
    importState: async () => {
      attempts += 1;
      if (attempts === 1) throw new Error("Terraform failed before remote state mutation");
      state = importedState();
    },
  });
  await assert.rejects(() => runExistingRevisionForwardRecovery(run), /before remote state mutation/);
  assert.equal(run.journal.read().phase, "IMPORTING");
  assert.equal(run.journal.read().importCalls, 1);
  run.validateImportBindings = () => { gates += 1; };
  const result = await runExistingRevisionForwardRecovery(run);
  assert.equal(result.imported, true);
  assert.equal(attempts, 2);
  assert.equal(run.journal.read().importAttemptCount, 2);
  assert.equal(gates, 4);
});

test("IMPORTING replay rejects an absent candidate when the authoritative state drift is ambiguous", async () => {
  let state = emptyState();
  let attempts = 0;
  const run = common({
    readState: async () => structuredClone(state),
    importState: async () => { attempts += 1; throw new Error("Terraform failed before remote state mutation"); },
  });
  await assert.rejects(() => runExistingRevisionForwardRecovery(run), /before remote state mutation/);
  state.resources.push({ mode: "managed", type: "aws_s3_bucket", name: "drift", instances: [] });
  await assert.rejects(() => runExistingRevisionForwardRecovery(run), /ambiguous/);
  assert.equal(attempts, 1);
  assert.equal(run.journal.read().importCalls, 1);
});

test("IMPORTING retry guard authenticates the exact pre-import checkpoint", async () => {
  const journal = { phase: "IMPORTING", importCalls: 1, importMayHaveOccurred: true, importAttemptOutcome: "FAILED_BEFORE_STATE_MUTATION", importFailureStateSha256: stateSnapshotSha256(emptyState()), stateBeforeSha256: stateSnapshotSha256(emptyState()) };
  assert.deepEqual(assertForwardImportRetryState({ journalState: journal, state: emptyState() }), { stateSha256: journal.stateBeforeSha256, retryAuthorized: true });
  assert.throws(() => assertForwardImportRetryState({ journalState: journal, state: emptyState(95) }), /lineage|serial/);
  assert.throws(() => assertForwardImportRetryState({ journalState: journal, state: { ...emptyState(), resources: [...emptyState().resources, { mode: "managed", type: "aws_s3_bucket", name: "drift", instances: [] }] } }), /ambiguous/);
});

async function importingRun() {
  const run = common({ interruptAt: (phase) => { if (phase === "AFTER_IMPORT") throw new Error("interrupted after import"); } });
  await assert.rejects(() => runExistingRevisionForwardRecovery(run), /interrupted/);
  assert.equal(run.journal.read().phase, "IMPORTING");
  return run;
}

async function twoShaImportingRun() {
  const run = common({
    imageAuthorization: twoShaImageAuthorization,
    bindings: { ...bindings, imageAuthorization: twoShaImageAuthorization },
    imageAuthorizationValidation: { now: twoShaImageFixture.now, verifyImageEvidence: twoShaImageFixture.verifyImageEvidence },
    proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === authorizationSourceSha && descendantSha === sourceSha,
    interruptAt: (phase) => { if (phase === "AFTER_IMPORT") throw new Error("interrupted after import"); },
  });
  await assert.rejects(() => runExistingRevisionForwardRecovery(run), /interrupted/);
  assert.equal(run.journal.read().phase, "IMPORTING");
  return run;
}

async function preparedRun(overrides = {}) {
  const run = common(overrides);
  const write = run.journal.write;
  run.journal.write = (value) => { write(value); if (value.phase === "PREPARED") throw new Error("interrupted after PREPARED"); };
  await assert.rejects(() => runExistingRevisionForwardRecovery(run), /interrupted/);
  assert.equal(run.journal.read().phase, "PREPARED");
  run.journal.write = write;
  return run;
}

test("same-source PREPARED resume remains fresh and imports exactly once", async () => {
  const first = await preparedRun();
  const replay = common({ journal: first.journal, evidence: first.evidence });
  const result = await runExistingRevisionForwardRecovery(replay);
  assert.equal(result.imported, true);
  assert.deepEqual(replay.counts, { imports: 1, registrations: 0 });
});

test("PREPARED import path requires the canonical tfvars gate", async () => {
  let gates = 0;
  const first = await preparedRun({ validateImportBindings: () => { gates += 1; } });
  assert.equal(gates, 1);
  const replay = common({ journal: first.journal, evidence: first.evidence, validateImportBindings: () => { gates += 1; } });
  await runExistingRevisionForwardRecovery(replay);
  assert.equal(gates, 3);
  assert.deepEqual(replay.counts, { imports: 1, registrations: 0 });
});

test("descendant PREPARED resume reauthorizes without mutation", async () => {
  const first = await preparedRun();
  const executorSha = "e".repeat(40);
  const executorTree = "f".repeat(64);
  const replay = common({
    sourceSha: executorSha,
    bindings: { ...bindings, sourceSha: executorSha, toolingSha: executorSha, toolingTreeSha256: executorTree },
    protectedCheckout: { currentHead: executorSha, originMainHead: executorSha, toolingSha: executorSha, porcelainStatus: "" },
    journal: first.journal,
    deriveProvenance: () => ({ toolingTreeSha256: executorTree, sourceContractSha256: bindings.sourceContractSha256 }),
    deriveImageReuse: ({ imageReleaseSha: release, toolingSha }) => ({ ...deriveImageReuse({ imageReleaseSha: release, toolingSha }), toolingSha, imageReleaseSha: release, toolingInputTreeSha256: executorTree, comparisonHeadSha256: executorTree }),
    proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === sourceSha && descendantSha === executorSha,
  });
  const result = await runExistingRevisionForwardRecovery(replay);
  assert.equal(result.reauthorized, true);
  assert.deepEqual(replay.counts, { imports: 0, registrations: 0 });
  const cliResult = classifyForwardRecoveryResult(result);
  assert.equal(cliResult.status, "reauthorized-pending");
  assert.notEqual(cliResult.status, "already-reconciled");
  assert.equal(cliResult.phase, "PREPARED");
  assert.equal(replay.journal.read().sourceSha, executorSha);
  assert.equal(replay.journal.read().phase, "PREPARED");
});

test("PREPARED resume rejects unrelated, dirty, drifted, stale, and mismatched inputs", async () => {
  const unrelated = await preparedRun();
  const unrelatedSha = "d".repeat(40);
  await assert.rejects(() => runExistingRevisionForwardRecovery(common({ journal: unrelated.journal, sourceSha: unrelatedSha, protectedCheckout: { currentHead: unrelatedSha, originMainHead: unrelatedSha, toolingSha: unrelatedSha, porcelainStatus: "" }, proveDescendant: () => false })), /ancestor/);
  const dirty = await preparedRun();
  await assert.rejects(() => runExistingRevisionForwardRecovery(common({ journal: dirty.journal, protectedCheckout: { ...protectedCheckout, porcelainStatus: " M" } })), /clean/);
  const stateDrift = await preparedRun();
  const driftReplay = common({ journal: stateDrift.journal, readState: async () => emptyState(95) });
  await assert.rejects(() => runExistingRevisionForwardRecovery(driftReplay), /prepared|serial|state/);
  const fingerprintDrift = await preparedRun();
  const badReadback = structuredClone(readback);
  badReadback.taskDefinition.containerDefinitions[0].image = `${backendImage.slice(0, -1)}0`;
  const fingerprintReplay = common({ journal: fingerprintDrift.journal, describe: async () => badReadback });
  await assert.rejects(() => runExistingRevisionForwardRecovery(fingerprintReplay), /fingerprint|image/);
  const stale = await preparedRun();
  const staleReplay = common({ journal: stale.journal, imageAuthorizationValidation: { now: new Date(Date.parse(imageFixture.now) + 2 * 24 * 60 * 60 * 1000).toISOString(), verifyImageEvidence: () => { throw new Error("expired authorization"); } } });
  await assert.rejects(() => runExistingRevisionForwardRecovery(staleReplay), /expired|authorization/);
});

test("same-source importing replay does not require fresh image authorization", async () => {
  const first = await importingRun();
  const replay = common({
    bindings: { ...bindings, imageAuthorization: undefined },
    journal: first.journal,
    evidence: first.evidence,
    readState: async () => importedState(),
    imageAuthorizationValidation: { now: new Date(Date.parse(imageFixture.now) + 2 * 24 * 60 * 60 * 1000).toISOString(), verifyImageEvidence: () => { throw new Error("expired authorization must not be revalidated"); } },
  });
  const result = await runExistingRevisionForwardRecovery(replay);
  assert.equal(result.imported, false);
  assert.deepEqual(replay.counts, { imports: 0, registrations: 0 });
});

test("two-SHA importing replay preserves the original ancestor authorization source", async () => {
  const first = await twoShaImportingRun();
  assert.equal(first.journal.read().imageAuthorizationSourceSha, authorizationSourceSha);
  const executorSha = "e".repeat(40);
  const replay = common({
    sourceSha: executorSha,
    protectedCheckout: { currentHead: executorSha, originMainHead: executorSha, toolingSha: executorSha, porcelainStatus: "" },
    bindings: { ...bindings, imageAuthorization: twoShaImageAuthorization },
    imageAuthorization: twoShaImageAuthorization,
    imageAuthorizationValidation: { now: new Date(Date.parse(twoShaImageFixture.now) + 2 * 24 * 60 * 60 * 1000).toISOString(), verifyImageEvidence: () => { throw new Error("expired authorization must not be revalidated"); } },
    journal: first.journal,
    evidence: first.evidence,
    readState: async () => importedState(),
    proveDescendant: ({ ancestorSha: ancestor, descendantSha }) => (ancestor === authorizationSourceSha && descendantSha === sourceSha) || (ancestor === sourceSha && descendantSha === executorSha),
  });
  const result = await runExistingRevisionForwardRecovery(replay);
  assert.equal(result.imported, false);
  assert.deepEqual(replay.counts, { imports: 0, registrations: 0 });
  assert.equal(replay.journal.read().phase, "COMPLETED");
});

test("two-SHA importing replay rejects changed authorization identity", async () => {
  const first = await twoShaImportingRun();
  const executorSha = "e".repeat(40);
  const replayBase = {
    sourceSha: executorSha,
    protectedCheckout: { currentHead: executorSha, originMainHead: executorSha, toolingSha: executorSha, porcelainStatus: "" },
    bindings: { ...bindings, imageAuthorization: twoShaImageAuthorization },
    journal: first.journal,
    evidence: first.evidence,
    readState: async () => importedState(),
    proveDescendant: ({ ancestorSha: ancestor, descendantSha }) => (ancestor === authorizationSourceSha && descendantSha === sourceSha) || (ancestor === sourceSha && descendantSha === executorSha),
  };
  for (const authorization of [
    { ...twoShaImageAuthorization, sourceSha: "f".repeat(40) },
    { ...twoShaImageAuthorization, evidenceSha256: "f".repeat(64) },
    { ...twoShaImageAuthorization, imageReleaseSha: "8".repeat(40) },
    { ...twoShaImageAuthorization, backendDigest: "sha256:" + "f".repeat(64) },
  ]) {
    const replay = common({ ...replayBase, imageAuthorization: authorization });
    await assert.rejects(() => runExistingRevisionForwardRecovery(replay), /authorization|digest|identity/);
    assert.deepEqual(replay.counts, { imports: 0, registrations: 0 });
  }
  const changedJournal = { ...first.journal.read(), incidentIdentity: "f".repeat(64) };
  const replay = common({ ...replayBase, journal: journalAdapter(changedJournal), imageAuthorization: twoShaImageAuthorization });
  await assert.rejects(() => runExistingRevisionForwardRecovery(replay), /identity|incomplete/);
  assert.deepEqual(replay.counts, { imports: 0, registrations: 0 });
});

test("descendant importing replay does not require fresh image authorization", async () => {
  const first = await importingRun();
  const executorSha = "e".repeat(40);
  const replay = common({
    sourceSha: executorSha,
    protectedCheckout: { currentHead: executorSha, originMainHead: executorSha, toolingSha: executorSha, porcelainStatus: "" },
    journal: first.journal,
    evidence: first.evidence,
    readState: async () => importedState(),
    imageAuthorizationValidation: { now: new Date(Date.parse(imageFixture.now) + 2 * 24 * 60 * 60 * 1000).toISOString(), verifyImageEvidence: () => { throw new Error("expired authorization must not be revalidated"); } },
    proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === sourceSha && descendantSha === executorSha,
  });
  const result = await runExistingRevisionForwardRecovery(replay);
  assert.equal(result.imported, false);
  assert.deepEqual(replay.counts, { imports: 0, registrations: 0 });
});

test("consumed descendant replay still rejects image-affecting executor drift", async () => {
  const first = await importingRun();
  const executorSha = "e".repeat(40);
  const replay = common({
    sourceSha: executorSha,
    protectedCheckout: { currentHead: executorSha, originMainHead: executorSha, toolingSha: executorSha, porcelainStatus: "" },
    journal: first.journal,
    evidence: first.evidence,
    readState: async () => importedState(),
    deriveImageReuse: ({ imageReleaseSha: release, toolingSha }) => ({ ...deriveImageReuse({ imageReleaseSha: release, toolingSha }), toolingSha, imageReleaseSha: release, imageAffectingFiles: ["backend/src/app.ts"], imageBuildInputsChanged: true }),
    proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === sourceSha && descendantSha === executorSha,
  });
  await assert.rejects(() => runExistingRevisionForwardRecovery(replay), /image|closure/);
  assert.deepEqual(replay.counts, { imports: 0, registrations: 0 });
});

test("consumed importing replay fails closed when state does not prove the import", async () => {
  const first = await importingRun();
  const replay = common({ journal: first.journal, evidence: first.evidence, readState: async () => emptyState() });
  await assert.rejects(() => runExistingRevisionForwardRecovery(replay), /ambiguous|lineage|serial|candidate/);
  assert.deepEqual(replay.counts, { imports: 0, registrations: 0 });
});

test("prepared recovery still requires fresh image authorization", async () => {
  const expired = common({ imageAuthorizationValidation: { now: new Date(Date.parse(imageFixture.now) + 2 * 24 * 60 * 60 * 1000).toISOString(), verifyImageEvidence: imageFixture.verifyImageEvidence } });
  await assert.rejects(() => runExistingRevisionForwardRecovery(expired), /stale|malformed|evidence|authorization/);
  assert.deepEqual(expired.counts, { imports: 0, registrations: 0 });
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
  assert.throws(() => canonicalForwardRecoveryIncidentIdentity({ sourceSha, toolingTreeSha256: bindings.toolingTreeSha256, sourceContractSha256: bindings.sourceContractSha256, imageReleaseSha, authorizedBackendDigest: imageAuthorization.backendDigest, imageAuthorizationSha256: imageAuthorization.evidenceSha256, imageAuthorizationSourceSha: imageAuthorization.sourceSha, stateLineage: CONTRACT.lineage, stateSerial: 93, stateBeforeSha256: canonicalSha256(emptyState()), existingRevisionArn: arn, censusSha256: "c".repeat(64), fingerprint }), /incomplete/);
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
  assert.doesNotThrow(() => buildForwardRecoveryTerraformEnvironment(dataDir, { PATH: "/usr/bin" }));
  for (const [key, value] of [["TF_CLI_ARGS", "-lock=false"], ["TF_CLI_ARGS_import", "-lock=false"], ["TF_CLI_ARGS_import", "-lock-timeout=0s"], ["TF_CLI_ARGS_plan", "-destroy"], ["TF_CLI_ARGS_custom", "-input=false"], ["TF_CLI_CONFIG_FILE", "/tmp/unreviewed.tfrc"], ["TF_PLUGIN_CACHE_DIR", "/tmp/unreviewed-cache"], ["TF_INPUT", "1"], ["TF_IN_AUTOMATION", "0"], ["TF_LOG", "TRACE"], ["TF_LOG_PATH", "/tmp/terraform.log"], ["TF_VAR_region", "wrong"]]) {
    assert.throws(() => buildForwardRecoveryTerraformEnvironment(dataDir, { [key]: value }), /Terraform override variables/);
  }
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

test("forward recovery revalidates the complete ECS census and :9 immediately before import", async () => {
  const newer = structuredClone(readback);
  newer.taskDefinition.taskDefinitionArn = `${arn.slice(0, -1)}10`;
  newer.taskDefinition.revision = 10;
  const historical = structuredClone(readback);
  historical.taskDefinition.taskDefinitionArn = `${arn.slice(0, -1)}8`;
  historical.taskDefinition.revision = 8;
  const cases = [
    ["newer revision", (calls) => calls === 2 ? { complete: true, revisions: [{ arn: newer.taskDefinition.taskDefinitionArn, readback: newer }, { arn, readback }] } : census],
    ["incomplete census", (calls) => calls === 2 ? { complete: false, revisions: [] } : census],
    ["ordering change", (calls) => calls === 1 ? { complete: true, revisions: [{ arn, readback }, { arn: historical.taskDefinition.taskDefinitionArn, readback: historical }] } : { complete: true, revisions: [{ arn: historical.taskDefinition.taskDefinitionArn, readback: historical }, { arn, readback }] }],
  ];
  for (const [label, makeCensus] of cases) {
    let calls = 0;
    const run = common({ census: async () => makeCensus(++calls) });
    await assert.rejects(() => runExistingRevisionForwardRecovery(run), /census|newer|newest/, label);
    assert.equal(run.counts.imports, 0, label);
  }
  let describeCalls = 0;
  const changed = structuredClone(readback);
  changed.taskDefinition.containerDefinitions[0].image = `${backendImage.slice(0, -1)}0`;
  const readbackRace = common({ describe: async () => ++describeCalls === 1 ? readback : changed });
  await assert.rejects(() => runExistingRevisionForwardRecovery(readbackRace), /fingerprint|image|readback/);
  assert.equal(readbackRace.counts.imports, 0);
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

test("ordinary CLI recovery treats the absent journal path as an output, not a historical input", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-forward-cli-"));
  fs.chmodSync(directory, 0o700);
  const terraformDataDir = path.join(directory, "terraform-data");
  fs.mkdirSync(terraformDataDir, { mode: 0o700 });
  const bindingsPath = path.join(directory, "bindings.json");
  const imageAuthorizationPath = path.join(directory, "authorization.json");
  const evidencePath = path.join(directory, "evidence.json");
  const journalPath = path.join(directory, "journal.json");
  fs.writeFileSync(bindingsPath, "{}", { mode: 0o600 });
  fs.writeFileSync(imageAuthorizationPath, "{}", { mode: 0o600 });
  await assert.rejects(() => runForwardRecoveryCli([
    "--execute", "--source-sha", sourceSha, "--bindings", bindingsPath, "--image-authorization", imageAuthorizationPath,
    "--aws-profile", "release-deployer", "--terraform-data-dir", terraformDataDir, "--evidence-out", evidencePath,
    "--forward-recovery-state", journalPath,
  ], { readProtectedCheckout: () => ({ currentHead: sourceSha, originMainHead: sourceSha, toolingSha: sourceSha, porcelainStatus: "" }) }), (error) => {
    assert.doesNotMatch(error.message, /Historical forward recovery journal/);
    return true;
  });
  assert.equal(fs.existsSync(journalPath), false);
});

test("supersession CLI requires the existing historical journal before any contract evaluation", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-forward-supersession-"));
  fs.chmodSync(directory, 0o700);
  const oldJournalPath = path.join(directory, "ambiguous.json");
  const supersessionPath = path.join(directory, "supersession.json");
  const evidencePath = path.join(directory, "supersession.evidence.json");
  const bindingsPath = path.join(directory, "bindings.json");
  const imageAuthorizationPath = path.join(directory, "authorization.json");
  fs.writeFileSync(bindingsPath, "{}", { mode: 0o600 });
  fs.writeFileSync(imageAuthorizationPath, "{}", { mode: 0o600 });
  await assert.rejects(() => runForwardRecoveryCli([
    "--execute", "--source-sha", sourceSha, "--bindings", bindingsPath, "--image-authorization", imageAuthorizationPath,
    "--aws-profile", "release-deployer", "--terraform-data-dir", path.join(directory, "terraform-data"), "--evidence-out", evidencePath,
    "--forward-recovery-state", oldJournalPath, "--supersede-ambiguous-import", "--supersession-state", supersessionPath,
  ], { readProtectedCheckout: () => ({ currentHead: sourceSha, originMainHead: sourceSha, toolingSha: sourceSha, porcelainStatus: "" }) }), /Historical forward recovery journal/);
});

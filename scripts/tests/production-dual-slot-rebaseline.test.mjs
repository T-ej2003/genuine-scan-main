import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  PRODUCTION_DUAL_SLOT_REBASELINE, REBASELINE_SLOTS, REBASELINE_SLOT_ORDER, BASELINE_COMPLETE,
  buildAbandonmentEvidence, buildRebaselineIdentity, buildRebaselinePayloads, buildRebaselineWritePlan,
  buildRebaselinePreparation, assertRebaselinePreconditions, assertRebaselinePreparation,
  createProductionDualSlotRebaselineAuthorization, deterministicWriteIdentity, executeProductionDualSlotRebaseline,
  generateRebaselineMaterial, buildRebaselineRotationBindings, assertBaselineCompletion, canonicalSha256, REBASELINE_HISTORICAL_SOURCE_SHAS,
} from "../aws/production-dual-slot-rebaseline-contract.mjs";
import { createProductionEnvironmentApprovalEvidence, PRODUCTION_ENVIRONMENT_APPROVAL } from "../aws/production-github-environment-approval.mjs";
import { assertBindings } from "../aws/production-cutover-runtime-bootstrap.mjs";

const sourceSha = "a".repeat(40);
const historicalRotationId = "rotation-20260826060632-b15b3f51";
const rotationId = "rotation-20260828000000-rebase";
const resources = Object.fromEntries(REBASELINE_SLOT_ORDER.map((slot) => [slot, `arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr-prod-${slot}`]));
const currentVersionIds = Object.fromEntries(REBASELINE_SLOT_ORDER.map((slot) => [slot, `historical-${slot}`]));
const legacyBaseline = {
  jwtCurrent: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:legacy-jwt",
  qrPrivateCurrent: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:legacy-qr-private",
  qrPublicCurrent: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:legacy-qr-public",
  qrCurrentVersion: "legacy-v1",
};
const abandoned = buildAbandonmentEvidence({ sourceSha, historicalRotationId, historicalSourceShas: REBASELINE_HISTORICAL_SOURCE_SHAS, resources, currentVersionIds, liveReferenceAudit: "PASS", legacyRuntimeAuthoritative: true, observedAt: "2026-08-28T10:00:00.000Z" });
const preconditions = { environment: "production", accountId: PRODUCTION_DUAL_SLOT_REBASELINE.accountId, region: PRODUCTION_DUAL_SLOT_REBASELINE.region, sourceSha, sourceCas: true, cleanWorktree: true, existingSecretResources: true, liveReferenceAudit: "PASS", legacyRuntimeAuthoritative: true, databaseDependencies: 0, externalConsumers: 0, dualSlotReferences: 0, runningTasks: 2, pendingTasks: 0, activeTaskDefinition: "mscqr-backend:50", resources, abandonmentEvidence: abandoned };
const material = generateRebaselineMaterial();
const identity = buildRebaselineIdentity({ sourceSha, rotationId, resources, abandonmentEvidenceSha256: abandoned.evidenceSha256, legacyBaseline });
const payloads = buildRebaselinePayloads({ sourceSha, rotationId, generatedMaterial: material, legacyBaseline });
const writePlan = buildRebaselineWritePlan({ sourceSha, rotationId, resources, baselineIdentitySha256: identity.identitySha256, payloads });

function environmentEvidence() {
  return createProductionEnvironmentApprovalEvidence({
    environmentConfig: { name: "production", id: 17, can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: { id: 7, login: "checker" } }] }] },
    repository: PRODUCTION_DUAL_SLOT_REBASELINE.repository, environment: "production", sourceSha,
    workflowRef: PRODUCTION_ENVIRONMENT_APPROVAL.dualSlotRebaselineWorkflowRef, eventName: "workflow_dispatch", workflowRunId: "123456", workflowRunAttempt: "1", executionActor: "checker", observedAt: "2026-08-28T10:01:00.000Z",
  });
}

function authorization() {
  return createProductionDualSlotRebaselineAuthorization({ protectedEnvironmentApprovalEvidence: environmentEvidence(), sourceSha, historicalRotationId, rotationId, abandonmentEvidenceSha256: abandoned.evidenceSha256, baselineIdentitySha256: identity.identitySha256, resources, writeIdentities: Object.fromEntries(writePlan.map(({ slot, clientRequestToken }) => [slot, clientRequestToken])), expectedSecretValueWrites: 7, expectedSecretDeletes: 0, liveReferenceAudit: "PASS", reason: "Abandon pre-cutover state and establish a clean baseline", approvedBy: "checker", approverRole: "production-independent-checker", verificationRef: "ticket-rebaseline-1" });
}

function executionAdapters({ failAt = -1, liveReferenceAudit = { dualSlotReferences: 0, legacyRuntimeAuthoritative: true } } = {}) {
  const store = new Map(REBASELINE_SLOT_ORDER.map((slot) => [slot, [{ versionId: currentVersionIds[slot], stages: ["AWSCURRENT"], payloadSha256: "0".repeat(64) }]]));
  let calls = 0;
  return {
    store,
    readReferenceAudit: async () => liveReferenceAudit,
    readSlot: async (slot, secretArn) => ({ arn: secretArn, versions: store.get(slot) }),
    writeSlot: async ({ slot, secretArn, clientRequestToken, payload, payloadSha256 }) => {
      const entry = { versionId: clientRequestToken, stages: ["AWSCURRENT"], payloadSha256: payloadSha256 || canonicalSha256(payload) };
      store.set(slot, store.get(slot).map((version) => ({ ...version, stages: version.stages.includes("AWSCURRENT") ? ["AWSPREVIOUS"] : version.stages })).concat(entry));
      calls += 1;
      if (calls === failAt) throw new Error("injected interruption after remote write");
      return { arn: secretArn, versionId: clientRequestToken };
    },
  };
}

test("exact abandoned pre-cutover topology produces a seven-write, source-bound preparation", () => {
  const preparation = buildRebaselinePreparation({ preconditions, sourceSha, rotationId, baselineIdentity: identity, writePlan });
  assert.equal(preparation.kind, "PRODUCTION_DUAL_SLOT_REBASELINE_PREPARATION");
  assert.equal(preparation.writePlan.length, 7);
  assertRebaselinePreparation(preparation, { sourceSha, rotationId });
  assert.equal(JSON.stringify(preparation).includes(material.jwt), false);
  assert.equal(JSON.stringify(preparation).includes("value"), false);
});

test("live dual-slot references and arbitrary abandonment evidence fail closed", () => {
  assert.throws(() => assertRebaselinePreconditions({ ...preconditions, dualSlotReferences: 1 }), /not safe/);
  assert.throws(() => assertRebaselinePreconditions({ ...preconditions, abandonmentEvidence: { ...abandoned, evidenceSha256: "0".repeat(64) } }), /hash/);
  assert.throws(() => assertRebaselinePreconditions({ ...preconditions, resources: { ...resources, jwtPending: `${resources.jwtPending}-wrong` } }), /resources|hash/);
});

test("authorization is operation-specific, exact seven-resource, and protected-environment bound", () => {
  const value = authorization();
  assert.equal(value.operation, PRODUCTION_DUAL_SLOT_REBASELINE.kind);
  assert.equal(value.expectedSecretValueWrites, 7);
  assert.equal(value.expectedSecretDeletes, 0);
  assert.deepEqual(value.protectedEnvironmentApprovalEvidence.workflowRef, PRODUCTION_ENVIRONMENT_APPROVAL.dualSlotRebaselineWorkflowRef);
  assert.throws(() => createProductionDualSlotRebaselineAuthorization({ ...value, protectedEnvironmentApprovalEvidence: environmentEvidence(), writeIdentities: { ...value.writeIdentities, jwtPending: "wrong" } }), /writeIdentities/);
  assert.throws(() => createProductionDualSlotRebaselineAuthorization({ ...value, resources: { ...resources, jwtPending: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:other" } }), /writeIdentities|resources/);
});

test("seven-slot execution is resumable after every write boundary and emits no secret material", async () => {
  const value = authorization();
  for (let failAt = 1; failAt <= 7; failAt += 1) {
    const adapters = executionAdapters({ failAt });
    await assert.rejects(() => executeProductionDualSlotRebaseline({ preconditions, sourceSha, rotationId, baselineIdentity: identity, writePlan, authorizationBinding: value.authorizationSha256, ...adapters }), /interruption/);
    const resumed = await executeProductionDualSlotRebaseline({ preconditions, sourceSha, rotationId, baselineIdentity: identity, writePlan, authorizationBinding: value.authorizationSha256, ...adapters });
    assert.equal(resumed.baselineComplete, true);
    assert.equal(JSON.stringify(resumed.completion).includes(material.jwt), false);
    assert.equal(resumed.completion.kind, BASELINE_COMPLETE);
  }
});

test("unexpected reference or mismatched deterministic state cannot reach a write", async () => {
  const value = authorization();
  const adapters = executionAdapters({ liveReferenceAudit: { dualSlotReferences: 1, legacyRuntimeAuthoritative: true } });
  await assert.rejects(() => executeProductionDualSlotRebaseline({ preconditions, sourceSha, rotationId, baselineIdentity: identity, writePlan, authorizationBinding: value.authorizationSha256, ...adapters }), /reference audit changed/);
  assert.equal([...adapters.store.values()].every((versions) => versions.length === 1), true);
  assert.notEqual(deterministicWriteIdentity({ sourceSha, rotationId, slot: "jwtPending", secretArn: resources.jwtPending, baselineIdentitySha256: identity.identitySha256 }), deterministicWriteIdentity({ sourceSha, rotationId, slot: "jwtPrevious", secretArn: resources.jwtPrevious, baselineIdentitySha256: identity.identitySha256 }));
});

test("baseline completion is the only runtime-consumable rebaseline state", async () => {
  const value = authorization();
  const adapters = executionAdapters();
  const result = await executeProductionDualSlotRebaseline({ preconditions, sourceSha, rotationId, baselineIdentity: identity, writePlan, authorizationBinding: value.authorizationSha256, ...adapters });
  assertBaselineCompletion(result.completion, { sourceSha, rotationId, resources, authorizationBinding: value.authorizationSha256 });
  const bindings = buildRebaselineRotationBindings({ sourceSha, rotationId, legacyBaseline, resources, abandonmentEvidence: abandoned, completion: result.completion });
  assert.equal(bindings.operation, PRODUCTION_DUAL_SLOT_REBASELINE.kind);
  assert.equal(bindings.baselineCompletionSha256, result.completion.baselineBindingSha256);
  assert.equal(bindings.qr.previousKeyVersion, legacyBaseline.qrCurrentVersion);
  assert.doesNotThrow(() => assertBindings(bindings));
  assert.throws(() => assertBindings({ ...bindings, baselineCompletion: undefined }), /Completed dual-slot baseline/);
});

test("the rebaseline boundary has no unrelated mutation escape hatch", () => {
  const contract = readFileSync(new URL("../aws/production-dual-slot-rebaseline-contract.mjs", import.meta.url), "utf8");
  const executor = readFileSync(new URL("../aws/rebaseline-production-dual-slot.mjs", import.meta.url), "utf8");
  assert.equal(/new\s+(DeleteSecret|UpdateSecret|RegisterTaskDefinition|PutResourcePolicy)Command|\["ecs",\s*"(update-service|register-task-definition)"\]/i.test(contract), false);
  assert.equal(/new\s+(DeleteSecret|UpdateSecret|RegisterTaskDefinition|PutResourcePolicy)Command|\["ecs",\s*"(update-service|register-task-definition)"\]/i.test(executor), false);
  assert.equal(executor.includes("PutSecretValueCommand"), true);
});

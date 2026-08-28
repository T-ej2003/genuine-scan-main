import assert from "node:assert/strict";
import fs from "node:fs";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  PRODUCTION_DUAL_SLOT_REBASELINE, REBASELINE_SLOT_ORDER, BASELINE_COMPLETE,
  buildAbandonmentEvidence, buildRebaselineIdentity, buildRebaselinePayloads, buildRebaselineWritePlan,
  buildRebaselinePreparation, assertRebaselinePreconditions, assertRebaselinePreparation,
  createProductionDualSlotRebaselineAuthorization, deterministicWriteIdentity, executeProductionDualSlotRebaseline,
  generateRebaselineMaterial, assertBaselineCompletion, canonicalSha256, historicalSlotIdentity,
  REBASELINE_HISTORICAL_SOURCE_SHAS, REBASELINE_SLOTS, assertRebaselineRotationBindings, assertProductionDualSlotRebaselineAuthorization, resolveProductionDualSlotRebaselineAuthorizationArtifact, readBoundBaselineCompletion, writeRebaselineMaterialJournal, persistExactPrivateJson, rebaselineWritePayloadIdentities, verifyLiveProductionDualSlotRebaselineWithRunner, sha256,
} from "../aws/production-dual-slot-rebaseline-contract.mjs";
import { auditLiveProductionDualSlotReferences, readAuthenticatedRebaselineCheckout, readPreparedDualSlotTopology, runProductionDualSlotRebaselineCli, verifyLiveProductionDualSlotRebaseline } from "../aws/rebaseline-production-dual-slot.mjs";
import { createProductionEnvironmentApprovalEvidence, PRODUCTION_ENVIRONMENT_APPROVAL } from "../aws/production-github-environment-approval.mjs";
import { assertBindings, buildInitialMigrationSourceAdvance, buildProductionRotationConfig } from "../aws/production-cutover-runtime-bootstrap.mjs";
import { createProductionCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "../aws/production-cutover-production-adapters.mjs";

const sourceSha = "a".repeat(40);
const historicalRotationId = "rotation-20260826060632-b15b3f51";
const rotationId = "rotation-20260828000000-rebase";
const resources = Object.fromEntries(REBASELINE_SLOT_ORDER.map((slot, index) => [slot, `arn:aws:secretsmanager:eu-west-2:${PRODUCTION_DUAL_SLOT_REBASELINE.accountId}:secret:fixture/${REBASELINE_SLOTS[slot]}-${index}`]));
const currentVersionIds = Object.fromEntries(REBASELINE_SLOT_ORDER.map((slot) => [slot, sha256(`fixture-version:${slot}`)]));
const historicalTopologySha256 = canonicalSha256({ resources, versionIds: currentVersionIds });
const legacyBaseline = { jwtCurrent: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:legacy-jwt", qrPrivateCurrent: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:legacy-qr-private", qrPublicCurrent: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:legacy-qr-public", qrCurrentVersion: "legacy-v1" };
const shapes = { jwtPending: ["jwt_secrets", "pending"], qrPrivatePending: ["qr_signing_keys", "pending-private"], qrPublicPending: ["qr_signing_keys", "pending-public"], jwtPrevious: ["jwt_secrets", "empty"], qrPublicPrevious: ["qr_signing_keys", "empty"], qrCurrentVersion: ["qr_key_versions", "current"], qrPreviousVersion: ["qr_key_versions", "previous-empty"] };
function historicalPayload(slot, { source = REBASELINE_HISTORICAL_SOURCE_SHAS[0], rotation = historicalRotationId, value = `historical-${slot}` } = {}) { const [family, payloadSlot] = shapes[slot]; return { value, family, slot: payloadSlot, initialMigration: true, ...(rotation === undefined ? {} : { rotationId: rotation }), ...(source === undefined ? {} : { sourceSha: source }) }; }
const observedSlotIdentities = Object.fromEntries(REBASELINE_SLOT_ORDER.map((slot) => [slot, historicalSlotIdentity({ slot, secretArn: resources[slot], versionId: currentVersionIds[slot], stages: ["AWSCURRENT"], payload: historicalPayload(slot, { source: slot === "qrPublicPending" ? REBASELINE_HISTORICAL_SOURCE_SHAS[1] : slot === "qrPreviousVersion" ? undefined : undefined }) })]));
const audit = Object.freeze({ status: "PASS", dualSlotReferences: 0, legacyRuntimeAuthoritative: true, databaseDependencies: 0, externalConsumers: 0, auditSha256: canonicalSha256({ observation: "fixture", resources, tasks: ["task-a"] }), stableAuditSha256: canonicalSha256({ stable: "fixture", resources, taskDefinitions: ["mscqr-backend:50"] }) });
const abandoned = buildAbandonmentEvidence({ sourceSha, historicalRotationId, historicalSourceShas: REBASELINE_HISTORICAL_SOURCE_SHAS, resources, currentVersionIds, historicalTopologySha256, observedSlotIdentities, liveReferenceAudit: "PASS", liveReferenceAuditSha256: audit.stableAuditSha256, legacyRuntimeAuthoritative: true, observedAt: "2026-08-28T10:00:00.000Z" });
const preconditions = { environment: "production", accountId: PRODUCTION_DUAL_SLOT_REBASELINE.accountId, region: PRODUCTION_DUAL_SLOT_REBASELINE.region, sourceSha, sourceCas: true, cleanWorktree: true, existingSecretResources: true, liveReferenceAudit: "PASS", liveReferenceAuditSha256: audit.stableAuditSha256, legacyRuntimeAuthoritative: true, databaseDependencies: 0, externalConsumers: 0, dualSlotReferences: 0, runningTasks: 2, pendingTasks: 0, activeTaskDefinition: "mscqr-backend:50", resources, historicalTopologySha256, abandonmentEvidence: abandoned };
const material = generateRebaselineMaterial();
const identity = buildRebaselineIdentity({ sourceSha, rotationId, resources, abandonmentEvidenceSha256: abandoned.evidenceSha256, legacyBaseline });
const payloads = buildRebaselinePayloads({ sourceSha, rotationId, generatedMaterial: material, legacyBaseline });
const writePlan = buildRebaselineWritePlan({ sourceSha, rotationId, resources, baselineIdentitySha256: identity.identitySha256, payloads });
const preparation = buildRebaselinePreparation({ preconditions, sourceSha, rotationId, baselineIdentity: identity, writePlan });
const temporary = () => { const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rebaseline-test-")); chmodSync(directory, 0o700); return { directory, completionFile: path.join(directory, "completion.json"), bindingsFile: path.join(directory, "rotation-bindings.json") }; };

function environmentEvidence() { return createProductionEnvironmentApprovalEvidence({ environmentConfig: { name: "production", id: 17, can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: { id: 7, login: "checker" } }] }] }, repository: PRODUCTION_DUAL_SLOT_REBASELINE.repository, environment: "production", sourceSha, workflowRef: PRODUCTION_ENVIRONMENT_APPROVAL.dualSlotRebaselineWorkflowRef, eventName: "workflow_dispatch", workflowRunId: "123456", workflowRunAttempt: "1", executionActor: "checker", observedAt: "2026-08-28T10:01:00.000Z" }); }
function authorization({ baselineIdentitySha256 = identity.identitySha256, writePayloadIdentities = rebaselineWritePayloadIdentities(writePlan) } = {}) { return createProductionDualSlotRebaselineAuthorization({ protectedEnvironmentApprovalEvidence: environmentEvidence(), sourceSha, historicalRotationId, rotationId, abandonmentEvidenceSha256: abandoned.evidenceSha256, baselineIdentitySha256, resources, writeIdentities: Object.fromEntries(REBASELINE_SLOT_ORDER.map((slot) => [slot, deterministicWriteIdentity({ sourceSha, rotationId, slot, secretArn: resources[slot], baselineIdentitySha256 })])), writePayloadIdentities, expectedSecretValueWrites: 7, expectedSecretDeletes: 0, liveReferenceAudit: "PASS", liveReferenceAuditSha256: audit.stableAuditSha256, observedSlotIdentitiesSha256: abandoned.observedSlotIdentitiesSha256, reason: "Abandon pre-cutover state and establish a clean baseline", approvedBy: "checker", approverRole: "production-independent-checker", verificationRef: "ticket-rebaseline-1" }); }
function executionAdapters({ failAt = -1, liveReferenceAudit = audit } = {}) {
  const store = new Map(REBASELINE_SLOT_ORDER.map((slot) => [slot, [{
    versionId: currentVersionIds[slot], stages: ["AWSCURRENT"],
    payloadSha256: observedSlotIdentities[slot].payloadSha256,
  }]]));
  let calls = 0;
  return {
    store,
    readReferenceAudit: async () => typeof liveReferenceAudit === "function" ? liveReferenceAudit() : liveReferenceAudit,
    readSlot: async (slot, secretArn) => {
      const versions = store.get(slot); const current = versions.find(({ stages }) => stages.includes("AWSCURRENT"));
      return { arn: secretArn, versions, currentVersionId: current?.versionId, currentStages: current?.stages, currentPayloadSha256: current?.payloadSha256 };
    },
    writeSlot: async ({ slot, secretArn, clientRequestToken, payload, payloadSha256 }) => {
      const entry = { versionId: clientRequestToken, stages: ["AWSCURRENT"], payloadSha256: payloadSha256 || canonicalSha256(payload) };
      store.set(slot, store.get(slot).map((version) => ({ ...version, stages: version.stages.includes("AWSCURRENT") ? ["AWSPREVIOUS"] : version.stages })).concat(entry));
      calls += 1;
      if (calls === failAt) throw new Error("injected interruption after remote write");
      return { arn: secretArn, versionId: clientRequestToken };
    },
  };
}
function execute(adapters, outputs, extra = {}) { return executeProductionDualSlotRebaseline({ preconditions, sourceSha, rotationId, baselineIdentity: identity, writePlan, authorization: authorization(), completionFile: outputs.completionFile, bindingsFile: outputs.bindingsFile, repositoryRoot: process.cwd(), ...adapters, ...extra }); }

function cliTopologyClient(completedSlots = [], overrides = {}) {
  const completed = new Set(completedSlots);
  return { send: async (command) => {
    const input = command.input;
    const slot = Object.entries(REBASELINE_SLOTS).find(([, name]) => name === input.SecretId)?.[0] || Object.entries(resources).find(([, arn]) => arn === input.SecretId)?.[0];
    if (!slot) throw new Error("unexpected secret identity");
    const expected = writePlan.find((entry) => entry.slot === slot);
    const oldVersionId = currentVersionIds[slot];
    const currentVersionId = overrides[slot]?.versionId || (completed.has(slot) ? expected.clientRequestToken : oldVersionId);
    const payload = overrides[slot]?.payload || (completed.has(slot) ? expected.payload : historicalPayload(slot, { source: slot === "qrPublicPending" ? REBASELINE_HISTORICAL_SOURCE_SHAS[1] : slot === "qrPreviousVersion" ? undefined : REBASELINE_HISTORICAL_SOURCE_SHAS[0] }));
    const name = command.constructor.name;
    if (name === "DescribeSecretCommand") return { Name: input.SecretId, ARN: overrides[slot]?.arn || resources[slot], VersionIdsToStages: { [currentVersionId]: overrides[slot]?.stages || ["AWSCURRENT"], ...(currentVersionId === oldVersionId ? {} : { [oldVersionId]: ["AWSPREVIOUS"] }) } };
    if (name === "GetSecretValueCommand") return { SecretString: JSON.stringify(payload), VersionId: input.VersionId };
    throw new Error(`unexpected command ${name}`);
  } };
}

function cliTopologyRunner(completedSlots = [], overrides = {}) {
  const completed = new Set(completedSlots);
  return (args) => {
    const secretArn = args[args.indexOf("--secret-id") + 1];
    const slot = Object.entries(resources).find(([, arn]) => arn === secretArn)?.[0];
    if (!slot) throw new Error("unexpected secret identity");
    const expected = writePlan.find((entry) => entry.slot === slot);
    const currentVersionId = overrides[slot]?.versionId || (completed.has(slot) ? expected.clientRequestToken : currentVersionIds[slot]);
    const payload = overrides[slot]?.payload || (completed.has(slot) ? expected.payload : historicalPayload(slot, { source: slot === "qrPublicPending" ? REBASELINE_HISTORICAL_SOURCE_SHAS[1] : slot === "qrPreviousVersion" ? undefined : REBASELINE_HISTORICAL_SOURCE_SHAS[0] }));
    if (args[0] === "secretsmanager" && args[1] === "describe-secret") return JSON.stringify({ ARN: overrides[slot]?.arn || secretArn, VersionIdsToStages: { [currentVersionId]: overrides[slot]?.stages || ["AWSCURRENT"] } });
    if (args[0] === "secretsmanager" && args[1] === "get-secret-value") return JSON.stringify({ VersionId: args[args.indexOf("--version-id") + 1], SecretString: JSON.stringify(payload) });
    throw new Error("unexpected command");
  };
}

test("observed abandonment identities bind exact payloads without plaintext", () => {
  const preparation = buildRebaselinePreparation({ preconditions, sourceSha, rotationId, baselineIdentity: identity, writePlan });
  assert.equal(preparation.writePlan.length, 7); assertRebaselinePreparation(preparation, { sourceSha, rotationId }); assert.equal(JSON.stringify(abandoned).includes(material.jwt), false);
  assert.throws(() => historicalSlotIdentity({ slot: "jwtPending", secretArn: resources.jwtPending, versionId: currentVersionIds.jwtPending, stages: ["AWSCURRENT"], payload: historicalPayload("jwtPending", { rotation: "rotation-wrong" }) }), /provenance/);
  assert.throws(() => historicalSlotIdentity({ slot: "jwtPending", secretArn: resources.jwtPending, versionId: currentVersionIds.jwtPending, stages: ["AWSCURRENT"], payload: historicalPayload("jwtPending", { source: "b".repeat(40) }) }), /source provenance/);
  assert.throws(() => historicalSlotIdentity({ slot: "jwtPending", secretArn: resources.jwtPending, versionId: currentVersionIds.jwtPending, stages: ["AWSCURRENT"], payload: { ...historicalPayload("jwtPending"), family: "unrelated_json" } }), /kind/);
  assert.throws(() => historicalSlotIdentity({ slot: "jwtPending", secretArn: resources.jwtPending, versionId: currentVersionIds.jwtPending, stages: ["AWSCURRENT"], payload: { ...historicalPayload("jwtPending"), materialFingerprint: "tampered" } }), /fingerprint/);
  assert.throws(() => historicalSlotIdentity({ slot: "jwtPending", secretArn: resources.jwtPending, versionId: currentVersionIds.jwtPending, stages: ["AWSPREVIOUS"], payload: historicalPayload("jwtPending") }), /stages/);
  assert.throws(() => buildAbandonmentEvidence({ sourceSha, historicalRotationId, historicalSourceShas: REBASELINE_HISTORICAL_SOURCE_SHAS, resources, currentVersionIds: { ...currentVersionIds, jwtPending: "changed-version" }, observedSlotIdentities, liveReferenceAudit: "PASS", liveReferenceAuditSha256: audit.stableAuditSha256, legacyRuntimeAuthoritative: true }), /exact|identity/);
  assert.doesNotThrow(() => historicalSlotIdentity({ slot: "qrPreviousVersion", secretArn: resources.qrPreviousVersion, versionId: currentVersionIds.qrPreviousVersion, stages: ["AWSCURRENT"], payload: historicalPayload("qrPreviousVersion", { source: undefined }) }));
  assert.doesNotThrow(() => historicalSlotIdentity({ slot: "qrPublicPending", secretArn: resources.qrPublicPending, versionId: currentVersionIds.qrPublicPending, stages: ["AWSCURRENT"], payload: historicalPayload("qrPublicPending", { source: REBASELINE_HISTORICAL_SOURCE_SHAS[1] }) }));
  const tampered = structuredClone(abandoned); tampered.observedSlotIdentities.jwtPending.payloadSha256 = "0".repeat(64);
  assert.throws(() => assertRebaselinePreconditions({ ...preconditions, abandonmentEvidence: tampered }), /hash/);
});

test("authorization binds observed historical and complete ECS audit identities", () => {
  const value = authorization(); assert.equal(value.operation, PRODUCTION_DUAL_SLOT_REBASELINE.kind);
  assert.throws(() => assertProductionDualSlotRebaselineAuthorization({ ...value, observedSlotIdentitiesSha256: "0".repeat(64) }, { sourceSha, rotationId, resources }), /hash|identity/);
  assert.throws(() => assertRebaselinePreconditions({ ...preconditions, liveReferenceAuditSha256: "0".repeat(64) }), /bound|safe/);
});

test("shared executor independently binds the authorization baseline and all seven deterministic writes", async () => {
  const outputs = temporary(); const adapters = executionAdapters(); const auth = authorization();
  await assert.rejects(() => executeProductionDualSlotRebaseline({ preconditions, sourceSha, rotationId, baselineIdentity: identity, writePlan, authorization: authorization({ baselineIdentitySha256: sha256("other-authorized-baseline") }), completionFile: outputs.completionFile, bindingsFile: outputs.bindingsFile, repositoryRoot: process.cwd(), ...adapters }), /baseline identity/i);
  await assert.rejects(() => executeProductionDualSlotRebaseline({ preconditions, sourceSha, rotationId, baselineIdentity: identity, writePlan, authorization: { ...auth, writeIdentities: { ...auth.writeIdentities, jwtPending: sha256("cross-slot-token") } }, completionFile: outputs.completionFile, bindingsFile: outputs.bindingsFile, repositoryRoot: process.cwd(), ...adapters }), /writeIdentities|identity|hash/i);
  assert.equal([...adapters.store.values()].every((versions) => versions.length === 1), true); rmSync(outputs.directory, { recursive: true, force: true });
});

test("production CLI topology reader resumes every authenticated H-to-N boundary", async () => {
  for (let completed = 0; completed <= REBASELINE_SLOT_ORDER.length; completed += 1) {
    const completedSlots = REBASELINE_SLOT_ORDER.slice(0, completed);
    const topology = await readPreparedDualSlotTopology({ client: cliTopologyClient(completedSlots), preparation, writePlan });
    assert.deepEqual(Object.values(topology.classifications).filter((value) => value === "REBASELINE_WRITE_ALREADY_COMPLETE").length, completed);
    assert.deepEqual(Object.values(topology.classifications).filter((value) => value === "HISTORICAL_NOT_YET_WRITTEN").length, 7 - completed);
  }
});

test("production CLI rejects every third topology state during resume", async () => {
  const slot = REBASELINE_SLOT_ORDER[0];
  const cases = [
    { versionId: writePlan[0].clientRequestToken, payload: { ...writePlan[0].payload, value: "wrong-prepared-material" } },
    { versionId: sha256("unexpected-version"), payload: writePlan[0].payload },
    { versionId: writePlan[0].clientRequestToken, payload: { ...writePlan[0].payload, sourceSha: "b".repeat(40) } },
    { versionId: writePlan[0].clientRequestToken, payload: writePlan[1].payload },
    { versionId: currentVersionIds[slot], payload: { ...historicalPayload(slot), value: "replaced-historical-material" } },
  ];
  for (const value of cases) await assert.rejects(() => readPreparedDualSlotTopology({ client: cliTopologyClient([], { [slot]: value }), preparation, writePlan }), /authenticate|identity|historical|prepared|version/i);
});

test("runtime consumes a rebaseline completion only after independent live seven-slot authentication", async () => {
  const outputs = temporary();
  try {
    const result = await execute(executionAdapters(), outputs);
    const forged = structuredClone(result.bindings);
    forged.baselineCompletion.versionIds.jwtPending = sha256("forged-version");
    const forgedCompletionIdentity = { ...forged.baselineCompletion }; delete forgedCompletionIdentity.baselineBindingSha256;
    forged.baselineCompletion.baselineBindingSha256 = canonicalSha256(forgedCompletionIdentity);
    forged.baselineCompletionSha256 = forged.baselineCompletion.baselineBindingSha256;
    assert.throws(() => assertRebaselineRotationBindings(forged, { authorization: authorization() }), /version identities/i);
    for (let completed = 0; completed < REBASELINE_SLOT_ORDER.length; completed += 1) {
      await assert.rejects(() => verifyLiveProductionDualSlotRebaseline({ client: cliTopologyClient(REBASELINE_SLOT_ORDER.slice(0, completed)), bindings: result.bindings, authorization: authorization() }), /exact completed|payload/i);
    }
    const verified = await verifyLiveProductionDualSlotRebaseline({ client: cliTopologyClient(REBASELINE_SLOT_ORDER), bindings: result.bindings, authorization: authorization() });
    assert.equal(verified.livePostWriteSha256.length, 64);
    const slot = REBASELINE_SLOT_ORDER[0];
    await assert.rejects(() => verifyLiveProductionDualSlotRebaseline({ client: cliTopologyClient(REBASELINE_SLOT_ORDER, { [slot]: { payload: { ...writePlan[0].payload, value: "wrong-material" } } }), bindings: result.bindings, authorization: authorization() }), /payload/i);
    await assert.rejects(() => verifyLiveProductionDualSlotRebaseline({ client: cliTopologyClient(REBASELINE_SLOT_ORDER, { [slot]: { versionId: sha256("competing-current"), payload: writePlan[0].payload } }), bindings: result.bindings, authorization: authorization() }), /exact completed/i);
    await assert.rejects(() => verifyLiveProductionDualSlotRebaseline({ client: cliTopologyClient(REBASELINE_SLOT_ORDER, { [slot]: { stages: ["AWSCURRENT", "AWSPREVIOUS"] } }), bindings: result.bindings, authorization: authorization() }), /exact completed/i);
  } finally { rmSync(outputs.directory, { recursive: true, force: true }); }
});

test("the runtime CLI verifier grounds completion claims in live Secrets Manager reads", async () => {
  const outputs = temporary();
  try {
    const result = await execute(executionAdapters(), outputs);
    for (let completed = 0; completed < REBASELINE_SLOT_ORDER.length; completed += 1) assert.throws(() => verifyLiveProductionDualSlotRebaselineWithRunner({ run: cliTopologyRunner(REBASELINE_SLOT_ORDER.slice(0, completed)), bindings: result.bindings, authorization: authorization() }), /exact completed|payload/i);
    assert.doesNotThrow(() => verifyLiveProductionDualSlotRebaselineWithRunner({ run: cliTopologyRunner(REBASELINE_SLOT_ORDER), bindings: result.bindings, authorization: authorization() }));
  } finally { rmSync(outputs.directory, { recursive: true, force: true }); }
});

test("runtime call graph propagates independently resolved rebaseline authorization", async () => {
  const outputs = temporary();
  try {
    const auth = authorization();
    const result = await execute(executionAdapters(), outputs);
    const liveLegacyBaseline = { ...legacyBaseline };
    assert.equal(buildInitialMigrationSourceAdvance({ currentSourceSha: sourceSha, rotationBindings: result.bindings, rebaselineAuthorization: auth, liveLegacyBaseline }), undefined);
    assert.throws(() => buildInitialMigrationSourceAdvance({ currentSourceSha: sourceSha, rotationBindings: result.bindings, liveLegacyBaseline }), /authorization/i);
    assert.throws(() => buildInitialMigrationSourceAdvance({ currentSourceSha: sourceSha, rotationBindings: result.bindings, rebaselineAuthorization: { ...auth, sourceSha: "b".repeat(40) }, liveLegacyBaseline }), /authorization|hash|source/i);
    assert.throws(() => buildInitialMigrationSourceAdvance({ currentSourceSha: sourceSha, rotationBindings: result.bindings, rebaselineAuthorization: { ...auth, rotationId: "rotation-other-authorized" }, liveLegacyBaseline }), /authorization|hash|rotation/i);
    const config = buildProductionRotationConfig({ sourceSha, rotationId, approval: { ticket: "CHG-REBASELINE-1", approvedBy: "checker", approverRole: "production-independent-checker", reason: "fixture", verificationRef: "ticket-fixture", minimumGraceSeconds: 2592000 }, bindings: result.bindings, rebaselineAuthorization: auth, rebaselineAuthorizationCoordinates: { workflowRunId: "123456", workflowRunAttempt: "1" }, verifyRebaselineLivePostWrite: () => ({ kind: "PRODUCTION_DUAL_SLOT_REBASELINE_LIVE_POST_WRITE", sourceSha, rotationId, authorizationSha256: auth.authorizationSha256, resources, versionIds: auth.writeIdentities, payloadIdentities: auth.writePayloadIdentities, livePostWriteSha256: canonicalSha256({ kind: "PRODUCTION_DUAL_SLOT_REBASELINE_LIVE_POST_WRITE", sourceSha, rotationId, authorizationSha256: auth.authorizationSha256, resources, versionIds: auth.writeIdentities, payloadIdentities: auth.writePayloadIdentities }) }) });
    assert.equal(config.operation, PRODUCTION_DUAL_SLOT_REBASELINE.kind);
    const configInput = { sourceSha, rotationId, approval: { ticket: "CHG-REBASELINE-1", approvedBy: "checker", approverRole: "production-independent-checker", reason: "fixture", verificationRef: "ticket-fixture", minimumGraceSeconds: 2592000 }, bindings: result.bindings, rebaselineAuthorization: auth, verifyRebaselineLivePostWrite: () => ({ kind: "PRODUCTION_DUAL_SLOT_REBASELINE_LIVE_POST_WRITE", sourceSha, rotationId, authorizationSha256: auth.authorizationSha256, resources, versionIds: auth.writeIdentities, payloadIdentities: auth.writePayloadIdentities, livePostWriteSha256: canonicalSha256({ kind: "PRODUCTION_DUAL_SLOT_REBASELINE_LIVE_POST_WRITE", sourceSha, rotationId, authorizationSha256: auth.authorizationSha256, resources, versionIds: auth.writeIdentities, payloadIdentities: auth.writePayloadIdentities }) }) };
    assert.throws(() => buildProductionRotationConfig({ ...configInput }), /coordinates/i);
    assert.throws(() => buildProductionRotationConfig({ ...configInput, rebaselineAuthorizationCoordinates: { workflowRunId: "123456", workflowRunAttempt: "1" }, rebaselineAuthorization: undefined }), /authorization/i);
  } finally { rmSync(outputs.directory, { recursive: true, force: true }); }
});

test("production command runner preserves binary authorization-artifact options", () => {
  let captured;
  const run = createProductionCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.INJECTED_TEST, exec: (file, args, options) => {
    captured = { file, args, options };
    return Buffer.from("artifact");
  } });
  assert.deepEqual(run(["gh", "api", "repos/example/actions/artifacts/1/zip"], { encoding: null, maxBuffer: 1234 }), Buffer.from("artifact"));
  assert.equal(captured.file, "gh");
  assert.equal(captured.options.encoding, null);
  assert.equal(captured.options.maxBuffer, 1234);
});

test("production topology rejects ambiguous current staging and substituted Secret Manager reads", async () => {
  const ambiguous = cliTopologyClient(); const sendAmbiguous = ambiguous.send;
  ambiguous.send = async (command) => {
    const response = await sendAmbiguous(command);
    return command.constructor.name === "DescribeSecretCommand" ? { ...response, VersionIdsToStages: { ...response.VersionIdsToStages, [sha256("second-current")]: ["AWSCURRENT"] } } : response;
  };
  await assert.rejects(() => readPreparedDualSlotTopology({ client: ambiguous, preparation, writePlan }), /exactly one/i);
  const substituted = cliTopologyClient(); const sendSubstituted = substituted.send;
  substituted.send = async (command) => {
    const response = await sendSubstituted(command);
    return command.constructor.name === "GetSecretValueCommand" ? { ...response, VersionId: sha256("substituted-version") } : response;
  };
  await assert.rejects(() => readPreparedDualSlotTopology({ client: substituted, preparation, writePlan }), /substituted/i);
});

test("production execute CLI authenticates every H-to-N resume state before invoking its executor", async () => {
  for (let completed = 0; completed <= 7; completed += 1) {
    const outputs = temporary(); const preparationFile = path.join(outputs.directory, "preparation.json"); const journalFile = path.join(outputs.directory, "journal.json");
    writeFileSync(preparationFile, JSON.stringify(preparation), { mode: 0o600 }); chmodSync(preparationFile, 0o600);
    writeRebaselineMaterialJournal({ filePath: journalFile, repositoryRoot: process.cwd(), sourceSha, rotationId, baselineIdentitySha256: identity.identitySha256, generatedMaterial: material });
    const captured = []; const client = { ...cliTopologyClient(REBASELINE_SLOT_ORDER.slice(0, completed)), assertCredentialIdentity: async () => {} };
    const result = await runProductionDualSlotRebaselineCli({
      argv: ["--execute", "--source-sha", sourceSha, "--rotation-id", rotationId, "--preparation", preparationFile, "--material-journal", journalFile, "--workflow-run-id", "123456", "--workflow-run-attempt", "1", "--completion-output", outputs.completionFile, "--rotation-bindings-output", outputs.bindingsFile],
      repositoryRoot: process.cwd(), readCheckout: () => ({ toolingSha: sourceSha, porcelainStatus: "" }), createRun: () => () => "{}", createClient: () => client,
      resolveAuthorization: () => ({ authorization: authorization() }), auditReferences: () => audit,
      executePrepared: async (input) => { captured.push(input); return { baselineComplete: true, writes: 0, completion: { baselineBindingSha256: "c".repeat(64) }, completionPath: outputs.completionFile, completionSha256: "d".repeat(64), bindingsPath: outputs.bindingsFile, bindingsSha256: "e".repeat(64) }; }, output: () => {},
    });
    assert.equal(result.baselineComplete, true); assert.equal(captured.length, 1); assert.equal(captured[0].currentPreconditions.liveReferenceAuditSha256, audit.stableAuditSha256);
    rmSync(outputs.directory, { recursive: true, force: true });
  }
});

test("production execute CLI never regenerates missing resume material", async () => {
  const outputs = temporary(); const preparationFile = path.join(outputs.directory, "preparation.json");
  writeFileSync(preparationFile, JSON.stringify(preparation), { mode: 0o600 }); chmodSync(preparationFile, 0o600);
  let topologyRead = false;
  await assert.rejects(() => runProductionDualSlotRebaselineCli({
    argv: ["--execute", "--source-sha", sourceSha, "--rotation-id", rotationId, "--preparation", preparationFile, "--material-journal", path.join(outputs.directory, "missing-journal.json"), "--workflow-run-id", "123456", "--workflow-run-attempt", "1", "--completion-output", outputs.completionFile, "--rotation-bindings-output", outputs.bindingsFile],
    repositoryRoot: process.cwd(), readCheckout: () => ({ toolingSha: sourceSha, porcelainStatus: "" }), createRun: () => () => "{}", createClient: () => ({ assertCredentialIdentity: async () => {} }), resolveAuthorization: () => ({ authorization: authorization() }), readPreparedTopology: async () => { topologyRead = true; throw new Error("must not read topology"); }, output: () => {},
  }), /material journal|ENOENT|does not exist/i);
  assert.equal(topologyRead, false); rmSync(outputs.directory, { recursive: true, force: true });
});

test("production prepare CLI reuses authenticated abandonment evidence after a preparation crash", async () => {
  const outputs = temporary(); const args = ["--prepare", "--source-sha", sourceSha, "--rotation-id", rotationId, "--output-directory", outputs.directory, "--database-dependencies", "0", "--external-consumers", "0"];
  const auditWithLegacy = { ...audit, legacy: legacyBaseline, runningTasks: 2, pendingTasks: 0, activeTaskDefinition: "fixture-backend:1" };
  const common = {
    argv: args, repositoryRoot: process.cwd(), readCheckout: () => ({ toolingSha: sourceSha, porcelainStatus: "" }), createRun: () => () => "{}", createClient: () => ({ assertCredentialIdentity: async () => {} }), historicalTopologySha256,
    gitRun: (gitArgs) => { if (gitArgs[0] === "fetch" || gitArgs[0] === "merge-base") return ""; if (gitArgs[0] === "status") return ""; if (gitArgs[0] === "rev-parse" && gitArgs[1] === "--is-shallow-repository") return "false"; if (gitArgs[0] === "rev-parse" && (gitArgs[1] === "FETCH_HEAD" || gitArgs[1] === "HEAD")) return `${sourceSha}\n`; if (gitArgs[0] === "rev-parse" && gitArgs[1] === "--git-path") return ".git/absent"; if (gitArgs[0] === "symbolic-ref") return "refs/remotes/origin/main"; throw new Error(`unexpected git ${gitArgs.join(" ")}`); },
    readTopology: async () => ({ resources, currentVersionIds, observedSlotIdentities, observedSlotIdentitiesSha256: canonicalSha256(observedSlotIdentities) }), auditReferences: () => auditWithLegacy, output: () => {},
  };
  let crash = true;
  await assert.rejects(() => runProductionDualSlotRebaselineCli({ ...common, afterAbandonmentPersist: async () => { if (crash) throw new Error("injected preparation crash"); } }), /injected preparation crash/);
  const abandonmentPath = path.join(outputs.directory, "abandonment-evidence.json"); const firstEvidence = readFileSync(abandonmentPath);
  assert.equal(existsSync(path.join(outputs.directory, "rebaseline-preparation.json")), false);
  crash = false;
  const resumed = await runProductionDualSlotRebaselineCli({ ...common });
  assert.equal(resumed.writeCount, 7); assert.deepEqual(readFileSync(abandonmentPath), firstEvidence); assert.equal(existsSync(resumed.preparationFile), true);
  rmSync(outputs.directory, { recursive: true, force: true });
});

test("production prepare CLI resumes an exact preparation published before its process acknowledgement", async () => {
  const outputs = temporary();
  const auditWithLegacy = { ...audit, legacy: legacyBaseline, runningTasks: 2, pendingTasks: 0, activeTaskDefinition: "fixture-backend:1" };
  const common = {
    argv: ["--prepare", "--source-sha", sourceSha, "--rotation-id", rotationId, "--output-directory", outputs.directory, "--database-dependencies", "0", "--external-consumers", "0"],
    repositoryRoot: process.cwd(), readCheckout: () => ({ toolingSha: sourceSha, porcelainStatus: "" }), createRun: () => () => "{}", createClient: () => ({ assertCredentialIdentity: async () => {} }), historicalTopologySha256,
    gitRun: (gitArgs) => { if (gitArgs[0] === "fetch" || gitArgs[0] === "merge-base") return ""; if (gitArgs[0] === "status") return ""; if (gitArgs[0] === "rev-parse" && gitArgs[1] === "--is-shallow-repository") return "false"; if (gitArgs[0] === "rev-parse" && (gitArgs[1] === "FETCH_HEAD" || gitArgs[1] === "HEAD")) return `${sourceSha}\n`; if (gitArgs[0] === "rev-parse" && gitArgs[1] === "--git-path") return ".git/absent"; if (gitArgs[0] === "symbolic-ref") return "refs/remotes/origin/main"; throw new Error(`unexpected git ${gitArgs.join(" ")}`); },
    readTopology: async () => ({ resources, currentVersionIds, observedSlotIdentities, observedSlotIdentitiesSha256: canonicalSha256(observedSlotIdentities) }), auditReferences: () => auditWithLegacy, output: () => {},
  };
  await assert.rejects(() => runProductionDualSlotRebaselineCli({ ...common, afterPreparationPersist: async () => { throw new Error("injected post-preparation crash"); } }), /injected post-preparation crash/);
  const preparationPath = path.join(outputs.directory, "rebaseline-preparation.json");
  const firstPreparation = readFileSync(preparationPath);
  const resumed = await runProductionDualSlotRebaselineCli(common);
  assert.equal(resumed.preparationSha256.length, 64);
  assert.deepEqual(readFileSync(preparationPath), firstPreparation);
  const divergent = JSON.parse(readFileSync(preparationPath, "utf8"));
  divergent.writePlan[0].clientRequestToken = sha256("divergent-preparation-write");
  const { preparationSha256, ...preparationBody } = divergent;
  divergent.preparationSha256 = canonicalSha256(preparationBody);
  writeFileSync(preparationPath, `${JSON.stringify(divergent)}\n`);
  await assert.rejects(() => runProductionDualSlotRebaselineCli(common), /write plan|preparation/i);
  rmSync(outputs.directory, { recursive: true, force: true });
});

test("production prepare CLI rejects a divergent existing abandonment artifact", async () => {
  const outputs = temporary(); const args = ["--prepare", "--source-sha", sourceSha, "--rotation-id", rotationId, "--output-directory", outputs.directory, "--database-dependencies", "0", "--external-consumers", "0"];
  const auditWithLegacy = { ...audit, legacy: legacyBaseline, runningTasks: 2, pendingTasks: 0, activeTaskDefinition: "fixture-backend:1" };
  const common = {
    argv: args, repositoryRoot: process.cwd(), readCheckout: () => ({ toolingSha: sourceSha, porcelainStatus: "" }), createRun: () => () => "{}", createClient: () => ({ assertCredentialIdentity: async () => {} }), historicalTopologySha256,
    gitRun: (gitArgs) => { if (gitArgs[0] === "fetch" || gitArgs[0] === "merge-base") return ""; if (gitArgs[0] === "status") return ""; if (gitArgs[0] === "rev-parse" && gitArgs[1] === "--is-shallow-repository") return "false"; if (gitArgs[0] === "rev-parse" && (gitArgs[1] === "FETCH_HEAD" || gitArgs[1] === "HEAD")) return `${sourceSha}\n`; if (gitArgs[0] === "rev-parse" && gitArgs[1] === "--git-path") return ".git/absent"; if (gitArgs[0] === "symbolic-ref") return "refs/remotes/origin/main"; throw new Error(`unexpected git ${gitArgs.join(" ")}`); },
    readTopology: async () => ({ resources, currentVersionIds, observedSlotIdentities, observedSlotIdentitiesSha256: canonicalSha256(observedSlotIdentities) }), auditReferences: () => auditWithLegacy, output: () => {},
  };
  await runProductionDualSlotRebaselineCli({ ...common });
  const abandonmentPath = path.join(outputs.directory, "abandonment-evidence.json"); const divergent = JSON.parse(readFileSync(abandonmentPath, "utf8")); divergent.currentVersionIds = { ...divergent.currentVersionIds, jwtPending: "divergent-version" }; writeFileSync(abandonmentPath, `${JSON.stringify(divergent, null, 2)}\n`);
  await assert.rejects(() => runProductionDualSlotRebaselineCli({ ...common }), /hash|identity|match|exact/i);
  rmSync(outputs.directory, { recursive: true, force: true });
});

test("seven-slot execution resumes at every write boundary and persists exact completion plus bindings", async () => {
  for (let failAt = 1; failAt <= 7; failAt += 1) { const outputs = temporary(); const adapters = executionAdapters({ failAt }); await assert.rejects(() => execute(adapters, outputs), /interruption/); const resumed = await execute(adapters, outputs); assert.equal(resumed.baselineComplete, true); assert.equal(JSON.stringify(resumed.completion).includes(material.jwt), false); assert.equal(readFileSync(outputs.completionFile, "utf8").includes(material.jwt), false); rmSync(outputs.directory, { recursive: true, force: true }); }
});

test("every partial write boundary resumes through harmless ECS task replacement but not a changed task-definition set", async () => {
  for (let failAt = 0; failAt <= 7; failAt += 1) {
    const outputs = temporary(); let observation = 0;
    const adapters = executionAdapters({ failAt, liveReferenceAudit: () => ({ ...audit, auditSha256: canonicalSha256({ observation: observation++, taskArn: `replacement-${observation}` }) }) });
    if (failAt > 0) await assert.rejects(() => execute(adapters, outputs), /interruption/);
    const resumed = await execute(adapters, outputs); assert.equal(resumed.baselineComplete, true); assert.equal(resumed.writes, failAt === 0 ? 7 : 7 - failAt);
    rmSync(outputs.directory, { recursive: true, force: true });
  }
  const outputs = temporary(); const unsafe = executionAdapters({ liveReferenceAudit: { ...audit, stableAuditSha256: "0".repeat(64) } });
  await assert.rejects(() => execute(unsafe, outputs), /security topology/); assert.equal([...unsafe.store.values()].every((versions) => versions.length === 1), true);
  rmSync(outputs.directory, { recursive: true, force: true });
});

test("executor rejects an unrecognized current secret version before another write", async () => {
  const outputs = temporary(); const adapters = executionAdapters(); const slot = REBASELINE_SLOT_ORDER[0];
  adapters.store.set(slot, [{ versionId: sha256("unexpected-current"), stages: ["AWSCURRENT"], payloadSha256: canonicalSha256({ value: "unrelated" }) }]);
  await assert.rejects(() => execute(adapters, outputs), /neither the authenticated historical state nor the exact prepared write/);
  assert.equal([...adapters.store.values()].every((versions) => versions.length === 1), true);
  rmSync(outputs.directory, { recursive: true, force: true });
});

test("completion and bindings persistence crash windows resume with zero duplicate secret versions", async () => {
  for (const hook of ["afterCompletionPersist", "afterBindingsPersist"]) {
    const outputs = temporary(); const adapters = executionAdapters(); let injected = false;
    await assert.rejects(() => execute(adapters, outputs, { [hook]: async () => { if (!injected) { injected = true; throw new Error(`crash after ${hook}`); } } }), /crash/);
    const resumed = await execute(adapters, outputs); assert.equal(resumed.writes, 0); assert.equal(resumed.baselineComplete, true); rmSync(outputs.directory, { recursive: true, force: true });
  }
});

test("immutable JSON publication never leaves a partial final path across crash points", () => {
  const value = { schemaVersion: 1, kind: "crash-safe-fixture", identity: "a".repeat(64) };
  const crashMethods = ["openSync", "writeSync", "fsyncSync", "closeSync", "linkSync"];
  for (const method of crashMethods) {
    const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-persist-crash-")); chmodSync(directory, 0o700);
    const filePath = path.join(directory, "completion.json"); let crashed = false;
    const fsOps = new Proxy(fs, { get(target, property) { const operation = target[property]; if (property !== method || typeof operation !== "function") return operation; return (...args) => { if (!crashed) { crashed = true; throw new Error(`injected ${method} crash`); } return operation(...args); }; } });
    assert.throws(() => persistExactPrivateJson({ filePath, value, repositoryRoot: process.cwd(), label: "Crash fixture", fsOps }), /crash/);
    assert.equal(fs.existsSync(filePath), false); assert.doesNotThrow(() => persistExactPrivateJson({ filePath, value, repositoryRoot: process.cwd(), label: "Crash fixture" }));
    assert.deepEqual(JSON.parse(readFileSync(filePath, "utf8")), value); rmSync(directory, { recursive: true, force: true });
  }
});

test("immutable JSON publication resumes exact finals, ignores orphan temps, and rejects races or replacements", () => {
  const value = { schemaVersion: 1, kind: "publication-fixture", identity: "b".repeat(64) }; const other = { ...value, identity: "c".repeat(64) };
  const scenarios = [
    (directory, filePath) => { writeFileSync(path.join(directory, ".stage-b-private-orphan.tmp"), "truncated", { mode: 0o600 }); },
    (directory, filePath) => { writeFileSync(path.join(directory, ".stage-b-private-complete.tmp"), `${JSON.stringify(value)}\n`, { mode: 0o600 }); },
  ];
  for (const seedOrphan of scenarios) { const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-persist-orphan-")); chmodSync(directory, 0o700); const filePath = path.join(directory, "bindings.json"); seedOrphan(directory, filePath); assert.doesNotThrow(() => persistExactPrivateJson({ filePath, value, repositoryRoot: process.cwd(), label: "Orphan fixture" })); rmSync(directory, { recursive: true, force: true }); }
  for (const seed of [value, other]) { const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-persist-final-")); chmodSync(directory, 0o700); const filePath = path.join(directory, "bindings.json"); writeFileSync(filePath, `${JSON.stringify(seed, null, 2)}\n`, { mode: 0o600 }); if (seed === value) assert.doesNotThrow(() => persistExactPrivateJson({ filePath, value, repositoryRoot: process.cwd(), label: "Existing fixture" })); else assert.throws(() => persistExactPrivateJson({ filePath, value, repositoryRoot: process.cwd(), label: "Existing fixture" }), /different|identity/i); rmSync(directory, { recursive: true, force: true }); }
  for (const raceValue of [value, other]) { const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-persist-race-")); chmodSync(directory, 0o700); const filePath = path.join(directory, "completion.json"); const fsOps = new Proxy(fs, { get(target, property) { const operation = target[property]; if (property !== "linkSync") return operation; return (temporary, final) => { writeFileSync(final, `${JSON.stringify(raceValue, null, 2)}\n`, { mode: 0o600, flag: "wx" }); return operation.call(target, temporary, final); }; } }); if (raceValue === value) assert.doesNotThrow(() => persistExactPrivateJson({ filePath, value, repositoryRoot: process.cwd(), label: "Race fixture", fsOps })); else assert.throws(() => persistExactPrivateJson({ filePath, value, repositoryRoot: process.cwd(), label: "Race fixture", fsOps }), /different|identity/i); rmSync(directory, { recursive: true, force: true }); }
});

test("publication failure after no-replace link leaves a complete final that retries safely", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-persist-after-link-")); chmodSync(directory, 0o700); const filePath = path.join(directory, "completion.json"); const value = { kind: "after-link", identity: "d".repeat(64) }; let fsyncCalls = 0;
  const fsOps = new Proxy(fs, { get(target, property) { const operation = target[property]; if (property !== "fsyncSync") return operation; return (...args) => { fsyncCalls += 1; if (fsyncCalls === 2) throw new Error("injected post-publication crash"); return operation(...args); }; } });
  assert.throws(() => persistExactPrivateJson({ filePath, value, repositoryRoot: process.cwd(), label: "Post-link fixture", fsOps }), /post-publication/); assert.deepEqual(JSON.parse(readFileSync(filePath, "utf8")), value); assert.doesNotThrow(() => persistExactPrivateJson({ filePath, value, repositoryRoot: process.cwd(), label: "Post-link fixture" })); rmSync(directory, { recursive: true, force: true });
});

test("material journal uses the same crash-safe immutable publication path", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-journal-crash-")); chmodSync(directory, 0o700); const filePath = path.join(directory, "material-journal.json"); let failed = false;
  const fsOps = new Proxy(fs, { get(target, property) { const operation = target[property]; if (property !== "writeSync") return operation; return (...args) => { if (!failed) { failed = true; throw new Error("injected journal write crash"); } return operation(...args); }; } });
  assert.throws(() => writeRebaselineMaterialJournal({ filePath, repositoryRoot: process.cwd(), sourceSha, rotationId, baselineIdentitySha256: identity.identitySha256, generatedMaterial: material, fsOps }), /journal write crash/); assert.equal(fs.existsSync(filePath), false); assert.doesNotThrow(() => writeRebaselineMaterialJournal({ filePath, repositoryRoot: process.cwd(), sourceSha, rotationId, baselineIdentitySha256: identity.identitySha256, generatedMaterial: material })); rmSync(directory, { recursive: true, force: true });
});

test("durable output preflight fails before any secret write when an existing output accompanies a partial baseline", async () => {
  const outputs = temporary(); writeFileSync(outputs.completionFile, "{}", { mode: 0o600 }); const adapters = executionAdapters();
  await assert.rejects(() => execute(adapters, outputs), /output|incomplete/i);
  assert.equal([...adapters.store.entries()].every(([slot, versions]) => versions.length === 1 && versions[0].versionId === currentVersionIds[slot]), true);
  rmSync(outputs.directory, { recursive: true, force: true });
});

test("runtime admits only a declared rebaseline producer anchored to independent authorization", async () => {
  const outputs = temporary(); const result = await execute(executionAdapters(), outputs); const auth = authorization();
  assertBaselineCompletion(result.completion, { sourceSha, rotationId, resources, authorizationBinding: auth.authorizationSha256, writePayloadIdentities: auth.writePayloadIdentities }); assertRebaselineRotationBindings(result.bindings, { authorization: auth }); assert.doesNotThrow(() => assertBindings(result.bindings, { rebaselineAuthorization: auth }));
  const stripped = { ...result.bindings }; delete stripped.operation; delete stripped.baselineCompletionSha256; assert.throws(() => assertBindings(stripped, { rebaselineAuthorization: auth }), /schema|producer|rebaseline/i);
  const fabricated = { ...result.completion, authorizationBinding: "f".repeat(64) }; fabricated.baselineBindingSha256 = canonicalSha256(Object.fromEntries(Object.entries(fabricated).filter(([key]) => key !== "baselineBindingSha256"))); const bad = { ...result.bindings, baselineCompletion: fabricated, baselineCompletionSha256: fabricated.baselineBindingSha256 }; assert.throws(() => assertBindings(bad, { rebaselineAuthorization: auth }), /authorization/i);
  assert.doesNotThrow(() => readBoundBaselineCompletion({ filePath: outputs.completionFile, expectedSha256: result.completionSha256, authorization: auth }));
  assert.throws(() => readBoundBaselineCompletion({ filePath: outputs.completionFile, expectedSha256: result.completionSha256, authorization: { ...auth, authorizationSha256: "f".repeat(64) } }), /hash|authorization/i);
  rmSync(outputs.directory, { recursive: true, force: true });
});

test("runtime legacy/current secret identifiers are anchored to the authorized baseline identity", async () => {
  const outputs = temporary(); const result = await execute(executionAdapters(), outputs); const auth = authorization();
  for (const [group, field] of [["jwt", "currentSecretId"], ["qr", "privateCurrentSecretId"], ["qr", "publicCurrentSecretId"]]) {
    const tampered = structuredClone(result.bindings); tampered[group][field] = `${tampered[group][field]}-substituted`;
    assert.throws(() => assertRebaselineRotationBindings(tampered, { authorization: auth }), /legacy baseline|authorization|inconsistent/i);
  }
  const swapped = structuredClone(result.bindings); swapped.jwt.currentSecretId = result.bindings.qr.publicCurrentSecretId; swapped.legacy.jwtCurrent = swapped.jwt.currentSecretId;
  assert.throws(() => assertRebaselineRotationBindings(swapped, { authorization: auth }), /legacy baseline|authorization|inconsistent/i);
  rmSync(outputs.directory, { recursive: true, force: true });
});

test("runtime authorization resolver derives the expected digest from GitHub provenance, never the completion", () => {
  const auth = authorization(); const archive = Buffer.from("zip-fixture"); const seen = [];
  const run = (command, args, options) => {
    seen.push({ command, args, options });
    if (command === "gh" && args[1] === "repos/T-ej2003/genuine-scan-main/actions/runs/123456") return JSON.stringify({ id: 123456, repository: { id: 9, full_name: PRODUCTION_DUAL_SLOT_REBASELINE.repository }, head_repository: { full_name: PRODUCTION_DUAL_SLOT_REBASELINE.repository }, path: ".github/workflows/authorize-production-dual-slot-rebaseline.yml", event: "workflow_dispatch", head_sha: sourceSha, status: "completed", conclusion: "success", run_attempt: 1, actor: { login: "checker" } });
    if (command === "gh" && args[1].endsWith("/artifacts")) return JSON.stringify([{ artifacts: [{ id: 91, name: "production-dual-slot-rebaseline-authorization", expired: false, workflow_run: { id: 123456, head_sha: sourceSha, repository_id: 9 }, digest: `sha256:${sha256(archive)}` }] }]);
    if (command === "gh" && args[1].endsWith("/zip")) return archive;
    if (command === "unzip" && args[0] === "-Z1") return "authorization.json\n";
    if (command === "unzip" && args[0] === "-Z") return "-  authorization.json\n";
    if (command === "unzip" && args[0] === "-p") return JSON.stringify(auth);
    throw new Error(`unexpected ${command} ${args.join(" ")}`);
  };
  const resolved = resolveProductionDualSlotRebaselineAuthorizationArtifact({ workflowRunId: "123456", workflowRunAttempt: "1", sourceSha, rotationId, resources, run });
  assert.equal(resolved.authorization.authorizationSha256, auth.authorizationSha256); const zip = seen.find(({ args }) => args[1].endsWith("/zip")); assert.equal(zip.options.encoding, null); assert.equal(zip.args.includes("--output"), false);
});

test("full live ECS audit rejects a legacy running revision when service points at a newer revision", () => {
  const old = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:50"; const current = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:51"; const legacy = [legacyBaseline.jwtCurrent, legacyBaseline.qrPrivateCurrent, legacyBaseline.qrPublicCurrent]; const definition = (arn, references = []) => ({ taskDefinition: { taskDefinitionArn: arn, containerDefinitions: [{ name: "backend", secrets: [...legacy, ...references].map((valueFrom, index) => ({ name: ["JWT_SECRET", "QR_SIGN_PRIVATE_KEY", "QR_SIGN_PUBLIC_KEY"][index] || `EXTRA_${index}`, valueFrom })), environment: [{ name: "QR_SIGN_ACTIVE_KEY_VERSION", value: "legacy-v1" }] }] } });
  const run = (args) => { if (args[1] === "describe-services") return JSON.stringify({ services: [{ serviceArn: "arn:aws:ecs:eu-west-2:368992683803:service/mscqr", taskDefinition: current, desiredCount: 2, runningCount: 1, pendingCount: 1, deployments: [{ id: "primary", status: "PRIMARY", taskDefinition: current }, { id: "rollback", status: "ACTIVE", taskDefinition: old }], deploymentController: { type: "ECS" } }] }); if (args[1] === "list-tasks") return JSON.stringify({ taskArns: args.includes("RUNNING") ? ["arn:aws:ecs:eu-west-2:368992683803:task/old"] : args.includes("PENDING") ? ["arn:aws:ecs:eu-west-2:368992683803:task/pending"] : [] }); if (args[1] === "describe-tasks") return JSON.stringify({ tasks: [{ taskArn: "arn:aws:ecs:eu-west-2:368992683803:task/old", taskDefinitionArn: old, lastStatus: "RUNNING", desiredStatus: "RUNNING" }, { taskArn: "arn:aws:ecs:eu-west-2:368992683803:task/pending", taskDefinitionArn: old, lastStatus: "PENDING", desiredStatus: "RUNNING" }] }); if (args[1] === "describe-task-definition") return JSON.stringify(args[args.indexOf("--task-definition") + 1] === old ? definition(old, [resources.jwtPending]) : definition(current)); throw new Error(`unexpected ${args.join(" ")}`); };
  const result = auditLiveProductionDualSlotReferences({ run, resources }); assert.equal(result.status, "FAIL"); assert.equal(result.dualSlotReferences, 1); assert.equal(result.evidence.taskDefinitionArns.includes(old), true);
});

test("ECS audit distinguishes harmless task replacement from a safe-but-reauthorization-worthy definition change", () => {
  const td50 = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:50"; const td51 = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:51";
  const legacy = [legacyBaseline.jwtCurrent, legacyBaseline.qrPrivateCurrent, legacyBaseline.qrPublicCurrent];
  const definition = (arn) => ({ taskDefinition: { taskDefinitionArn: arn, containerDefinitions: [{ name: "backend", secrets: legacy.map((valueFrom, index) => ({ name: ["JWT_SECRET", "QR_SIGN_PRIVATE_KEY", "QR_SIGN_PUBLIC_KEY"][index], valueFrom })), environment: [{ name: "QR_SIGN_ACTIVE_KEY_VERSION", value: "legacy-v1" }] }] } });
  const run = (taskArn, taskDefinition) => (args) => {
    if (args[1] === "describe-services") return JSON.stringify({ services: [{ serviceArn: "arn:aws:ecs:eu-west-2:368992683803:service/mscqr", taskDefinition, desiredCount: 2, runningCount: 2, pendingCount: 0, deployments: [{ id: "primary", status: "PRIMARY", taskDefinition }], deploymentController: { type: "ECS" } }] });
    if (args[1] === "list-tasks") return JSON.stringify({ taskArns: args.includes("RUNNING") ? [taskArn] : [] });
    if (args[1] === "describe-tasks") return JSON.stringify({ tasks: [{ taskArn, taskDefinitionArn: taskDefinition, lastStatus: "RUNNING", desiredStatus: "RUNNING" }] });
    if (args[1] === "describe-task-definition") return JSON.stringify(definition(args[args.indexOf("--task-definition") + 1]));
    throw new Error(`unexpected ${args.join(" ")}`);
  };
  const first = auditLiveProductionDualSlotReferences({ run: run("arn:aws:ecs:eu-west-2:368992683803:task/old", td50), resources });
  const replacement = auditLiveProductionDualSlotReferences({ run: run("arn:aws:ecs:eu-west-2:368992683803:task/new", td50), resources });
  const changedDefinition = auditLiveProductionDualSlotReferences({ run: run("arn:aws:ecs:eu-west-2:368992683803:task/newer", td51), resources });
  assert.equal(first.status, "PASS"); assert.notEqual(first.auditSha256, replacement.auditSha256); assert.equal(first.stableAuditSha256, replacement.stableAuditSha256);
  assert.equal(changedDefinition.status, "PASS"); assert.notEqual(first.stableAuditSha256, changedDefinition.stableAuditSha256);
});

test("ECS audit fails closed when a listed task cannot be tied to an inspected definition", () => {
  const run = (args) => {
    if (args[1] === "describe-services") return JSON.stringify({ services: [{ serviceArn: "arn:aws:ecs:eu-west-2:368992683803:service/mscqr", taskDefinition: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:50", deployments: [], deploymentController: { type: "ECS" } }] });
    if (args[1] === "list-tasks") return JSON.stringify({ taskArns: args.includes("RUNNING") ? ["arn:aws:ecs:eu-west-2:368992683803:task/uninspectable"] : [] });
    if (args[1] === "describe-tasks") return JSON.stringify({ tasks: [{ taskArn: "arn:aws:ecs:eu-west-2:368992683803:task/uninspectable" }] });
    throw new Error(`unexpected ${args.join(" ")}`);
  };
  assert.throws(() => auditLiveProductionDualSlotReferences({ run, resources }), /inventory is incomplete/i);
});

test("protected checkout rejects tracked, staged, untracked, and substituted source state", () => {
  const fixture = (status = "", head = sourceSha, remote = sourceSha) => (args) => { if (args[0] === "fetch" || args[0] === "merge-base") return ""; if (args[0] === "rev-parse" && args[1] === "FETCH_HEAD") return remote; if (args[0] === "rev-parse" && args[1] === "HEAD") return head; if (args[0] === "rev-parse" && args[1] === "--is-shallow-repository") return "false"; if (args[0] === "rev-parse" && args[1] === "--git-path") return ".git/NOPE"; if (args[0] === "symbolic-ref") return "refs/remotes/origin/main"; if (args[0] === "status") return status; throw new Error(`unexpected git ${args.join(" ")}`); };
  assert.doesNotThrow(() => readAuthenticatedRebaselineCheckout({ sourceSha, gitRun: fixture(), repositoryRoot: process.cwd() })); for (const status of [" M scripts/a.mjs", "M  scripts/a.mjs", "?? node_modules/evil.mjs"]) assert.throws(() => readAuthenticatedRebaselineCheckout({ sourceSha, gitRun: fixture(status), repositoryRoot: process.cwd() }), /modification|untracked/); assert.throws(() => readAuthenticatedRebaselineCheckout({ sourceSha, gitRun: fixture("", "b".repeat(40)), repositoryRoot: process.cwd() }), /requested|match/);
});

test("the rebaseline boundary has no unrelated mutation escape hatch", () => { const contract = readFileSync(new URL("../aws/production-dual-slot-rebaseline-contract.mjs", import.meta.url), "utf8"); const executor = readFileSync(new URL("../aws/rebaseline-production-dual-slot.mjs", import.meta.url), "utf8"); assert.equal(/new\s+(DeleteSecret|UpdateSecret|RegisterTaskDefinition|PutResourcePolicy)Command|\["ecs",\s*"(update-service|register-task-definition)"\]/i.test(contract), false); assert.equal(/new\s+(DeleteSecret|UpdateSecret|RegisterTaskDefinition|PutResourcePolicy)Command|\["ecs",\s*"(update-service|register-task-definition)"\]/i.test(executor), false); assert.equal(executor.includes("PutSecretValueCommand"), true); });

test("production entrypoints pin the private historical topology digest", () => {
  const executor = readFileSync(new URL("../aws/rebaseline-production-dual-slot.mjs", import.meta.url), "utf8");
  const runtime = readFileSync(new URL("../aws/prepare-production-cutover-runtime.mjs", import.meta.url), "utf8");
  assert.match(executor, /historical topology is not the protected-source abandoned identity/);
  assert.match(runtime, /historicalTopologySha256 !== REBASELINE_ABANDONED_HISTORICAL_TOPOLOGY_SHA256/);
  assert.equal(/arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr\/prod\/rotation/.test(readFileSync(new URL("../aws/production-dual-slot-rebaseline-contract.mjs", import.meta.url), "utf8")), false);
});

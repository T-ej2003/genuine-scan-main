import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  REBASELINE_SLOT_ORDER, REBASELINE_HISTORICAL_SOURCE_SHAS,
  buildAbandonmentEvidence, buildRebaselineIdentity, buildRebaselinePayloads,
  buildRebaselineWritePlan, buildBaselineCompletion, buildRebaselineRotationBindings,
  createProductionDualSlotRebaselineAuthorization, generateRebaselineMaterial,
  historicalSlotIdentity, canonicalSha256, fingerprint, sha256, rebaselineWritePayloadIdentities,
  assertRebaselineQrHandoff, PARTIAL_REBASELINE_RECOVERY_BASE_SOURCE_SHA,
  createPartialRebaselineRecoveryAuthorization, buildPartialRebaselineRecoveryCompletion,
  buildPartialRebaselineRecoveryRotationBindings,
} from "../aws/production-dual-slot-rebaseline-contract.mjs";
import { productionSupersessionEvidenceIdentity, productionSupersessionVersionId, assertProductionInitialMigrationSourceAdvance } from "../security/production-initial-migration-source-advance.mjs";
import { createProductionEnvironmentApprovalEvidence, PRODUCTION_ENVIRONMENT_APPROVAL } from "../aws/production-github-environment-approval.mjs";
import { buildProductionRotationConfig } from "../aws/production-cutover-runtime-bootstrap.mjs";
import { prepare, readCurrentState } from "../../backend/scripts/security/rotate-production-signing-material.mjs";
import { validateRotationTransition } from "../security/check-production-rotation-transition.mjs";
import { partialRecoveryEnvelopeFixture, partialRecoveryOriginalPreparationFixture } from "./fixtures/partial-rebaseline-runtime.mjs";
import { makeCanonicalImageAuthorization } from "./fixtures/canonical-image-authorization.mjs";

// Real identities and ownership topology, synthetic Ed25519 key material. No
// production private key or secret payload is retained in this source fixture.
const sourceSha = "eb675a7f806b718e53196fa3dc1bf4845bcc872a";
const rotationId = "rotation-20260829015311-765c8a16";
const historicalRotationId = "rotation-20260826060632-b15b3f51";
const arn = (slot) => `arn:aws:secretsmanager:eu-west-2:368992683803:secret:fixture/${slot}-abcdef`;
const shapes = { jwtPending: ["jwt_secrets", "pending"], qrPrivatePending: ["qr_signing_keys", "pending-private"], qrPublicPending: ["qr_signing_keys", "pending-public"], jwtPrevious: ["jwt_secrets", "empty"], qrPublicPrevious: ["qr_signing_keys", "empty"], qrCurrentVersion: ["qr_key_versions", "current"], qrPreviousVersion: ["qr_key_versions", "previous-empty"] };

test("exact production handoff identities authenticate without retaining production secret material", () => {
  const envelope = partialRecoveryEnvelopeFixture();
  const originalPreparation = partialRecoveryOriginalPreparationFixture();
  assert.equal(envelope.originalSourceSha, sourceSha);
  assert.equal(envelope.rotationId, rotationId);
  assert.equal(originalPreparation.legacyBaseline.qrCurrentVersion, "2026-04-20");
  const predecessor = originalPreparation.abandonmentEvidence.observedSlotIdentities;
  assert.equal(predecessor.qrPublicPending.keyVersion, "c41ca96ab047dd25");
  assert.equal(predecessor.qrPublicPending.observedRotationId, historicalRotationId);
  const recoverySource = PARTIAL_REBASELINE_RECOVERY_BASE_SOURCE_SHA;
  const image = makeCanonicalImageAuthorization({ sourceSha: recoverySource, imageReleaseSha: recoverySource });
  const protectedEnvironmentApprovalEvidence = createProductionEnvironmentApprovalEvidence({ environmentConfig: { name: "production", id: 17, can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: { id: 7, login: "checker" } }] }] }, repository: "T-ej2003/genuine-scan-main", environment: "production", sourceSha: recoverySource, workflowRef: PRODUCTION_ENVIRONMENT_APPROVAL.dualSlotRebaselineRecoveryWorkflowRef, eventName: "workflow_dispatch", workflowRunId: "987655", workflowRunAttempt: "1", executionActor: "operator", observedAt: image.now, actualApproval: { state: "approved", environmentId: 17, environmentName: "production", userId: 7, userLogin: "checker" } });
  const authorization = createPartialRebaselineRecoveryAuthorization({ protectedEnvironmentApprovalEvidence, sourceSha: recoverySource, recoveryEnvelope: envelope, imageAuthorization: image.authorization, imageAuthorizationValidation: { now: image.now, verifyImageEvidence: image.verifyImageEvidence }, liveReferenceAuditSha256: sha256("fixture audit"), liveLegacyBaselineIdentitySha256: sha256("fixture legacy"), observedSlotIdentitiesSha256: sha256("fixture slots"), reason: "source-only handoff fixture", approverRole: "checker", verificationRef: "fixture-handoff", proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === recoverySource && descendantSha === recoverySource });
  const finalSnapshots = originalPreparation.writePlan.map(({ slot, secretArn, clientRequestToken, payloadSha256 }) => ({ slot, arn: secretArn, currentVersionId: clientRequestToken, currentStages: ["AWSCURRENT"], currentPayloadSha256: payloadSha256, versions: [{ versionId: clientRequestToken, stages: ["AWSCURRENT"], payloadSha256 }] }));
  const writePlan = originalPreparation.writePlan.map((entry) => ({ ...entry, payload: { keyVersion: entry.payloadIdentity.keyVersion } }));
  const completion = buildPartialRebaselineRecoveryCompletion({ originalPreparation, sourceSha: recoverySource, recoveryEnvelope: envelope, recoveryAuthorization: authorization, finalSnapshots, writePlan });
  const bindings = buildPartialRebaselineRecoveryRotationBindings({ sourceSha: recoverySource, originalPreparation, recoveryEnvelope: envelope, recoveryAuthorization: authorization, completion });
  const config = { sourceSha: recoverySource, rotationId, jwt: bindings.jwt, qr: bindings.qr, baselineCompletionSha256: completion.baselineBindingSha256, rebaselineRuntime: { bindings, authorization, recoveryEnvelope: envelope, originalPreparation } };
  const state = { pending: { jwtVersionId: completion.versionIds.jwtPending, qrPrivateVersionId: completion.versionIds.qrPrivatePending, qrPublicVersionId: completion.versionIds.qrPublicPending },
    qr: { historicalContinuity: "VERIFIED_PREVIOUS_QR", rollbackCapable: true, oldMetadataKeyVersion: "c41ca96ab047dd25", oldKeyVersion: "2026-04-20", oldPublicFingerprint: predecessor.qrPublicPending.materialFingerprint, oldPrivateFingerprint: predecessor.qrPrivatePending.materialFingerprint,
      newPublicFingerprint: completion.payloadIdentities.qrPublicPending.keyVersion, newKeyVersion: completion.payloadIdentities.qrPublicPending.keyVersion } };
  // Metadata-only half of the proof: all seven exact authorized payload hashes
  // and versions are validated by the real completion/binding contracts above.
  // The synthetic-key tests below exercise the actual snapshot and promotion.
  assert.equal(assertRebaselineQrHandoff({ config, state }), "c41ca96ab047dd25");
  for (const field of ["historicalContinuity", "rollbackCapable", "oldMetadataKeyVersion", "oldKeyVersion", "oldPublicFingerprint", "oldPrivateFingerprint", "newPublicFingerprint", "newKeyVersion"]) {
    const forged = structuredClone(state); forged.qr[field] = "substituted";
    assert.throws(() => assertRebaselineQrHandoff({ config, state: forged }));
  }
  for (const field of Object.keys(state.pending)) {
    const forged = structuredClone(state); forged.pending[field] = "substituted";
    assert.throws(() => assertRebaselineQrHandoff({ config, state: forged }));
  }
  for (const field of ["sourceSha", "rotationId"]) assert.throws(() => assertRebaselineQrHandoff({ config: { ...config, [field]: "substituted" }, state }));
});

test("authenticated initial-migration source advance permits a descendant coordinator source", () => {
  const f = fixture();
  try {
    const currentSourceSha = "f".repeat(40);
    const resources = f.config.rebaselineRuntime.bindings.baselineCompletion.resources;
    const evidence = { schemaVersion: 1, transition: "SUPERSEDE_STALE_PENDING", sourceSha, staleSourceSha: "7".repeat(40), rotationId, staleRotationId: "rotation-stale-source", generatedAt: "2026-08-29T02:00:00.000Z", resources: Object.fromEntries(Object.entries(resources).map(([slot, arn]) => [slot, { arn, versionId: productionSupersessionVersionId(sourceSha, rotationId, slot), stages: ["AWSCURRENT"] }])) };
    evidence.evidenceIdentitySha256 = productionSupersessionEvidenceIdentity(evidence);
    const config = { ...f.config, sourceSha: currentSourceSha, initialMigrationSourceAdvance: { schemaVersion: 1, kind: "PRODUCTION_INITIAL_MIGRATION_SOURCE_ADVANCE", currentSourceSha, supersessionEvidence: evidence } };
    assert.doesNotThrow(() => assertProductionInitialMigrationSourceAdvance(config.initialMigrationSourceAdvance));
    assert.doesNotThrow(() => assertRebaselineQrHandoff({ config, proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === sourceSha && descendantSha === currentSourceSha }));
    assert.throws(() => assertRebaselineQrHandoff({ config: { ...config, initialMigrationSourceAdvance: undefined } }));
    const forged = structuredClone(config); forged.initialMigrationSourceAdvance.currentSourceSha = "e".repeat(40);
    assert.throws(() => assertRebaselineQrHandoff({ config: forged }));
    const wrongPredecessor = structuredClone(config); wrongPredecessor.initialMigrationSourceAdvance.supersessionEvidence.sourceSha = "d".repeat(40);
    wrongPredecessor.initialMigrationSourceAdvance.supersessionEvidence.evidenceIdentitySha256 = productionSupersessionEvidenceIdentity(wrongPredecessor.initialMigrationSourceAdvance.supersessionEvidence);
    assert.throws(() => assertRebaselineQrHandoff({ config: wrongPredecessor }));
  } finally { f.dispose(); }
});

test("production config validates descendant rebaseline authorization at its binding source", () => {
  const f = fixture();
  try {
    const currentSourceSha = "f".repeat(40);
    const runtime = f.config.rebaselineRuntime;
    const bindings = runtime.bindings;
    const resources = bindings.baselineCompletion.resources;
    const livePostWrite = { kind: "PRODUCTION_DUAL_SLOT_REBASELINE_LIVE_POST_WRITE", sourceSha, rotationId, authorizationSha256: runtime.authorization.authorizationSha256, resources, versionIds: runtime.authorization.writeIdentities, payloadIdentities: runtime.authorization.writePayloadIdentities };
    assert.doesNotThrow(() => buildProductionRotationConfig({ sourceSha: currentSourceSha, rotationId, approval: { ticket: "CHG-HANDOFF", approvedBy: "checker", approverRole: "production-independent-checker", reason: "fixture", verificationRef: "ticket-handoff-fixture", minimumGraceSeconds: 2592000 }, bindings, rebaselineAuthorization: runtime.authorization, rebaselineAuthorizationCoordinates: { workflowRunId: "123456", workflowRunAttempt: "1" }, verifyRebaselineLivePostWrite: () => ({ ...livePostWrite, livePostWriteSha256: canonicalSha256(livePostWrite) }), verifyInitialBindingOrigin: () => { throw new Error("not initial bindings"); } }));
  } finally { f.dispose(); }
});

test("production-shaped descendant handoff routes through prepare", async () => {
  const f = fixture();
  try {
    const currentSourceSha = "f".repeat(40);
    const resources = f.config.rebaselineRuntime.bindings.baselineCompletion.resources;
    const evidence = { schemaVersion: 1, transition: "SUPERSEDE_STALE_PENDING", sourceSha, staleSourceSha: "7".repeat(40), rotationId, staleRotationId: "rotation-stale-source", generatedAt: "2026-08-29T02:00:00.000Z", resources: Object.fromEntries(Object.entries(resources).map(([slot, arn]) => [slot, { arn, versionId: productionSupersessionVersionId(sourceSha, rotationId, slot), stages: ["AWSCURRENT"] }])) };
    evidence.evidenceIdentitySha256 = productionSupersessionEvidenceIdentity(evidence);
    const config = { ...f.config, sourceSha: currentSourceSha, initialMigrationSourceAdvance: { schemaVersion: 1, kind: "PRODUCTION_INITIAL_MIGRATION_SOURCE_ADVANCE", currentSourceSha, supersessionEvidence: evidence } };
    const context = { ...f.context, config, proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === sourceSha && descendantSha === currentSourceSha };
    await prepare(context);
    const state = readCurrentState(context);
    assert.equal(state.phase, "overlap-deploy-required");
    assert.equal(state.sourceSha, currentSourceSha);
    assert.equal(state.qr.oldMetadataKeyVersion, f.old.qrKeyVersion);
    assert.equal(state.qr.oldKeyVersion, "2026-04-20");
    const count = f.writes.length;
    await prepare(context);
    assert.equal(f.writes.length, count);
  } finally { f.dispose(); }
});

test("ordinary initial migration keeps the strict marker gate", async () => {
  const f = fixture();
  try {
    const currentSourceSha = "f".repeat(40);
    const resources = f.config.rebaselineRuntime.bindings.baselineCompletion.resources;
    const evidence = { schemaVersion: 1, transition: "SUPERSEDE_STALE_PENDING", sourceSha, staleSourceSha: "7".repeat(40), rotationId, staleRotationId: "rotation-stale-source", generatedAt: "2026-08-29T02:00:00.000Z", resources: Object.fromEntries(Object.entries(resources).map(([slot, arn]) => [slot, { arn, versionId: productionSupersessionVersionId(sourceSha, rotationId, slot), stages: ["AWSCURRENT"] }])) };
    evidence.evidenceIdentitySha256 = productionSupersessionEvidenceIdentity(evidence);
    const config = { ...f.config, sourceSha: currentSourceSha, rebaselineRuntime: undefined, initialMigrationSourceAdvance: { schemaVersion: 1, kind: "PRODUCTION_INITIAL_MIGRATION_SOURCE_ADVANCE", currentSourceSha, supersessionEvidence: evidence } };
    await assert.rejects(prepare({ ...f.context, config, proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === sourceSha && descendantSha === currentSourceSha }), /initial-migration source advance does not match authenticated live state/);
    assert.equal(f.writes.length, 0);
  } finally { f.dispose(); }
});

test("production-shaped handoff rejects an unproven source advance", async () => {
  const f = fixture();
  try {
    const currentSourceSha = "f".repeat(40);
    const resources = f.config.rebaselineRuntime.bindings.baselineCompletion.resources;
    const evidence = { schemaVersion: 1, transition: "SUPERSEDE_STALE_PENDING", sourceSha, staleSourceSha: "7".repeat(40), rotationId, staleRotationId: "rotation-stale-source", generatedAt: "2026-08-29T02:00:00.000Z", resources: Object.fromEntries(Object.entries(resources).map(([slot, arn]) => [slot, { arn, versionId: productionSupersessionVersionId(sourceSha, rotationId, slot), stages: ["AWSCURRENT"] }])) };
    evidence.evidenceIdentitySha256 = productionSupersessionEvidenceIdentity(evidence);
    const config = { ...f.config, sourceSha: currentSourceSha, initialMigrationSourceAdvance: { schemaVersion: 1, kind: "PRODUCTION_INITIAL_MIGRATION_SOURCE_ADVANCE", currentSourceSha, supersessionEvidence: evidence } };
    await assert.rejects(prepare({ ...f.context, config, proveDescendant: () => false }), /QR handoff source ancestry is not authenticated/);
    assert.equal(f.writes.length, 0);
  } finally { f.dispose(); }
});

test("production-shaped handoff rejects substituted legacy JWT", async () => {
  const f = fixture();
  try {
    const record = f.records.get(f.config.jwt.currentSecretId);
    record.payload.value = "substituted-jwt-material";
    await assert.rejects(prepare(f.context), /current JWT does not match prepared lineage|legacy current JWT is not the authenticated predecessor/);
    assert.equal(f.writes.length, 0);
  } finally { f.dispose(); }
});

function fixture() {
  const old = generateRebaselineMaterial();
  const next = generateRebaselineMaterial();
  const resources = Object.fromEntries(REBASELINE_SLOT_ORDER.map((slot) => [slot, arn(slot)]));
  const currentVersionIds = Object.fromEntries(REBASELINE_SLOT_ORDER.map((slot) => [slot, canonicalSha256({ historical: slot })]));
  const historicalTopologySha256 = canonicalSha256({ resources, versionIds: currentVersionIds });
  const historical = Object.fromEntries(REBASELINE_SLOT_ORDER.map((slot) => {
    const [family, kind] = shapes[slot];
    const value = { jwtPending: old.jwt, qrPrivatePending: old.qrPrivate, qrPublicPending: old.qrPublic }[slot];
    return [slot, value ? { rotationId: historicalRotationId, family, slot: kind, ...(family === "qr_signing_keys" ? { keyVersion: old.qrKeyVersion } : {}), materialFingerprint: fingerprint(value), sourceSha: REBASELINE_HISTORICAL_SOURCE_SHAS[0], value } : { family, slot: kind, initialMigration: true, sourceSha: REBASELINE_HISTORICAL_SOURCE_SHAS[0], value: slot === "qrCurrentVersion" ? old.qrKeyVersion : "" }];
  }));
  const observedSlotIdentities = Object.fromEntries(REBASELINE_SLOT_ORDER.map((slot) => [slot, historicalSlotIdentity({ slot, secretArn: resources[slot], versionId: currentVersionIds[slot], stages: ["AWSCURRENT"], payload: historical[slot] })]));
  const liveReferenceAuditSha256 = canonicalSha256({ fixture: "no dual-slot runtime consumers" });
  const abandonmentEvidence = buildAbandonmentEvidence({ sourceSha, historicalRotationId, historicalSourceShas: REBASELINE_HISTORICAL_SOURCE_SHAS, resources, currentVersionIds, historicalTopologySha256, observedSlotIdentities, liveReferenceAudit: "PASS", liveReferenceAuditSha256, legacyRuntimeAuthoritative: true });
  const legacyBaseline = { jwtCurrent: arn("jwtCurrent"), qrPrivateCurrent: arn("qrPrivateCurrent"), qrPublicCurrent: arn("qrPublicCurrent"), qrCurrentVersion: "2026-04-20" };
  const baselineIdentity = buildRebaselineIdentity({ sourceSha, rotationId, resources, abandonmentEvidenceSha256: abandonmentEvidence.evidenceSha256, legacyBaseline });
  const payloads = buildRebaselinePayloads({ sourceSha, rotationId, generatedMaterial: next, legacyBaseline });
  const writePlan = buildRebaselineWritePlan({ sourceSha, rotationId, resources, baselineIdentitySha256: baselineIdentity.identitySha256, payloads });
  const writePayloadIdentities = rebaselineWritePayloadIdentities(writePlan);
  const writeIdentities = Object.fromEntries(writePlan.map(({ slot, clientRequestToken }) => [slot, clientRequestToken]));
  const protectedEnvironmentApprovalEvidence = createProductionEnvironmentApprovalEvidence({ environmentConfig: { name: "production", id: 17, can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: { id: 7, login: "checker" } }] }] }, repository: "T-ej2003/genuine-scan-main", environment: "production", sourceSha, workflowRef: PRODUCTION_ENVIRONMENT_APPROVAL.dualSlotRebaselineWorkflowRef, eventName: "workflow_dispatch", workflowRunId: "123456", workflowRunAttempt: "1", executionActor: "operator", observedAt: "2026-08-29T02:00:00.000Z", actualApproval: { state: "approved", environmentId: 17, environmentName: "production", userId: 7, userLogin: "checker" } });
  const authorization = createProductionDualSlotRebaselineAuthorization({ protectedEnvironmentApprovalEvidence, sourceSha, historicalRotationId, rotationId, abandonmentEvidenceSha256: abandonmentEvidence.evidenceSha256, baselineIdentitySha256: baselineIdentity.identitySha256, resources, writeIdentities, writePayloadIdentities, materialJournalSha256: "b".repeat(64), materialJournalFileSha256: "c".repeat(64), expectedSecretValueWrites: 7, expectedSecretDeletes: 0, liveReferenceAudit: "PASS", liveReferenceAuditSha256, observedSlotIdentitiesSha256: abandonmentEvidence.observedSlotIdentitiesSha256, reason: "Authenticate synthetic rebaseline handoff", approvedBy: "checker", approverRole: "production-independent-checker", verificationRef: "ticket-handoff-fixture" });
  const preconditions = { environment: "production", accountId: "368992683803", region: "eu-west-2", sourceSha, sourceCas: true, cleanWorktree: true, existingSecretResources: true, liveReferenceAudit: "PASS", liveReferenceAuditSha256, legacyRuntimeAuthoritative: true, liveLegacyBaselineCount: 1, databaseDependencies: 0, externalConsumers: 0, dualSlotReferences: 0, runningTasks: 2, pendingTasks: 0, activeTaskDefinition: "mscqr-backend:50", resources, historicalTopologySha256, abandonmentEvidence };
  const finalSnapshots = writePlan.map(({ slot, secretArn, clientRequestToken, payload }) => ({ slot, arn: secretArn, versions: [{ versionId: clientRequestToken, stages: ["AWSCURRENT"], payloadSha256: canonicalSha256(payload) }], currentVersionId: clientRequestToken, currentStages: ["AWSCURRENT"], currentPayloadSha256: canonicalSha256(payload) }));
  const completion = buildBaselineCompletion({ preconditions, sourceSha, rotationId, baselineIdentity, writePlan, finalSnapshots, authorizationBinding: authorization.authorizationSha256, authorizedWritePayloadIdentities: writePayloadIdentities });
  const bindings = buildRebaselineRotationBindings({ sourceSha, rotationId, legacyBaseline, resources, abandonmentEvidence, completion, authorization });
  const livePostWrite = { kind: "PRODUCTION_DUAL_SLOT_REBASELINE_LIVE_POST_WRITE", sourceSha, rotationId, authorizationSha256: authorization.authorizationSha256, resources, versionIds: writeIdentities, payloadIdentities: writePayloadIdentities };
  const config = buildProductionRotationConfig({ sourceSha, rotationId, approval: { ticket: "CHG-HANDOFF", approvedBy: "checker", approverRole: "production-independent-checker", reason: "fixture", verificationRef: "ticket-handoff-fixture", minimumGraceSeconds: 2592000 }, bindings, rebaselineAuthorization: authorization, rebaselineAuthorizationCoordinates: { workflowRunId: "123456", workflowRunAttempt: "1" }, verifyRebaselineLivePostWrite: () => ({ ...livePostWrite, livePostWriteSha256: canonicalSha256(livePostWrite) }), verifyInitialBindingOrigin: () => { throw new Error("not initial bindings"); } });
  const records = new Map(writePlan.map(({ secretArn, clientRequestToken, payload }) => [secretArn, { payload: structuredClone(payload), versionId: clientRequestToken }]));
  for (const [name, value, family, slot] of [["jwtCurrent", old.jwt, "jwt_secrets", "current"], ["qrPrivateCurrent", old.qrPrivate, "qr_signing_keys", "current-private"], ["qrPublicCurrent", old.qrPublic, "qr_signing_keys", "current-public"]]) records.set(arn(name), { versionId: canonicalSha256({ legacyCurrent: name }), payload: { rotationId: historicalRotationId, family, slot, ...(family === "qr_signing_keys" ? { keyVersion: old.qrKeyVersion } : {}), materialFingerprint: fingerprint(value), value } });
  const writes = [];
  const sm = { failAfter: 0, async send(command) {
    const input = command.input;
    if (command.constructor.name === "GetSecretValueCommand") { const record = records.get(input.SecretId); assert.ok(record); return { VersionId: record.versionId, SecretString: JSON.stringify(record.payload) }; }
    assert.equal(command.constructor.name, "PutSecretValueCommand");
    const payload = JSON.parse(input.SecretString);
    records.set(input.SecretId, { payload, versionId: input.ClientRequestToken });
    writes.push({ id: input.SecretId, payload });
    if (sm.failAfter === writes.length) throw new Error("simulated durable-write interruption");
    return { VersionId: input.ClientRequestToken };
  } };
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-handoff-test-"));
  const stateFile = path.join(directory, "state.json");
  const context = { config, sm, identity: "arn:aws:sts::368992683803:assumed-role/mscqr-release-deployer/fixture", clock: () => Date.parse("2026-09-07T00:00:00.000Z"), values: new Map([["state-file", stateFile], ["fixture-file", path.join(directory, "previous-qr.json")]]) };
  return { old, next, config, records, writes, sm, context, stateFile, dispose: () => rmSync(directory, { recursive: true, force: true }) };
}

test("authenticated rebaseline preserves the runtime label and old key identity through promotion and resume", async () => {
  const f = fixture();
  try {
    await prepare(f.context);
    const state = readCurrentState(f.context);
    assert.equal(state.phase, "overlap-deploy-required");
    assert.equal(state.qr.oldKeyVersion, "2026-04-20");
    assert.equal(state.qr.oldMetadataKeyVersion, f.old.qrKeyVersion);
    assert.equal(state.qr.newKeyVersion, f.next.qrKeyVersion);
    assert.equal(f.records.get(arn("qrPublicPrevious")).payload.value, f.old.qrPublic);
    assert.equal(f.records.get(arn("qrPublicPrevious")).payload.keyVersion, "2026-04-20");
    const rawState = readFileSync(f.stateFile);
    assert.equal(validateRotationTransition({ mode: "rotation-overlap", sourceSha, rotationId,
      deploymentSha: state.overlapDeploymentSha, rawState, stateSha256: sha256(rawState),
      taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:51",
      expectedCurrentTaskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:50",
      imageDigest: `sha256:${"d".repeat(64)}`, now: Date.now(),
    }).phase, "overlap-deploy-required");
    const count = f.writes.length;
    await prepare(f.context);
    assert.equal(f.writes.length, count);
  } finally { f.dispose(); }
});

test("completed handoff cannot be replayed as fresh preparation with the same authority", async () => {
  const f = fixture();
  try {
    await prepare(f.context);
    const count = f.writes.length;
    unlinkSync(f.stateFile);
    await assert.rejects(prepare(f.context));
    assert.equal(f.writes.length, count);
  } finally { f.dispose(); }
});

for (const after of [1, 2, 3, 4, 5, 6, 7]) test(`authenticated handoff resumes after promotion write ${after}`, async () => {
  const f = fixture();
  try {
    f.sm.failAfter = after;
    await assert.rejects(prepare(f.context), /simulated durable-write interruption/);
    f.sm.failAfter = 0;
    await prepare(f.context);
    assert.equal(readCurrentState(f.context).phase, "overlap-deploy-required");
    assert.equal(f.writes.length, 7);
  } finally { f.dispose(); }
});

const attacks = {
  "arbitrary metadata mismatch": (f) => { f.records.get(arn("qrPublicCurrent")).payload.keyVersion = "wrong-key"; },
  "substituted current public key": (f) => { f.records.get(arn("qrPublicCurrent")).payload.value = f.next.qrPublic; },
  "wrong adopted label": (f) => { f.records.get(arn("qrCurrentVersion")).payload.value = "wrong-label"; },
  "wrong rotation": (f) => { f.config.rotationId = historicalRotationId; },
  "wrong source": (f) => { f.config.sourceSha = "a".repeat(40); },
  "modified pending material": (f) => { f.records.get(arn("jwtPending")).payload.value += "substituted"; },
  "cross-rotation pending material": (f) => { f.records.get(arn("qrPublicPending")).payload.rotationId = historicalRotationId; },
  "nonempty previous slot": (f) => { f.records.get(arn("jwtPrevious")).payload.value = "not-empty"; },
  "forged initial marker": (f) => { f.records.get(arn("qrPublicPrevious")).payload.sourceSha = "a".repeat(40); },
  "missing provenance": (f) => { delete f.config.rebaselineRuntime; },
  "forged authorization": (f) => { f.config.rebaselineRuntime = structuredClone(f.config.rebaselineRuntime); f.config.rebaselineRuntime.authorization.authorizationSha256 = "a".repeat(64); },
  "mismatched private pair": (f) => { f.records.get(arn("qrPrivateCurrent")).payload.value = f.next.qrPrivate; },
  "unbound abandoned owner": (f) => { f.records.get(arn("qrPublicCurrent")).payload.rotationId = rotationId; },
  "invalid current JWT version": (f) => { f.records.get(arn("jwtCurrent")).versionId = "bad"; },
  "substituted current JWT metadata": (f) => { f.records.get(arn("jwtCurrent")).payload.materialFingerprint = fingerprint(f.next.jwt); },
  "cross-rotation current JWT": (f) => { f.records.get(arn("jwtCurrent")).payload.rotationId = "rotation-unrelated-2026"; },
};
for (const [name, attack] of Object.entries(attacks)) test(`handoff rejects ${name} before mutation`, async () => {
  const f = fixture();
  try { attack(f); await assert.rejects(prepare(f.context)); assert.equal(f.writes.length, 0); } finally { f.dispose(); }
});

test("prepared handoff rejects substituted recorded old-key lineage", async () => {
  const f = fixture();
  try {
    f.sm.failAfter = 1;
    await assert.rejects(prepare(f.context));
    const state = JSON.parse(readFileSync(f.stateFile, "utf8"));
    state.qr.oldPublicFingerprint = f.next.qrKeyVersion;
    writeFileSync(f.stateFile, JSON.stringify(state));
    await assert.rejects(prepare(f.context));
    assert.equal(f.writes.length, 1);
  } finally { f.dispose(); }
});

test("prepared handoff rejects substituted legacy current JWT before promotion", async () => {
  const f = fixture();
  try {
    f.sm.failAfter = 1;
    await assert.rejects(prepare(f.context));
    f.records.get(arn("jwtCurrent")).payload.value = "substituted-jwt-material";
    await assert.rejects(prepare(f.context), /current JWT does not match prepared lineage|legacy current JWT is not the authenticated predecessor/);
    assert.equal(f.writes.length, 1);
  } finally { f.dispose(); }
});

test("prepared handoff rejects substituted new private-key lineage before another write", async () => {
  const f = fixture();
  try {
    f.sm.failAfter = 1;
    await assert.rejects(prepare(f.context));
    const state = JSON.parse(readFileSync(f.stateFile, "utf8"));
    state.qr.newPrivateFingerprint = "f".repeat(16);
    writeFileSync(f.stateFile, JSON.stringify(state));
    await assert.rejects(prepare(f.context));
    assert.equal(f.writes.length, 1);
  } finally { f.dispose(); }
});

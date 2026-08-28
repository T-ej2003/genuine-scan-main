import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import { execFileSync } from "node:child_process";
import { ensureStageBPrivateDirectory, readStageBPrivateFileBytes, writeStageBPrivateFileAtomicExclusive } from "./stage-b-artifact-contract.mjs";
import path from "node:path";
import { assertProductionEnvironmentApprovalIdentity, assertProductionEnvironmentReviewer, PRODUCTION_ENVIRONMENT_APPROVAL } from "./production-github-environment-approval.mjs";

export const PRODUCTION_DUAL_SLOT_REBASELINE = Object.freeze({ schemaVersion: 1, kind: "PRODUCTION_DUAL_SLOT_REBASELINE", repository: "T-ej2003/genuine-scan-main", environment: "production", accountId: "368992683803", region: "eu-west-2", maxSecretValueWrites: 7 });
export const REBASELINE_SLOTS = Object.freeze({ jwtPending: "mscqr/prod/rotation/jwt-pending", qrPrivatePending: "mscqr/prod/rotation/qr-private-pending", qrPublicPending: "mscqr/prod/rotation/qr-public-pending", jwtPrevious: "mscqr/prod/rotation/jwt-previous", qrPublicPrevious: "mscqr/prod/rotation/qr-public-previous", qrCurrentVersion: "mscqr/prod/rotation/qr-current-version", qrPreviousVersion: "mscqr/prod/rotation/qr-previous-version" });
export const REBASELINE_SLOT_ORDER = Object.freeze(Object.keys(REBASELINE_SLOTS));
export const ABANDONED_PRE_CUTOVER = "ABANDONED_PRE_CUTOVER";
export const BASELINE_COMPLETE = "BASELINE_COMPLETE";
export const REBASELINE_WRITE_IDENTITY_DOMAIN = "MSCQR_PRODUCTION_DUAL_SLOT_REBASELINE_WRITE_V1";
export const REBASELINE_AUTHORIZATION_KIND = "PRODUCTION_DUAL_SLOT_REBASELINE_AUTHORIZATION";
export const REBASELINE_MATERIAL_JOURNAL_KIND = "PRODUCTION_DUAL_SLOT_REBASELINE_MATERIAL_JOURNAL";
export const REBASELINE_PREPARATION_KIND = "PRODUCTION_DUAL_SLOT_REBASELINE_PREPARATION";
export const REBASELINE_ROTATION_BINDINGS_KIND = "PRODUCTION_DUAL_SLOT_REBASELINE_ROTATION_BINDINGS";
export const REBASELINE_ROTATION_BINDINGS_PRODUCER = "scripts/aws/production-dual-slot-rebaseline-contract.mjs:buildRebaselineRotationBindings";
export const REBASELINE_HISTORICAL_SOURCE_SHAS = Object.freeze(["5506cbe3972a27a77c211f2891756c3b97de7197", "9f39d1c4f646467146c12c0587fd7ad585f3fe10"]);
// SHA-256 of private retained supersession evidence's exact {resources,versionIds}.
// Production ARNs and version IDs remain private evidence, not committed source.
export const REBASELINE_ABANDONED_HISTORICAL_TOPOLOGY_SHA256 = "80ec0c997561f13e4162e1aeaf9133dd58e4b5aa40f8eba5b13ee3474528e1ae";

const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const ROTATION_ID = /^[A-Za-z0-9._-]{8,128}$/;
const VERSION_ID = /^[A-Za-z0-9+=/:._-]{7,256}$/;
const LEGACY_VERSION_ID = /^[A-Za-z0-9._:-]{1,128}$/;
const SECRET_ARN = new RegExp(`^arn:aws:secretsmanager:${PRODUCTION_DUAL_SLOT_REBASELINE.region}:${PRODUCTION_DUAL_SLOT_REBASELINE.accountId}:secret:[A-Za-z0-9/_+=.@-]+$`);
const canonical = (value) => Array.isArray(value) ? `[${value.map(canonical).join(",")}]` : value && typeof value === "object" ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}` : JSON.stringify(value);
const fail = (message) => { throw new Error(message); };
const text = (value, label) => { if (typeof value !== "string" || !value.trim()) fail(`${label} is required.`); return value.trim(); };
const exactKeys = (value, expected, label) => { if (!value || typeof value !== "object" || Array.isArray(value) || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...expected].sort())) fail(`${label} schema is invalid.`); };
const assertSha40 = (value, label) => { if (!SHA40.test(value || "")) fail(`${label} must be a full source SHA.`); return value; };
const assertSha256 = (value, label) => { if (!SHA256.test(value || "")) fail(`${label} must be a SHA-256.`); return value; };
const assertVersion = (value, label) => { if (!VERSION_ID.test(value || "")) fail(`${label} is invalid.`); return value; };
const assertArn = (value, label) => { if (!SECRET_ARN.test(value || "")) fail(`${label} is outside the production secret boundary.`); return value; };
const assertRotation = (value, label) => { if (!ROTATION_ID.test(value || "")) fail(`${label} is invalid.`); return value; };
export const sha256 = (value) => crypto.createHash("sha256").update(Buffer.isBuffer(value) ? value : String(value)).digest("hex");
export const canonicalSha256 = (value) => sha256(canonical(value));
export const fingerprint = (value) => sha256(value).slice(0, 16);

function assertSlotMap(map, label) {
  exactKeys(map, REBASELINE_SLOT_ORDER, label);
  for (const slot of REBASELINE_SLOT_ORDER) assertArn(map[slot], `${label}.${slot}`);
  if (new Set(Object.values(map)).size !== REBASELINE_SLOT_ORDER.length) fail(`${label} contains duplicate secret resources.`);
  return Object.freeze({ ...map });
}

function assertLegacyBaseline(value, label = "legacyBaseline") {
  exactKeys(value, ["jwtCurrent", "qrPrivateCurrent", "qrPublicCurrent", "qrCurrentVersion"], label);
  for (const name of ["jwtCurrent", "qrPrivateCurrent", "qrPublicCurrent"]) assertArn(value[name], `${label}.${name}`);
  if (!LEGACY_VERSION_ID.test(value.qrCurrentVersion || "")) fail(`${label}.qrCurrentVersion is invalid.`);
  if (new Set([value.jwtCurrent, value.qrPrivateCurrent, value.qrPublicCurrent]).size !== 3) fail(`${label} contains duplicate live secret resources.`);
  return Object.freeze({ ...value });
}

function assertHistoricalSources(sources) {
  if (!Array.isArray(sources) || canonical(sources) !== canonical(REBASELINE_HISTORICAL_SOURCE_SHAS)) fail("Historical source provenance is invalid.");
  return Object.freeze([...sources]);
}

const HISTORICAL_SLOT_SHAPES = Object.freeze({
  jwtPending: Object.freeze({ family: "jwt_secrets", slot: "pending" }),
  qrPrivatePending: Object.freeze({ family: "qr_signing_keys", slot: "pending-private" }),
  qrPublicPending: Object.freeze({ family: "qr_signing_keys", slot: "pending-public" }),
  jwtPrevious: Object.freeze({ family: "jwt_secrets", slot: "empty" }),
  qrPublicPrevious: Object.freeze({ family: "qr_signing_keys", slot: "empty" }),
  qrCurrentVersion: Object.freeze({ family: "qr_key_versions", slot: "current" }),
  qrPreviousVersion: Object.freeze({ family: "qr_key_versions", slot: "previous-empty" }),
});

export function historicalSlotIdentity({ slot, secretArn, versionId, stages, payload } = {}) {
  if (!REBASELINE_SLOT_ORDER.includes(slot)) fail("Historical rotation slot is invalid.");
  assertArn(secretArn, "Historical secret ARN"); assertVersion(versionId, "Historical secret VersionId");
  if (!Array.isArray(stages) || canonical([...stages].sort()) !== canonical(["AWSCURRENT"])) fail("Historical secret version stages are not exact.");
  if (!payload || typeof payload !== "object" || Array.isArray(payload) || typeof payload.value !== "string") fail("Historical secret payload is malformed.");
  const expected = HISTORICAL_SLOT_SHAPES[slot];
  if (payload.family !== expected.family || payload.slot !== expected.slot) fail(`Historical ${slot} payload kind is not authentic.`);
  const sourceSha = payload.sourceSha === undefined ? undefined : assertSha40(payload.sourceSha, `Historical ${slot} sourceSha`);
  if (sourceSha !== undefined && !REBASELINE_HISTORICAL_SOURCE_SHAS.includes(sourceSha)) fail(`Historical ${slot} source provenance is not approved.`);
  const rotationId = payload.rotationId === undefined ? undefined : assertRotation(payload.rotationId, `Historical ${slot} rotationId`);
  if (rotationId !== undefined && rotationId !== "rotation-20260826060632-b15b3f51") fail(`Historical ${slot} rotation provenance is not approved.`);
  if (payload.materialFingerprint !== undefined && (typeof payload.materialFingerprint !== "string" || payload.materialFingerprint !== fingerprint(payload.value))) fail(`Historical ${slot} material fingerprint is not authentic.`);
  // The original bootstrap schema legitimately omitted sourceSha on marker payloads.
  if (sourceSha === undefined && payload.initialMigration !== true) fail(`Historical ${slot} source-less schema is not authentic.`);
  const payloadSchema = sourceSha === undefined ? "INITIAL_DUAL_SLOT_LEGACY_SOURCELESS_V1" : rotationId === undefined ? "INITIAL_DUAL_SLOT_SOURCE_ADVANCE_V1" : "INITIAL_DUAL_SLOT_ROTATION_V1";
  const body = {
    schemaVersion: 1, slot, secretArn, versionId, stages: ["AWSCURRENT"], payloadSchema,
    payloadKind: Object.freeze({ family: payload.family, slot: payload.slot, initialMigration: payload.initialMigration === true }),
    ...(rotationId === undefined ? {} : { observedRotationId: rotationId }),
    ...(sourceSha === undefined ? {} : { observedSourceSha: sourceSha }),
    payloadSha256: canonicalSha256(payload),
    ...(typeof payload.materialFingerprint === "string" ? { materialFingerprint: payload.materialFingerprint } : {}),
    ...(typeof payload.keyVersion === "string" ? { keyVersion: payload.keyVersion } : {}),
  };
  return Object.freeze({ ...body, identitySha256: canonicalSha256(body) });
}

function assertHistoricalSlotIdentity(value, { slot, secretArn, versionId } = {}) {
  const allowed = ["schemaVersion", "slot", "secretArn", "versionId", "stages", "payloadSchema", "payloadKind", "observedRotationId", "observedSourceSha", "payloadSha256", "materialFingerprint", "keyVersion", "identitySha256"];
  if (!value || typeof value !== "object" || Object.keys(value).some((key) => !allowed.includes(key))) fail("Historical slot identity schema is invalid.");
  if (value.schemaVersion !== 1 || value.slot !== slot || value.secretArn !== secretArn || value.versionId !== versionId || canonical(value.stages) !== canonical(["AWSCURRENT"]) || !HISTORICAL_SLOT_SHAPES[slot] || !value.payloadKind || value.payloadKind.family !== HISTORICAL_SLOT_SHAPES[slot].family || value.payloadKind.slot !== HISTORICAL_SLOT_SHAPES[slot].slot || typeof value.payloadKind.initialMigration !== "boolean") fail("Historical slot identity is not exact.");
  if (!SHA256.test(value.payloadSha256 || "") || !SHA256.test(value.identitySha256 || "") || !/^INITIAL_DUAL_SLOT_(LEGACY_SOURCELESS|SOURCE_ADVANCE|ROTATION)_V1$/.test(value.payloadSchema || "")) fail("Historical slot identity hash or schema is invalid.");
  if (value.observedSourceSha !== undefined && !REBASELINE_HISTORICAL_SOURCE_SHAS.includes(value.observedSourceSha)) fail("Historical slot source provenance is invalid.");
  if (value.observedSourceSha === undefined && value.payloadSchema !== "INITIAL_DUAL_SLOT_LEGACY_SOURCELESS_V1") fail("Historical source-less payload schema is invalid.");
  if (value.observedRotationId !== undefined && value.observedRotationId !== "rotation-20260826060632-b15b3f51") fail("Historical slot rotation provenance is invalid.");
  const { identitySha256, ...body } = value; if (canonicalSha256(body) !== identitySha256) fail("Historical slot identity hash is invalid.");
  return value;
}

function assertHistoricalTopology(resources, currentVersionIds, historicalTopologySha256 = REBASELINE_ABANDONED_HISTORICAL_TOPOLOGY_SHA256) {
  const checkedResources = assertSlotMap(resources, "Historical topology resources"); exactKeys(currentVersionIds, REBASELINE_SLOT_ORDER, "Historical topology version IDs");
  for (const slot of REBASELINE_SLOT_ORDER) assertVersion(currentVersionIds[slot], `Historical topology version ID ${slot}`);
  assertSha256(historicalTopologySha256, "Historical topology identity");
  if (canonicalSha256({ resources: checkedResources, versionIds: currentVersionIds }) !== historicalTopologySha256) fail("Historical topology does not match the authenticated abandoned identity.");
  return Object.freeze({ resources: checkedResources, versionIds: Object.freeze({ ...currentVersionIds }), historicalTopologySha256 });
}

function assertHistoricalSlotIdentities(identities, resources, currentVersionIds, historicalTopologySha256) {
  assertHistoricalTopology(resources, currentVersionIds, historicalTopologySha256);
  exactKeys(identities, REBASELINE_SLOT_ORDER, "observedSlotIdentities");
  for (const slot of REBASELINE_SLOT_ORDER) assertHistoricalSlotIdentity(identities[slot], { slot, secretArn: resources[slot], versionId: currentVersionIds[slot] });
  return Object.freeze({ ...identities });
}

export function generateRebaselineMaterial() {
  const pair = crypto.generateKeyPairSync("ed25519", { privateKeyEncoding: { format: "pem", type: "pkcs8" }, publicKeyEncoding: { format: "pem", type: "spki" } });
  const qrPrivate = pair.privateKey;
  const qrPublic = pair.publicKey;
  return Object.freeze({ jwt: crypto.randomBytes(48).toString("base64url"), qrPrivate, qrPublic, qrKeyVersion: fingerprint(qrPublic) });
}

export function assertGeneratedMaterial(material) {
  if (!material || typeof material.jwt !== "string" || !material.jwt || typeof material.qrPrivate !== "string" || typeof material.qrPublic !== "string" || !/^[a-f0-9]{16}$/.test(material.qrKeyVersion || "")) fail("Generated rebaseline material is malformed.");
  let derivedPublic;
  try { derivedPublic = crypto.createPublicKey(material.qrPrivate).export({ format: "pem", type: "spki" }); } catch { fail("Generated rebaseline QR private key is malformed."); }
  if (derivedPublic !== material.qrPublic || fingerprint(derivedPublic) !== material.qrKeyVersion) fail("Generated rebaseline QR key pair is inconsistent.");
  return material;
}

export function buildAbandonmentEvidence({ sourceSha, historicalRotationId, historicalSourceShas, resources, currentVersionIds, historicalTopologySha256 = REBASELINE_ABANDONED_HISTORICAL_TOPOLOGY_SHA256, observedSlotIdentities, liveReferenceAudit, liveReferenceAuditSha256, legacyRuntimeAuthoritative, observedAt = new Date().toISOString() } = {}) {
  assertSha40(sourceSha, "sourceSha"); assertRotation(historicalRotationId, "historicalRotationId");
  const checkedResources = assertSlotMap(resources, "resources"); exactKeys(currentVersionIds, REBASELINE_SLOT_ORDER, "currentVersionIds");
  for (const slot of REBASELINE_SLOT_ORDER) assertVersion(currentVersionIds[slot], `currentVersionIds.${slot}`);
  const checkedIdentities = assertHistoricalSlotIdentities(observedSlotIdentities, checkedResources, currentVersionIds, historicalTopologySha256);
  if (liveReferenceAudit !== "PASS" || !SHA256.test(liveReferenceAuditSha256 || "") || legacyRuntimeAuthoritative !== true) fail("Historical rotation is not proven abandoned before cutover.");
  const timestamp = new Date(observedAt); if (!Number.isFinite(timestamp.getTime()) || timestamp.toISOString() !== observedAt) fail("observedAt is invalid.");
  const body = { schemaVersion: 2, kind: ABANDONED_PRE_CUTOVER, environment: "production", accountId: PRODUCTION_DUAL_SLOT_REBASELINE.accountId, region: PRODUCTION_DUAL_SLOT_REBASELINE.region, sourceSha, historicalRotationId, historicalSourceShas: assertHistoricalSources(historicalSourceShas), resources: checkedResources, currentVersionIds: Object.freeze({ ...currentVersionIds }), historicalTopologySha256, observedSlotIdentities: checkedIdentities, observedSlotIdentitiesSha256: canonicalSha256(checkedIdentities), liveReferenceAudit, liveReferenceAuditSha256, legacyRuntimeAuthoritative, observedAt };
  return Object.freeze({ ...body, evidenceSha256: canonicalSha256(body) });
}

export function assertAbandonmentEvidence(evidence, { sourceSha, resources, historicalTopologySha256 = REBASELINE_ABANDONED_HISTORICAL_TOPOLOGY_SHA256 } = {}) {
  exactKeys(evidence, ["schemaVersion", "kind", "environment", "accountId", "region", "sourceSha", "historicalRotationId", "historicalSourceShas", "resources", "currentVersionIds", "historicalTopologySha256", "observedSlotIdentities", "observedSlotIdentitiesSha256", "liveReferenceAudit", "liveReferenceAuditSha256", "legacyRuntimeAuthoritative", "observedAt", "evidenceSha256"], "Abandonment evidence");
  if (evidence.schemaVersion !== 2 || evidence.kind !== ABANDONED_PRE_CUTOVER || evidence.environment !== "production" || evidence.accountId !== PRODUCTION_DUAL_SLOT_REBASELINE.accountId || evidence.region !== PRODUCTION_DUAL_SLOT_REBASELINE.region || evidence.sourceSha !== sourceSha || evidence.liveReferenceAudit !== "PASS" || !SHA256.test(evidence.liveReferenceAuditSha256 || "") || evidence.legacyRuntimeAuthoritative !== true) fail("Abandonment evidence identity is invalid.");
  assertRotation(evidence.historicalRotationId, "historicalRotationId"); assertHistoricalSources(evidence.historicalSourceShas);
  const expectedResources = assertSlotMap(resources || evidence.resources, "resources"); if (canonical(evidence.resources) !== canonical(expectedResources)) fail("Abandonment evidence resources are not exact.");
  exactKeys(evidence.currentVersionIds, REBASELINE_SLOT_ORDER, "currentVersionIds"); for (const slot of REBASELINE_SLOT_ORDER) assertVersion(evidence.currentVersionIds[slot], `currentVersionIds.${slot}`);
  if (evidence.historicalTopologySha256 !== historicalTopologySha256) fail("Abandonment evidence historical topology identity is not exact.");
  assertHistoricalSlotIdentities(evidence.observedSlotIdentities, evidence.resources, evidence.currentVersionIds, historicalTopologySha256);
  if (evidence.observedSlotIdentitiesSha256 !== canonicalSha256(evidence.observedSlotIdentities)) fail("Abandonment evidence historical payload identities are not bound.");
  const observed = new Date(evidence.observedAt); if (!Number.isFinite(observed.getTime()) || observed.toISOString() !== evidence.observedAt) fail("Abandonment evidence timestamp is invalid.");
  const { evidenceSha256, ...body } = evidence; if (!SHA256.test(evidenceSha256 || "") || canonicalSha256(body) !== evidenceSha256) fail("Abandonment evidence hash is invalid.");
  return evidence;
}

export function assertRebaselinePreconditions(preconditions = {}) {
  if (preconditions.environment !== "production" || preconditions.accountId !== PRODUCTION_DUAL_SLOT_REBASELINE.accountId || preconditions.region !== PRODUCTION_DUAL_SLOT_REBASELINE.region) fail("Rebaseline environment identity is invalid.");
  assertSha40(preconditions.sourceSha, "sourceSha"); if (preconditions.sourceCas !== true || preconditions.cleanWorktree !== true) fail("Protected source CAS is not valid.");
  if (preconditions.existingSecretResources !== true || preconditions.liveReferenceAudit !== "PASS" || !SHA256.test(preconditions.liveReferenceAuditSha256 || "") || preconditions.legacyRuntimeAuthoritative !== true || preconditions.databaseDependencies !== 0 || preconditions.externalConsumers !== 0 || preconditions.dualSlotReferences !== 0) fail("Rebaseline preconditions are not safe.");
  if (!Number.isSafeInteger(preconditions.runningTasks) || preconditions.runningTasks < 0 || !Number.isSafeInteger(preconditions.pendingTasks) || preconditions.pendingTasks < 0 || typeof preconditions.activeTaskDefinition !== "string" || !preconditions.activeTaskDefinition) fail("Live ECS topology evidence is incomplete.");
  if (preconditions.historicalTopologySha256 !== undefined) assertSha256(preconditions.historicalTopologySha256, "historicalTopologySha256");
  const resources = assertSlotMap(preconditions.resources, "resources"); const abandonmentEvidence = assertAbandonmentEvidence(preconditions.abandonmentEvidence, { sourceSha: preconditions.sourceSha, resources, historicalTopologySha256: preconditions.historicalTopologySha256 });
  if (abandonmentEvidence.liveReferenceAuditSha256 !== preconditions.liveReferenceAuditSha256) fail("Rebaseline live reference audit is not bound to abandonment evidence.");
  return Object.freeze({ ...preconditions, resources, abandonmentEvidence, historicalRotationId: abandonmentEvidence.historicalRotationId });
}

export function buildRebaselineIdentity({ sourceSha, rotationId, resources, abandonmentEvidenceSha256, legacyBaseline } = {}) {
  assertSha40(sourceSha, "sourceSha"); assertRotation(rotationId, "rotationId"); const checkedResources = assertSlotMap(resources, "resources"); assertSha256(abandonmentEvidenceSha256, "abandonmentEvidenceSha256");
  const checkedLegacyBaseline = assertLegacyBaseline(legacyBaseline);
  const identity = { operation: PRODUCTION_DUAL_SLOT_REBASELINE.kind, schemaVersion: 1, sourceSha, rotationId, resources: checkedResources, abandonmentEvidenceSha256, legacyBaseline: checkedLegacyBaseline };
  return Object.freeze({ ...identity, identitySha256: canonicalSha256(identity) });
}

export function deterministicWriteIdentity({ sourceSha, rotationId, slot, secretArn, baselineIdentitySha256 } = {}) {
  assertSha40(sourceSha, "sourceSha"); assertRotation(rotationId, "rotationId"); if (!REBASELINE_SLOT_ORDER.includes(slot)) fail("Unknown rebaseline slot."); assertArn(secretArn, "secretArn"); assertSha256(baselineIdentitySha256, "baselineIdentitySha256");
  return sha256(`${REBASELINE_WRITE_IDENTITY_DOMAIN}\0${sourceSha}\0${rotationId}\0${slot}\0${secretArn}\0${baselineIdentitySha256}`);
}

const marker = ({ sourceSha, rotationId, family, slot, value = "", baselineMarker }) => ({ sourceSha, rotationId, family, slot, value, baselineMarker, initialMigration: true });

export function buildRebaselinePayloads({ sourceSha, rotationId, generatedMaterial, legacyBaseline } = {}) {
  assertSha40(sourceSha, "sourceSha"); assertRotation(rotationId, "rotationId"); assertGeneratedMaterial(generatedMaterial);
  const checkedLegacyBaseline = assertLegacyBaseline(legacyBaseline);
  return Object.freeze({
    jwtPending: { sourceSha, rotationId, family: "jwt_secrets", slot: "pending", materialType: "fresh-generated", materialFingerprint: fingerprint(generatedMaterial.jwt), value: generatedMaterial.jwt },
    qrPrivatePending: { sourceSha, rotationId, family: "qr_signing_keys", slot: "pending-private", materialType: "fresh-generated", keyVersion: generatedMaterial.qrKeyVersion, materialFingerprint: fingerprint(generatedMaterial.qrPrivate), value: generatedMaterial.qrPrivate },
    qrPublicPending: { sourceSha, rotationId, family: "qr_signing_keys", slot: "pending-public", materialType: "fresh-generated", keyVersion: generatedMaterial.qrKeyVersion, materialFingerprint: fingerprint(generatedMaterial.qrPublic), value: generatedMaterial.qrPublic },
    jwtPrevious: marker({ sourceSha, rotationId, family: "jwt_secrets", slot: "empty", baselineMarker: "empty-baseline-marker" }),
    qrPublicPrevious: marker({ sourceSha, rotationId, family: "qr_signing_keys", slot: "empty", baselineMarker: "empty-baseline-marker" }),
    qrCurrentVersion: marker({ sourceSha, rotationId, family: "qr_key_versions", slot: "current", value: checkedLegacyBaseline.qrCurrentVersion, baselineMarker: "adopted-authenticated-legacy-active-identity" }),
    qrPreviousVersion: marker({ sourceSha, rotationId, family: "qr_key_versions", slot: "previous-empty", baselineMarker: "empty-baseline-marker" }),
  });
}

export function buildRebaselineWritePlan({ sourceSha, rotationId, resources, baselineIdentitySha256, payloads } = {}) {
  const checkedResources = assertSlotMap(resources, "resources"); assertSha40(sourceSha, "sourceSha"); assertRotation(rotationId, "rotationId"); assertSha256(baselineIdentitySha256, "baselineIdentitySha256"); exactKeys(payloads, REBASELINE_SLOT_ORDER, "payloads");
  return Object.freeze(REBASELINE_SLOT_ORDER.map((slot) => { const payload = payloads[slot]; if (!payload || payload.sourceSha !== sourceSha || payload.rotationId !== rotationId) fail(`Payload ${slot} is not bound to the rebaseline.`); const clientRequestToken = deterministicWriteIdentity({ sourceSha, rotationId, slot, secretArn: checkedResources[slot], baselineIdentitySha256 }); return Object.freeze({ slot, secretArn: checkedResources[slot], clientRequestToken, payload, payloadSha256: canonicalSha256(payload), materialType: payload.materialType || payload.baselineMarker }); }));
}

export function safeWriteDescriptors(writePlan) { if (!Array.isArray(writePlan) || writePlan.length !== 7) fail("Rebaseline write plan is incomplete."); return Object.freeze(writePlan.map(({ slot, secretArn, clientRequestToken, payloadSha256, materialType }) => ({ slot, secretArn, clientRequestToken, payloadSha256, materialType }))); }

export function buildRebaselinePreparation({ preconditions, sourceSha, rotationId, baselineIdentity, writePlan } = {}) {
  const checked = assertRebaselinePreconditions(preconditions); if (checked.sourceSha !== sourceSha || !baselineIdentity || baselineIdentity.identitySha256 !== buildRebaselineIdentity({ sourceSha, rotationId, resources: checked.resources, abandonmentEvidenceSha256: checked.abandonmentEvidence.evidenceSha256, legacyBaseline: baselineIdentity.legacyBaseline }).identitySha256) fail("Rebaseline preparation identity is invalid.");
  const safePlan = safeWriteDescriptors(writePlan); const body = { schemaVersion: 2, kind: REBASELINE_PREPARATION_KIND, operation: PRODUCTION_DUAL_SLOT_REBASELINE.kind, environment: checked.environment, accountId: checked.accountId, region: checked.region, sourceCas: checked.sourceCas, cleanWorktree: checked.cleanWorktree, existingSecretResources: checked.existingSecretResources, sourceSha, historicalRotationId: checked.historicalRotationId, rotationId, abandonmentEvidence: checked.abandonmentEvidence, abandonmentEvidenceSha256: checked.abandonmentEvidence.evidenceSha256, historicalTopologySha256: checked.abandonmentEvidence.historicalTopologySha256, resources: checked.resources, legacyBaseline: baselineIdentity.legacyBaseline, baselineIdentity, writePlan: safePlan, expectedSecretValueWrites: 7, expectedSecretDeletes: 0, liveReferenceAudit: checked.liveReferenceAudit, liveReferenceAuditSha256: checked.liveReferenceAuditSha256, databaseDependencies: checked.databaseDependencies, externalConsumers: checked.externalConsumers, dualSlotReferences: checked.dualSlotReferences, runningTasks: checked.runningTasks, pendingTasks: checked.pendingTasks, activeTaskDefinition: checked.activeTaskDefinition };
  return Object.freeze({ ...body, preparationSha256: canonicalSha256(body) });
}

export function assertRebaselinePreparation(value, { sourceSha, rotationId } = {}) {
  exactKeys(value, ["schemaVersion", "kind", "operation", "environment", "accountId", "region", "sourceCas", "cleanWorktree", "existingSecretResources", "sourceSha", "historicalRotationId", "rotationId", "abandonmentEvidence", "abandonmentEvidenceSha256", "historicalTopologySha256", "resources", "legacyBaseline", "baselineIdentity", "writePlan", "expectedSecretValueWrites", "expectedSecretDeletes", "liveReferenceAudit", "liveReferenceAuditSha256", "databaseDependencies", "externalConsumers", "dualSlotReferences", "runningTasks", "pendingTasks", "activeTaskDefinition", "preparationSha256"], "Rebaseline preparation");
  if (value.schemaVersion !== 2 || value.kind !== REBASELINE_PREPARATION_KIND || value.operation !== PRODUCTION_DUAL_SLOT_REBASELINE.kind || value.environment !== "production" || value.accountId !== PRODUCTION_DUAL_SLOT_REBASELINE.accountId || value.region !== PRODUCTION_DUAL_SLOT_REBASELINE.region || value.sourceSha !== sourceSha || value.rotationId !== rotationId || value.sourceCas !== true || value.cleanWorktree !== true || value.existingSecretResources !== true || value.expectedSecretValueWrites !== 7 || value.expectedSecretDeletes !== 0 || value.liveReferenceAudit !== "PASS" || !SHA256.test(value.liveReferenceAuditSha256 || "") || value.databaseDependencies !== 0 || value.externalConsumers !== 0 || value.dualSlotReferences !== 0) fail("Rebaseline preparation identity is invalid.");
  assertRotation(value.historicalRotationId, "historicalRotationId"); assertSha256(value.historicalTopologySha256, "historicalTopologySha256"); assertAbandonmentEvidence(value.abandonmentEvidence, { sourceSha, resources: value.resources, historicalTopologySha256: value.historicalTopologySha256 }); if (value.abandonmentEvidenceSha256 !== value.abandonmentEvidence.evidenceSha256) fail("Rebaseline preparation abandonment evidence is not bound.");
  const identity = buildRebaselineIdentity({ sourceSha, rotationId, resources: value.resources, abandonmentEvidenceSha256: value.abandonmentEvidence.evidenceSha256, legacyBaseline: value.legacyBaseline }); if (canonical(value.baselineIdentity) !== canonical(identity)) fail("Rebaseline preparation baseline identity is invalid.");
  const plan = value.writePlan; if (!Array.isArray(plan) || plan.length !== 7 || plan.some((entry) => !entry || typeof entry.slot !== "string" || !REBASELINE_SLOT_ORDER.includes(entry.slot) || entry.secretArn !== value.resources[entry.slot] || !VERSION_ID.test(entry.clientRequestToken) || !SHA256.test(entry.payloadSha256))) fail("Rebaseline preparation write plan is invalid.");
  if (new Set(plan.map(({ slot }) => slot)).size !== 7) fail("Rebaseline preparation write plan has duplicate slots.");
  const { preparationSha256, ...body } = value; if (!SHA256.test(preparationSha256 || "") || canonicalSha256(body) !== preparationSha256) fail("Rebaseline preparation hash is invalid."); return value;
}

export function createRebaselineMaterialJournal({ sourceSha, rotationId, baselineIdentitySha256, generatedMaterial } = {}) {
  assertSha40(sourceSha, "sourceSha"); assertRotation(rotationId, "rotationId"); assertSha256(baselineIdentitySha256, "baselineIdentitySha256"); assertGeneratedMaterial(generatedMaterial);
  const body = { schemaVersion: 1, kind: REBASELINE_MATERIAL_JOURNAL_KIND, operation: PRODUCTION_DUAL_SLOT_REBASELINE.kind, sourceSha, rotationId, baselineIdentitySha256, generatedMaterial };
  return Object.freeze({ ...body, journalSha256: canonicalSha256(body) });
}

export function assertRebaselineMaterialJournal(value, { sourceSha, rotationId, baselineIdentitySha256 } = {}) {
  exactKeys(value, ["schemaVersion", "kind", "operation", "sourceSha", "rotationId", "baselineIdentitySha256", "generatedMaterial", "journalSha256"], "Rebaseline material journal");
  if (value.schemaVersion !== 1 || value.kind !== REBASELINE_MATERIAL_JOURNAL_KIND || value.operation !== PRODUCTION_DUAL_SLOT_REBASELINE.kind || value.sourceSha !== sourceSha || value.rotationId !== rotationId || value.baselineIdentitySha256 !== baselineIdentitySha256) fail("Rebaseline material journal identity is invalid.");
  assertGeneratedMaterial(value.generatedMaterial);
  const { journalSha256, ...body } = value; if (!SHA256.test(journalSha256 || "") || canonicalSha256(body) !== journalSha256) fail("Rebaseline material journal hash is invalid.");
  return value;
}

export function writeRebaselineMaterialJournal({ filePath, repositoryRoot = process.cwd(), sourceSha, rotationId, baselineIdentitySha256, generatedMaterial, fsOps = fs } = {}) {
  const journal = createRebaselineMaterialJournal({ sourceSha, rotationId, baselineIdentitySha256, generatedMaterial });
  ensureStageBPrivateDirectory({ directory: path.dirname(path.resolve(filePath)), repositoryRoot, create: true, normalize: true, fsOps, label: "Dual-slot rebaseline material journal directory" });
  writeStageBPrivateFileAtomicExclusive({ filePath, bytes: Buffer.from(`${JSON.stringify(journal)}\n`), repositoryRoot, fsOps, label: "Dual-slot rebaseline material journal" });
  return Object.freeze({ journal, material: generatedMaterial, sha256: journal.journalSha256, path: path.resolve(filePath) });
}

export function readRebaselineMaterialJournal({ filePath, repositoryRoot = process.cwd(), sourceSha, rotationId, baselineIdentitySha256 } = {}) {
  const captured = readStageBPrivateFileBytes({ filePath, repositoryRoot, label: "Dual-slot rebaseline material journal" });
  const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(captured.bytes));
  assertRebaselineMaterialJournal(value, { sourceSha, rotationId, baselineIdentitySha256 });
  return Object.freeze({ journal: value, material: value.generatedMaterial, sha256: captured.sha256, path: captured.path });
}

export function loadOrCreateRebaselineMaterialJournal({ filePath, repositoryRoot = process.cwd(), sourceSha, rotationId, baselineIdentitySha256, generatedMaterial, fsOps = fs } = {}) {
  if (fsOps.lstatSync(filePath, { throwIfNoEntry: false })) return readRebaselineMaterialJournal({ filePath, repositoryRoot, sourceSha, rotationId, baselineIdentitySha256 });
  return writeRebaselineMaterialJournal({ filePath, repositoryRoot, sourceSha, rotationId, baselineIdentitySha256, generatedMaterial: generatedMaterial || generateRebaselineMaterial(), fsOps });
}

export function prepareRebaselineWritePlan({ sourceSha, rotationId, resources, baselineIdentity, legacyBaseline, materialJournalFile, repositoryRoot = process.cwd(), generatedMaterial } = {}) {
  const identity = baselineIdentity;
  if (!identity || typeof identity !== "object") fail("Authenticated baseline identity is required before material preparation.");
  assertSha256(identity.identitySha256, "baselineIdentity.identitySha256");
  const journal = materialJournalFile ? loadOrCreateRebaselineMaterialJournal({ filePath: materialJournalFile, repositoryRoot, sourceSha, rotationId, baselineIdentitySha256: identity.identitySha256, generatedMaterial }) : null;
  const material = journal?.material || generatedMaterial || generateRebaselineMaterial();
  const payloads = buildRebaselinePayloads({ sourceSha, rotationId, generatedMaterial: material, legacyBaseline });
  return Object.freeze({ identity, material, payloads, writePlan: buildRebaselineWritePlan({ sourceSha, rotationId, resources, baselineIdentitySha256: identity.identitySha256, payloads }) });
}

function assertReadSnapshot(snapshot, expected, label, historicalIdentity) {
  if (!snapshot || snapshot.arn !== expected.secretArn || !Array.isArray(snapshot.versions)) fail(`${label} topology is malformed.`);
  const matches = snapshot.versions.filter(({ versionId }) => versionId === expected.clientRequestToken); if (matches.length > 1) fail(`${label} has duplicate deterministic versions.`);
  if (matches.length === 1) { if (matches[0].payloadSha256 !== expected.payloadSha256 || !Array.isArray(matches[0].stages) || matches[0].stages.length !== 1 || matches[0].stages[0] !== "AWSCURRENT") fail(`${label} deterministic version does not authenticate.`); return "COMPLETED"; }
  if (!historicalIdentity || snapshot.currentVersionId !== historicalIdentity.versionId || snapshot.currentPayloadSha256 !== historicalIdentity.payloadSha256 || canonical(snapshot.currentStages) !== canonical(["AWSCURRENT"])) fail(`${label} current version is neither the authenticated historical state nor the exact prepared write.`);
  if (snapshot.unexpectedRebaselineIdentity === true) fail(`${label} contains an unexpected competing rebaseline.`); return "PENDING";
}

function assertStableLiveReferenceAudit(audit, expectedStableAuditSha256) {
  if (!audit || audit.status !== "PASS" || audit.dualSlotReferences !== 0 || audit.legacyRuntimeAuthoritative !== true || audit.databaseDependencies !== 0 || audit.externalConsumers !== 0 || audit.stableAuditSha256 !== expectedStableAuditSha256) fail("Live reference audit no longer satisfies the authorization-bound security topology.");
  return audit;
}

export function buildBaselineCompletion({ preconditions, sourceSha, rotationId, baselineIdentity, writePlan, finalSnapshots, authorizationBinding } = {}) {
  const checked = assertRebaselinePreconditions(preconditions); if (checked.sourceSha !== sourceSha) fail("Completion source does not match preconditions."); assertRotation(rotationId, "rotationId");
  const expectedIdentity = buildRebaselineIdentity({ sourceSha, rotationId, resources: checked.resources, abandonmentEvidenceSha256: checked.abandonmentEvidence.evidenceSha256, legacyBaseline: baselineIdentity.legacyBaseline }); if (!baselineIdentity || baselineIdentity.identitySha256 !== expectedIdentity.identitySha256) fail("Baseline identity is invalid.");
  const expectedPlan = buildRebaselineWritePlan({ sourceSha, rotationId, resources: checked.resources, baselineIdentitySha256: baselineIdentity.identitySha256, payloads: Object.fromEntries(writePlan.map(({ slot, payload }) => [slot, payload])) }); if (!Array.isArray(finalSnapshots) || finalSnapshots.length !== 7) fail("Final seven-slot verification is incomplete.");
  for (const expected of expectedPlan) { const snapshot = finalSnapshots.find((candidate) => candidate.slot === expected.slot); if (assertReadSnapshot(snapshot, expected, `Final ${expected.slot}`) !== "COMPLETED") fail(`Final ${expected.slot} is not complete.`); }
  if (!SHA256.test(authorizationBinding || "")) fail("Authorization binding is required.");
  const identity = { operation: PRODUCTION_DUAL_SLOT_REBASELINE.kind, schemaVersion: 2, sourceSha, rotationId, historicalRotationId: checked.historicalRotationId, abandonmentEvidenceSha256: checked.abandonmentEvidence.evidenceSha256, resources: checked.resources, versionIds: Object.fromEntries(expectedPlan.map(({ slot, clientRequestToken }) => [slot, clientRequestToken])), payloadIdentities: Object.fromEntries(expectedPlan.map(({ slot, payloadSha256, materialType, payload }) => [slot, { payloadSha256, materialType, ...(payload.keyVersion ? { keyVersion: payload.keyVersion } : {}) }])), liveReferenceAudit: checked.liveReferenceAudit, liveReferenceAuditSha256: checked.liveReferenceAuditSha256, authorizationBinding, expectedSecretValueWrites: 7, expectedSecretDeletes: 0 };
  const completion = { schemaVersion: 2, kind: BASELINE_COMPLETE, ...identity };
  return Object.freeze({ ...completion, baselineBindingSha256: canonicalSha256(completion) });
}

export function assertBaselineCompletion(value, { sourceSha, rotationId, resources, authorizationBinding, historicalRotationId, abandonmentEvidenceSha256 } = {}) {
  exactKeys(value, ["schemaVersion", "kind", "operation", "sourceSha", "rotationId", "historicalRotationId", "abandonmentEvidenceSha256", "resources", "versionIds", "payloadIdentities", "liveReferenceAudit", "liveReferenceAuditSha256", "authorizationBinding", "expectedSecretValueWrites", "expectedSecretDeletes", "baselineBindingSha256"], "Baseline completion");
  if (value.schemaVersion !== 2 || value.kind !== BASELINE_COMPLETE || value.operation !== PRODUCTION_DUAL_SLOT_REBASELINE.kind || value.sourceSha !== sourceSha || value.rotationId !== rotationId || value.liveReferenceAudit !== "PASS" || !SHA256.test(value.liveReferenceAuditSha256 || "") || value.expectedSecretValueWrites !== 7 || value.expectedSecretDeletes !== 0) fail("Baseline completion identity is invalid.");
  assertRotation(value.historicalRotationId, "historicalRotationId"); assertSha256(value.abandonmentEvidenceSha256, "abandonmentEvidenceSha256"); assertSlotMap(value.resources, "resources"); exactKeys(value.versionIds, REBASELINE_SLOT_ORDER, "versionIds"); exactKeys(value.payloadIdentities, REBASELINE_SLOT_ORDER, "payloadIdentities");
  for (const slot of REBASELINE_SLOT_ORDER) { assertVersion(value.versionIds[slot], `versionIds.${slot}`); assertSha256(value.payloadIdentities[slot].payloadSha256, `payloadIdentities.${slot}.payloadSha256`); text(value.payloadIdentities[slot].materialType, `payloadIdentities.${slot}.materialType`); if (["qrPrivatePending", "qrPublicPending"].includes(slot)) text(value.payloadIdentities[slot].keyVersion, `payloadIdentities.${slot}.keyVersion`); }
  if (historicalRotationId !== undefined && value.historicalRotationId !== historicalRotationId) fail("Baseline completion historical rotation does not match."); if (abandonmentEvidenceSha256 !== undefined && value.abandonmentEvidenceSha256 !== abandonmentEvidenceSha256) fail("Baseline completion abandonment evidence does not match."); if (!SHA256.test(value.authorizationBinding || "")) fail("Baseline completion authorization binding is invalid."); if (resources && canonical(value.resources) !== canonical(assertSlotMap(resources, "resources"))) fail("Baseline completion resources do not match expected resources."); if (authorizationBinding !== undefined && value.authorizationBinding !== authorizationBinding) fail("Baseline completion authorization binding does not match.");
  const { baselineBindingSha256, ...identity } = value; if (!SHA256.test(baselineBindingSha256 || "") || canonicalSha256(identity) !== baselineBindingSha256) fail("Baseline completion hash is invalid."); return value;
}

export function buildRebaselineRotationBindings({ sourceSha, rotationId, legacyBaseline, resources, abandonmentEvidence, completion, authorization } = {}) {
  if (!completion || completion.kind !== BASELINE_COMPLETE) fail("Completed dual-slot baseline evidence is required for runtime binding.");
  const checkedAbandonment = assertAbandonmentEvidence(abandonmentEvidence, { sourceSha, resources, historicalTopologySha256: abandonmentEvidence?.historicalTopologySha256 });
  assertProductionDualSlotRebaselineAuthorization(authorization, { sourceSha, rotationId, resources });
  assertBaselineCompletion(completion, { sourceSha, rotationId, resources, authorizationBinding: authorization.authorizationSha256, historicalRotationId: checkedAbandonment.historicalRotationId, abandonmentEvidenceSha256: checkedAbandonment.evidenceSha256 });
  const checkedLegacyBaseline = assertLegacyBaseline(legacyBaseline);
  const expectedBaselineIdentity = buildRebaselineIdentity({ sourceSha, rotationId, resources, abandonmentEvidenceSha256: checkedAbandonment.evidenceSha256, legacyBaseline: checkedLegacyBaseline });
  if (authorization.baselineIdentitySha256 !== expectedBaselineIdentity.identitySha256) fail("Rebaseline runtime legacy baseline is not bound to the authorization.");
  const bindings = {
    schemaVersion: 2, kind: REBASELINE_ROTATION_BINDINGS_KIND, producer: REBASELINE_ROTATION_BINDINGS_PRODUCER, operation: PRODUCTION_DUAL_SLOT_REBASELINE.kind, sourceSha, rotationId,
    legacy: checkedLegacyBaseline,
    jwt: { currentSecretId: checkedLegacyBaseline.jwtCurrent, previousSecretId: resources.jwtPrevious, pendingSecretId: resources.jwtPending },
    qr: { privateCurrentSecretId: checkedLegacyBaseline.qrPrivateCurrent, privatePendingSecretId: resources.qrPrivatePending, publicCurrentSecretId: checkedLegacyBaseline.qrPublicCurrent, publicPreviousSecretId: resources.qrPublicPrevious, publicPendingSecretId: resources.qrPublicPending, currentKeyVersionSecretId: resources.qrCurrentVersion, previousKeyVersionSecretId: resources.qrPreviousVersion, previousKeyVersion: checkedLegacyBaseline.qrCurrentVersion, pendingKeyVersion: completion.payloadIdentities.qrPublicPending.keyVersion || completion.payloadIdentities.qrPrivatePending.keyVersion || "" },
    historicalRotationId: checkedAbandonment.historicalRotationId, abandonmentEvidenceSha256: checkedAbandonment.evidenceSha256, abandonmentEvidence: checkedAbandonment, baselineCompletionSha256: completion.baselineBindingSha256, baselineCompletion: completion, authorizationSha256: authorization.authorizationSha256,
  };
  return Object.freeze(bindings);
}

export function assertRebaselineRotationBindings(bindings, { authorization } = {}) {
  exactKeys(bindings, ["schemaVersion", "kind", "producer", "operation", "sourceSha", "rotationId", "legacy", "jwt", "qr", "historicalRotationId", "abandonmentEvidenceSha256", "abandonmentEvidence", "baselineCompletionSha256", "baselineCompletion", "authorizationSha256"], "Rebaseline rotation bindings");
  if (bindings.schemaVersion !== 2 || bindings.kind !== REBASELINE_ROTATION_BINDINGS_KIND || bindings.producer !== REBASELINE_ROTATION_BINDINGS_PRODUCER || bindings.operation !== PRODUCTION_DUAL_SLOT_REBASELINE.kind) fail("Rebaseline rotation binding producer identity is invalid.");
  const resources = { jwtPending: bindings.jwt?.pendingSecretId, qrPrivatePending: bindings.qr?.privatePendingSecretId, qrPublicPending: bindings.qr?.publicPendingSecretId, jwtPrevious: bindings.jwt?.previousSecretId, qrPublicPrevious: bindings.qr?.publicPreviousSecretId, qrCurrentVersion: bindings.qr?.currentKeyVersionSecretId, qrPreviousVersion: bindings.qr?.previousKeyVersionSecretId };
  const checkedResources = assertSlotMap(resources, "Rebaseline runtime resources");
  const checkedAbandonment = assertAbandonmentEvidence(bindings.abandonmentEvidence, { sourceSha: bindings.sourceSha, resources: checkedResources, historicalTopologySha256: bindings.abandonmentEvidence?.historicalTopologySha256 });
  if (bindings.historicalRotationId !== checkedAbandonment.historicalRotationId || bindings.abandonmentEvidenceSha256 !== checkedAbandonment.evidenceSha256 || !SHA256.test(bindings.authorizationSha256 || "")) fail("Rebaseline rotation binding provenance is invalid.");
  assertProductionDualSlotRebaselineAuthorization(authorization, { sourceSha: bindings.sourceSha, rotationId: bindings.rotationId, resources: checkedResources });
  if (authorization.authorizationSha256 !== bindings.authorizationSha256 || authorization.abandonmentEvidenceSha256 !== bindings.abandonmentEvidenceSha256) fail("Rebaseline rotation binding authorization is not independently authenticated.");
  const checkedLegacyBaseline = assertLegacyBaseline(bindings.legacy, "Rebaseline runtime legacy baseline");
  if (bindings.jwt?.currentSecretId !== checkedLegacyBaseline.jwtCurrent || bindings.qr?.privateCurrentSecretId !== checkedLegacyBaseline.qrPrivateCurrent || bindings.qr?.publicCurrentSecretId !== checkedLegacyBaseline.qrPublicCurrent || bindings.qr?.previousKeyVersion !== checkedLegacyBaseline.qrCurrentVersion) fail("Rebaseline runtime legacy bindings are inconsistent.");
  const expectedBaselineIdentity = buildRebaselineIdentity({ sourceSha: bindings.sourceSha, rotationId: bindings.rotationId, resources: checkedResources, abandonmentEvidenceSha256: checkedAbandonment.evidenceSha256, legacyBaseline: checkedLegacyBaseline });
  if (authorization.baselineIdentitySha256 !== expectedBaselineIdentity.identitySha256) fail("Rebaseline runtime legacy baseline is not bound to the authorization.");
  assertBaselineCompletion(bindings.baselineCompletion, { sourceSha: bindings.sourceSha, rotationId: bindings.rotationId, resources: checkedResources, authorizationBinding: authorization.authorizationSha256, historicalRotationId: bindings.historicalRotationId, abandonmentEvidenceSha256: bindings.abandonmentEvidenceSha256 });
  if (bindings.baselineCompletionSha256 !== bindings.baselineCompletion.baselineBindingSha256) fail("Rebaseline completion hash is not bound to runtime bindings.");
  return bindings;
}

export function persistExactPrivateJson({ filePath, value, repositoryRoot, label, fsOps = fs }) {
  ensureStageBPrivateDirectory({ directory: path.dirname(path.resolve(filePath)), repositoryRoot, create: true, normalize: true, fsOps, label: `${label} directory` });
  const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
  return writeStageBPrivateFileAtomicExclusive({ filePath, bytes, repositoryRoot, fsOps, label });
}

function assertDurableOutputWritable(filePath) {
  const probe = path.join(path.dirname(path.resolve(filePath)), `.rebaseline-output-probe-${crypto.randomUUID()}`);
  let descriptor;
  try {
    descriptor = fs.openSync(probe, "wx", 0o600);
    fs.fsyncSync(descriptor);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    fs.rmSync(probe, { force: true });
  }
}

export async function executeProductionDualSlotRebaseline({ preconditions, sourceSha, rotationId, baselineIdentity, writePlan, readReferenceAudit, readSlot, writeSlot, completionFile, bindingsFile, repositoryRoot = process.cwd(), authorization, afterCompletionPersist, afterBindingsPersist } = {}) {
  const checked = assertRebaselinePreconditions(preconditions); if (checked.sourceSha !== sourceSha) fail("Execution source does not match preconditions."); if (typeof readReferenceAudit !== "function" || typeof readSlot !== "function" || typeof writeSlot !== "function") fail("Rebaseline execution adapters are incomplete.");
  if (!completionFile || !bindingsFile) fail("Durable completion and rotation-binding outputs are required before rebaseline mutation.");
  if (path.resolve(completionFile) === path.resolve(bindingsFile)) fail("Completion and rotation-binding outputs must be distinct.");
  ensureStageBPrivateDirectory({ directory: path.dirname(path.resolve(completionFile)), repositoryRoot, create: true, normalize: true, label: "Dual-slot baseline completion directory" });
  ensureStageBPrivateDirectory({ directory: path.dirname(path.resolve(bindingsFile)), repositoryRoot, create: true, normalize: true, label: "Dual-slot rebaseline runtime binding directory" });
  assertDurableOutputWritable(completionFile);
  assertDurableOutputWritable(bindingsFile);
  const outputExists = [completionFile, bindingsFile].map((filePath) => {
    const stat = fs.lstatSync(filePath, { throwIfNoEntry: false });
    if (!stat) return false;
    if (!stat.isFile() || stat.isSymbolicLink()) fail("Rebaseline durable output is not a private regular file.");
    readStageBPrivateFileBytes({ filePath, repositoryRoot, label: "Rebaseline durable output" });
    return true;
  });
  assertProductionDualSlotRebaselineAuthorization(authorization, { sourceSha, rotationId, resources: checked.resources });
  if (authorization.abandonmentEvidenceSha256 !== checked.abandonmentEvidence.evidenceSha256 || authorization.liveReferenceAuditSha256 !== checked.liveReferenceAuditSha256) fail("Rebaseline authorization does not bind the observed preconditions.");
  const expectedIdentity = buildRebaselineIdentity({ sourceSha, rotationId, resources: checked.resources, abandonmentEvidenceSha256: checked.abandonmentEvidence.evidenceSha256, legacyBaseline: baselineIdentity.legacyBaseline }); if (!baselineIdentity || baselineIdentity.identitySha256 !== expectedIdentity.identitySha256) fail("Rebaseline identity changed.");
  if (authorization.baselineIdentitySha256 !== baselineIdentity.identitySha256) fail("Rebaseline authorization baseline identity does not match execution.");
  const expectedPlan = buildRebaselineWritePlan({ sourceSha, rotationId, resources: checked.resources, baselineIdentitySha256: baselineIdentity.identitySha256, payloads: Object.fromEntries(writePlan.map(({ slot, payload }) => [slot, payload])) });
  if (canonical(Object.fromEntries(expectedPlan.map(({ slot, clientRequestToken }) => [slot, clientRequestToken]))) !== canonical(authorization.writeIdentities)) fail("Rebaseline authorization write identities do not match execution.");
  let writes = 0;
  const historicalBySlot = checked.abandonmentEvidence.observedSlotIdentities;
  const initialSnapshots = await Promise.all(expectedPlan.map(async (expected) => ({ expected, snapshot: await readSlot(expected.slot, expected.secretArn, expected.clientRequestToken, { sourceSha, rotationId, historicalIdentity: historicalBySlot[expected.slot] }) })));
  if (outputExists.some(Boolean) && initialSnapshots.some(({ expected, snapshot }) => assertReadSnapshot(snapshot, expected, `Output preflight ${expected.slot}`, historicalBySlot[expected.slot]) !== "COMPLETED")) fail("Existing durable rebaseline outputs cannot accompany an incomplete secret baseline.");
  for (const expected of expectedPlan) { assertStableLiveReferenceAudit(await readReferenceAudit(), checked.liveReferenceAuditSha256); const historicalIdentity = historicalBySlot[expected.slot]; const snapshot = await readSlot(expected.slot, expected.secretArn, expected.clientRequestToken, { sourceSha, rotationId, historicalIdentity }); if (assertReadSnapshot(snapshot, expected, `Pre-write ${expected.slot}`, historicalIdentity) === "COMPLETED") continue; const result = await writeSlot({ slot: expected.slot, secretArn: expected.secretArn, clientRequestToken: expected.clientRequestToken, payload: expected.payload, payloadSha256: expected.payloadSha256 }); writes += 1; if (result?.versionId !== expected.clientRequestToken || result?.arn !== expected.secretArn) fail(`Rebaseline write identity for ${expected.slot} is invalid.`); const verified = await readSlot(expected.slot, expected.secretArn, expected.clientRequestToken, { sourceSha, rotationId, historicalIdentity }); if (assertReadSnapshot(verified, expected, `Post-write ${expected.slot}`, historicalIdentity) !== "COMPLETED") fail(`Rebaseline write ${expected.slot} did not converge.`); }
  assertStableLiveReferenceAudit(await readReferenceAudit(), checked.liveReferenceAuditSha256);
  const finalSnapshots = []; for (const expected of expectedPlan) finalSnapshots.push({ slot: expected.slot, ...(await readSlot(expected.slot, expected.secretArn, expected.clientRequestToken, { sourceSha, rotationId, historicalIdentity: historicalBySlot[expected.slot] })) }); const completion = buildBaselineCompletion({ preconditions: checked, sourceSha, rotationId, baselineIdentity, writePlan, finalSnapshots, authorizationBinding: authorization.authorizationSha256 });
  const completionCapture = persistExactPrivateJson({ filePath: completionFile, value: completion, repositoryRoot, label: "Dual-slot baseline completion evidence" });
  if (typeof afterCompletionPersist === "function") await afterCompletionPersist();
  const bindings = buildRebaselineRotationBindings({ sourceSha, rotationId, legacyBaseline: baselineIdentity.legacyBaseline, resources: checked.resources, abandonmentEvidence: checked.abandonmentEvidence, completion, authorization });
  const bindingsCapture = persistExactPrivateJson({ filePath: bindingsFile, value: bindings, repositoryRoot, label: "Dual-slot rebaseline runtime bindings" });
  if (typeof afterBindingsPersist === "function") await afterBindingsPersist();
  assertBaselineCompletion(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(completionCapture.bytes)), { sourceSha, rotationId, resources: checked.resources, authorizationBinding: authorization.authorizationSha256 });
  assertRebaselineRotationBindings(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bindingsCapture.bytes)), { authorization });
  return Object.freeze({ baselineComplete: true, writes, completion, bindings, completionPath: completionCapture.path, completionSha256: completionCapture.sha256, bindingsPath: bindingsCapture.path, bindingsSha256: bindingsCapture.sha256, writePlan: safeWriteDescriptors(expectedPlan) });
}

export function readBoundBaselineCompletion({ filePath, expectedSha256, authorization, repositoryRoot = process.cwd() } = {}) { const captured = readStageBPrivateFileBytes({ filePath, repositoryRoot, label: "Dual-slot baseline completion evidence" }); if (captured.sha256 !== expectedSha256) fail("Dual-slot baseline completion evidence changed."); const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(captured.bytes)); assertProductionDualSlotRebaselineAuthorization(authorization, { sourceSha: value.sourceSha, rotationId: value.rotationId, resources: value.resources }); assertBaselineCompletion(value, { sourceSha: value.sourceSha, rotationId: value.rotationId, resources: value.resources, authorizationBinding: authorization.authorizationSha256 }); return Object.freeze({ value, sha256: captured.sha256, path: captured.path }); }

export function createProductionDualSlotRebaselineAuthorization(input = {}) {
  const evidence = input.protectedEnvironmentApprovalEvidence;
  assertProductionEnvironmentApprovalIdentity(evidence, { sourceSha: input.sourceSha, repository: PRODUCTION_DUAL_SLOT_REBASELINE.repository });
  if (evidence.workflowRef !== PRODUCTION_ENVIRONMENT_APPROVAL.dualSlotRebaselineWorkflowRef) fail("Rebaseline authorization requires the dedicated protected-environment workflow.");
  const resources = assertSlotMap(input.resources, "resources");
  const identities = input.writeIdentities;
  assertSha256(input.baselineIdentitySha256, "baselineIdentitySha256");
  exactKeys(identities, REBASELINE_SLOT_ORDER, "writeIdentities");
  for (const slot of REBASELINE_SLOT_ORDER) { assertVersion(identities[slot], `writeIdentities.${slot}`); if (identities[slot] !== deterministicWriteIdentity({ sourceSha: input.sourceSha, rotationId: input.rotationId, slot, secretArn: resources[slot], baselineIdentitySha256: input.baselineIdentitySha256 })) fail(`writeIdentities.${slot} is not bound to the exact resource and baseline.`); }
  assertSha40(input.sourceSha, "sourceSha"); assertRotation(input.historicalRotationId, "historicalRotationId"); assertRotation(input.rotationId, "rotationId");
  if (input.rotationId === input.historicalRotationId) fail("Rebaseline rotation must be new.");
  if (input.liveReferenceAudit !== "PASS" || !SHA256.test(input.liveReferenceAuditSha256 || "") || !SHA256.test(input.observedSlotIdentitiesSha256 || "")) fail("Rebaseline authorization requires a passing bound live-reference audit.");
  if (input.expectedSecretValueWrites !== 7 || input.expectedSecretDeletes !== 0) fail("Rebaseline authorization mutation counts are invalid.");
  for (const [name, value] of Object.entries({ reason: input.reason, approvedBy: input.approvedBy, approverRole: input.approverRole, verificationRef: input.verificationRef })) text(value, name);
  assertProductionEnvironmentReviewer(evidence, { approvedBy: input.approvedBy, executionActor: evidence.executionActor });
  const body = {
    schemaVersion: 1, kind: REBASELINE_AUTHORIZATION_KIND, operation: PRODUCTION_DUAL_SLOT_REBASELINE.kind,
    environment: "production", accountId: PRODUCTION_DUAL_SLOT_REBASELINE.accountId, region: PRODUCTION_DUAL_SLOT_REBASELINE.region,
    sourceSha: input.sourceSha, historicalRotationId: input.historicalRotationId, rotationId: input.rotationId,
    abandonmentEvidenceSha256: assertSha256(input.abandonmentEvidenceSha256, "abandonmentEvidenceSha256"), baselineIdentitySha256: input.baselineIdentitySha256, resources,
    writeIdentities: Object.freeze({ ...identities }), expectedSecretValueWrites: 7, expectedSecretDeletes: 0,
    liveReferenceAudit: input.liveReferenceAudit, liveReferenceAuditSha256: input.liveReferenceAuditSha256, observedSlotIdentitiesSha256: input.observedSlotIdentitiesSha256, reason: input.reason, approvedBy: input.approvedBy,
    approverRole: input.approverRole, verificationRef: input.verificationRef,
    protectedEnvironmentApprovalEvidence: evidence, protectedEnvironmentApprovalEvidenceSha256: evidence.evidenceSha256,
    exclusions: Object.freeze(["Terraform apply", "ECS RegisterTaskDefinition", "ECS UpdateService", "database mutation", "IAM mutation", "KMS policy mutation", "image publication", "network mutation", "DeleteSecret"]),
  };
  return Object.freeze({ ...body, authorizationSha256: canonicalSha256(body) });
}

export function assertProductionDualSlotRebaselineAuthorization(value, { sourceSha, rotationId, resources } = {}) {
  const fields = ["schemaVersion", "kind", "operation", "environment", "accountId", "region", "sourceSha", "historicalRotationId", "rotationId", "abandonmentEvidenceSha256", "baselineIdentitySha256", "resources", "writeIdentities", "expectedSecretValueWrites", "expectedSecretDeletes", "liveReferenceAudit", "liveReferenceAuditSha256", "observedSlotIdentitiesSha256", "reason", "approvedBy", "approverRole", "verificationRef", "protectedEnvironmentApprovalEvidence", "protectedEnvironmentApprovalEvidenceSha256", "exclusions", "authorizationSha256"];
  exactKeys(value, fields, "Rebaseline authorization");
  if (value.schemaVersion !== 1 || value.kind !== REBASELINE_AUTHORIZATION_KIND || value.operation !== PRODUCTION_DUAL_SLOT_REBASELINE.kind || value.environment !== "production" || value.accountId !== PRODUCTION_DUAL_SLOT_REBASELINE.accountId || value.region !== PRODUCTION_DUAL_SLOT_REBASELINE.region || value.sourceSha !== sourceSha || value.rotationId !== rotationId || value.expectedSecretValueWrites !== 7 || value.expectedSecretDeletes !== 0 || value.liveReferenceAudit !== "PASS" || !SHA256.test(value.liveReferenceAuditSha256 || "") || !SHA256.test(value.observedSlotIdentitiesSha256 || "")) fail("Rebaseline authorization identity is invalid.");
  assertRotation(value.historicalRotationId, "historicalRotationId"); assertRotation(value.rotationId, "rotationId"); if (value.rotationId === value.historicalRotationId) fail("Rebaseline rotation is not new."); assertSha256(value.abandonmentEvidenceSha256, "abandonmentEvidenceSha256"); assertSha256(value.baselineIdentitySha256, "baselineIdentitySha256"); assertSlotMap(value.resources, "resources"); exactKeys(value.writeIdentities, REBASELINE_SLOT_ORDER, "writeIdentities"); for (const slot of REBASELINE_SLOT_ORDER) { assertVersion(value.writeIdentities[slot], `writeIdentities.${slot}`); if (value.writeIdentities[slot] !== deterministicWriteIdentity({ sourceSha, rotationId, slot, secretArn: value.resources[slot], baselineIdentitySha256: value.baselineIdentitySha256 })) fail(`writeIdentities.${slot} is not bound to the exact resource and baseline.`); }
  for (const name of ["reason", "approvedBy", "approverRole", "verificationRef"]) text(value[name], name);
  if (canonical(value.exclusions) !== canonical(["Terraform apply", "ECS RegisterTaskDefinition", "ECS UpdateService", "database mutation", "IAM mutation", "KMS policy mutation", "image publication", "network mutation", "DeleteSecret"])) fail("Rebaseline authorization exclusions are incomplete.");
  assertProductionEnvironmentApprovalIdentity(value.protectedEnvironmentApprovalEvidence, { sourceSha, repository: PRODUCTION_DUAL_SLOT_REBASELINE.repository }); if (value.protectedEnvironmentApprovalEvidence.workflowRef !== PRODUCTION_ENVIRONMENT_APPROVAL.dualSlotRebaselineWorkflowRef || value.protectedEnvironmentApprovalEvidenceSha256 !== value.protectedEnvironmentApprovalEvidence.evidenceSha256) fail("Rebaseline protected-environment evidence is not exact.");
  if (resources && canonical(value.resources) !== canonical(assertSlotMap(resources, "resources"))) fail("Rebaseline authorization resources do not match."); const { authorizationSha256, ...body } = value; if (!SHA256.test(authorizationSha256 || "") || canonicalSha256(body) !== authorizationSha256) fail("Rebaseline authorization hash is invalid."); return value;
}

export function resolveProductionDualSlotRebaselineAuthorizationArtifact({ workflowRunId, workflowRunAttempt, sourceSha, rotationId, resources, run = (command, args, options = {}) => execFileSync(command, args, { encoding: options.encoding === null ? null : "utf8", maxBuffer: options.maxBuffer }) } = {}) {
  if (!/^[1-9][0-9]*$/.test(String(workflowRunId || "")) || !/^[1-9][0-9]*$/.test(String(workflowRunAttempt || "")) || !SHA40.test(sourceSha || "")) fail("Rebaseline authorization workflow coordinates are invalid.");
  const workflow = JSON.parse(run("gh", ["api", `repos/${PRODUCTION_DUAL_SLOT_REBASELINE.repository}/actions/runs/${workflowRunId}`]));
  if (String(workflow.id) !== String(workflowRunId) || workflow.repository?.full_name !== PRODUCTION_DUAL_SLOT_REBASELINE.repository || workflow.head_repository?.full_name !== PRODUCTION_DUAL_SLOT_REBASELINE.repository || workflow.path !== ".github/workflows/authorize-production-dual-slot-rebaseline.yml" || workflow.event !== "workflow_dispatch" || workflow.head_sha !== sourceSha || workflow.status !== "completed" || workflow.conclusion !== "success" || String(workflow.run_attempt) !== String(workflowRunAttempt)) fail("Rebaseline authorization workflow provenance is not authentic.");
  const pages = JSON.parse(run("gh", ["api", `repos/${PRODUCTION_DUAL_SLOT_REBASELINE.repository}/actions/runs/${workflowRunId}/artifacts`, "--paginate", "--slurp"]));
  const artifacts = Array.isArray(pages) ? pages.flatMap((page) => page?.artifacts || []) : [];
  const matches = artifacts.filter((artifact) => artifact.name === "production-dual-slot-rebaseline-authorization" && artifact.expired === false && String(artifact.workflow_run?.id) === String(workflowRunId) && artifact.workflow_run?.head_sha === sourceSha && artifact.workflow_run?.repository_id === workflow.repository.id && /^sha256:[a-f0-9]{64}$/.test(artifact.digest || ""));
  if (matches.length !== 1 || !Number.isSafeInteger(matches[0]?.id) || matches[0].id < 1) fail("Rebaseline authorization artifact identity is not exact.");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-rebaseline-authorization-")); const archive = path.join(directory, "authorization.zip");
  try {
    const bytes = run("gh", ["api", `repos/${PRODUCTION_DUAL_SLOT_REBASELINE.repository}/actions/artifacts/${matches[0].id}/zip`], { encoding: null, maxBuffer: 64 * 1024 * 1024 });
    if (!Buffer.isBuffer(bytes) || bytes.length === 0 || `sha256:${sha256(bytes)}` !== matches[0].digest) fail("Rebaseline authorization archive bytes are not authenticated.");
    fs.writeFileSync(archive, bytes, { mode: 0o600, flag: "wx" });
    const entries = String(run("unzip", ["-Z1", archive])).trim().split("\n").filter(Boolean);
    if (canonical(entries) !== canonical(["authorization.json"])) fail("Rebaseline authorization archive contents are not exact.");
    const listing = String(run("unzip", ["-Z", "-l", archive])).split("\n").filter((line) => line.trim().endsWith(" authorization.json"));
    if (listing.length !== 1 || !listing[0].trim().startsWith("-")) fail("Rebaseline authorization archive payload is not a regular file.");
    const authorization = JSON.parse(Buffer.from(run("unzip", ["-p", archive, "authorization.json"])).toString("utf8"));
    assertProductionDualSlotRebaselineAuthorization(authorization, { sourceSha, rotationId, resources });
    const evidence = authorization.protectedEnvironmentApprovalEvidence;
    if (evidence.workflowRunId !== String(workflow.id) || evidence.workflowRunAttempt !== String(workflow.run_attempt) || evidence.executionActor?.toLowerCase() !== String(workflow.actor?.login || "").toLowerCase()) fail("Rebaseline authorization artifact is not bound to the authenticated workflow execution.");
    return Object.freeze({ workflow, artifact: matches[0], authorization, authorizationArtifactDigest: matches[0].digest });
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

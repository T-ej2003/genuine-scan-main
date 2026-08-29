import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import { execFileSync } from "node:child_process";
import { ensureStageBPrivateDirectory, readStageBPrivateFileBytes, writeStageBPrivateFileAtomicExclusive } from "./stage-b-artifact-contract.mjs";
import path from "node:path";
import { assertProductionEnvironmentActualReviewer, assertProductionEnvironmentApprovalIdentity, PRODUCTION_ENVIRONMENT_APPROVAL } from "./production-github-environment-approval.mjs";
import { assertProductionSupersessionEvidence } from "../security/production-initial-migration-source-advance.mjs";

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
export const REBASELINE_ABANDONED_HISTORICAL_ROTATION_ID = "rotation-20260826060632-b15b3f51";
export const AUTHENTICATED_PRE_CUTOVER_COORDINATOR_TRANSITION = "AUTHENTICATED_PRE_CUTOVER_COORDINATOR_TRANSITION";
export const REBASELINE_COORDINATOR_SOURCE_SHA = REBASELINE_HISTORICAL_SOURCE_SHAS[1];
export const REBASELINE_COORDINATOR_WRITER = "backend/scripts/security/rotate-production-signing-material.mjs:putMaterial";
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

// This is a reviewed trust anchor for the one retained coordinator transition that
// may be adopted.  The supplied evidence remains an integrity envelope; it is not
// allowed to mint historical authority by recomputing its own digest.
const AUTHENTICATED_COORDINATOR_TRANSITION_ANCHOR = Object.freeze({
  schemaVersion: 1,
  kind: AUTHENTICATED_PRE_CUTOVER_COORDINATOR_TRANSITION,
  coordinatorSourceSha: REBASELINE_COORDINATOR_SOURCE_SHA,
  historicalRotationId: REBASELINE_ABANDONED_HISTORICAL_ROTATION_ID,
  writer: Object.freeze({ sourceSha: REBASELINE_COORDINATOR_SOURCE_SHA, module: "backend/scripts/security/rotate-production-signing-material.mjs", operation: "putMaterial", semanticsVersion: 1 }),
  originalSupersessionEvidenceSha256: "1e417d5f42d821f8022a56be1f07e257c48c4a81e44fc67822ff0d1c164f6df7",
  historicalTopologySha256: REBASELINE_ABANDONED_HISTORICAL_TOPOLOGY_SHA256,
  resourcesSha256: "107e412e699b03ab324ddf6d3ebb0173a2b0d589db400dc921de22a91f56d1ab",
  predecessorVersionIds: Object.freeze({
    jwtPending: "737fd4b9a57f9ee005ffdece208220e842883f29f0166d07b763d6b55644e908",
    qrPrivatePending: "a0f20f429e5b2d289a676d13e3ea3e9d098874e3c783546e59c6afc952e2b1ba",
    qrPublicPending: "c2d8cbe2804d92fda7396a7181377da77f87775dd87f8115a216897b11eef45e",
    jwtPrevious: "61e8a3601210b8e7df43138088132fb1dedcdcd1b5c6e161d7af0285575355fc",
    qrPublicPrevious: "bf432d60e346a18245fb3e85a6a28137ecea73cf52768ef2a6ded98283038548",
    qrCurrentVersion: "11ce28ae6f806270413faabef2d055bd97db30fb75f53bd59b59cdb121ca30d4",
    qrPreviousVersion: "eff7b3dc6ca8dcdbaec9b7e300811ea603c813ba646d8f654388e66d6b68f5e3",
  }),
  postVersionIds: Object.freeze({
    jwtPending: "737fd4b9a57f9ee005ffdece208220e842883f29f0166d07b763d6b55644e908",
    qrPrivatePending: "a0f20f429e5b2d289a676d13e3ea3e9d098874e3c783546e59c6afc952e2b1ba",
    qrPublicPending: "c2d8cbe2804d92fda7396a7181377da77f87775dd87f8115a216897b11eef45e",
    jwtPrevious: "0c82ddd3f3dfd07cc0b563445403b726e76af0a1bdbf8b915983cf8e84fa54de",
    qrPublicPrevious: "bf432d60e346a18245fb3e85a6a28137ecea73cf52768ef2a6ded98283038548",
    qrCurrentVersion: "6f6155c7984e7b7b5b4ddfe0f8852f5bd630e5c88d3391b4024a20376c26bbc0",
    qrPreviousVersion: "eff7b3dc6ca8dcdbaec9b7e300811ea603c813ba646d8f654388e66d6b68f5e3",
  }),
  authorization: Object.freeze({ reference: "GH-ISSUE-391", sourceSha: REBASELINE_COORDINATOR_SOURCE_SHA, rotationId: REBASELINE_ABANDONED_HISTORICAL_ROTATION_ID, resourcesSha256: "107e412e699b03ab324ddf6d3ebb0173a2b0d589db400dc921de22a91f56d1ab", evidenceSha256: "4da8122764c5d404d668320a222c2f590e78db34217a4e5d72dfc8b22b0354b8" }),
  rotationState: Object.freeze({ stateVersion: 4, sourceSha: REBASELINE_COORDINATOR_SOURCE_SHA, rotationId: REBASELINE_ABANDONED_HISTORICAL_ROTATION_ID, phase: "overlap-deploy-required", initialMigrationSourceSha: REBASELINE_HISTORICAL_SOURCE_SHAS[0], stateSha256: "1769b305a1aea0619c1a58f478aa3fc4dd8f0c2505c6c39cc34326bfaf78744c" }),
  predecessorPayloadIdentities: Object.freeze({
    jwtPending: Object.freeze({ payloadSchema: "INITIAL_DUAL_SLOT_ROTATION_V1", payloadKind: Object.freeze({ family: "jwt_secrets", slot: "pending", initialMigration: false }), observedRotationId: REBASELINE_ABANDONED_HISTORICAL_ROTATION_ID, observedSourceSha: REBASELINE_HISTORICAL_SOURCE_SHAS[0], payloadSha256: "f5fd4550c84c9e6c4d3b814abe34baf262e23bdf69d389a9477eb342481fa3f5", materialFingerprint: "465ccccb1c54732a", keyVersion: null }),
    qrPrivatePending: Object.freeze({ payloadSchema: "INITIAL_DUAL_SLOT_ROTATION_V1", payloadKind: Object.freeze({ family: "qr_signing_keys", slot: "pending-private", initialMigration: false }), observedRotationId: REBASELINE_ABANDONED_HISTORICAL_ROTATION_ID, observedSourceSha: REBASELINE_HISTORICAL_SOURCE_SHAS[0], payloadSha256: "4c452f500a4b3397e9563fc32c9673ff2236da2793b02f4355995b882af2e306", materialFingerprint: "52535062f8f92570", keyVersion: "c41ca96ab047dd25" }),
    qrPublicPending: Object.freeze({ payloadSchema: "INITIAL_DUAL_SLOT_ROTATION_V1", payloadKind: Object.freeze({ family: "qr_signing_keys", slot: "pending-public", initialMigration: false }), observedRotationId: REBASELINE_ABANDONED_HISTORICAL_ROTATION_ID, observedSourceSha: REBASELINE_HISTORICAL_SOURCE_SHAS[0], payloadSha256: "230e8c09214455fc73fb14fe3232b8c4534e6f6a827a798dd8dcda59eaf1cb08", materialFingerprint: "c41ca96ab047dd25", keyVersion: "c41ca96ab047dd25" }),
    jwtPrevious: Object.freeze({ payloadSchema: "INITIAL_DUAL_SLOT_SOURCE_ADVANCE_V1", payloadKind: Object.freeze({ family: "jwt_secrets", slot: "empty", initialMigration: true }), observedRotationId: null, observedSourceSha: REBASELINE_HISTORICAL_SOURCE_SHAS[0], payloadSha256: "6142323165b798617aa7c16d01bce85be1598f304a5d8f1615fcae4cd8ce0442", materialFingerprint: null, keyVersion: null }),
    qrPublicPrevious: Object.freeze({ payloadSchema: "INITIAL_DUAL_SLOT_SOURCE_ADVANCE_V1", payloadKind: Object.freeze({ family: "qr_signing_keys", slot: "empty", initialMigration: true }), observedRotationId: null, observedSourceSha: REBASELINE_HISTORICAL_SOURCE_SHAS[0], payloadSha256: "2b9556af5ac261ebf168cdab1061e8d165b6d6b9e54563320a981449dea1167a", materialFingerprint: null, keyVersion: null }),
    qrCurrentVersion: Object.freeze({ payloadSchema: "INITIAL_DUAL_SLOT_SOURCE_ADVANCE_V1", payloadKind: Object.freeze({ family: "qr_key_versions", slot: "current", initialMigration: true }), observedRotationId: null, observedSourceSha: REBASELINE_HISTORICAL_SOURCE_SHAS[0], payloadSha256: "46248c1e25e4825213ac2c9260a5c129296fb7acf531a0c6438690cfbc5d444e", materialFingerprint: null, keyVersion: null }),
    qrPreviousVersion: Object.freeze({ payloadSchema: "INITIAL_DUAL_SLOT_SOURCE_ADVANCE_V1", payloadKind: Object.freeze({ family: "qr_key_versions", slot: "previous-empty", initialMigration: true }), observedRotationId: null, observedSourceSha: REBASELINE_HISTORICAL_SOURCE_SHAS[0], payloadSha256: "06ec3870a4dbceb768bd35a0480999b30e2bfb50a8a9cce7712601abaab4b715", materialFingerprint: null, keyVersion: null }),
  }),
  postPayloadIdentities: Object.freeze({
    jwtPending: Object.freeze({ payloadSchema: "INITIAL_DUAL_SLOT_ROTATION_V1", payloadKind: Object.freeze({ family: "jwt_secrets", slot: "pending", initialMigration: false }), observedRotationId: REBASELINE_ABANDONED_HISTORICAL_ROTATION_ID, observedSourceSha: REBASELINE_HISTORICAL_SOURCE_SHAS[0], payloadSha256: "f5fd4550c84c9e6c4d3b814abe34baf262e23bdf69d389a9477eb342481fa3f5", materialFingerprint: "465ccccb1c54732a", keyVersion: null }),
    qrPrivatePending: Object.freeze({ payloadSchema: "INITIAL_DUAL_SLOT_ROTATION_V1", payloadKind: Object.freeze({ family: "qr_signing_keys", slot: "pending-private", initialMigration: false }), observedRotationId: REBASELINE_ABANDONED_HISTORICAL_ROTATION_ID, observedSourceSha: REBASELINE_HISTORICAL_SOURCE_SHAS[0], payloadSha256: "4c452f500a4b3397e9563fc32c9673ff2236da2793b02f4355995b882af2e306", materialFingerprint: "52535062f8f92570", keyVersion: "c41ca96ab047dd25" }),
    qrPublicPending: Object.freeze({ payloadSchema: "INITIAL_DUAL_SLOT_ROTATION_V1", payloadKind: Object.freeze({ family: "qr_signing_keys", slot: "pending-public", initialMigration: false }), observedRotationId: REBASELINE_ABANDONED_HISTORICAL_ROTATION_ID, observedSourceSha: REBASELINE_HISTORICAL_SOURCE_SHAS[0], payloadSha256: "230e8c09214455fc73fb14fe3232b8c4534e6f6a827a798dd8dcda59eaf1cb08", materialFingerprint: "c41ca96ab047dd25", keyVersion: "c41ca96ab047dd25" }),
    jwtPrevious: Object.freeze({ payloadSchema: "COORDINATOR_ROTATION_WRITER_V1", payloadKind: Object.freeze({ family: "jwt_secrets", slot: "previous" }), observedRotationId: REBASELINE_ABANDONED_HISTORICAL_ROTATION_ID, observedSourceSha: null, payloadSha256: "b1b4ab8a1b75414c9ac67c5805712d2d0d5c77abe759a50080a92b43295333dc", materialFingerprint: "f08038af478ff7cc", keyVersion: null }),
    qrPublicPrevious: Object.freeze({ payloadSchema: "INITIAL_DUAL_SLOT_SOURCE_ADVANCE_V1", payloadKind: Object.freeze({ family: "qr_signing_keys", slot: "empty", initialMigration: true }), observedRotationId: null, observedSourceSha: REBASELINE_HISTORICAL_SOURCE_SHAS[0], payloadSha256: "2b9556af5ac261ebf168cdab1061e8d165b6d6b9e54563320a981449dea1167a", materialFingerprint: null, keyVersion: null }),
    qrCurrentVersion: Object.freeze({ payloadSchema: "COORDINATOR_ROTATION_WRITER_V1", payloadKind: Object.freeze({ family: "qr_key_versions", slot: "current" }), observedRotationId: REBASELINE_ABANDONED_HISTORICAL_ROTATION_ID, observedSourceSha: REBASELINE_COORDINATOR_SOURCE_SHA, payloadSha256: "084036f486c0269ad9e56ba406d391cda77b3c51f301ea2772b336de38ad65a8", materialFingerprint: null, keyVersion: "c41ca96ab047dd25" }),
    qrPreviousVersion: Object.freeze({ payloadSchema: "INITIAL_DUAL_SLOT_SOURCE_ADVANCE_V1", payloadKind: Object.freeze({ family: "qr_key_versions", slot: "previous-empty", initialMigration: true }), observedRotationId: null, observedSourceSha: REBASELINE_HISTORICAL_SOURCE_SHAS[0], payloadSha256: "06ec3870a4dbceb768bd35a0480999b30e2bfb50a8a9cce7712601abaab4b715", materialFingerprint: null, keyVersion: null }),
  }),
  unexplainedSlotCount: 0,
  conflictSlotCount: 0,
  dualSlotReferences: 0,
});

export const EXPECTED_AUTHENTICATED_PRE_CUTOVER_COORDINATOR_TRANSITION_SHA256 = "82e33f535b53254c531ccbb6151fe9aee116d3401d7509d472da54626cb9b580";
if (canonicalSha256(AUTHENTICATED_COORDINATOR_TRANSITION_ANCHOR) !== EXPECTED_AUTHENTICATED_PRE_CUTOVER_COORDINATOR_TRANSITION_SHA256) throw new Error("Protected coordinator transition anchor is internally inconsistent.");

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
  if (rotationId !== undefined && rotationId !== REBASELINE_ABANDONED_HISTORICAL_ROTATION_ID) fail(`Historical ${slot} rotation provenance is not approved.`);
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
  if (value.observedRotationId !== undefined && value.observedRotationId !== REBASELINE_ABANDONED_HISTORICAL_ROTATION_ID) fail("Historical slot rotation provenance is invalid.");
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
  if (historicalTopologySha256 === REBASELINE_ABANDONED_HISTORICAL_TOPOLOGY_SHA256) {
    const observedPayloadIdentities = Object.fromEntries(REBASELINE_SLOT_ORDER.map((slot) => [slot, coordinatorTransitionPayloadIdentity(identities[slot])]));
    if (canonicalSha256(resources) !== AUTHENTICATED_COORDINATOR_TRANSITION_ANCHOR.resourcesSha256 || canonical(currentVersionIds) !== canonical(AUTHENTICATED_COORDINATOR_TRANSITION_ANCHOR.predecessorVersionIds) || canonical(observedPayloadIdentities) !== canonical(AUTHENTICATED_COORDINATOR_TRANSITION_ANCHOR.predecessorPayloadIdentities)) fail("Historical slot payload identities do not match the protected historical authority anchor.");
  }
  return Object.freeze({ ...identities });
}

const coordinatorTransitionToken = (rotationId, slot) => slot === "jwtPrevious"
  ? sha256(`${rotationId}:jwt:previous`)
  : slot === "qrCurrentVersion" ? sha256(`${rotationId}:qr:current-version`) : undefined;

export function coordinatorTransitionVersionId({ historicalRotationId = REBASELINE_ABANDONED_HISTORICAL_ROTATION_ID, slot } = {}) {
  if (historicalRotationId !== REBASELINE_ABANDONED_HISTORICAL_ROTATION_ID || !REBASELINE_SLOT_ORDER.includes(slot) || !coordinatorTransitionToken(historicalRotationId, slot)) fail("Coordinator transition slot is invalid.");
  assertRotation(historicalRotationId, "historicalRotationId");
  return coordinatorTransitionToken(historicalRotationId, slot);
}

export function coordinatorTransitionSlotIdentity({ slot, secretArn, versionId, stages, payload } = {}) {
  if (!['jwtPrevious', 'qrCurrentVersion'].includes(slot)) fail("Coordinator transition slot is invalid.");
  assertArn(secretArn, "Coordinator transition secret ARN");
  assertVersion(versionId, "Coordinator transition VersionId");
  if (versionId !== coordinatorTransitionVersionId({ slot }) || !Array.isArray(stages) || canonical([...stages].sort()) !== canonical(["AWSCURRENT"])) fail("Coordinator transition VersionId or stages are not exact.");
  if (!payload || typeof payload !== "object" || Array.isArray(payload) || typeof payload.value !== "string" || payload.rotationId !== REBASELINE_ABANDONED_HISTORICAL_ROTATION_ID) fail("Coordinator transition payload is malformed.");
  const expected = slot === "jwtPrevious" ? { family: "jwt_secrets", slot: "previous" } : HISTORICAL_SLOT_SHAPES[slot];
  if (payload.family !== expected.family || payload.slot !== expected.slot) fail(`Coordinator transition ${slot} payload kind is not authentic.`);
  if (slot === "jwtPrevious") {
    if (payload.sourceSha !== undefined || typeof payload.materialFingerprint !== "string" || payload.materialFingerprint !== fingerprint(payload.value)) fail("Coordinator jwtPrevious source-less writer shape is not authentic.");
  } else if (payload.sourceSha !== REBASELINE_COORDINATOR_SOURCE_SHA || typeof payload.keyVersion !== "string" || !payload.keyVersion) fail("Coordinator qrCurrentVersion writer shape is not authentic.");
  const body = {
    schemaVersion: 1, kind: AUTHENTICATED_PRE_CUTOVER_COORDINATOR_TRANSITION, slot, secretArn, versionId, stages: ["AWSCURRENT"],
    payloadSchema: "COORDINATOR_ROTATION_WRITER_V1", payloadKind: { family: payload.family, slot: payload.slot },
    observedRotationId: payload.rotationId, ...(payload.sourceSha === undefined ? {} : { observedSourceSha: payload.sourceSha }),
    payloadSha256: canonicalSha256(payload), ...(payload.materialFingerprint ? { materialFingerprint: payload.materialFingerprint } : {}), ...(payload.keyVersion ? { keyVersion: payload.keyVersion } : {}),
  };
  return Object.freeze({ ...body, identitySha256: canonicalSha256(body) });
}

function assertCoordinatorTransitionSlotIdentity(value, { slot, secretArn, versionId } = {}) {
  const allowed = ["schemaVersion", "kind", "slot", "secretArn", "versionId", "stages", "payloadSchema", "payloadKind", "observedRotationId", "observedSourceSha", "payloadSha256", "materialFingerprint", "keyVersion", "identitySha256"];
  if (!value || typeof value !== "object" || Object.keys(value).some((key) => !allowed.includes(key)) || value.schemaVersion !== 1 || value.kind !== AUTHENTICATED_PRE_CUTOVER_COORDINATOR_TRANSITION || value.slot !== slot || value.secretArn !== secretArn || value.versionId !== versionId || canonical(value.stages) !== canonical(["AWSCURRENT"]) || value.payloadSchema !== "COORDINATOR_ROTATION_WRITER_V1" || value.observedRotationId !== REBASELINE_ABANDONED_HISTORICAL_ROTATION_ID || !SHA256.test(value.payloadSha256 || "") || !SHA256.test(value.identitySha256 || "")) fail("Coordinator transition slot identity is invalid.");
  const expected = slot === "jwtPrevious" ? { family: "jwt_secrets", slot: "previous" } : { family: "qr_key_versions", slot: "current" };
  if (value.payloadKind?.family !== expected.family || value.payloadKind?.slot !== expected.slot || (slot === "jwtPrevious" ? value.observedSourceSha !== undefined || typeof value.materialFingerprint !== "string" : value.observedSourceSha !== REBASELINE_COORDINATOR_SOURCE_SHA || typeof value.keyVersion !== "string" || !value.keyVersion)) fail("Coordinator transition slot provenance is invalid.");
  const { identitySha256, ...body } = value;
  if (canonicalSha256(body) !== identitySha256) fail("Coordinator transition slot identity hash is invalid.");
  return value;
}

function assertCoordinatorTransitionIdentityMap(identities, resources, versionIds, label, coordinatorSlots = ["jwtPrevious", "qrCurrentVersion"]) {
  exactKeys(identities, REBASELINE_SLOT_ORDER, label);
  for (const slot of REBASELINE_SLOT_ORDER) {
    if (coordinatorSlots.includes(slot)) assertCoordinatorTransitionSlotIdentity(identities[slot], { slot, secretArn: resources[slot], versionId: versionIds[slot] });
    else assertHistoricalSlotIdentity(identities[slot], { slot, secretArn: resources[slot], versionId: versionIds[slot] });
  }
  return Object.freeze({ ...identities });
}

function coordinatorTransitionPayloadIdentity(value) {
  return Object.freeze({
    payloadSchema: value.payloadSchema,
    payloadKind: value.payloadKind,
    observedRotationId: value.observedRotationId ?? null,
    observedSourceSha: value.observedSourceSha ?? null,
    payloadSha256: value.payloadSha256,
    materialFingerprint: value.materialFingerprint ?? null,
    keyVersion: value.keyVersion ?? null,
  });
}

function coordinatorTransitionAnchorProjection(value, resources) {
  return {
    schemaVersion: value.schemaVersion,
    kind: value.kind,
    coordinatorSourceSha: value.coordinatorSourceSha,
    historicalRotationId: value.historicalRotationId,
    writer: value.writer,
    originalSupersessionEvidenceSha256: value.originalSupersessionEvidenceSha256,
    historicalTopologySha256: canonicalSha256({ resources, versionIds: value.predecessorVersionIds }),
    resourcesSha256: canonicalSha256(resources),
    predecessorVersionIds: value.predecessorVersionIds,
    postVersionIds: value.postVersionIds,
    authorization: value.authorization,
    rotationState: value.rotationState,
    predecessorPayloadIdentities: Object.fromEntries(REBASELINE_SLOT_ORDER.map((slot) => [slot, coordinatorTransitionPayloadIdentity(value.predecessorSlotIdentities[slot])])),
    postPayloadIdentities: Object.fromEntries(REBASELINE_SLOT_ORDER.map((slot) => [slot, coordinatorTransitionPayloadIdentity(value.postSlotIdentities[slot])])),
    unexplainedSlotCount: value.unexplainedSlotCount,
    conflictSlotCount: value.conflictSlotCount,
    dualSlotReferences: value.dualSlotReferences,
  };
}

function assertCoordinatorTransitionEnvelope(value, { resources, observedVersionIds, observedSlotIdentities, liveReferenceAuditSha256, liveLegacyBaselineIdentitySha256 } = {}) {
  const keys = ["schemaVersion", "kind", "coordinatorSourceSha", "historicalRotationId", "writer", "originalSupersessionEvidence", "originalSupersessionEvidenceSha256", "predecessorVersionIds", "predecessorSlotIdentities", "postVersionIds", "postSlotIdentities", "authorization", "rotationState", "unexplainedSlotCount", "conflictSlotCount", "dualSlotReferences", "liveReferenceAuditSha256", "liveLegacyBaselineIdentitySha256", "transitionSha256"];
  exactKeys(value, keys, "Coordinator transition evidence");
  if (value.schemaVersion !== 1 || value.kind !== AUTHENTICATED_PRE_CUTOVER_COORDINATOR_TRANSITION || value.coordinatorSourceSha !== REBASELINE_COORDINATOR_SOURCE_SHA || value.historicalRotationId !== REBASELINE_ABANDONED_HISTORICAL_ROTATION_ID || value.unexplainedSlotCount !== 0 || value.conflictSlotCount !== 0 || value.dualSlotReferences !== 0 || !SHA256.test(value.liveReferenceAuditSha256 || "") || !SHA256.test(value.liveLegacyBaselineIdentitySha256 || "")) fail("Coordinator transition evidence identity is invalid.");
  exactKeys(value.writer, ["sourceSha", "module", "operation", "semanticsVersion"], "Coordinator transition writer");
  if (value.writer.sourceSha !== REBASELINE_COORDINATOR_SOURCE_SHA || value.writer.module !== "backend/scripts/security/rotate-production-signing-material.mjs" || value.writer.operation !== "putMaterial" || value.writer.semanticsVersion !== 1) fail("Coordinator transition writer provenance is invalid.");
  assertProductionSupersessionEvidence(value.originalSupersessionEvidence);
  if (value.originalSupersessionEvidence.sourceSha !== REBASELINE_HISTORICAL_SOURCE_SHAS[0] || value.originalSupersessionEvidence.rotationId !== value.historicalRotationId || value.originalSupersessionEvidenceSha256 !== value.originalSupersessionEvidence.evidenceIdentitySha256) fail("Coordinator predecessor supersession evidence is invalid.");
  const checkedResources = assertSlotMap(resources || Object.fromEntries(REBASELINE_SLOT_ORDER.map((slot) => [slot, value.predecessorSlotIdentities[slot]?.secretArn])), "Coordinator transition resources");
  if (canonical(value.originalSupersessionEvidence.resources) !== canonical(Object.fromEntries(REBASELINE_SLOT_ORDER.map((slot) => [slot, { arn: checkedResources[slot], stages: ["AWSCURRENT"], versionId: value.predecessorVersionIds[slot] }]))) ) fail("Coordinator predecessor resources are not exact.");
  exactKeys(value.predecessorVersionIds, REBASELINE_SLOT_ORDER, "Coordinator predecessorVersionIds");
  exactKeys(value.postVersionIds, REBASELINE_SLOT_ORDER, "Coordinator postVersionIds");
  for (const slot of REBASELINE_SLOT_ORDER) {
    assertVersion(value.predecessorVersionIds[slot], `Coordinator predecessor VersionId ${slot}`);
    assertVersion(value.postVersionIds[slot], `Coordinator post VersionId ${slot}`);
    if (value.postVersionIds[slot] !== (coordinatorTransitionToken(value.historicalRotationId, slot) || value.predecessorVersionIds[slot])) fail(`Coordinator ${slot} transition VersionId is not deterministic.`);
  }
  if (canonicalSha256({ resources: checkedResources, versionIds: value.predecessorVersionIds }) !== canonicalSha256({ resources: checkedResources, versionIds: value.originalSupersessionEvidence.resources && Object.fromEntries(REBASELINE_SLOT_ORDER.map((slot) => [slot, value.originalSupersessionEvidence.resources[slot].versionId])) })) fail("Coordinator predecessor topology is not bound to supersession evidence.");
  assertHistoricalSlotIdentities(value.predecessorSlotIdentities, checkedResources, value.predecessorVersionIds, canonicalSha256({ resources: checkedResources, versionIds: value.predecessorVersionIds }));
  assertCoordinatorTransitionIdentityMap(value.postSlotIdentities, checkedResources, value.postVersionIds);
  exactKeys(value.authorization, ["reference", "sourceSha", "rotationId", "resourcesSha256", "evidenceSha256"], "Coordinator transition authorization");
  if (value.authorization.reference !== "GH-ISSUE-391" || value.authorization.sourceSha !== REBASELINE_COORDINATOR_SOURCE_SHA || value.authorization.rotationId !== value.historicalRotationId || value.authorization.resourcesSha256 !== canonicalSha256(checkedResources)) fail("Coordinator transition authorization is invalid.");
  const { evidenceSha256: authorizationEvidenceSha, ...authorizationBody } = value.authorization;
  if (authorizationEvidenceSha !== canonicalSha256(authorizationBody)) fail("Coordinator transition authorization evidence hash is invalid.");
  exactKeys(value.rotationState, ["stateVersion", "sourceSha", "rotationId", "phase", "initialMigrationSourceSha", "stateSha256"], "Coordinator transition rotation state");
  if (value.rotationState.stateVersion !== 4 || value.rotationState.sourceSha !== REBASELINE_COORDINATOR_SOURCE_SHA || value.rotationState.rotationId !== value.historicalRotationId || value.rotationState.phase !== "overlap-deploy-required" || value.rotationState.initialMigrationSourceSha !== REBASELINE_HISTORICAL_SOURCE_SHAS[0]) fail("Coordinator transition rotation state is invalid.");
  const { stateSha256, ...stateBody } = value.rotationState;
  if (stateSha256 !== canonicalSha256(stateBody)) fail("Coordinator transition rotation state hash is invalid.");
  if (observedVersionIds && canonical(observedVersionIds) !== canonical(value.postVersionIds)) fail("Observed coordinator transition versions are not exact.");
  if (observedSlotIdentities) {
    assertCoordinatorTransitionIdentityMap(observedSlotIdentities, checkedResources, value.postVersionIds);
    if (canonical(observedSlotIdentities) !== canonical(value.postSlotIdentities)) fail("Observed coordinator transition identities are not exact.");
  }
  if (liveReferenceAuditSha256 !== undefined && value.liveReferenceAuditSha256 !== liveReferenceAuditSha256) fail("Coordinator transition live-reference evidence is not exact.");
  if (liveLegacyBaselineIdentitySha256 !== undefined && value.liveLegacyBaselineIdentitySha256 !== liveLegacyBaselineIdentitySha256) fail("Coordinator transition legacy baseline evidence is not exact.");
  const { transitionSha256, ...body } = value;
  if (!SHA256.test(transitionSha256 || "") || canonicalSha256(body) !== transitionSha256) fail("Coordinator transition evidence hash is invalid.");
  const anchor = coordinatorTransitionAnchorProjection(value, checkedResources);
  if (canonicalSha256(anchor) !== EXPECTED_AUTHENTICATED_PRE_CUTOVER_COORDINATOR_TRANSITION_SHA256) fail("Coordinator transition evidence does not match the protected historical authority anchor.");
  return Object.freeze({ ...value, resources: checkedResources });
}

export function assertAuthenticatedPreCutoverCoordinatorTransition(value, options = {}) {
  if (!options.resources || !options.observedVersionIds || !options.observedSlotIdentities) fail("Authenticated coordinator transition requires exact live resource and slot observations.");
  return assertCoordinatorTransitionEnvelope(value, options);
}

export function buildAuthenticatedPreCutoverCoordinatorTransition({ coordinatorSourceSha = REBASELINE_COORDINATOR_SOURCE_SHA, historicalRotationId = REBASELINE_ABANDONED_HISTORICAL_ROTATION_ID, resources, originalSupersessionEvidence, predecessorSlotIdentities, postSlotIdentities, authorization, rotationState, liveReferenceAuditSha256, liveLegacyBaselineIdentitySha256 } = {}) {
  const checkedResources = assertSlotMap(resources, "Coordinator transition resources");
  assertProductionSupersessionEvidence(originalSupersessionEvidence);
  const predecessorVersionIds = Object.fromEntries(REBASELINE_SLOT_ORDER.map((slot) => [slot, originalSupersessionEvidence.resources[slot].versionId]));
  const postVersionIds = Object.fromEntries(REBASELINE_SLOT_ORDER.map((slot) => [slot, coordinatorTransitionToken(historicalRotationId, slot) || predecessorVersionIds[slot]]));
  const body = { schemaVersion: 1, kind: AUTHENTICATED_PRE_CUTOVER_COORDINATOR_TRANSITION, coordinatorSourceSha, historicalRotationId, writer: { sourceSha: coordinatorSourceSha, module: "backend/scripts/security/rotate-production-signing-material.mjs", operation: "putMaterial", semanticsVersion: 1 }, originalSupersessionEvidence, originalSupersessionEvidenceSha256: originalSupersessionEvidence.evidenceIdentitySha256, predecessorVersionIds, predecessorSlotIdentities, postVersionIds, postSlotIdentities, authorization, rotationState, unexplainedSlotCount: 0, conflictSlotCount: 0, dualSlotReferences: 0, liveReferenceAuditSha256, liveLegacyBaselineIdentitySha256 };
  const result = { ...body, transitionSha256: canonicalSha256(body) };
  assertCoordinatorTransitionEnvelope(result, { resources: checkedResources });
  return Object.freeze(result);
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

export function buildAbandonmentEvidence({ sourceSha, historicalRotationId, historicalSourceShas, resources, currentVersionIds, historicalTopologySha256 = REBASELINE_ABANDONED_HISTORICAL_TOPOLOGY_SHA256, observedSlotIdentities, historicalTransitionEvidence, liveReferenceAudit, liveReferenceAuditSha256, liveLegacyBaselineIdentitySha256, legacyRuntimeAuthoritative, observedAt = new Date().toISOString() } = {}) {
  assertSha40(sourceSha, "sourceSha"); assertRotation(historicalRotationId, "historicalRotationId"); if (historicalRotationId !== REBASELINE_ABANDONED_HISTORICAL_ROTATION_ID) fail("Historical rotation identity is not the approved abandoned pre-cutover rotation.");
  const checkedResources = assertSlotMap(resources, "resources"); exactKeys(currentVersionIds, REBASELINE_SLOT_ORDER, "currentVersionIds");
  for (const slot of REBASELINE_SLOT_ORDER) assertVersion(currentVersionIds[slot], `currentVersionIds.${slot}`);
  const checkedIdentities = historicalTransitionEvidence
    ? (assertAuthenticatedPreCutoverCoordinatorTransition(historicalTransitionEvidence, { resources: checkedResources, observedVersionIds: currentVersionIds, observedSlotIdentities, liveReferenceAuditSha256, liveLegacyBaselineIdentitySha256 }).postSlotIdentities)
    : assertHistoricalSlotIdentities(observedSlotIdentities, checkedResources, currentVersionIds, historicalTopologySha256);
  if (liveReferenceAudit !== "PASS" || !SHA256.test(liveReferenceAuditSha256 || "") || legacyRuntimeAuthoritative !== true || (historicalTransitionEvidence && !SHA256.test(liveLegacyBaselineIdentitySha256 || ""))) fail("Historical rotation is not proven abandoned before cutover.");
  const timestamp = new Date(observedAt); if (!Number.isFinite(timestamp.getTime()) || timestamp.toISOString() !== observedAt) fail("observedAt is invalid.");
  const body = { schemaVersion: historicalTransitionEvidence ? 3 : 2, kind: ABANDONED_PRE_CUTOVER, environment: "production", accountId: PRODUCTION_DUAL_SLOT_REBASELINE.accountId, region: PRODUCTION_DUAL_SLOT_REBASELINE.region, sourceSha, historicalRotationId, historicalSourceShas: assertHistoricalSources(historicalSourceShas), resources: checkedResources, currentVersionIds: Object.freeze({ ...currentVersionIds }), historicalTopologySha256, observedSlotIdentities: checkedIdentities, observedSlotIdentitiesSha256: canonicalSha256(checkedIdentities), liveReferenceAudit, liveReferenceAuditSha256, legacyRuntimeAuthoritative, observedAt, ...(historicalTransitionEvidence ? { historicalTransitionEvidence, observedTopologySha256: canonicalSha256({ resources: checkedResources, versionIds: currentVersionIds }), liveLegacyBaselineIdentitySha256 } : {}) };
  return Object.freeze({ ...body, evidenceSha256: canonicalSha256(body) });
}

export function assertAbandonmentEvidence(evidence, { sourceSha, resources, historicalTopologySha256 = REBASELINE_ABANDONED_HISTORICAL_TOPOLOGY_SHA256 } = {}) {
  const commonKeys = ["schemaVersion", "kind", "environment", "accountId", "region", "sourceSha", "historicalRotationId", "historicalSourceShas", "resources", "currentVersionIds", "historicalTopologySha256", "observedSlotIdentities", "observedSlotIdentitiesSha256", "liveReferenceAudit", "liveReferenceAuditSha256", "legacyRuntimeAuthoritative", "observedAt", "evidenceSha256"];
  const transitionKeys = ["historicalTransitionEvidence", "observedTopologySha256", "liveLegacyBaselineIdentitySha256"];
  exactKeys(evidence, evidence?.schemaVersion === 3 ? [...commonKeys, ...transitionKeys] : commonKeys, "Abandonment evidence");
  if (![2, 3].includes(evidence.schemaVersion) || evidence.kind !== ABANDONED_PRE_CUTOVER || evidence.environment !== "production" || evidence.accountId !== PRODUCTION_DUAL_SLOT_REBASELINE.accountId || evidence.region !== PRODUCTION_DUAL_SLOT_REBASELINE.region || evidence.sourceSha !== sourceSha || evidence.liveReferenceAudit !== "PASS" || !SHA256.test(evidence.liveReferenceAuditSha256 || "") || evidence.legacyRuntimeAuthoritative !== true) fail("Abandonment evidence identity is invalid.");
  assertRotation(evidence.historicalRotationId, "historicalRotationId"); if (evidence.historicalRotationId !== REBASELINE_ABANDONED_HISTORICAL_ROTATION_ID) fail("Abandonment evidence historical rotation is not exact."); assertHistoricalSources(evidence.historicalSourceShas);
  const expectedResources = assertSlotMap(resources || evidence.resources, "resources"); if (canonical(evidence.resources) !== canonical(expectedResources)) fail("Abandonment evidence resources are not exact.");
  exactKeys(evidence.currentVersionIds, REBASELINE_SLOT_ORDER, "currentVersionIds"); for (const slot of REBASELINE_SLOT_ORDER) assertVersion(evidence.currentVersionIds[slot], `currentVersionIds.${slot}`);
  if (evidence.historicalTopologySha256 !== historicalTopologySha256) fail("Abandonment evidence historical topology identity is not exact.");
  if (evidence.schemaVersion === 3) {
    assertSha256(evidence.observedTopologySha256, "observedTopologySha256");
    if (evidence.observedTopologySha256 !== canonicalSha256({ resources: evidence.resources, versionIds: evidence.currentVersionIds }) || !SHA256.test(evidence.liveLegacyBaselineIdentitySha256 || "")) fail("Abandonment evidence observed topology is invalid.");
    assertAuthenticatedPreCutoverCoordinatorTransition(evidence.historicalTransitionEvidence, { resources: expectedResources, observedVersionIds: evidence.currentVersionIds, observedSlotIdentities: evidence.observedSlotIdentities, liveReferenceAuditSha256: evidence.liveReferenceAuditSha256, liveLegacyBaselineIdentitySha256: evidence.liveLegacyBaselineIdentitySha256 });
  } else assertHistoricalSlotIdentities(evidence.observedSlotIdentities, evidence.resources, evidence.currentVersionIds, historicalTopologySha256);
  if (evidence.observedSlotIdentitiesSha256 !== canonicalSha256(evidence.observedSlotIdentities)) fail("Abandonment evidence historical payload identities are not bound.");
  const observed = new Date(evidence.observedAt); if (!Number.isFinite(observed.getTime()) || observed.toISOString() !== evidence.observedAt) fail("Abandonment evidence timestamp is invalid.");
  const { evidenceSha256, ...body } = evidence; if (!SHA256.test(evidenceSha256 || "") || canonicalSha256(body) !== evidenceSha256) fail("Abandonment evidence hash is invalid.");
  return evidence;
}

export function assertRebaselinePreconditions(preconditions = {}) {
  if (preconditions.environment !== "production" || preconditions.accountId !== PRODUCTION_DUAL_SLOT_REBASELINE.accountId || preconditions.region !== PRODUCTION_DUAL_SLOT_REBASELINE.region) fail("Rebaseline environment identity is invalid.");
  assertSha40(preconditions.sourceSha, "sourceSha"); if (preconditions.sourceCas !== true || preconditions.cleanWorktree !== true) fail("Protected source CAS is not valid.");
  if (preconditions.existingSecretResources !== true || preconditions.liveReferenceAudit !== "PASS" || !SHA256.test(preconditions.liveReferenceAuditSha256 || "") || preconditions.legacyRuntimeAuthoritative !== true || preconditions.liveLegacyBaselineCount !== 1 || preconditions.databaseDependencies !== 0 || preconditions.externalConsumers !== 0 || preconditions.dualSlotReferences !== 0) fail("Rebaseline preconditions are not safe.");
  if (!Number.isSafeInteger(preconditions.runningTasks) || preconditions.runningTasks < 0 || !Number.isSafeInteger(preconditions.pendingTasks) || preconditions.pendingTasks < 0 || typeof preconditions.activeTaskDefinition !== "string" || !preconditions.activeTaskDefinition) fail("Live ECS topology evidence is incomplete.");
  if (preconditions.historicalTopologySha256 !== undefined) assertSha256(preconditions.historicalTopologySha256, "historicalTopologySha256");
  const resources = assertSlotMap(preconditions.resources, "resources"); const abandonmentEvidence = assertAbandonmentEvidence(preconditions.abandonmentEvidence, { sourceSha: preconditions.sourceSha, resources, historicalTopologySha256: preconditions.historicalTopologySha256 });
  if (abandonmentEvidence.liveReferenceAuditSha256 !== preconditions.liveReferenceAuditSha256) fail("Rebaseline live reference audit is not bound to abandonment evidence.");
  if (abandonmentEvidence.schemaVersion === 3 && preconditions.legacyBaseline && abandonmentEvidence.liveLegacyBaselineIdentitySha256 !== canonicalSha256(assertLegacyBaseline(preconditions.legacyBaseline))) fail("Rebaseline live legacy baseline is not bound to abandonment evidence.");
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

export function rebaselineWritePayloadIdentities(writePlan) {
  if (!Array.isArray(writePlan) || writePlan.length !== REBASELINE_SLOT_ORDER.length) fail("Rebaseline write plan is incomplete.");
  const identities = Object.fromEntries(writePlan.map(({ slot, payload, payloadSha256, materialType }) => [slot, Object.freeze({ payloadSha256: assertSha256(payloadSha256, `payloadSha256.${slot}`), materialType: text(materialType, `materialType.${slot}`), keyVersion: payload?.keyVersion || null })]));
  exactKeys(identities, REBASELINE_SLOT_ORDER, "writePayloadIdentities");
  return Object.freeze(identities);
}

function assertRebaselineWritePayloadIdentities(value, label = "writePayloadIdentities") {
  exactKeys(value, REBASELINE_SLOT_ORDER, label);
  for (const slot of REBASELINE_SLOT_ORDER) {
    exactKeys(value[slot], ["payloadSha256", "materialType", "keyVersion"], `${label}.${slot}`);
    assertSha256(value[slot].payloadSha256, `${label}.${slot}.payloadSha256`);
    text(value[slot].materialType, `${label}.${slot}.materialType`);
    if (value[slot].keyVersion !== null && !LEGACY_VERSION_ID.test(value[slot].keyVersion || "")) fail(`${label}.${slot}.keyVersion is invalid.`);
    if (["qrPrivatePending", "qrPublicPending"].includes(slot) !== (value[slot].keyVersion !== null)) fail(`${label}.${slot}.keyVersion is not exact.`);
  }
  return Object.freeze(Object.fromEntries(REBASELINE_SLOT_ORDER.map((slot) => [slot, Object.freeze({ ...value[slot] })])));
}

export function safeWriteDescriptors(writePlan) { if (!Array.isArray(writePlan) || writePlan.length !== 7) fail("Rebaseline write plan is incomplete."); const payloadIdentities = rebaselineWritePayloadIdentities(writePlan); return Object.freeze(writePlan.map(({ slot, secretArn, clientRequestToken, payloadSha256, materialType }) => ({ slot, secretArn, clientRequestToken, payloadSha256, materialType, payloadIdentity: payloadIdentities[slot] }))); }

export function buildRebaselinePreparation({ preconditions, sourceSha, rotationId, baselineIdentity, writePlan } = {}) {
  const checked = assertRebaselinePreconditions(preconditions); if (checked.sourceSha !== sourceSha || !baselineIdentity || baselineIdentity.identitySha256 !== buildRebaselineIdentity({ sourceSha, rotationId, resources: checked.resources, abandonmentEvidenceSha256: checked.abandonmentEvidence.evidenceSha256, legacyBaseline: baselineIdentity.legacyBaseline }).identitySha256) fail("Rebaseline preparation identity is invalid.");
  const safePlan = safeWriteDescriptors(writePlan); const body = { schemaVersion: 2, kind: REBASELINE_PREPARATION_KIND, operation: PRODUCTION_DUAL_SLOT_REBASELINE.kind, environment: checked.environment, accountId: checked.accountId, region: checked.region, sourceCas: checked.sourceCas, cleanWorktree: checked.cleanWorktree, existingSecretResources: checked.existingSecretResources, sourceSha, historicalRotationId: checked.historicalRotationId, rotationId, abandonmentEvidence: checked.abandonmentEvidence, abandonmentEvidenceSha256: checked.abandonmentEvidence.evidenceSha256, historicalTopologySha256: checked.abandonmentEvidence.historicalTopologySha256, resources: checked.resources, legacyBaseline: baselineIdentity.legacyBaseline, baselineIdentity, writePlan: safePlan, expectedSecretValueWrites: 7, expectedSecretDeletes: 0, liveReferenceAudit: checked.liveReferenceAudit, liveReferenceAuditSha256: checked.liveReferenceAuditSha256, databaseDependencies: checked.databaseDependencies, externalConsumers: checked.externalConsumers, dualSlotReferences: checked.dualSlotReferences, runningTasks: checked.runningTasks, pendingTasks: checked.pendingTasks, activeTaskDefinition: checked.activeTaskDefinition };
  return Object.freeze({ ...body, preparationSha256: canonicalSha256(body) });
}

export function assertRebaselinePreparation(value, { sourceSha, rotationId } = {}) {
  exactKeys(value, ["schemaVersion", "kind", "operation", "environment", "accountId", "region", "sourceCas", "cleanWorktree", "existingSecretResources", "sourceSha", "historicalRotationId", "rotationId", "abandonmentEvidence", "abandonmentEvidenceSha256", "historicalTopologySha256", "resources", "legacyBaseline", "baselineIdentity", "writePlan", "expectedSecretValueWrites", "expectedSecretDeletes", "liveReferenceAudit", "liveReferenceAuditSha256", "databaseDependencies", "externalConsumers", "dualSlotReferences", "runningTasks", "pendingTasks", "activeTaskDefinition", "preparationSha256"], "Rebaseline preparation");
  if (value.schemaVersion !== 2 || value.kind !== REBASELINE_PREPARATION_KIND || value.operation !== PRODUCTION_DUAL_SLOT_REBASELINE.kind || value.environment !== "production" || value.accountId !== PRODUCTION_DUAL_SLOT_REBASELINE.accountId || value.region !== PRODUCTION_DUAL_SLOT_REBASELINE.region || value.sourceSha !== sourceSha || value.rotationId !== rotationId || value.sourceCas !== true || value.cleanWorktree !== true || value.existingSecretResources !== true || value.expectedSecretValueWrites !== 7 || value.expectedSecretDeletes !== 0 || value.liveReferenceAudit !== "PASS" || !SHA256.test(value.liveReferenceAuditSha256 || "") || value.databaseDependencies !== 0 || value.externalConsumers !== 0 || value.dualSlotReferences !== 0) fail("Rebaseline preparation identity is invalid.");
  assertRotation(value.historicalRotationId, "historicalRotationId"); if (value.historicalRotationId !== REBASELINE_ABANDONED_HISTORICAL_ROTATION_ID) fail("Rebaseline preparation historical rotation is not exact."); assertSha256(value.historicalTopologySha256, "historicalTopologySha256"); assertAbandonmentEvidence(value.abandonmentEvidence, { sourceSha, resources: value.resources, historicalTopologySha256: value.historicalTopologySha256 }); if (value.abandonmentEvidenceSha256 !== value.abandonmentEvidence.evidenceSha256) fail("Rebaseline preparation abandonment evidence is not bound.");
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

const REBASELINE_WRITE_CONVERGENCE_ATTEMPTS = 6;
const rebaselineWriteConvergenceDelay = (attempt) => Math.min(1_000, 100 * (2 ** attempt));
const sleepForRebaselineWriteConvergence = (milliseconds) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds);

async function awaitExactRebaselineWriteConvergence({ expected, historicalIdentity, readSlot, sleep = sleepForRebaselineWriteConvergence } = {}) {
  for (let attempt = 0; attempt < REBASELINE_WRITE_CONVERGENCE_ATTEMPTS; attempt += 1) {
    const snapshot = await readSlot(expected.slot, expected.secretArn, expected.clientRequestToken, { sourceSha: expected.payload.sourceSha, rotationId: expected.payload.rotationId, historicalIdentity });
    if (assertReadSnapshot(snapshot, expected, `Post-write ${expected.slot}`, historicalIdentity) === "COMPLETED") return snapshot;
    if (attempt < REBASELINE_WRITE_CONVERGENCE_ATTEMPTS - 1) sleep(rebaselineWriteConvergenceDelay(attempt));
  }
  fail(`Rebaseline write ${expected.slot} did not converge after ${REBASELINE_WRITE_CONVERGENCE_ATTEMPTS} read-only observations.`);
}

function assertStableLiveReferenceAudit(audit, expectedStableAuditSha256) {
  if (!audit || audit.status !== "PASS" || audit.dualSlotReferences !== 0 || audit.legacyRuntimeAuthoritative !== true || audit.liveLegacyBaselineCount !== 1 || audit.databaseDependencies !== 0 || audit.externalConsumers !== 0 || audit.stableAuditSha256 !== expectedStableAuditSha256) fail("Live reference audit no longer satisfies the authorization-bound security topology.");
  return audit;
}

export function buildBaselineCompletion({ preconditions, sourceSha, rotationId, baselineIdentity, writePlan, finalSnapshots, authorizationBinding, authorizedWritePayloadIdentities } = {}) {
  const checked = assertRebaselinePreconditions(preconditions); if (checked.sourceSha !== sourceSha) fail("Completion source does not match preconditions."); assertRotation(rotationId, "rotationId");
  const expectedIdentity = buildRebaselineIdentity({ sourceSha, rotationId, resources: checked.resources, abandonmentEvidenceSha256: checked.abandonmentEvidence.evidenceSha256, legacyBaseline: baselineIdentity.legacyBaseline }); if (!baselineIdentity || baselineIdentity.identitySha256 !== expectedIdentity.identitySha256) fail("Baseline identity is invalid.");
  const expectedPlan = buildRebaselineWritePlan({ sourceSha, rotationId, resources: checked.resources, baselineIdentitySha256: baselineIdentity.identitySha256, payloads: Object.fromEntries(writePlan.map(({ slot, payload }) => [slot, payload])) }); if (!Array.isArray(finalSnapshots) || finalSnapshots.length !== 7) fail("Final seven-slot verification is incomplete.");
  for (const expected of expectedPlan) { const snapshot = finalSnapshots.find((candidate) => candidate.slot === expected.slot); if (assertReadSnapshot(snapshot, expected, `Final ${expected.slot}`) !== "COMPLETED") fail(`Final ${expected.slot} is not complete.`); }
  if (!SHA256.test(authorizationBinding || "")) fail("Authorization binding is required.");
  const payloadIdentities = rebaselineWritePayloadIdentities(expectedPlan);
  if (canonical(assertRebaselineWritePayloadIdentities(authorizedWritePayloadIdentities)) !== canonical(payloadIdentities)) fail("Authorization payload identities do not match the authenticated write plan.");
  const identity = { operation: PRODUCTION_DUAL_SLOT_REBASELINE.kind, schemaVersion: 2, sourceSha, rotationId, historicalRotationId: checked.historicalRotationId, abandonmentEvidenceSha256: checked.abandonmentEvidence.evidenceSha256, resources: checked.resources, versionIds: Object.fromEntries(expectedPlan.map(({ slot, clientRequestToken }) => [slot, clientRequestToken])), payloadIdentities, liveReferenceAudit: checked.liveReferenceAudit, liveReferenceAuditSha256: checked.liveReferenceAuditSha256, authorizationBinding, expectedSecretValueWrites: 7, expectedSecretDeletes: 0 };
  const completion = { schemaVersion: 2, kind: BASELINE_COMPLETE, ...identity };
  return Object.freeze({ ...completion, baselineBindingSha256: canonicalSha256(completion) });
}

export function assertBaselineCompletion(value, { sourceSha, rotationId, resources, authorizationBinding, historicalRotationId, abandonmentEvidenceSha256, writeIdentities, writePayloadIdentities, liveReferenceAuditSha256 } = {}) {
  exactKeys(value, ["schemaVersion", "kind", "operation", "sourceSha", "rotationId", "historicalRotationId", "abandonmentEvidenceSha256", "resources", "versionIds", "payloadIdentities", "liveReferenceAudit", "liveReferenceAuditSha256", "authorizationBinding", "expectedSecretValueWrites", "expectedSecretDeletes", "baselineBindingSha256"], "Baseline completion");
  if (value.schemaVersion !== 2 || value.kind !== BASELINE_COMPLETE || value.operation !== PRODUCTION_DUAL_SLOT_REBASELINE.kind || value.sourceSha !== sourceSha || value.rotationId !== rotationId || value.liveReferenceAudit !== "PASS" || !SHA256.test(value.liveReferenceAuditSha256 || "") || value.expectedSecretValueWrites !== 7 || value.expectedSecretDeletes !== 0) fail("Baseline completion identity is invalid.");
  assertRotation(value.historicalRotationId, "historicalRotationId"); assertSha256(value.abandonmentEvidenceSha256, "abandonmentEvidenceSha256"); assertSlotMap(value.resources, "resources"); exactKeys(value.versionIds, REBASELINE_SLOT_ORDER, "versionIds");
  const checkedPayloadIdentities = assertRebaselineWritePayloadIdentities(value.payloadIdentities, "payloadIdentities");
  if (historicalRotationId !== undefined && value.historicalRotationId !== historicalRotationId) fail("Baseline completion historical rotation does not match."); if (abandonmentEvidenceSha256 !== undefined && value.abandonmentEvidenceSha256 !== abandonmentEvidenceSha256) fail("Baseline completion abandonment evidence does not match."); if (!SHA256.test(value.authorizationBinding || "")) fail("Baseline completion authorization binding is invalid."); if (resources && canonical(value.resources) !== canonical(assertSlotMap(resources, "resources"))) fail("Baseline completion resources do not match expected resources."); if (authorizationBinding !== undefined && value.authorizationBinding !== authorizationBinding) fail("Baseline completion authorization binding does not match.");
  if (writeIdentities && canonical(value.versionIds) !== canonical(writeIdentities)) fail("Baseline completion version identities do not match authorization.");
  if (writePayloadIdentities && canonical(checkedPayloadIdentities) !== canonical(assertRebaselineWritePayloadIdentities(writePayloadIdentities))) fail("Baseline completion payload identities do not match authorization.");
  if (liveReferenceAuditSha256 && value.liveReferenceAuditSha256 !== liveReferenceAuditSha256) fail("Baseline completion live-reference audit does not match authorization.");
  const { baselineBindingSha256, ...identity } = value; if (!SHA256.test(baselineBindingSha256 || "") || canonicalSha256(identity) !== baselineBindingSha256) fail("Baseline completion hash is invalid."); return value;
}

export function buildRebaselineRotationBindings({ sourceSha, rotationId, legacyBaseline, resources, abandonmentEvidence, completion, authorization } = {}) {
  if (!completion || completion.kind !== BASELINE_COMPLETE) fail("Completed dual-slot baseline evidence is required for runtime binding.");
  const checkedAbandonment = assertAbandonmentEvidence(abandonmentEvidence, { sourceSha, resources, historicalTopologySha256: abandonmentEvidence?.historicalTopologySha256 });
  assertProductionDualSlotRebaselineAuthorization(authorization, { sourceSha, rotationId, resources });
  assertBaselineCompletion(completion, { sourceSha, rotationId, resources, authorizationBinding: authorization.authorizationSha256, historicalRotationId: checkedAbandonment.historicalRotationId, abandonmentEvidenceSha256: checkedAbandonment.evidenceSha256, writeIdentities: authorization.writeIdentities, writePayloadIdentities: authorization.writePayloadIdentities, liveReferenceAuditSha256: authorization.liveReferenceAuditSha256 });
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
  assertBaselineCompletion(bindings.baselineCompletion, { sourceSha: bindings.sourceSha, rotationId: bindings.rotationId, resources: checkedResources, authorizationBinding: authorization.authorizationSha256, historicalRotationId: bindings.historicalRotationId, abandonmentEvidenceSha256: bindings.abandonmentEvidenceSha256, writeIdentities: authorization.writeIdentities, writePayloadIdentities: authorization.writePayloadIdentities, liveReferenceAuditSha256: authorization.liveReferenceAuditSha256 });
  if (bindings.baselineCompletionSha256 !== bindings.baselineCompletion.baselineBindingSha256) fail("Rebaseline completion hash is not bound to runtime bindings.");
  return bindings;
}

export function verifyLiveProductionDualSlotRebaselineWithRunner({ run, bindings, authorization } = {}) {
  if (typeof run !== "function") fail("Live post-write rebaseline command runner is required.");
  assertRebaselineRotationBindings(bindings, { authorization });
  const resources = {
    jwtPending: bindings.jwt.pendingSecretId,
    qrPrivatePending: bindings.qr.privatePendingSecretId,
    qrPublicPending: bindings.qr.publicPendingSecretId,
    jwtPrevious: bindings.jwt.previousSecretId,
    qrPublicPrevious: bindings.qr.publicPreviousSecretId,
    qrCurrentVersion: bindings.qr.currentKeyVersionSecretId,
    qrPreviousVersion: bindings.qr.previousKeyVersionSecretId,
  };
  assertProductionDualSlotRebaselineAuthorization(authorization, { sourceSha: bindings.sourceSha, rotationId: bindings.rotationId, resources });
  const versionIds = {};
  const payloadIdentities = {};
  for (const [slot, secretArn] of Object.entries(resources)) {
    const described = JSON.parse(run(["secretsmanager", "describe-secret", "--secret-id", secretArn, "--output", "json", "--no-cli-pager"]));
    if (described.ARN !== secretArn) fail(`Live ${slot} secret ARN is substituted.`);
    const current = Object.entries(described.VersionIdsToStages || {}).filter(([, stages]) => Array.isArray(stages) && stages.includes("AWSCURRENT"));
    const expectedVersionId = authorization.writeIdentities[slot];
    if (current.length !== 1 || current[0][0] !== expectedVersionId || current[0][1].length !== 1 || current[0][1][0] !== "AWSCURRENT") fail(`Live ${slot} secret is not the exact completed rebaseline version.`);
    const response = JSON.parse(run(["secretsmanager", "get-secret-value", "--secret-id", secretArn, "--version-id", expectedVersionId, "--output", "json", "--no-cli-pager"]));
    if (response?.VersionId !== expectedVersionId || typeof response?.SecretString !== "string") fail(`Live ${slot} secret version is substituted or unreadable.`);
    let payload;
    try { payload = JSON.parse(response.SecretString); } catch { fail(`Live ${slot} secret payload is not reviewed JSON.`); }
    if (!payload || typeof payload !== "object" || Array.isArray(payload) || typeof payload.value !== "string") fail(`Live ${slot} secret payload is malformed.`);
    const expected = authorization.writePayloadIdentities[slot];
    const expectedShape = HISTORICAL_SLOT_SHAPES[slot];
    if (canonicalSha256(payload) !== expected.payloadSha256 || payload.sourceSha !== bindings.sourceSha || payload.rotationId !== bindings.rotationId || payload.family !== expectedShape.family || payload.slot !== expectedShape.slot || (payload.materialType !== undefined ? payload.materialType : payload.baselineMarker) !== expected.materialType || (payload.keyVersion || null) !== expected.keyVersion) fail(`Live ${slot} secret payload does not match the protected rebaseline authorization.`);
    versionIds[slot] = expectedVersionId;
    payloadIdentities[slot] = expected;
  }
  const body = { kind: "PRODUCTION_DUAL_SLOT_REBASELINE_LIVE_POST_WRITE", sourceSha: bindings.sourceSha, rotationId: bindings.rotationId, authorizationSha256: authorization.authorizationSha256, resources, versionIds, payloadIdentities };
  return Object.freeze({ ...body, livePostWriteSha256: canonicalSha256(body) });
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

export async function executeProductionDualSlotRebaseline({ preconditions, sourceSha, rotationId, baselineIdentity, writePlan, readReferenceAudit, readSlot, writeSlot, completionFile, bindingsFile, repositoryRoot = process.cwd(), authorization, sleep = sleepForRebaselineWriteConvergence, afterCompletionPersist, afterBindingsPersist } = {}) {
  const checked = assertRebaselinePreconditions(preconditions); if (checked.sourceSha !== sourceSha) fail("Execution source does not match preconditions."); if (typeof readReferenceAudit !== "function" || typeof readSlot !== "function" || typeof writeSlot !== "function" || typeof sleep !== "function") fail("Rebaseline execution adapters are incomplete.");
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
  if (canonical(Object.fromEntries(expectedPlan.map(({ slot, clientRequestToken }) => [slot, clientRequestToken]))) !== canonical(authorization.writeIdentities) || canonical(rebaselineWritePayloadIdentities(expectedPlan)) !== canonical(authorization.writePayloadIdentities)) fail("Rebaseline authorization write identities do not match execution.");
  let writes = 0;
  const historicalBySlot = checked.abandonmentEvidence.observedSlotIdentities;
  const initialSnapshots = await Promise.all(expectedPlan.map(async (expected) => ({ expected, snapshot: await readSlot(expected.slot, expected.secretArn, expected.clientRequestToken, { sourceSha, rotationId, historicalIdentity: historicalBySlot[expected.slot] }) })));
  if (outputExists.some(Boolean) && initialSnapshots.some(({ expected, snapshot }) => assertReadSnapshot(snapshot, expected, `Output preflight ${expected.slot}`, historicalBySlot[expected.slot]) !== "COMPLETED")) fail("Existing durable rebaseline outputs cannot accompany an incomplete secret baseline.");
  for (const expected of expectedPlan) { assertStableLiveReferenceAudit(await readReferenceAudit(), checked.liveReferenceAuditSha256); const historicalIdentity = historicalBySlot[expected.slot]; const snapshot = await readSlot(expected.slot, expected.secretArn, expected.clientRequestToken, { sourceSha, rotationId, historicalIdentity }); if (assertReadSnapshot(snapshot, expected, `Pre-write ${expected.slot}`, historicalIdentity) === "COMPLETED") continue; const result = await writeSlot({ slot: expected.slot, secretArn: expected.secretArn, clientRequestToken: expected.clientRequestToken, payload: expected.payload, payloadSha256: expected.payloadSha256 }); writes += 1; if (result?.versionId !== expected.clientRequestToken || result?.arn !== expected.secretArn) fail(`Rebaseline write identity for ${expected.slot} is invalid.`); await awaitExactRebaselineWriteConvergence({ expected, historicalIdentity, readSlot, sleep }); }
  assertStableLiveReferenceAudit(await readReferenceAudit(), checked.liveReferenceAuditSha256);
  const finalSnapshots = []; for (const expected of expectedPlan) finalSnapshots.push({ slot: expected.slot, ...(await readSlot(expected.slot, expected.secretArn, expected.clientRequestToken, { sourceSha, rotationId, historicalIdentity: historicalBySlot[expected.slot] })) }); const completion = buildBaselineCompletion({ preconditions: checked, sourceSha, rotationId, baselineIdentity, writePlan, finalSnapshots, authorizationBinding: authorization.authorizationSha256, authorizedWritePayloadIdentities: authorization.writePayloadIdentities });
  const completionCapture = persistExactPrivateJson({ filePath: completionFile, value: completion, repositoryRoot, label: "Dual-slot baseline completion evidence" });
  if (typeof afterCompletionPersist === "function") await afterCompletionPersist();
  const bindings = buildRebaselineRotationBindings({ sourceSha, rotationId, legacyBaseline: baselineIdentity.legacyBaseline, resources: checked.resources, abandonmentEvidence: checked.abandonmentEvidence, completion, authorization });
  const bindingsCapture = persistExactPrivateJson({ filePath: bindingsFile, value: bindings, repositoryRoot, label: "Dual-slot rebaseline runtime bindings" });
  if (typeof afterBindingsPersist === "function") await afterBindingsPersist();
  assertBaselineCompletion(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(completionCapture.bytes)), { sourceSha, rotationId, resources: checked.resources, authorizationBinding: authorization.authorizationSha256, writeIdentities: authorization.writeIdentities, writePayloadIdentities: authorization.writePayloadIdentities, liveReferenceAuditSha256: authorization.liveReferenceAuditSha256 });
  assertRebaselineRotationBindings(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bindingsCapture.bytes)), { authorization });
  return Object.freeze({ baselineComplete: true, writes, completion, bindings, completionPath: completionCapture.path, completionSha256: completionCapture.sha256, bindingsPath: bindingsCapture.path, bindingsSha256: bindingsCapture.sha256, writePlan: safeWriteDescriptors(expectedPlan) });
}

export function readBoundBaselineCompletion({ filePath, expectedSha256, authorization, repositoryRoot = process.cwd() } = {}) { const captured = readStageBPrivateFileBytes({ filePath, repositoryRoot, label: "Dual-slot baseline completion evidence" }); if (captured.sha256 !== expectedSha256) fail("Dual-slot baseline completion evidence changed."); const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(captured.bytes)); assertProductionDualSlotRebaselineAuthorization(authorization, { sourceSha: value.sourceSha, rotationId: value.rotationId, resources: value.resources }); assertBaselineCompletion(value, { sourceSha: value.sourceSha, rotationId: value.rotationId, resources: value.resources, authorizationBinding: authorization.authorizationSha256, writeIdentities: authorization.writeIdentities, writePayloadIdentities: authorization.writePayloadIdentities, liveReferenceAuditSha256: authorization.liveReferenceAuditSha256 }); return Object.freeze({ value, sha256: captured.sha256, path: captured.path }); }

export function createProductionDualSlotRebaselineAuthorization(input = {}) {
  const evidence = input.protectedEnvironmentApprovalEvidence;
  assertProductionEnvironmentApprovalIdentity(evidence, { sourceSha: input.sourceSha, repository: PRODUCTION_DUAL_SLOT_REBASELINE.repository });
  if (evidence.workflowRef !== PRODUCTION_ENVIRONMENT_APPROVAL.dualSlotRebaselineWorkflowRef) fail("Rebaseline authorization requires the dedicated protected-environment workflow.");
  const resources = assertSlotMap(input.resources, "resources");
  const identities = input.writeIdentities;
  const payloadIdentities = assertRebaselineWritePayloadIdentities(input.writePayloadIdentities);
  assertSha256(input.baselineIdentitySha256, "baselineIdentitySha256");
  exactKeys(identities, REBASELINE_SLOT_ORDER, "writeIdentities");
  for (const slot of REBASELINE_SLOT_ORDER) { assertVersion(identities[slot], `writeIdentities.${slot}`); if (identities[slot] !== deterministicWriteIdentity({ sourceSha: input.sourceSha, rotationId: input.rotationId, slot, secretArn: resources[slot], baselineIdentitySha256: input.baselineIdentitySha256 })) fail(`writeIdentities.${slot} is not bound to the exact resource and baseline.`); }
  assertSha40(input.sourceSha, "sourceSha"); assertRotation(input.historicalRotationId, "historicalRotationId"); if (input.historicalRotationId !== REBASELINE_ABANDONED_HISTORICAL_ROTATION_ID) fail("Rebaseline authorization historical rotation is not exact."); assertRotation(input.rotationId, "rotationId");
  if (input.rotationId === input.historicalRotationId) fail("Rebaseline rotation must be new.");
  if (input.liveReferenceAudit !== "PASS" || !SHA256.test(input.liveReferenceAuditSha256 || "") || !SHA256.test(input.observedSlotIdentitiesSha256 || "")) fail("Rebaseline authorization requires a passing bound live-reference audit.");
  if (input.expectedSecretValueWrites !== 7 || input.expectedSecretDeletes !== 0) fail("Rebaseline authorization mutation counts are invalid.");
  for (const [name, value] of Object.entries({ reason: input.reason, approverRole: input.approverRole, verificationRef: input.verificationRef })) text(value, name);
  const approvedBy = assertProductionEnvironmentActualReviewer(evidence, { sourceSha: input.sourceSha, repository: PRODUCTION_DUAL_SLOT_REBASELINE.repository, executionActor: evidence.executionActor });
  if (input.approvedBy !== undefined && input.approvedBy !== approvedBy) fail("Dispatcher-supplied approver identity does not match the authenticated GitHub approval event.");
  const body = {
    schemaVersion: 1, kind: REBASELINE_AUTHORIZATION_KIND, operation: PRODUCTION_DUAL_SLOT_REBASELINE.kind,
    environment: "production", accountId: PRODUCTION_DUAL_SLOT_REBASELINE.accountId, region: PRODUCTION_DUAL_SLOT_REBASELINE.region,
    sourceSha: input.sourceSha, historicalRotationId: input.historicalRotationId, rotationId: input.rotationId,
    abandonmentEvidenceSha256: assertSha256(input.abandonmentEvidenceSha256, "abandonmentEvidenceSha256"), baselineIdentitySha256: input.baselineIdentitySha256, resources,
    writeIdentities: Object.freeze({ ...identities }), writePayloadIdentities: payloadIdentities, expectedSecretValueWrites: 7, expectedSecretDeletes: 0,
    liveReferenceAudit: input.liveReferenceAudit, liveReferenceAuditSha256: input.liveReferenceAuditSha256, observedSlotIdentitiesSha256: input.observedSlotIdentitiesSha256, reason: input.reason, approvedBy,
    approverRole: input.approverRole, verificationRef: input.verificationRef,
    protectedEnvironmentApprovalEvidence: evidence, protectedEnvironmentApprovalEvidenceSha256: evidence.evidenceSha256,
    exclusions: Object.freeze(["Terraform apply", "ECS RegisterTaskDefinition", "ECS UpdateService", "database mutation", "IAM mutation", "KMS policy mutation", "image publication", "network mutation", "DeleteSecret"]),
  };
  return Object.freeze({ ...body, authorizationSha256: canonicalSha256(body) });
}

export function assertProductionDualSlotRebaselineAuthorization(value, { sourceSha, rotationId, resources } = {}) {
  const fields = ["schemaVersion", "kind", "operation", "environment", "accountId", "region", "sourceSha", "historicalRotationId", "rotationId", "abandonmentEvidenceSha256", "baselineIdentitySha256", "resources", "writeIdentities", "writePayloadIdentities", "expectedSecretValueWrites", "expectedSecretDeletes", "liveReferenceAudit", "liveReferenceAuditSha256", "observedSlotIdentitiesSha256", "reason", "approvedBy", "approverRole", "verificationRef", "protectedEnvironmentApprovalEvidence", "protectedEnvironmentApprovalEvidenceSha256", "exclusions", "authorizationSha256"];
  exactKeys(value, fields, "Rebaseline authorization");
  if (value.schemaVersion !== 1 || value.kind !== REBASELINE_AUTHORIZATION_KIND || value.operation !== PRODUCTION_DUAL_SLOT_REBASELINE.kind || value.environment !== "production" || value.accountId !== PRODUCTION_DUAL_SLOT_REBASELINE.accountId || value.region !== PRODUCTION_DUAL_SLOT_REBASELINE.region || value.sourceSha !== sourceSha || value.rotationId !== rotationId || value.expectedSecretValueWrites !== 7 || value.expectedSecretDeletes !== 0 || value.liveReferenceAudit !== "PASS" || !SHA256.test(value.liveReferenceAuditSha256 || "") || !SHA256.test(value.observedSlotIdentitiesSha256 || "")) fail("Rebaseline authorization identity is invalid.");
  assertRotation(value.historicalRotationId, "historicalRotationId"); if (value.historicalRotationId !== REBASELINE_ABANDONED_HISTORICAL_ROTATION_ID) fail("Rebaseline authorization historical rotation is not exact."); assertRotation(value.rotationId, "rotationId"); if (value.rotationId === value.historicalRotationId) fail("Rebaseline rotation is not new."); assertSha256(value.abandonmentEvidenceSha256, "abandonmentEvidenceSha256"); assertSha256(value.baselineIdentitySha256, "baselineIdentitySha256"); assertSlotMap(value.resources, "resources"); exactKeys(value.writeIdentities, REBASELINE_SLOT_ORDER, "writeIdentities"); assertRebaselineWritePayloadIdentities(value.writePayloadIdentities); for (const slot of REBASELINE_SLOT_ORDER) { assertVersion(value.writeIdentities[slot], `writeIdentities.${slot}`); if (value.writeIdentities[slot] !== deterministicWriteIdentity({ sourceSha, rotationId, slot, secretArn: value.resources[slot], baselineIdentitySha256: value.baselineIdentitySha256 })) fail(`writeIdentities.${slot} is not bound to the exact resource and baseline.`); }
  for (const name of ["reason", "approvedBy", "approverRole", "verificationRef"]) text(value[name], name);
  if (canonical(value.exclusions) !== canonical(["Terraform apply", "ECS RegisterTaskDefinition", "ECS UpdateService", "database mutation", "IAM mutation", "KMS policy mutation", "image publication", "network mutation", "DeleteSecret"])) fail("Rebaseline authorization exclusions are incomplete.");
  assertProductionEnvironmentApprovalIdentity(value.protectedEnvironmentApprovalEvidence, { sourceSha, repository: PRODUCTION_DUAL_SLOT_REBASELINE.repository }); if (value.protectedEnvironmentApprovalEvidence.workflowRef !== PRODUCTION_ENVIRONMENT_APPROVAL.dualSlotRebaselineWorkflowRef || value.protectedEnvironmentApprovalEvidenceSha256 !== value.protectedEnvironmentApprovalEvidence.evidenceSha256 || value.protectedEnvironmentApprovalEvidence.schemaVersion !== 3 || value.approvedBy !== value.protectedEnvironmentApprovalEvidence.actualApproval.userLogin) fail("Rebaseline protected-environment approval identity is not authenticated from the actual approval event.");
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

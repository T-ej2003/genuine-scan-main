import { createHash, createPublicKey } from "node:crypto";
import { createRequire } from "node:module";
import { lstatSync, unlinkSync } from "node:fs";
import path from "node:path";
import { ensureStageBPrivateDirectory, readStageBPrivateFileBytes, writeStageBPrivateFileAtomic, writeStageBPrivateFileAtomicExclusive } from "./stage-b-artifact-contract.mjs";
import { rotationBindingsToTaskBindings } from "./production-cutover-runtime-bootstrap.mjs";
import {
  assertProductionStaleSupersessionPredecessor,
  assertProductionSupersessionEvidence,
  PRODUCTION_STALE_SUPERSESSION_PREDECESSOR_KIND,
  productionStaleSupersessionPredecessorIdentity,
  productionSupersessionEvidenceIdentity,
} from "../security/production-initial-migration-source-advance.mjs";
import { deriveLegacyRotationBaseline } from "./production-legacy-rotation-baseline.mjs";
import { assertCompletedRebaselinePayload, generateRebaselineMaterial, PARTIAL_REBASELINE_RECOVERY_ORIGINAL_SOURCE_SHA, fingerprint as secureFingerprint } from "./production-dual-slot-rebaseline-contract.mjs";
import { MIXED_DUAL_SLOT_RECOVERY_ORDER, MIXED_DUAL_SLOT_RECOVERY_SUCCESSOR, MIXED_DUAL_SLOT_RECOVERY_SUCCESSOR_CANONICAL_ID, MIXED_DUAL_SLOT_RETAINED_HISTORY, MIXED_DUAL_SLOT_RETAINED_HISTORY_CANONICAL_ID } from "./production-mixed-dual-slot-recovery-contract.mjs";

export { deriveLegacyRotationBaseline } from "./production-legacy-rotation-baseline.mjs";

const requireBackend = createRequire(path.resolve("backend/package.json"));
const {
  CreateSecretCommand,
  DescribeSecretCommand,
  GetSecretValueCommand,
  PutSecretValueCommand,
  SecretsManagerClient,
} = requireBackend("@aws-sdk/client-secrets-manager");
const { STSClient, GetCallerIdentityCommand } = requireBackend("@aws-sdk/client-sts");
const { fromIni } = requireBackend("@aws-sdk/credential-provider-ini");

export const INITIAL_DUAL_SLOT_SCHEMA_VERSION = 1;
export const INITIAL_DUAL_SLOT_ROTATION_BINDINGS_KIND = "PRODUCTION_INITIAL_DUAL_SLOT_ROTATION_BINDINGS";
export const INITIAL_DUAL_SLOT_ROTATION_BINDINGS_PRODUCER = "scripts/aws/production-initial-dual-slot-bootstrap.mjs:bootstrapInitialDualSlotRotation";
export const INITIAL_DUAL_SLOT_ACCOUNT = "368992683803";
export const INITIAL_DUAL_SLOT_REGION = "eu-west-2";
export const INITIAL_DUAL_SLOT_NAMES = Object.freeze({
  jwtPrevious: "mscqr/prod/rotation/jwt-previous",
  jwtPending: "mscqr/prod/rotation/jwt-pending",
  qrPrivatePending: "mscqr/prod/rotation/qr-private-pending",
  qrPublicPrevious: "mscqr/prod/rotation/qr-public-previous",
  qrPublicPending: "mscqr/prod/rotation/qr-public-pending",
  qrCurrentVersion: "mscqr/prod/rotation/qr-current-version",
  qrPreviousVersion: "mscqr/prod/rotation/qr-previous-version",
});

const SECRET_ARN = new RegExp(`^arn:aws:secretsmanager:${INITIAL_DUAL_SLOT_REGION}:${INITIAL_DUAL_SLOT_ACCOUNT}:secret:[A-Za-z0-9/_+=.@-]+$`);
const SHA40 = /^[a-f0-9]{40}$/;
const ROTATION_ID = /^[A-Za-z0-9._-]{8,128}$/;
const VERSION = /^[A-Za-z0-9._:-]{1,128}$/;
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const fingerprint = secureFingerprint;
const canonical = (value) => Array.isArray(value) ? `[${value.map(canonical).join(",")}]` : value && typeof value === "object" ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}` : JSON.stringify(value);
const canonicalSha256 = (value) => sha256(canonical(value));
const materialFileFor = (outputFile) => `${path.resolve(outputFile)}.material`;
export const STALE_ROTATION_SUPERSESSION_WRITE_ORDER = Object.freeze(["jwtPending", "qrPrivatePending", "qrPublicPending", "jwtPrevious", "qrPublicPrevious", "qrCurrentVersion", "qrPreviousVersion"]);
const required = (value, label) => {
  if (typeof value !== "string" || !value.trim()) throw new Error(`${label} is required.`);
  return value.trim();
};
const notFound = (error) => /ResourceNotFoundException|not exist|can't find/i.test(String(error?.name || error?.message || error));

const emptySlot = (family, slot, sourceSha) => ({ value: "", family, slot, sourceSha, initialMigration: true });
const versionSlot = (value, slot, sourceSha) => ({ value, family: "qr_key_versions", slot, sourceSha, initialMigration: true });

export const generatePendingMaterial = generateRebaselineMaterial;

function pendingPayloads({ rotationId, material }) {
  return {
    jwtPending: { rotationId, family: "jwt_secrets", slot: "pending", materialFingerprint: fingerprint(material.jwt), value: material.jwt },
    qrPrivatePending: { rotationId, family: "qr_signing_keys", slot: "pending-private", keyVersion: material.qrKeyVersion, materialFingerprint: fingerprint(material.qrPrivate), value: material.qrPrivate },
    qrPublicPending: { rotationId, family: "qr_signing_keys", slot: "pending-public", keyVersion: material.qrKeyVersion, materialFingerprint: fingerprint(material.qrPublic), value: material.qrPublic },
  };
}

function assertPendingMaterial(material) {
  if (!material || typeof material.jwt !== "string" || typeof material.qrPrivate !== "string" || typeof material.qrPublic !== "string" || !VERSION.test(material.qrKeyVersion || "")) throw new Error("Replacement material journal is malformed.");
  let derivedPublic;
  try { derivedPublic = createPublicKey(material.qrPrivate).export({ format: "pem", type: "spki" }); } catch { throw new Error("Replacement material journal contains a malformed QR private key."); }
  if (derivedPublic !== material.qrPublic || sha256(derivedPublic).slice(0, 16) !== material.qrKeyVersion) throw new Error("Replacement material journal contains an inconsistent QR key pair.");
  return material;
}

function readMaterialJournal(filePath, sourceSha, rotationId, repositoryRoot) {
  const stat = lstatSync(filePath, { throwIfNoEntry: false });
  if (!stat) return null;
  const captured = readStageBPrivateFileBytes({ filePath: path.resolve(filePath), repositoryRoot, label: "Replacement material journal" });
  let journal;
  try { journal = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(captured.bytes)); } catch { throw new Error("Replacement material journal is malformed."); }
  if (journal.schemaVersion !== 1 || journal.sourceSha !== sourceSha || journal.rotationId !== rotationId) throw new Error("Replacement material journal identity does not match the requested transition.");
  return assertPendingMaterial(journal.material);
}

function writeMaterialJournal(filePath, sourceSha, rotationId, material, repositoryRoot) {
  const existing = readMaterialJournal(filePath, sourceSha, rotationId, repositoryRoot);
  if (existing) return existing;
  writeStageBPrivateFileAtomicExclusive({ filePath, bytes: Buffer.from(`${JSON.stringify({ schemaVersion: 1, sourceSha, rotationId, material })}\n`), repositoryRoot, label: "Replacement material journal" });
  return material;
}

async function recoverInitialPendingMaterial({ send, resources, sourceSha, rotationId, materialFile, repositoryRoot, requireExisting = false, recoveryHandoff }) {
  const pendingSlots = ["jwtPending", "qrPrivatePending", "qrPublicPending"];
  const existing = {};
  for (const slot of pendingSlots) {
    try {
      const response = await send(new GetSecretValueCommand({ SecretId: resources[slot] }));
      if (typeof recoveryHandoff?.[slot]?.current?.versionId === "string" && response?.VersionId === recoveryHandoff[slot].current.versionId) continue;
      existing[slot] = parseStoredValue(response, `${slot} pending`);
    } catch (error) {
      if (!notFound(error)) throw error;
    }
  }
  const present = pendingSlots.filter((slot) => existing[slot]).length;
  if (requireExisting && present !== pendingSlots.length) throw new Error("Governed supersession bootstrap requires every prepared pending value to exist.");
  const journal = readMaterialJournal(materialFile, sourceSha, rotationId, repositoryRoot);
  if (present > 0 && present < pendingSlots.length && !journal) throw new Error("Initial rotation has a partial pending prefix without authenticated replacement material.");
  if (present === pendingSlots.length) {
    const expected = {
      jwt: existing.jwtPending.value,
      qrPrivate: existing.qrPrivatePending.value,
      qrPublic: existing.qrPublicPending.value,
      qrKeyVersion: existing.qrPrivatePending.keyVersion,
    };
    for (const [slot, value] of Object.entries(existing)) {
      if (value.sourceSha !== sourceSha || value.rotationId !== rotationId || !value.materialFingerprint || value.materialFingerprint !== fingerprint(value.value)) throw new Error(`${slot} contains inconsistent pending metadata for the requested rotation.`);
    }
    return assertPendingMaterial(expected);
  }
  return journal || writeMaterialJournal(materialFile, sourceSha, rotationId, generatePendingMaterial(), repositoryRoot);
}

function exactArn(response, expectedName) {
  if (response?.Name !== expectedName || !SECRET_ARN.test(response?.ARN || "")) throw new Error(`Secret resource ${expectedName} is outside the reviewed production contract.`);
  return response.ARN;
}

async function describeOrCreate({ send, name, requireExisting = false }) {
  try {
    return { response: await send(new DescribeSecretCommand({ SecretId: name })), created: false };
  } catch (error) {
    if (!notFound(error) || requireExisting) throw new Error(`Secret resource lookup failed for ${name}.`);
    const response = await send(new CreateSecretCommand({
      Name: name,
      Description: "MSCQR production dual-slot rotation resource",
      Tags: [{ Key: "Environment", Value: "production" }, { Key: "ManagedBy", Value: "MSCQR" }, { Key: "Component", Value: "production-rotation" }],
    }));
    return { response, created: true };
  }
}

function parseStoredValue(response, name) {
  const value = response?.SecretString;
  if (typeof value !== "string") throw new Error(`${name} has no readable reviewed SecretString.`);
  let parsed;
  try { parsed = JSON.parse(value); } catch { throw new Error(`${name} contains a malformed rotation value.`); }
  if (!parsed || typeof parsed !== "object" || typeof parsed.value !== "string") throw new Error(`${name} contains a malformed rotation value.`);
  return parsed;
}

async function ensureValue({ send, arn, name, expected, rotationId, allowPendingResume = false, requireExisting = false, expectedPayloadSha256, ignoreCurrentVersionId }) {
  try {
    const response = await send(new GetSecretValueCommand({ SecretId: arn }));
    if (typeof ignoreCurrentVersionId === "string" && response?.VersionId === ignoreCurrentVersionId) {
      if (requireExisting) throw new Error(`${name} does not contain the authenticated supersession write.`);
      await send(new PutSecretValueCommand({ SecretId: arn, SecretString: JSON.stringify(expected) }));
      return { material: expected, wrote: true };
    }
    const existing = parseStoredValue(response, name);
    if (requireExisting) {
      if (!/^[a-f0-9]{64}$/.test(expectedPayloadSha256 || "") || canonicalSha256(existing) !== expectedPayloadSha256 || JSON.stringify(existing) !== JSON.stringify(expected)) throw new Error(`${name} differs from the authenticated supersession write plan.`);
      return { material: existing, wrote: false };
    }
    if (allowPendingResume) {
      if (existing.rotationId !== rotationId || existing.sourceSha !== expected.sourceSha || existing.family !== expected.family || existing.slot !== expected.slot || !existing.materialFingerprint || existing.materialFingerprint !== fingerprint(existing.value)) {
        throw new Error(`${name} contains inconsistent pending-migration metadata.`);
      }
      return { material: existing, wrote: false };
    }
    if (JSON.stringify(existing) !== JSON.stringify(expected)) throw new Error(`${name} contains inconsistent initial-migration metadata.`);
    return { material: existing, wrote: false };
  } catch (error) {
    if (!notFound(error) || requireExisting) throw error;
    await send(new PutSecretValueCommand({ SecretId: arn, SecretString: JSON.stringify(expected) }));
    return { material: expected, wrote: true };
  }
}

function assertLegacyMatches(legacy, baseline) {
  if (!legacy) return;
  if (legacy.jwtCurrent !== baseline.jwtCurrent || legacy.qrPrivateCurrent !== baseline.qrPrivateCurrent || legacy.qrPublicCurrent !== baseline.qrPublicCurrent) {
    throw new Error("Caller-supplied legacy signing identifiers do not match the verified live task definition.");
  }
}

const exactKeys = (value, keys, label) => {
  if (!value || typeof value !== "object" || Array.isArray(value) || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) throw new Error(`${label} schema is not exact.`);
};

function assertCurrentPayload(payload, { family, slot, qr = false } = {}) {
  exactKeys(payload, qr ? ["rotationId", "family", "slot", "keyVersion", "materialFingerprint", "value"] : ["rotationId", "family", "slot", "materialFingerprint", "value"], `Current ${slot}`);
  if (!ROTATION_ID.test(payload.rotationId || "") || payload.family !== family || payload.slot !== slot || typeof payload.value !== "string" || !payload.value || payload.materialFingerprint !== fingerprint(payload.value)) throw new Error(`Current ${slot} predecessor is not authenticated.`);
  if (qr && !VERSION.test(payload.keyVersion || "")) throw new Error(`Current ${slot} QR identity is invalid.`);
  return payload;
}

async function authenticateSupersessionPredecessor({ send, taskDefinition, sourceSha, staleSourceSha, rotationId, staleRotationId, supersessionEvidenceIdentitySha256, slotIdentities }) {
  const baseline = deriveLegacyRotationBaseline(taskDefinition);
  const specifications = {
    jwt: [baseline.jwtCurrent, "jwt_secrets", "current", false],
    qrPrivate: [baseline.qrPrivateCurrent, "qr_signing_keys", "current-private", true],
    qrPublic: [baseline.qrPublicCurrent, "qr_signing_keys", "current-public", true],
  };
  const current = {};
  const payloads = {};
  for (const [name, [secretArn, family, slot, qr]] of Object.entries(specifications)) {
    const described = await send(new DescribeSecretCommand({ SecretId: secretArn }));
    if (described?.ARN !== secretArn) throw new Error(`Current ${name} predecessor resource is not authenticated.`);
    const stages = assertRotationVersionTopology(described, `current ${name}`);
    const versionId = Object.entries(stages).find(([, labels]) => labels.includes("AWSCURRENT"))?.[0];
    const response = await send(new GetSecretValueCommand({ SecretId: secretArn, VersionId: versionId }));
    if (response?.VersionId !== versionId) throw new Error(`Current ${name} predecessor version is not authenticated.`);
    const payload = assertCurrentPayload(parseStoredValue(response, `current ${name}`), { family, slot, qr });
    payloads[name] = payload;
    current[name] = { secretArn, versionId, rotationId: payload.rotationId, family, slot, ...(qr ? { keyVersion: payload.keyVersion } : {}), materialFingerprint: payload.materialFingerprint };
  }
  if (new Set(Object.values(payloads).map(({ rotationId: owner }) => owner)).size !== 1) throw new Error("Current signing predecessor is owned by multiple rotations.");
  assertPendingMaterial({ jwt: payloads.jwt.value, qrPrivate: payloads.qrPrivate.value, qrPublic: payloads.qrPublic.value, qrKeyVersion: payloads.qrPublic.keyVersion });
  if (payloads.qrPrivate.keyVersion !== payloads.qrPublic.keyVersion) throw new Error("Current QR predecessor key identities are inconsistent.");
  const body = {
    schemaVersion: 1,
    kind: PRODUCTION_STALE_SUPERSESSION_PREDECESSOR_KIND,
    sourceSha,
    rotationId,
    staleSourceSha,
    staleRotationId,
    supersessionEvidenceIdentitySha256,
    runtimeQrVersionLabel: baseline.qrCurrentVersion,
    currentRotationId: payloads.jwt.rotationId,
    current,
    slotIdentities,
  };
  const predecessor = { ...body, predecessorIdentitySha256: productionStaleSupersessionPredecessorIdentity(body) };
  assertProductionStaleSupersessionPredecessor(predecessor, { sourceSha, rotationId });
  return { baseline, predecessor };
}

export function assertInitialDualSlotBindings(bindings) {
  const refs = [bindings?.jwt?.currentSecretId, bindings?.jwt?.previousSecretId, bindings?.jwt?.pendingSecretId, bindings?.qr?.privateCurrentSecretId, bindings?.qr?.privatePendingSecretId, bindings?.qr?.publicCurrentSecretId, bindings?.qr?.publicPreviousSecretId, bindings?.qr?.publicPendingSecretId, bindings?.qr?.currentKeyVersionSecretId, bindings?.qr?.previousKeyVersionSecretId];
  if (refs.some((value) => !SECRET_ARN.test(String(value || ""))) || new Set(refs).size !== refs.length) throw new Error("Initial dual-slot bindings must contain distinct production secret ARNs.");
  if (!VERSION.test(bindings?.qr?.previousKeyVersion || "")) throw new Error("Initial dual-slot previous QR key version is invalid.");
  if (![2, 3, 4, 5].includes(bindings?.schemaVersion) || bindings?.kind !== INITIAL_DUAL_SLOT_ROTATION_BINDINGS_KIND || bindings?.producer !== INITIAL_DUAL_SLOT_ROTATION_BINDINGS_PRODUCER || !SHA40.test(bindings?.sourceSha || "") || !ROTATION_ID.test(bindings?.rotationId || "")) throw new Error("Initial dual-slot identity binding is invalid.");
  if (bindings.schemaVersion === 3) {
    const evidence = assertProductionSupersessionEvidence(bindings.supersessionEvidence);
    assertProductionStaleSupersessionPredecessor(bindings.supersessionPredecessor, { sourceSha: bindings.sourceSha, rotationId: bindings.rotationId, supersessionEvidence: evidence });
  } else if (bindings.supersessionEvidence !== undefined || bindings.supersessionPredecessor !== undefined) throw new Error("Ordinary initial bindings cannot carry stale-supersession authority.");
  if ([4, 5].includes(bindings.schemaVersion)) {
    if (canonical(bindings.retainedHistory) !== canonical(MIXED_DUAL_SLOT_RETAINED_HISTORY) || bindings.retainedHistoryCanonicalId !== MIXED_DUAL_SLOT_RETAINED_HISTORY_CANONICAL_ID) throw new Error("Initial dual-slot retained-history binding is invalid.");
  } else if (bindings.retainedHistory !== undefined || bindings.retainedHistoryCanonicalId !== undefined) throw new Error("Only exact recovery handoff bindings may carry retained history.");
  if (bindings.schemaVersion === 5) {
    if (canonical(bindings.recoveryHandoff) !== canonical(MIXED_DUAL_SLOT_RECOVERY_SUCCESSOR) || bindings.recoveryHandoffCanonicalId !== MIXED_DUAL_SLOT_RECOVERY_SUCCESSOR_CANONICAL_ID) throw new Error("Initial dual-slot AWS-legal recovery handoff is invalid.");
  } else if (bindings.recoveryHandoff !== undefined || bindings.recoveryHandoffCanonicalId !== undefined) throw new Error("Only AWS-legal recovery bindings may carry a recovery handoff.");
  if (bindings?.ecs && JSON.stringify(bindings.ecs) !== JSON.stringify(rotationBindingsToTaskBindings(bindings))) throw new Error("Initial dual-slot ECS bindings do not match the canonical SDK bindings.");
  return true;
}

function assertInitialBindingSchemaClosed(bindings) {
  const exact = (value, keys, label) => { if (!value || typeof value !== "object" || Array.isArray(value) || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) throw new Error(`${label} schema is not closed.`); };
  exact(bindings, ["schemaVersion", "kind", "producer", "sourceSha", "rotationId", "legacy", "jwt", "qr", "ecs", ...(bindings.schemaVersion === 3 ? ["supersessionEvidence", "supersessionPredecessor"] : []), ...([4, 5].includes(bindings.schemaVersion) ? ["retainedHistory", "retainedHistoryCanonicalId"] : []), ...(bindings.schemaVersion === 5 ? ["recoveryHandoff", "recoveryHandoffCanonicalId"] : [])], "Initial dual-slot bindings");
  exact(bindings.legacy, ["jwtCurrent", "qrPrivateCurrent", "qrPublicCurrent", "qrCurrentVersion"], "Initial dual-slot legacy bindings");
  exact(bindings.jwt, ["currentSecretId", "previousSecretId", "pendingSecretId"], "Initial dual-slot JWT bindings");
  exact(bindings.qr, ["privateCurrentSecretId", "privatePendingSecretId", "publicCurrentSecretId", "publicPreviousSecretId", "publicPendingSecretId", "currentKeyVersionSecretId", "previousKeyVersionSecretId", "previousKeyVersion", "pendingKeyVersion"], "Initial dual-slot QR bindings");
  exact(bindings.ecs, ["JWT_SECRET_CURRENT", "JWT_SECRET_PREVIOUS", "QR_SIGN_PRIVATE_KEY_CURRENT", "QR_SIGN_PUBLIC_KEY_CURRENT", "QR_SIGN_ACTIVE_KEY_VERSION", "QR_SIGN_PUBLIC_KEY_PREVIOUS", "QR_SIGN_PREVIOUS_KEY_VERSION"], "Initial dual-slot ECS bindings");
}

function runnerJson(run, args, label) {
  let value;
  try { value = JSON.parse(String(run(args))); } catch { throw new Error(`${label} is not valid JSON.`); }
  return value;
}

function assertInitialLivePayload(slot, payload, bindings) {
  const supersessionKeys = bindings.schemaVersion === 3 ? ["supersessionPredecessorIdentitySha256"] : [];
  const expected = {
    jwtPending: ["family", "materialFingerprint", "rotationId", "slot", "sourceSha", "value"],
    qrPrivatePending: ["family", "keyVersion", "materialFingerprint", "rotationId", "slot", "sourceSha", "value"],
    qrPublicPending: ["family", "keyVersion", "materialFingerprint", "rotationId", "slot", "sourceSha", "value"],
    jwtPrevious: ["family", "initialMigration", "slot", "sourceSha", "value"],
    qrPublicPrevious: ["family", "initialMigration", "slot", "sourceSha", "value"],
    qrCurrentVersion: ["family", "initialMigration", "slot", "sourceSha", "value"],
    qrPreviousVersion: ["family", "initialMigration", "slot", "sourceSha", "value"],
  }[slot].concat(supersessionKeys);
  if (!payload || JSON.stringify(Object.keys(payload).sort()) !== JSON.stringify(expected.sort())) throw new Error(`Initial ${slot} payload schema is not exact.`);
  const shape = { jwtPending: ["jwt_secrets", "pending"], qrPrivatePending: ["qr_signing_keys", "pending-private"], qrPublicPending: ["qr_signing_keys", "pending-public"], jwtPrevious: ["jwt_secrets", "empty"], qrPublicPrevious: ["qr_signing_keys", "empty"], qrCurrentVersion: ["qr_key_versions", "current"], qrPreviousVersion: ["qr_key_versions", "previous-empty"] }[slot];
  if (payload.family !== shape[0] || payload.slot !== shape[1] || payload.sourceSha !== bindings.sourceSha || typeof payload.value !== "string") throw new Error(`Initial ${slot} payload identity is not authenticated.`);
  if (["jwtPending", "qrPrivatePending", "qrPublicPending"].includes(slot)) {
    if (payload.rotationId !== bindings.rotationId || payload.materialFingerprint !== fingerprint(payload.value)) throw new Error(`Initial ${slot} payload provenance is not authenticated.`);
  } else if (payload.initialMigration !== true || payload.value !== (slot === "qrCurrentVersion" ? bindings.legacy.qrCurrentVersion : "")) throw new Error(`Initial ${slot} baseline marker is not authenticated.`);
  if (bindings.schemaVersion === 3 && payload.supersessionPredecessorIdentitySha256 !== bindings.supersessionPredecessor.predecessorIdentitySha256) throw new Error(`Initial ${slot} stale-supersession predecessor is not authenticated.`);
  return Object.freeze({ payloadSha256: canonicalSha256(payload), materialFingerprint: payload.materialFingerprint || null, keyVersion: payload.keyVersion || null });
}

function assertSchemaV3SlotTopology(described, slot, evidence, predecessor) {
  const current = evidence.resources[slot];
  const previous = predecessor.slotIdentities[slot];
  const stages = assertRotationVersionTopology(described, `Initial ${slot}`);
  if (current.versionId === previous.versionId || JSON.stringify(stages[current.versionId]) !== '["AWSCURRENT"]' || JSON.stringify(stages[previous.versionId]) !== '["AWSPREVIOUS"]') throw new Error(`Initial ${slot} supersession version topology is not authenticated.`);
  return { currentVersionId: current.versionId, previousVersionId: previous.versionId };
}

function assertSchemaV3PreviousPayload(slot, payload, identity) {
  if (canonicalSha256(payload) !== identity.payloadSha256 || (payload.materialFingerprint || null) !== identity.materialFingerprint || (payload.keyVersion || null) !== identity.keyVersion) throw new Error(`Initial ${slot} supersession predecessor payload is not authenticated.`);
}

function retainedHistoryPayloadIdentity(slot, arn, versionId, payload, payloadHash = canonicalSha256, stagingLabels = ["AWSPREVIOUS"]) {
  return { arn, versionId, stagingLabels, payloadSha256: payloadHash(payload, slot), schemaKeys: Object.keys(payload || {}).sort(), sourceSha: payload?.sourceSha ?? null, rotationId: payload?.rotationId ?? null, slot: payload?.slot, materialFingerprint: payload?.materialFingerprint ?? null, keyVersion: payload?.keyVersion ?? null };
}

function assertSchemaV4SlotTopology(described, slot, retainedHistory) {
  const previous = retainedHistory[slot];
  const labelled = Object.entries(described.VersionIdsToStages || {}).filter(([, labels]) => Array.isArray(labels) && labels.length);
  const current = labelled.filter(([, labels]) => JSON.stringify(labels) === '["AWSCURRENT"]');
  if (labelled.length !== 2 || current.length !== 1 || current[0][0] === previous.versionId || canonical(labelled.find(([versionId]) => versionId === previous.versionId)?.[1]) !== canonical(["AWSPREVIOUS"])) throw new Error(`Initial ${slot} retained-history version topology is not authenticated.`);
  return { currentVersionId: current[0][0], previousVersionId: previous.versionId };
}

async function authenticateMixedRecoveryRetainedHistory({ send, resources, descriptions, payloadHash }) {
  const hasPrevious = Object.values(descriptions).some(({ VersionIdsToStages = {} }) => Object.values(VersionIdsToStages).some((labels) => labels?.includes("AWSPREVIOUS")));
  if (!hasPrevious) return undefined;
  const observed = {};
  const bootstrapProgress = [];
  for (const slot of MIXED_DUAL_SLOT_RECOVERY_ORDER) {
    const expected = MIXED_DUAL_SLOT_RECOVERY_SUCCESSOR[slot];
    const described = descriptions[slot];
    if (resources[slot] !== expected.current.arn || described?.ARN !== expected.current.arn) throw new Error(`Initial ${slot} AWS-legal recovery resource is not authenticated.`);
    const topology = described.VersionIdsToStages;
    const untouched = { [expected.current.versionId]: ["AWSCURRENT"], [expected.previous.versionId]: ["AWSPREVIOUS"] };
    if (canonical(topology) === canonical(untouched)) bootstrapProgress.push(false);
    else {
      const fresh = Object.entries(topology || {}).filter(([versionId, labels]) => versionId !== expected.current.versionId && versionId !== expected.previous.versionId && canonical(labels) === canonical(["AWSCURRENT"]));
      if (!topology || typeof topology !== "object" || Array.isArray(topology) || Object.keys(topology).length !== 2 || fresh.length !== 1 || canonical(topology[expected.current.versionId]) !== canonical(["AWSPREVIOUS"]) || topology[expected.previous.versionId] !== undefined) throw new Error(`Initial ${slot} AWS-legal recovery topology is not an authenticated bootstrap prefix.`);
      bootstrapProgress.push(true);
    }
    const current = await send(new GetSecretValueCommand({ SecretId: expected.current.arn, VersionId: expected.current.versionId }));
    const previous = await send(new GetSecretValueCommand({ SecretId: expected.previous.arn, VersionId: expected.previous.versionId }));
    if (current?.VersionId !== expected.current.versionId || previous?.VersionId !== expected.previous.versionId || typeof current.SecretString !== "string" || typeof previous.SecretString !== "string") throw new Error(`Initial ${slot} AWS-legal recovery version is not authenticated.`);
    let currentPayload; let previousPayload;
    try { currentPayload = JSON.parse(current.SecretString); previousPayload = JSON.parse(previous.SecretString); } catch { throw new Error(`Initial ${slot} AWS-legal recovery payload is malformed.`); }
    observed[slot] = {
      current: retainedHistoryPayloadIdentity(slot, described.ARN, current.VersionId, currentPayload, payloadHash, ["AWSCURRENT"]),
      previous: retainedHistoryPayloadIdentity(slot, described.ARN, previous.VersionId, previousPayload, payloadHash, ["AWSPREVIOUS"]),
    };
    if (canonical(observed[slot]) !== canonical(expected)) throw new Error(`Initial ${slot} AWS-legal recovery payload identity is not authenticated.`);
  }
  if (bootstrapProgress.some((completed, index) => !completed && bootstrapProgress.slice(index + 1).some(Boolean))) throw new Error("Initial AWS-legal recovery bootstrap prefix is not contiguous.");
  return Object.freeze({ recoveryHandoff: Object.freeze(observed), recoveryHandoffCanonicalId: MIXED_DUAL_SLOT_RECOVERY_SUCCESSOR_CANONICAL_ID, retainedHistory: MIXED_DUAL_SLOT_RETAINED_HISTORY, retainedHistoryCanonicalId: MIXED_DUAL_SLOT_RETAINED_HISTORY_CANONICAL_ID });
}

export function verifyLiveInitialDualSlotBindingWithRunner({ run, bindings, proveDescendant, retainedHistoryPayloadHash } = {}) {
  if (typeof run !== "function") throw new Error("Initial binding origin verification runner is required.");
  assertInitialBindingSchemaClosed(bindings);
  assertInitialDualSlotBindings(bindings);
  const resources = { jwtPrevious: bindings.jwt.previousSecretId, jwtPending: bindings.jwt.pendingSecretId, qrPrivatePending: bindings.qr.privatePendingSecretId, qrPublicPrevious: bindings.qr.publicPreviousSecretId, qrPublicPending: bindings.qr.publicPendingSecretId, qrCurrentVersion: bindings.qr.currentKeyVersionSecretId, qrPreviousVersion: bindings.qr.previousKeyVersionSecretId };
  let evidence;
  let predecessor;
  const retainedHistory = [4, 5].includes(bindings.schemaVersion) ? bindings.retainedHistory : undefined;
  if (bindings.schemaVersion === 3) {
    evidence = assertProductionSupersessionEvidence(bindings.supersessionEvidence);
    predecessor = assertProductionStaleSupersessionPredecessor(bindings.supersessionPredecessor, { sourceSha: bindings.sourceSha, rotationId: bindings.rotationId, supersessionEvidence: evidence });
    if (typeof proveDescendant !== "function" || proveDescendant({ ancestorSha: evidence.staleSourceSha, descendantSha: bindings.sourceSha }) !== true) throw new Error("Stale-supersession source ancestry is not independently authenticated.");
    if (predecessor.runtimeQrVersionLabel !== bindings.legacy.qrCurrentVersion) throw new Error("Stale-supersession runtime QR label does not match initial bindings.");
  }
  const observedSlots = {};
  for (const [slot, name] of Object.entries(INITIAL_DUAL_SLOT_NAMES)) {
    const arn = resources[slot];
    const described = runnerJson(run, ["aws", "secretsmanager", "describe-secret", "--secret-id", arn], `Initial ${slot} description`);
    if (described.Name !== name || described.ARN !== arn || !described.VersionIdsToStages) throw new Error(`Initial ${slot} resource identity is not authenticated.`);
    const { currentVersionId: versionId, previousVersionId } = predecessor
      ? assertSchemaV3SlotTopology(described, slot, evidence, predecessor)
      : retainedHistory
        ? assertSchemaV4SlotTopology(described, slot, retainedHistory)
      : (() => {
        if (Object.keys(described.VersionIdsToStages).length !== 1) throw new Error(`Initial ${slot} resource identity is not authenticated.`);
        const [[currentVersionId, stages]] = Object.entries(described.VersionIdsToStages);
        if (!Array.isArray(stages) || stages.length !== 1 || stages[0] !== "AWSCURRENT") throw new Error(`Initial ${slot} staging identity is not authenticated.`);
        return { currentVersionId, previousVersionId: null };
      })();
    const value = runnerJson(run, ["aws", "secretsmanager", "get-secret-value", "--secret-id", arn, "--version-id", versionId], `Initial ${slot} value`);
    if (value.VersionId !== versionId || typeof value.SecretString !== "string") throw new Error(`Initial ${slot} version identity is not authenticated.`);
    let payload;
    try { payload = JSON.parse(value.SecretString); } catch { throw new Error(`Initial ${slot} payload is malformed.`); }
    observedSlots[slot] = { arn, versionId, stages: ["AWSCURRENT"], ...assertInitialLivePayload(slot, payload, bindings) };
    if (previousVersionId) {
      const previous = runnerJson(run, ["aws", "secretsmanager", "get-secret-value", "--secret-id", arn, "--version-id", previousVersionId], `Initial ${slot} predecessor value`);
      if (previous.VersionId !== previousVersionId || typeof previous.SecretString !== "string") throw new Error(`Initial ${slot} predecessor version is not authenticated.`);
      let previousPayload;
      try { previousPayload = JSON.parse(previous.SecretString); } catch { throw new Error(`Initial ${slot} predecessor payload is malformed.`); }
      if (predecessor) assertSchemaV3PreviousPayload(slot, previousPayload, predecessor.slotIdentities[slot]);
      else if (canonical(retainedHistoryPayloadIdentity(slot, arn, previousVersionId, previousPayload, retainedHistoryPayloadHash)) !== canonical(retainedHistory[slot])) throw new Error(`Initial ${slot} retained-history payload is not authenticated.`);
    }
    if (bindings.recoveryHandoff) {
      const handoffPrevious = bindings.recoveryHandoff[slot].previous;
      if (described.VersionIdsToStages[handoffPrevious.versionId] !== undefined) throw new Error(`Initial ${slot} AWS-legal recovery handoff topology is not authenticated.`);
      const handoff = runnerJson(run, ["aws", "secretsmanager", "get-secret-value", "--secret-id", arn, "--version-id", handoffPrevious.versionId], `Initial ${slot} AWS-legal recovery handoff value`);
      if (handoff.VersionId !== handoffPrevious.versionId || typeof handoff.SecretString !== "string") throw new Error(`Initial ${slot} AWS-legal recovery handoff version is not authenticated.`);
      let handoffPayload;
      try { handoffPayload = JSON.parse(handoff.SecretString); } catch { throw new Error(`Initial ${slot} AWS-legal recovery handoff payload is malformed.`); }
      if (canonical(retainedHistoryPayloadIdentity(slot, arn, handoffPrevious.versionId, handoffPayload, retainedHistoryPayloadHash, [])) !== canonical({ ...handoffPrevious, stagingLabels: [] })) throw new Error(`Initial ${slot} AWS-legal recovery handoff payload is not authenticated.`);
    }
  }
  if (observedSlots.qrPrivatePending.keyVersion && observedSlots.qrPrivatePending.keyVersion !== observedSlots.qrPublicPending.keyVersion) throw new Error("Initial QR pending payload identities are inconsistent.");
  let supersessionPredecessorIdentitySha256;
  if (predecessor) {
    const payloads = {};
    for (const [name, expected] of Object.entries(predecessor.current)) {
      const described = runnerJson(run, ["aws", "secretsmanager", "describe-secret", "--secret-id", expected.secretArn], `Current ${name} predecessor description`);
      if (described.ARN !== expected.secretArn || described.VersionIdsToStages?.[expected.versionId]?.includes("AWSCURRENT") !== true) throw new Error(`Current ${name} predecessor resource/version is not authenticated.`);
      const value = runnerJson(run, ["aws", "secretsmanager", "get-secret-value", "--secret-id", expected.secretArn, "--version-id", expected.versionId], `Current ${name} predecessor value`);
      if (value.VersionId !== expected.versionId || typeof value.SecretString !== "string") throw new Error(`Current ${name} predecessor version is not authenticated.`);
      let payload;
      try { payload = JSON.parse(value.SecretString); } catch { throw new Error(`Current ${name} predecessor payload is malformed.`); }
      payloads[name] = assertCurrentPayload(payload, { family: expected.family, slot: expected.slot, qr: name !== "jwt" });
      const observed = { secretArn: expected.secretArn, versionId: expected.versionId, rotationId: payload.rotationId, family: payload.family, slot: payload.slot, ...(name !== "jwt" ? { keyVersion: payload.keyVersion } : {}), materialFingerprint: payload.materialFingerprint };
      if (canonical(observed) !== canonical(expected)) throw new Error(`Current ${name} predecessor does not match initial bindings.`);
    }
    assertPendingMaterial({ jwt: payloads.jwt.value, qrPrivate: payloads.qrPrivate.value, qrPublic: payloads.qrPublic.value, qrKeyVersion: payloads.qrPublic.keyVersion });
    supersessionPredecessorIdentitySha256 = predecessor.predecessorIdentitySha256;
  }
  const body = { schemaVersion: 1, kind: "PRODUCTION_INITIAL_DUAL_SLOT_BINDING_ORIGIN", producer: INITIAL_DUAL_SLOT_ROTATION_BINDINGS_PRODUCER, sourceSha: bindings.sourceSha, rotationId: bindings.rotationId, resources, observedSlots, ...(supersessionPredecessorIdentitySha256 ? { supersessionPredecessorIdentitySha256 } : {}), ...(retainedHistory ? { retainedHistoryCanonicalId: MIXED_DUAL_SLOT_RETAINED_HISTORY_CANONICAL_ID } : {}), ...(bindings.recoveryHandoff ? { recoveryHandoffCanonicalId: MIXED_DUAL_SLOT_RECOVERY_SUCCESSOR_CANONICAL_ID } : {}) };
  return Object.freeze({ ...body, bindingSha256: canonicalSha256(bindings), originSha256: canonicalSha256(body) });
}

export async function bootstrapInitialDualSlotRotation({ send, taskDefinition, sourceSha, rotationId, legacyBindings, supersessionEvidence, supersessionPredecessor, outputFile, repositoryRoot = process.cwd(), requireExisting = false, requiredWritePlan, retainedHistoryPayloadHash } = {}) {
  if (typeof send !== "function") throw new Error("Initial dual-slot bootstrap Secrets Manager sender is required.");
  if (!SHA40.test(sourceSha || "") || !ROTATION_ID.test(rotationId || "")) throw new Error("Initial dual-slot source/rotation identity is invalid.");
  if (typeof outputFile !== "string" || !outputFile) throw new Error("Initial dual-slot rotation binding output is required.");
  const baseline = deriveLegacyRotationBaseline(taskDefinition);
  assertLegacyMatches(legacyBindings, baseline);
  if ((supersessionEvidence === undefined) !== (supersessionPredecessor === undefined)) throw new Error("Complete stale-supersession predecessor evidence is required.");
  const checkedSupersessionEvidence = supersessionEvidence === undefined ? undefined : assertProductionSupersessionEvidence(supersessionEvidence);
  let checkedSupersessionPredecessor;
  if (checkedSupersessionEvidence) {
    checkedSupersessionPredecessor = assertProductionStaleSupersessionPredecessor(supersessionPredecessor, { sourceSha, rotationId, supersessionEvidence: checkedSupersessionEvidence });
    const observed = await authenticateSupersessionPredecessor({ send, taskDefinition, sourceSha, staleSourceSha: checkedSupersessionEvidence.staleSourceSha, rotationId, staleRotationId: checkedSupersessionEvidence.staleRotationId, supersessionEvidenceIdentitySha256: checkedSupersessionEvidence.evidenceIdentitySha256, slotIdentities: checkedSupersessionPredecessor.slotIdentities });
    if (canonical(observed.predecessor) !== canonical(checkedSupersessionPredecessor)) throw new Error("Live stale-supersession predecessor changed before binding generation.");
  }
  const resources = {};
  const descriptions = {};
  const created = [];
  for (const [slot, name] of Object.entries(INITIAL_DUAL_SLOT_NAMES)) {
    const result = await describeOrCreate({ send, name, requireExisting });
    resources[slot] = exactArn(result.response, name);
    descriptions[slot] = result.response;
    if (result.created) created.push(slot);
  }
  const recoveryHandoff = checkedSupersessionEvidence ? undefined : await authenticateMixedRecoveryRetainedHistory({ send, resources, descriptions, payloadHash: retainedHistoryPayloadHash });
  const retainedHistory = recoveryHandoff?.retainedHistory;
  if (checkedSupersessionEvidence && Object.entries(resources).some(([slot, arn]) => checkedSupersessionEvidence.resources[slot]?.arn !== arn)) throw new Error("Stale-supersession evidence resources do not match the initial binding topology.");
  if (requireExisting && (!Array.isArray(requiredWritePlan) || requiredWritePlan.length !== STALE_ROTATION_SUPERSESSION_WRITE_ORDER.length || requiredWritePlan.some((entry, index) => entry?.slot !== STALE_ROTATION_SUPERSESSION_WRITE_ORDER[index] || entry.secretArn !== resources[entry.slot] || !/^[a-f0-9]{64}$/.test(entry.payloadSha256 || "")))) throw new Error("Governed supersession bootstrap requires the exact approved seven-write plan.");
  const writePlanBySlot = new Map((requiredWritePlan || []).map((entry) => [entry.slot, entry]));
  const existingMaterial = {};
  let secretValueWrites = 0;
  ensureStageBPrivateDirectory({ directory: path.dirname(path.resolve(outputFile)), repositoryRoot, create: true, normalize: true, label: "Replacement material journal directory" });
  const materialFile = materialFileFor(outputFile);
  const material = await recoverInitialPendingMaterial({ send, resources, sourceSha, rotationId, materialFile, repositoryRoot, requireExisting, recoveryHandoff: recoveryHandoff?.recoveryHandoff });
  const payloads = pendingPayloads({ rotationId, material });
  for (const payload of Object.values(payloads)) payload.sourceSha = sourceSha;
  if (checkedSupersessionPredecessor) for (const payload of Object.values(payloads)) payload.supersessionPredecessorIdentitySha256 = checkedSupersessionPredecessor.predecessorIdentitySha256;
  const ensure = async (slot, options) => {
    const result = await ensureValue({ send, ...options, requireExisting, expectedPayloadSha256: writePlanBySlot.get(slot)?.payloadSha256, ignoreCurrentVersionId: recoveryHandoff?.recoveryHandoff?.[slot]?.current.versionId });
    secretValueWrites += result.wrote ? 1 : 0;
    return result.material;
  };
  existingMaterial.jwtPending = await ensure("jwtPending", { arn: resources.jwtPending, name: "JWT pending", expected: payloads.jwtPending, rotationId, allowPendingResume: true });
  existingMaterial.qrPrivatePending = await ensure("qrPrivatePending", { arn: resources.qrPrivatePending, name: "QR private pending", expected: payloads.qrPrivatePending, rotationId, allowPendingResume: true });
  let qrPublicExpected = payloads.qrPublicPending;
  if (existingMaterial.qrPrivatePending.value) {
    let derivedPublic;
    try { derivedPublic = createPublicKey(existingMaterial.qrPrivatePending.value).export({ format: "pem", type: "spki" }); } catch { throw new Error("QR pending private material is malformed."); }
    qrPublicExpected = { ...payloads.qrPublicPending, keyVersion: sha256(derivedPublic).slice(0, 16), materialFingerprint: fingerprint(derivedPublic), value: derivedPublic };
  }
  existingMaterial.qrPublicPending = await ensure("qrPublicPending", { arn: resources.qrPublicPending, name: "QR public pending", expected: qrPublicExpected, rotationId, allowPendingResume: true });
  if (existingMaterial.qrPrivatePending.value && existingMaterial.qrPublicPending.value) {
    let derivedPublic;
    try { derivedPublic = createPublicKey(existingMaterial.qrPrivatePending.value).export({ format: "pem", type: "spki" }); } catch { throw new Error("QR pending private material is malformed."); }
    if (derivedPublic !== existingMaterial.qrPublicPending.value || existingMaterial.qrPrivatePending.keyVersion !== existingMaterial.qrPublicPending.keyVersion || existingMaterial.qrPublicPending.keyVersion !== sha256(derivedPublic).slice(0, 16)) {
      throw new Error("QR pending material does not form the reviewed key pair.");
    }
  }
  const handoff = checkedSupersessionPredecessor ? { supersessionPredecessorIdentitySha256: checkedSupersessionPredecessor.predecessorIdentitySha256 } : {};
  await ensure("jwtPrevious", { arn: resources.jwtPrevious, name: "JWT previous", expected: { ...emptySlot("jwt_secrets", "empty", sourceSha), ...handoff }, rotationId });
  await ensure("qrPublicPrevious", { arn: resources.qrPublicPrevious, name: "QR public previous", expected: { ...emptySlot("qr_signing_keys", "empty", sourceSha), ...handoff }, rotationId });
  await ensure("qrCurrentVersion", { arn: resources.qrCurrentVersion, name: "QR current key version", expected: { ...versionSlot(baseline.qrCurrentVersion, "current", sourceSha), ...handoff }, rotationId });
  await ensure("qrPreviousVersion", { arn: resources.qrPreviousVersion, name: "QR previous key version", expected: { ...versionSlot("", "previous-empty", sourceSha), ...handoff }, rotationId });
  const bindings = {
    schemaVersion: checkedSupersessionPredecessor ? 3 : recoveryHandoff ? 5 : 2,
    kind: INITIAL_DUAL_SLOT_ROTATION_BINDINGS_KIND,
    producer: INITIAL_DUAL_SLOT_ROTATION_BINDINGS_PRODUCER,
    sourceSha,
    rotationId,
    legacy: baseline,
    ...(checkedSupersessionPredecessor ? { supersessionEvidence: checkedSupersessionEvidence, supersessionPredecessor: checkedSupersessionPredecessor } : {}),
    ...(retainedHistory ? { retainedHistory, retainedHistoryCanonicalId: MIXED_DUAL_SLOT_RETAINED_HISTORY_CANONICAL_ID } : {}),
    ...(recoveryHandoff ? { recoveryHandoff: recoveryHandoff.recoveryHandoff, recoveryHandoffCanonicalId: recoveryHandoff.recoveryHandoffCanonicalId } : {}),
    jwt: { currentSecretId: baseline.jwtCurrent, previousSecretId: resources.jwtPrevious, pendingSecretId: resources.jwtPending },
    qr: {
      privateCurrentSecretId: baseline.qrPrivateCurrent,
      privatePendingSecretId: resources.qrPrivatePending,
      publicCurrentSecretId: baseline.qrPublicCurrent,
      publicPreviousSecretId: resources.qrPublicPrevious,
      publicPendingSecretId: resources.qrPublicPending,
      currentKeyVersionSecretId: resources.qrCurrentVersion,
      previousKeyVersionSecretId: resources.qrPreviousVersion,
      previousKeyVersion: baseline.qrCurrentVersion,
      pendingKeyVersion: existingMaterial.qrPublicPending.keyVersion,
    },
  };
  bindings.ecs = rotationBindingsToTaskBindings(bindings);
  assertInitialDualSlotBindings(bindings);
  const output = JSON.stringify(bindings, null, 2) + "\n";
  const existingOutput = lstatSync(outputFile, { throwIfNoEntry: false });
  if (existingOutput) {
    const captured = readStageBPrivateFileBytes({ filePath: path.resolve(outputFile), repositoryRoot, label: "Initial dual-slot rotation bindings" });
    if (captured.bytes.toString("utf8") !== output) throw new Error("Existing initial dual-slot binding manifest does not match the verified topology.");
    if (lstatSync(materialFile, { throwIfNoEntry: false })) unlinkSync(materialFile);
    return { valid: true, bindings, bindingFile: path.resolve(outputFile), evidenceSha256: sha256(output), created, secretResourceCount: Object.keys(INITIAL_DUAL_SLOT_NAMES).length, secretValueWrites, pendingMaterialGenerated: true };
  }
  const evidence = writeStageBPrivateFileAtomic({ filePath: outputFile, bytes: Buffer.from(output), repositoryRoot, label: "Initial dual-slot rotation bindings" });
  if (lstatSync(materialFile, { throwIfNoEntry: false })) unlinkSync(materialFile);
  return { valid: true, bindings, bindingFile: evidence.path, evidenceSha256: evidence.sha256, created, secretResourceCount: Object.keys(INITIAL_DUAL_SLOT_NAMES).length, secretValueWrites, pendingMaterialGenerated: true };
}

export function createInitialDualSlotSecretsManagerClient({ region = INITIAL_DUAL_SLOT_REGION, profile, credentials = profile ? fromIni({ profile }) : undefined, stsClient } = {}) {
  if (!profile || typeof profile !== "string" || !profile.trim()) throw new Error("Secrets Manager mutation profile is required and must be explicit.");
  if (typeof credentials !== "function") throw new Error("Secrets Manager mutation credentials are incomplete.");
  const client = new SecretsManagerClient({ region, credentials });
  const sts = stsClient || new STSClient({ region, credentials });
  client.assertCredentialIdentity = async ({ account = INITIAL_DUAL_SLOT_ACCOUNT, callerPattern = new RegExp(`^arn:aws:sts::${INITIAL_DUAL_SLOT_ACCOUNT}:assumed-role/mscqr-production-release-deployer/[^/]+$`) } = {}) => {
    const identity = await sts.send(new GetCallerIdentityCommand({}));
    if (identity.Account !== account || !callerPattern.test(identity.Arn || "")) throw new Error("Secrets Manager mutation client caller identity is outside the reviewed account/principal contract.");
    return { account: identity.Account, callerArn: identity.Arn };
  };
  return client;
}

function assertRotationVersionTopology(response, name) {
  const stages = response?.VersionIdsToStages;
  if (!stages || typeof stages !== "object") throw new Error(`${name} rotation version topology is unavailable.`);
  const labels = Object.values(stages).flatMap((value) => Array.isArray(value) ? value : []);
  if (labels.some((label) => !["AWSCURRENT", "AWSPREVIOUS"].includes(label)) || labels.filter((label) => label === "AWSCURRENT").length !== 1 || labels.filter((label) => label === "AWSPREVIOUS").length > 1) {
    throw new Error(`${name} has an unexpected rotation version topology.`);
  }
  return stages;
}

function readExistingSupersessionEvidence({ outputFile, repositoryRoot, sourceSha, staleSourceSha, rotationId, staleRotationId, resources, transitionVersionId }) {
  const stat = lstatSync(outputFile, { throwIfNoEntry: false });
  if (!stat) return null;
  const { bytes } = readStageBPrivateFileBytes({ filePath: path.resolve(outputFile), repositoryRoot, label: "Stale rotation supersession evidence" });
  let evidence;
  try { evidence = JSON.parse(bytes.toString("utf8")); } catch { throw new Error("Existing stale rotation supersession evidence is malformed."); }
  const expectedResources = Object.fromEntries(Object.entries(resources).map(([slot, arn]) => [slot, { arn, versionId: transitionVersionId(slot), stages: ["AWSCURRENT"] }]));
  const checked = assertProductionSupersessionEvidence(evidence);
  const expectedIdentity = productionSupersessionEvidenceIdentity({ sourceSha, staleSourceSha, rotationId, staleRotationId, resources: expectedResources, predecessorSlotIdentities: checked.predecessorSlotIdentities });
  if (!checked.predecessorSlotIdentities || checked.sourceSha !== sourceSha || checked.staleSourceSha !== staleSourceSha || checked.rotationId !== rotationId || checked.staleRotationId !== staleRotationId || JSON.stringify(checked.resources) !== JSON.stringify(expectedResources) || checked.evidenceIdentitySha256 !== expectedIdentity || bytes.toString("utf8") !== `${JSON.stringify(checked, null, 2)}\n`) throw new Error("Existing stale rotation supersession evidence does not match the authenticated transition.");
  return { evidence: checked, sha256: sha256(bytes) };
}

export async function supersedeStalePendingRotation({ send, taskDefinition, sourceSha, staleSourceSha, rotationId, staleRotationId, outputFile, repositoryRoot = process.cwd(), proveDescendant, mode, authorizeWritePlan } = {}) {
  if (typeof send !== "function") throw new Error("Stale rotation supersession Secrets Manager sender is required.");
  if (!["prepare", "execute"].includes(mode)) throw new Error("Stale rotation supersession requires an explicit prepare or execute mode.");
  if (!SHA40.test(sourceSha || "") || !SHA40.test(staleSourceSha || "") || !ROTATION_ID.test(rotationId || "") || !ROTATION_ID.test(staleRotationId || "")) throw new Error("Stale rotation supersession identity is invalid.");
  if (sourceSha === staleSourceSha || rotationId === staleRotationId) throw new Error("Stale and replacement rotation identities must be distinct.");
  if (typeof proveDescendant !== "function" || proveDescendant({ ancestorSha: staleSourceSha, descendantSha: sourceSha }) !== true) throw new Error("Stale rotation source is not an authenticated ancestor of the replacement source.");
  const resources = {};
  const existing = {};
  const currentVersionIds = {};
  const versionTopologies = {};
  for (const [slot, name] of Object.entries(INITIAL_DUAL_SLOT_NAMES)) {
    const described = await send(new DescribeSecretCommand({ SecretId: name }));
    resources[slot] = exactArn(described, name);
    const stages = assertRotationVersionTopology(described, name);
    versionTopologies[slot] = stages;
    currentVersionIds[slot] = Object.entries(stages).find(([, labels]) => labels.includes("AWSCURRENT"))?.[0];
    const response = await send(new GetSecretValueCommand({ SecretId: resources[slot], VersionId: currentVersionIds[slot] }));
    if (response?.VersionId !== currentVersionIds[slot]) throw new Error(`Rotation supersession ${slot} predecessor version is not authenticated.`);
    existing[slot] = parseStoredValue(response, name);
  }
  const replacementOrder = STALE_ROTATION_SUPERSESSION_WRITE_ORDER;
  const definitions = {
    jwtPrevious: ["jwt_secrets", "empty"], jwtPending: ["jwt_secrets", "pending"], qrPrivatePending: ["qr_signing_keys", "pending-private"],
    qrPublicPrevious: ["qr_signing_keys", "empty"], qrPublicPending: ["qr_signing_keys", "pending-public"], qrCurrentVersion: ["qr_key_versions", "current"], qrPreviousVersion: ["qr_key_versions", "previous-empty"],
  };
  const transitionVersionId = (slot) => sha256(`${sourceSha}:${rotationId}:${slot}`);
  const classify = (slot) => {
    const value = existing[slot];
    const [family, expectedSlot] = definitions[slot];
    if (value.sourceSha !== staleSourceSha && value.sourceSha !== sourceSha) return "UNKNOWN";
    if (value.family !== family || value.slot !== expectedSlot || typeof value.value !== "string") return "INVALID";
    const pending = slot.endsWith("Pending");
    if (value.sourceSha === staleSourceSha) {
      if (staleSourceSha === PARTIAL_REBASELINE_RECOVERY_ORIGINAL_SOURCE_SHA) {
        try {
          assertCompletedRebaselinePayload({ slot, payload: value, sourceSha: staleSourceSha, rotationId: staleRotationId });
          return "OLD_AUTHENTICATED";
        } catch {
          return "INVALID";
        }
      }
      // The older initial-dual-slot predecessor has a separate exact schema.
      const expectedKeys = pending
        ? ["value", "sourceSha", "rotationId", "family", "slot", "materialFingerprint", ...(["qrPrivatePending", "qrPublicPending"].includes(slot) ? ["keyVersion"] : [])]
        : ["value", "sourceSha", "family", "slot", "initialMigration"];
      if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(expectedKeys.sort())) return "INVALID";
      if ((pending && value.rotationId !== staleRotationId) || (!pending && value.rotationId !== undefined)) return "INVALID";
      if (pending && (!value.materialFingerprint || value.materialFingerprint !== fingerprint(value.value))) return "INVALID";
      if (!pending && (value.initialMigration !== true || value.value !== (slot === "qrCurrentVersion" ? value.value : "") || (slot === "qrCurrentVersion" && !VERSION.test(value.value)))) return "INVALID";
      return "OLD_AUTHENTICATED";
    }
    if ((pending && value.rotationId !== rotationId) || (!pending && value.rotationId !== undefined)) return "INVALID";
    if (pending && (!value.materialFingerprint || value.materialFingerprint !== fingerprint(value.value))) return "INVALID";
    if (currentVersionIds[slot] !== transitionVersionId(slot)) return "INVALID";
    return "NEW_AUTHENTICATED";
  };
  const states = Object.fromEntries(Object.keys(INITIAL_DUAL_SLOT_NAMES).map((slot) => [slot, classify(slot)]));
  if (Object.values(states).some((state) => state === "UNKNOWN" || state === "INVALID")) throw new Error("Rotation state contains unknown or invalid slot evidence; refusing mutation.");
  const newSlots = replacementOrder.filter((slot) => states[slot] === "NEW_AUTHENTICATED");
  if (newSlots.some((slot, index) => slot !== replacementOrder[index])) throw new Error("Rotation state is not an authenticated resumable transition prefix.");
  const logicalPredecessors = {};
  for (const [slot, secretArn] of Object.entries(resources)) {
    let versionId = currentVersionIds[slot];
    let material = existing[slot];
    if (states[slot] === "NEW_AUTHENTICATED") {
      const previous = Object.entries(versionTopologies[slot]).filter(([, stages]) => Array.isArray(stages) && stages.includes("AWSPREVIOUS"));
      if (previous.length !== 1 || previous[0][0] === versionId || JSON.stringify(previous[0][1]) !== '["AWSPREVIOUS"]') throw new Error(`Rotation supersession cannot authenticate the expected prior ${slot} version for resume.`);
      [versionId] = previous[0];
      const response = await send(new GetSecretValueCommand({ SecretId: secretArn, VersionId: versionId }));
      if (response?.VersionId !== versionId) throw new Error(`Rotation supersession prior ${slot} version is not authenticated.`);
      material = parseStoredValue(response, `${slot} prior`);
    }
    if (staleSourceSha === PARTIAL_REBASELINE_RECOVERY_ORIGINAL_SOURCE_SHA) assertCompletedRebaselinePayload({ slot, payload: material, sourceSha: staleSourceSha, rotationId: staleRotationId });
    logicalPredecessors[slot] = { secretArn, versionId, material };
  }
  if (Object.keys(logicalPredecessors).length !== Object.keys(INITIAL_DUAL_SLOT_NAMES).length) throw new Error("Rotation supersession logical predecessor set is incomplete.");
  if (staleSourceSha === PARTIAL_REBASELINE_RECOVERY_ORIGINAL_SOURCE_SHA) {
    let derivedPublic;
    try { derivedPublic = createPublicKey(logicalPredecessors.qrPrivatePending.material.value).export({ format: "pem", type: "spki" }); } catch { throw new Error("Completed rebaseline QR private predecessor is malformed."); }
    if (derivedPublic !== logicalPredecessors.qrPublicPending.material.value || logicalPredecessors.qrPrivatePending.material.keyVersion !== logicalPredecessors.qrPublicPending.material.keyVersion) throw new Error("Completed rebaseline QR predecessor pair is not authenticated.");
  }
  const allNew = newSlots.length === replacementOrder.length;
  const expectedEvidenceResources = Object.fromEntries(Object.entries(resources).map(([slot, arn]) => [slot, { arn, versionId: transitionVersionId(slot), stages: ["AWSCURRENT"] }]));
  const existingEvidence = readExistingSupersessionEvidence({ outputFile, repositoryRoot, sourceSha, staleSourceSha, rotationId, staleRotationId, resources, transitionVersionId });
  const slotIdentities = {};
  for (const [slot, { secretArn, versionId, material }] of Object.entries(logicalPredecessors)) {
    slotIdentities[slot] = { secretArn, versionId, payloadSha256: canonicalSha256(material), materialFingerprint: material.materialFingerprint || null, keyVersion: material.keyVersion || null };
  }
  if (existingEvidence && canonical(existingEvidence.evidence.predecessorSlotIdentities) !== canonical(slotIdentities)) throw new Error("Existing stale rotation supersession predecessor evidence does not match live state.");
  const supersessionEvidenceIdentitySha256 = productionSupersessionEvidenceIdentity({ sourceSha, staleSourceSha, rotationId, staleRotationId, resources: expectedEvidenceResources, predecessorSlotIdentities: slotIdentities });
  const { baseline, predecessor } = await authenticateSupersessionPredecessor({ send, taskDefinition, sourceSha, staleSourceSha, rotationId, staleRotationId, supersessionEvidenceIdentitySha256, slotIdentities });
  if (logicalPredecessors.qrCurrentVersion.material.value !== baseline.qrCurrentVersion) throw new Error("Stale QR current key-version marker does not match the authenticated runtime baseline.");
  if (existingEvidence && !allNew) throw new Error("Existing stale rotation supersession evidence conflicts with a non-converged secret topology.");
  ensureStageBPrivateDirectory({ directory: path.dirname(path.resolve(outputFile)), repositoryRoot, create: true, label: "Stale rotation supersession transaction directory" });
  const materialFile = materialFileFor(outputFile);
  const journalMaterial = readMaterialJournal(materialFile, sourceSha, rotationId, repositoryRoot);
  if (allNew && existingEvidence && !journalMaterial) throw new Error("Stale rotation supersession authorization is already durably consumed by the completed transition.");
  if (allNew && !existingEvidence && !journalMaterial) throw new Error("All-new stale rotation supersession replay is missing its authenticated replacement material journal.");
  const material = allNew
    ? journalMaterial || { jwt: existing.jwtPending.value, qrPrivate: existing.qrPrivatePending.value, qrPublic: existing.qrPublicPending.value, qrKeyVersion: existing.qrPrivatePending.keyVersion }
    : journalMaterial || writeMaterialJournal(materialFile, sourceSha, rotationId, generatePendingMaterial(), repositoryRoot);
  const payloads = pendingPayloads({ rotationId, material });
  for (const payload of Object.values(payloads)) payload.sourceSha = sourceSha;
  let derivedPublic;
  try { derivedPublic = createPublicKey(material.qrPrivate).export({ format: "pem", type: "spki" }); } catch { throw new Error("Replacement QR pending private material is malformed."); }
  const qrKeyVersion = sha256(derivedPublic).slice(0, 16);
  payloads.qrPrivatePending = { ...payloads.qrPrivatePending, keyVersion: qrKeyVersion, materialFingerprint: fingerprint(material.qrPrivate), value: material.qrPrivate };
  if (states.qrPublicPending === "NEW_AUTHENTICATED" && existing.qrPublicPending.value !== derivedPublic) throw new Error("Replacement QR pending public material does not match its private key.");
  payloads.qrPublicPending = { ...payloads.qrPublicPending, keyVersion: qrKeyVersion, materialFingerprint: fingerprint(derivedPublic), value: derivedPublic };
  const replacement = {
    jwtPending: payloads.jwtPending,
    qrPrivatePending: payloads.qrPrivatePending,
    qrPublicPending: payloads.qrPublicPending,
    jwtPrevious: emptySlot("jwt_secrets", "empty", sourceSha),
    qrPublicPrevious: emptySlot("qr_signing_keys", "empty", sourceSha),
    qrCurrentVersion: versionSlot(logicalPredecessors.qrCurrentVersion.material.value, "current", sourceSha),
    qrPreviousVersion: versionSlot("", "previous-empty", sourceSha),
  };
  for (const payload of Object.values(replacement)) payload.supersessionPredecessorIdentitySha256 = predecessor.predecessorIdentitySha256;
  for (const slot of Object.keys(replacement)) if (states[slot] === "NEW_AUTHENTICATED" && JSON.stringify(existing[slot]) !== JSON.stringify(replacement[slot])) throw new Error(`Replacement ${slot} evidence does not match the authenticated transition.`);
  for (const [slot, name] of Object.entries(INITIAL_DUAL_SLOT_NAMES)) {
    const stages = assertRotationVersionTopology(await send(new DescribeSecretCommand({ SecretId: resources[slot] })), name);
    const currentVersionId = Object.entries(stages).find(([, labels]) => labels.includes("AWSCURRENT"))?.[0];
    if (currentVersionId !== currentVersionIds[slot]) throw new Error(`Rotation supersession ${slot} predecessor changed before mutation.`);
    if (states[slot] === "NEW_AUTHENTICATED" && JSON.stringify(stages[logicalPredecessors[slot].versionId]) !== '["AWSPREVIOUS"]') throw new Error(`Rotation supersession ${slot} expected predecessor changed before mutation.`);
  }
  for (const [name, expected] of Object.entries(predecessor.current)) {
    const described = await send(new DescribeSecretCommand({ SecretId: expected.secretArn }));
    if (described?.ARN !== expected.secretArn || described.VersionIdsToStages?.[expected.versionId]?.includes("AWSCURRENT") !== true) throw new Error(`Rotation supersession current ${name} predecessor changed before mutation.`);
  }
  const writePlan = Object.freeze(replacementOrder.map((slot) => Object.freeze({
    slot,
    secretArn: resources[slot],
    clientRequestToken: transitionVersionId(slot),
    payloadSha256: canonicalSha256(replacement[slot]),
  })));
  if (writePlan.length !== 7 || writePlan.some((entry, index) => entry.slot !== replacementOrder[index] || entry.secretArn !== resources[entry.slot])) throw new Error("Stale rotation supersession write plan is not the exact canonical seven-target plan.");
  const preparationInput = Object.freeze({
    sourceSha, staleSourceSha, rotationId, staleRotationId,
    resources: Object.freeze({ ...resources }),
    predecessorSlotIdentities: Object.freeze(structuredClone(slotIdentities)),
    currentPredecessor: predecessor,
    materialJournalFile: path.resolve(materialFile),
    materialJournalFileSha256: readStageBPrivateFileBytes({ filePath: materialFile, repositoryRoot, label: "Replacement material journal" }).sha256,
    writePlan,
  });
  if (mode === "prepare") return { valid: true, transition: "SUPERSEDE_STALE_PENDING_PREPARED", writes: 0, completedWriteCount: newSlots.length, preparationInput, predecessor, sourceSha, staleSourceSha, rotationId, staleRotationId, resources };
  const assertCurrentMutationTopology = async (writeIndex) => {
    for (const [slot, name] of Object.entries(INITIAL_DUAL_SLOT_NAMES)) {
      const described = await send(new DescribeSecretCommand({ SecretId: resources[slot] }));
      if (described?.ARN !== resources[slot]) throw new Error(`Rotation supersession ${slot} resource changed before write ${writeIndex + 1}.`);
      const stages = assertRotationVersionTopology(described, name);
      const transitioned = states[slot] === "NEW_AUTHENTICATED" || replacementOrder.indexOf(slot) < writeIndex;
      const expectedCurrent = transitioned ? transitionVersionId(slot) : currentVersionIds[slot];
      const observedCurrent = Object.entries(stages).find(([, labels]) => labels.includes("AWSCURRENT"))?.[0];
      if (observedCurrent !== expectedCurrent) throw new Error(`Rotation supersession ${slot} topology changed before write ${writeIndex + 1}.`);
      if (transitioned && JSON.stringify(stages[logicalPredecessors[slot].versionId]) !== '["AWSPREVIOUS"]') throw new Error(`Rotation supersession ${slot} predecessor changed before write ${writeIndex + 1}.`);
    }
    for (const [name, expected] of Object.entries(predecessor.current)) {
      const described = await send(new DescribeSecretCommand({ SecretId: expected.secretArn }));
      if (described?.ARN !== expected.secretArn || described.VersionIdsToStages?.[expected.versionId]?.includes("AWSCURRENT") !== true) throw new Error(`Rotation supersession current ${name} predecessor changed before write ${writeIndex + 1}.`);
    }
  };
  const versionIds = {};
  if (newSlots.length > 0 && (typeof authorizeWritePlan !== "function" || await authorizeWritePlan(preparationInput, { completedWriteCount: newSlots.length, existingPrefix: true, remainingWriteCount: replacementOrder.length - newSlots.length }) !== true)) throw new Error("Approved stale rotation supersession authorization is required for the authenticated write prefix.");
  for (const [writeIndex, slot] of replacementOrder.entries()) {
    if (states[slot] === "NEW_AUTHENTICATED") { versionIds[slot] = currentVersionIds[slot]; continue; }
    if (typeof authorizeWritePlan !== "function" || await authorizeWritePlan(preparationInput, { completedWriteCount: writeIndex, slot, writeIndex, remainingWriteCount: replacementOrder.length - writeIndex }) !== true) throw new Error("Approved stale rotation supersession authorization is required before PutSecretValue.");
    // The target topology is the last remote observation before its write;
    // slower cross-service authorization CAS checks run immediately above.
    await assertCurrentMutationTopology(writeIndex);
    const value = replacement[slot];
    const response = await send(new PutSecretValueCommand({ SecretId: resources[slot], ClientRequestToken: sha256(`${sourceSha}:${rotationId}:${slot}`), SecretString: JSON.stringify(value) }));
    if (response?.VersionId !== transitionVersionId(slot)) throw new Error(`Rotation supersession returned an unexpected version for ${slot}.`);
    versionIds[slot] = response.VersionId;
  }
  for (const [slot, name] of Object.entries(INITIAL_DUAL_SLOT_NAMES)) {
    const described = await send(new DescribeSecretCommand({ SecretId: name }));
    const stages = assertRotationVersionTopology(described, name);
    const currentVersionId = Object.entries(stages).find(([, labels]) => labels.includes("AWSCURRENT"))?.[0];
    if (currentVersionId !== transitionVersionId(slot)) throw new Error(`Rotation supersession readback did not select the deterministic new ${slot} version.`);
    const response = await send(new GetSecretValueCommand({ SecretId: resources[slot], VersionId: currentVersionId }));
    if (response?.VersionId !== currentVersionId) throw new Error(`Rotation supersession readback ${slot} version is not authenticated.`);
    const readback = parseStoredValue(response, name);
    if (JSON.stringify(readback) !== JSON.stringify(replacement[slot])) throw new Error(`Rotation supersession readback is not bound to the new ${slot} identity.`);
  }
  const evidenceCore = {
    schemaVersion: 1,
    transition: "SUPERSEDE_STALE_PENDING",
    sourceSha,
    staleSourceSha,
    rotationId,
    staleRotationId,
    generatedAt: new Date().toISOString(),
    resources: expectedEvidenceResources,
    predecessorSlotIdentities: slotIdentities,
  };
  const evidence = { ...evidenceCore, evidenceIdentitySha256: productionSupersessionEvidenceIdentity(evidenceCore) };
  const bytes = Buffer.from(`${JSON.stringify(evidence, null, 2)}\n`);
  const persisted = existingEvidence || writeStageBPrivateFileAtomic({ filePath: outputFile, bytes, repositoryRoot, label: "Stale rotation supersession evidence" });
  const returnedEvidence = existingEvidence?.evidence || evidence;
  return { valid: true, transition: returnedEvidence.transition, preWriteAuthorizationAuthenticated: true, idempotentReplay: allNew, writes: existingEvidence ? 0 : Object.keys(versionIds).filter((slot) => states[slot] !== "NEW_AUTHENTICATED").length, evidence: returnedEvidence, predecessor, evidenceFile: existingEvidence ? path.resolve(outputFile) : persisted.path, evidenceSha256: persisted.sha256, sourceSha, staleSourceSha, rotationId, staleRotationId, resources, versionIds };
}

export function finalizeStaleRotationSupersessionMaterialJournal({ outputFile, expectedFileSha256, repositoryRoot = process.cwd() } = {}) {
  const materialFile = materialFileFor(outputFile);
  const authenticated = readStageBPrivateFileBytes({ filePath: materialFile, repositoryRoot, label: "Replacement material journal" });
  if (!/^[a-f0-9]{64}$/.test(expectedFileSha256 || "") || authenticated.sha256 !== expectedFileSha256) throw new Error("Replacement material journal differs from the consumed supersession transaction.");
  unlinkSync(materialFile);
  return true;
}

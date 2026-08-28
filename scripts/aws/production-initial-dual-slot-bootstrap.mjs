import { createHash, createPublicKey } from "node:crypto";
import { createRequire } from "node:module";
import { chmodSync, lstatSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import path from "node:path";
import { ensureStageBPrivateDirectory, ensureStageBPrivateFile, writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";
import { rotationBindingsToTaskBindings } from "./production-cutover-runtime-bootstrap.mjs";
import { productionSupersessionEvidenceIdentity } from "../security/production-initial-migration-source-advance.mjs";
import { deriveLegacyRotationBaseline } from "./production-legacy-rotation-baseline.mjs";
import { generateRebaselineMaterial, fingerprint as secureFingerprint } from "./production-dual-slot-rebaseline-contract.mjs";

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
const materialFileFor = (outputFile) => `${path.resolve(outputFile)}.material`;
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

function readMaterialJournal(filePath, sourceSha, rotationId) {
  const stat = lstatSync(filePath, { throwIfNoEntry: false });
  if (!stat) return null;
  if (!stat.isFile() || (stat.mode & 0o077) !== 0) throw new Error("Replacement material journal must be a private regular file.");
  let journal;
  try { journal = JSON.parse(readFileSync(filePath, "utf8")); } catch { throw new Error("Replacement material journal is malformed."); }
  if (journal.schemaVersion !== 1 || journal.sourceSha !== sourceSha || journal.rotationId !== rotationId) throw new Error("Replacement material journal identity does not match the requested transition.");
  return assertPendingMaterial(journal.material);
}

function writeMaterialJournal(filePath, sourceSha, rotationId, material) {
  const existing = readMaterialJournal(filePath, sourceSha, rotationId);
  if (existing) return existing;
  const temporary = `${filePath}.tmp-${process.pid}`;
  writeFileSync(temporary, `${JSON.stringify({ schemaVersion: 1, sourceSha, rotationId, material })}\n`, { mode: 0o600, flag: "wx" });
  chmodSync(temporary, 0o600);
  renameSync(temporary, filePath);
  return material;
}

async function recoverInitialPendingMaterial({ send, resources, sourceSha, rotationId, materialFile }) {
  const pendingSlots = ["jwtPending", "qrPrivatePending", "qrPublicPending"];
  const existing = {};
  for (const slot of pendingSlots) {
    try {
      existing[slot] = parseStoredValue(await send(new GetSecretValueCommand({ SecretId: resources[slot] })), `${slot} pending`);
    } catch (error) {
      if (!notFound(error)) throw error;
    }
  }
  const present = pendingSlots.filter((slot) => existing[slot]).length;
  const journal = readMaterialJournal(materialFile, sourceSha, rotationId);
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
  return journal || writeMaterialJournal(materialFile, sourceSha, rotationId, generatePendingMaterial());
}

function exactArn(response, expectedName) {
  if (response?.Name !== expectedName || !SECRET_ARN.test(response?.ARN || "")) throw new Error(`Secret resource ${expectedName} is outside the reviewed production contract.`);
  return response.ARN;
}

async function describeOrCreate({ send, name }) {
  try {
    return { response: await send(new DescribeSecretCommand({ SecretId: name })), created: false };
  } catch (error) {
    if (!notFound(error)) throw new Error(`Secret resource lookup failed for ${name}.`);
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

async function ensureValue({ send, arn, name, expected, rotationId, allowPendingResume = false }) {
  try {
    const existing = parseStoredValue(await send(new GetSecretValueCommand({ SecretId: arn })), name);
    if (allowPendingResume) {
      if (existing.rotationId !== rotationId || existing.sourceSha !== expected.sourceSha || existing.family !== expected.family || existing.slot !== expected.slot || !existing.materialFingerprint || existing.materialFingerprint !== fingerprint(existing.value)) {
        throw new Error(`${name} contains inconsistent pending-migration metadata.`);
      }
      return { material: existing, wrote: false };
    }
    if (JSON.stringify(existing) !== JSON.stringify(expected)) throw new Error(`${name} contains inconsistent initial-migration metadata.`);
    return { material: existing, wrote: false };
  } catch (error) {
    if (!notFound(error)) throw error;
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

export function assertInitialDualSlotBindings(bindings) {
  const refs = [bindings?.jwt?.currentSecretId, bindings?.jwt?.previousSecretId, bindings?.jwt?.pendingSecretId, bindings?.qr?.privateCurrentSecretId, bindings?.qr?.privatePendingSecretId, bindings?.qr?.publicCurrentSecretId, bindings?.qr?.publicPreviousSecretId, bindings?.qr?.publicPendingSecretId, bindings?.qr?.currentKeyVersionSecretId, bindings?.qr?.previousKeyVersionSecretId];
  if (refs.some((value) => !SECRET_ARN.test(String(value || ""))) || new Set(refs).size !== refs.length) throw new Error("Initial dual-slot bindings must contain distinct production secret ARNs.");
  if (!VERSION.test(bindings?.qr?.previousKeyVersion || "")) throw new Error("Initial dual-slot previous QR key version is invalid.");
  if (!SHA40.test(bindings?.sourceSha || "") || !ROTATION_ID.test(bindings?.rotationId || "")) throw new Error("Initial dual-slot identity binding is invalid.");
  if (bindings?.ecs && JSON.stringify(bindings.ecs) !== JSON.stringify(rotationBindingsToTaskBindings(bindings))) throw new Error("Initial dual-slot ECS bindings do not match the canonical SDK bindings.");
  return true;
}

export async function bootstrapInitialDualSlotRotation({ send, taskDefinition, sourceSha, rotationId, legacyBindings, outputFile, repositoryRoot = process.cwd() } = {}) {
  if (typeof send !== "function") throw new Error("Initial dual-slot bootstrap Secrets Manager sender is required.");
  if (!SHA40.test(sourceSha || "") || !ROTATION_ID.test(rotationId || "")) throw new Error("Initial dual-slot source/rotation identity is invalid.");
  if (typeof outputFile !== "string" || !outputFile) throw new Error("Initial dual-slot rotation binding output is required.");
  const baseline = deriveLegacyRotationBaseline(taskDefinition);
  assertLegacyMatches(legacyBindings, baseline);
  const resources = {};
  const created = [];
  for (const [slot, name] of Object.entries(INITIAL_DUAL_SLOT_NAMES)) {
    const result = await describeOrCreate({ send, name });
    resources[slot] = exactArn(result.response, name);
    if (result.created) created.push(slot);
  }
  const existingMaterial = {};
  let secretValueWrites = 0;
  ensureStageBPrivateDirectory({ directory: path.dirname(path.resolve(outputFile)), repositoryRoot, create: true, normalize: true, label: "Replacement material journal directory" });
  const materialFile = materialFileFor(outputFile);
  const material = await recoverInitialPendingMaterial({ send, resources, sourceSha, rotationId, materialFile });
  const payloads = pendingPayloads({ rotationId, material });
  for (const payload of Object.values(payloads)) payload.sourceSha = sourceSha;
  const ensure = async (options) => {
    const result = await ensureValue({ send, ...options });
    secretValueWrites += result.wrote ? 1 : 0;
    return result.material;
  };
  existingMaterial.jwtPending = await ensure({ arn: resources.jwtPending, name: "JWT pending", expected: payloads.jwtPending, rotationId, allowPendingResume: true });
  existingMaterial.qrPrivatePending = await ensure({ arn: resources.qrPrivatePending, name: "QR private pending", expected: payloads.qrPrivatePending, rotationId, allowPendingResume: true });
  let qrPublicExpected = payloads.qrPublicPending;
  if (existingMaterial.qrPrivatePending.value) {
    let derivedPublic;
    try { derivedPublic = createPublicKey(existingMaterial.qrPrivatePending.value).export({ format: "pem", type: "spki" }); } catch { throw new Error("QR pending private material is malformed."); }
    qrPublicExpected = { ...payloads.qrPublicPending, keyVersion: sha256(derivedPublic).slice(0, 16), materialFingerprint: fingerprint(derivedPublic), value: derivedPublic };
  }
  existingMaterial.qrPublicPending = await ensure({ arn: resources.qrPublicPending, name: "QR public pending", expected: qrPublicExpected, rotationId, allowPendingResume: true });
  if (existingMaterial.qrPrivatePending.value && existingMaterial.qrPublicPending.value) {
    let derivedPublic;
    try { derivedPublic = createPublicKey(existingMaterial.qrPrivatePending.value).export({ format: "pem", type: "spki" }); } catch { throw new Error("QR pending private material is malformed."); }
    if (derivedPublic !== existingMaterial.qrPublicPending.value || existingMaterial.qrPrivatePending.keyVersion !== existingMaterial.qrPublicPending.keyVersion || existingMaterial.qrPublicPending.keyVersion !== sha256(derivedPublic).slice(0, 16)) {
      throw new Error("QR pending material does not form the reviewed key pair.");
    }
  }
  await ensure({ arn: resources.jwtPrevious, name: "JWT previous", expected: emptySlot("jwt_secrets", "empty", sourceSha), rotationId });
  await ensure({ arn: resources.qrPublicPrevious, name: "QR public previous", expected: emptySlot("qr_signing_keys", "empty", sourceSha), rotationId });
  await ensure({ arn: resources.qrCurrentVersion, name: "QR current key version", expected: versionSlot(baseline.qrCurrentVersion, "current", sourceSha), rotationId });
  await ensure({ arn: resources.qrPreviousVersion, name: "QR previous key version", expected: versionSlot("", "previous-empty", sourceSha), rotationId });
  const bindings = {
    schemaVersion: INITIAL_DUAL_SLOT_SCHEMA_VERSION,
    sourceSha,
    rotationId,
    legacy: baseline,
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
    ensureStageBPrivateFile({ filePath: outputFile, repositoryRoot, label: "Initial dual-slot rotation bindings" });
    if (readFileSync(outputFile, "utf8") !== output) throw new Error("Existing initial dual-slot binding manifest does not match the verified topology.");
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
  ensureStageBPrivateFile({ filePath: outputFile, repositoryRoot, label: "Stale rotation supersession evidence" });
  const bytes = readFileSync(outputFile);
  let evidence;
  try { evidence = JSON.parse(bytes.toString("utf8")); } catch { throw new Error("Existing stale rotation supersession evidence is malformed."); }
  const expectedResources = Object.fromEntries(Object.entries(resources).map(([slot, arn]) => [slot, { arn, versionId: transitionVersionId(slot), stages: ["AWSCURRENT"] }]));
  const expectedIdentity = productionSupersessionEvidenceIdentity({ sourceSha, staleSourceSha, rotationId, staleRotationId, resources: expectedResources });
  const expectedKeys = ["schemaVersion", "transition", "sourceSha", "staleSourceSha", "rotationId", "staleRotationId", "generatedAt", "resources", "evidenceIdentitySha256"];
  if (Object.keys(evidence).sort().join(",") !== expectedKeys.sort().join(",") || evidence.schemaVersion !== 1 || evidence.transition !== "SUPERSEDE_STALE_PENDING" || evidence.sourceSha !== sourceSha || evidence.staleSourceSha !== staleSourceSha || evidence.rotationId !== rotationId || evidence.staleRotationId !== staleRotationId || JSON.stringify(evidence.resources) !== JSON.stringify(expectedResources) || evidence.evidenceIdentitySha256 !== expectedIdentity || !Number.isFinite(Date.parse(evidence.generatedAt)) || bytes.toString("utf8") !== `${JSON.stringify(evidence, null, 2)}\n`) throw new Error("Existing stale rotation supersession evidence does not match the authenticated transition.");
  return { evidence, sha256: sha256(bytes) };
}

export async function supersedeStalePendingRotation({ send, sourceSha, staleSourceSha, rotationId, staleRotationId, outputFile, repositoryRoot = process.cwd() } = {}) {
  if (typeof send !== "function") throw new Error("Stale rotation supersession Secrets Manager sender is required.");
  if (!SHA40.test(sourceSha || "") || !SHA40.test(staleSourceSha || "") || !ROTATION_ID.test(rotationId || "") || !ROTATION_ID.test(staleRotationId || "")) throw new Error("Stale rotation supersession identity is invalid.");
  if (sourceSha === staleSourceSha || rotationId === staleRotationId) throw new Error("Stale and replacement rotation identities must be distinct.");
  const resources = {};
  const existing = {};
  const currentVersionIds = {};
  for (const [slot, name] of Object.entries(INITIAL_DUAL_SLOT_NAMES)) {
    const described = await send(new DescribeSecretCommand({ SecretId: name }));
    resources[slot] = exactArn(described, name);
    const stages = assertRotationVersionTopology(described, name);
    currentVersionIds[slot] = Object.entries(stages).find(([, labels]) => labels.includes("AWSCURRENT"))?.[0];
    existing[slot] = parseStoredValue(await send(new GetSecretValueCommand({ SecretId: resources[slot] })), name);
  }
  const replacementOrder = ["jwtPending", "qrPrivatePending", "qrPublicPending", "jwtPrevious", "qrPublicPrevious", "qrCurrentVersion", "qrPreviousVersion"];
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
      if ((pending && value.rotationId !== staleRotationId) || (!pending && value.rotationId !== undefined)) return "INVALID";
      if (pending && (!value.materialFingerprint || value.materialFingerprint !== fingerprint(value.value))) return "INVALID";
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
  const allNew = newSlots.length === replacementOrder.length;
  const expectedEvidenceResources = Object.fromEntries(Object.entries(resources).map(([slot, arn]) => [slot, { arn, versionId: transitionVersionId(slot), stages: ["AWSCURRENT"] }]));
  const existingEvidence = readExistingSupersessionEvidence({ outputFile, repositoryRoot, sourceSha, staleSourceSha, rotationId, staleRotationId, resources, transitionVersionId });
  if (existingEvidence && !allNew) throw new Error("Existing stale rotation supersession evidence conflicts with a non-converged secret topology.");
  const generated = allNew ? null : generatePendingMaterial();
  const materialFile = materialFileFor(outputFile);
  const journalMaterial = allNew ? null : readMaterialJournal(materialFile, sourceSha, rotationId);
  const material = allNew
    ? { jwt: existing.jwtPending.value, qrPrivate: existing.qrPrivatePending.value, qrPublic: existing.qrPublicPending.value, qrKeyVersion: existing.qrPrivatePending.keyVersion }
    : journalMaterial || writeMaterialJournal(materialFile, sourceSha, rotationId, generated);
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
    qrCurrentVersion: versionSlot(existing.qrCurrentVersion.value, "current", sourceSha),
    qrPreviousVersion: versionSlot("", "previous-empty", sourceSha),
  };
  for (const slot of Object.keys(replacement)) if (states[slot] === "NEW_AUTHENTICATED" && JSON.stringify(existing[slot]) !== JSON.stringify(replacement[slot])) throw new Error(`Replacement ${slot} evidence does not match the authenticated transition.`);
  const versionIds = {};
  for (const slot of replacementOrder) {
    if (states[slot] === "NEW_AUTHENTICATED") { versionIds[slot] = currentVersionIds[slot]; continue; }
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
    const readback = parseStoredValue(await send(new GetSecretValueCommand({ SecretId: resources[slot] })), name);
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
  };
  const evidence = { ...evidenceCore, evidenceIdentitySha256: productionSupersessionEvidenceIdentity(evidenceCore) };
  const bytes = Buffer.from(`${JSON.stringify(evidence, null, 2)}\n`);
  const persisted = existingEvidence || writeStageBPrivateFileAtomic({ filePath: outputFile, bytes, repositoryRoot, label: "Stale rotation supersession evidence" });
  if (lstatSync(materialFile, { throwIfNoEntry: false })) unlinkSync(materialFile);
  return { valid: true, transition: evidence.transition, idempotentReplay: allNew, writes: existingEvidence ? 0 : Object.keys(versionIds).filter((slot) => states[slot] !== "NEW_AUTHENTICATED").length, evidenceFile: existingEvidence ? path.resolve(outputFile) : persisted.path, evidenceSha256: persisted.sha256, sourceSha, staleSourceSha, rotationId, staleRotationId, resources, versionIds };
}

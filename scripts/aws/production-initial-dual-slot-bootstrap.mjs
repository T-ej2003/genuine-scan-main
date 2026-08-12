import { createHash, createPublicKey, generateKeyPairSync, randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import { lstatSync, readFileSync } from "node:fs";
import path from "node:path";
import { ensureStageBPrivateFile, writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";
import { rotationBindingsToTaskBindings } from "./production-cutover-runtime-bootstrap.mjs";

const requireBackend = createRequire(path.resolve("backend/package.json"));
const {
  CreateSecretCommand,
  DescribeSecretCommand,
  GetSecretValueCommand,
  PutSecretValueCommand,
  SecretsManagerClient,
} = requireBackend("@aws-sdk/client-secrets-manager");

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
const fingerprint = (value) => sha256(value).slice(0, 16);
const required = (value, label) => {
  if (typeof value !== "string" || !value.trim()) throw new Error(`${label} is required.`);
  return value.trim();
};
const notFound = (error) => /ResourceNotFoundException|not exist|can't find/i.test(String(error?.name || error?.message || error));

const legacySecret = (container, name) => container?.secrets?.find((secret) => secret.name === name)?.valueFrom;
const backendContainer = (taskDefinition) => {
  const container = (taskDefinition?.taskDefinition || taskDefinition)?.containerDefinitions?.find(({ name }) => name === "backend");
  if (!container) throw new Error("Live task definition does not contain the reviewed backend container.");
  return container;
};

export function deriveLegacyRotationBaseline(taskDefinition) {
  const container = backendContainer(taskDefinition);
  const environment = Object.fromEntries((container.environment || []).map(({ name, value }) => [name, value]));
  const baseline = {
    jwtCurrent: legacySecret(container, "JWT_SECRET"),
    qrPrivateCurrent: legacySecret(container, "QR_SIGN_PRIVATE_KEY"),
    qrPublicCurrent: legacySecret(container, "QR_SIGN_PUBLIC_KEY"),
    qrCurrentVersion: environment.QR_SIGN_ACTIVE_KEY_VERSION,
  };
  for (const [name, value] of Object.entries(baseline)) {
    if (name === "qrCurrentVersion") {
      if (!VERSION.test(String(value || ""))) throw new Error("Live QR active key version is invalid.");
    } else if (!SECRET_ARN.test(String(value || ""))) {
      throw new Error(`Live legacy ${name} binding is invalid.`);
    }
  }
  if (new Set([baseline.jwtCurrent, baseline.qrPrivateCurrent, baseline.qrPublicCurrent]).size !== 3) {
    throw new Error("Live legacy signing bindings must be distinct.");
  }
  return Object.freeze(baseline);
}

const emptySlot = (family, slot, sourceSha) => ({ value: "", family, slot, sourceSha, initialMigration: true });
const versionSlot = (value, slot, sourceSha) => ({ value, family: "qr_key_versions", slot, sourceSha, initialMigration: true });

function generatePendingMaterial() {
  const pair = generateKeyPairSync("ed25519", {
    privateKeyEncoding: { format: "pem", type: "pkcs8" },
    publicKeyEncoding: { format: "pem", type: "spki" },
  });
  const jwt = randomBytes(48).toString("base64url");
  const qrKeyVersion = sha256(pair.publicKey).slice(0, 16);
  return { jwt, qrPrivate: pair.privateKey, qrPublic: pair.publicKey, qrKeyVersion };
}

function pendingPayloads({ rotationId, material }) {
  return {
    jwtPending: { rotationId, family: "jwt_secrets", slot: "pending", materialFingerprint: fingerprint(material.jwt), value: material.jwt },
    qrPrivatePending: { rotationId, family: "qr_signing_keys", slot: "pending-private", keyVersion: material.qrKeyVersion, materialFingerprint: fingerprint(material.qrPrivate), value: material.qrPrivate },
    qrPublicPending: { rotationId, family: "qr_signing_keys", slot: "pending-public", keyVersion: material.qrKeyVersion, materialFingerprint: fingerprint(material.qrPublic), value: material.qrPublic },
  };
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
  const material = generatePendingMaterial();
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
    return { valid: true, bindings, bindingFile: path.resolve(outputFile), evidenceSha256: sha256(output), created, secretResourceCount: Object.keys(INITIAL_DUAL_SLOT_NAMES).length, secretValueWrites, pendingMaterialGenerated: true };
  }
  const evidence = writeStageBPrivateFileAtomic({ filePath: outputFile, bytes: Buffer.from(output), repositoryRoot, label: "Initial dual-slot rotation bindings" });
  return { valid: true, bindings, bindingFile: evidence.path, evidenceSha256: evidence.sha256, created, secretResourceCount: Object.keys(INITIAL_DUAL_SLOT_NAMES).length, secretValueWrites, pendingMaterialGenerated: true };
}

export function createInitialDualSlotSecretsManagerClient({ region = INITIAL_DUAL_SLOT_REGION } = {}) {
  return new SecretsManagerClient({ region });
}

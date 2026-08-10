import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign as cryptoSign, verify as cryptoVerify } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import jwt from "jsonwebtoken";
import {
  GetSecretValueCommand,
  PutSecretValueCommand,
  SecretsManagerClient,
} from "@aws-sdk/client-secrets-manager";

const PHASES = [
  "prepared", "overlap-deploy-required", "overlap-ready", "verified", "grace-wait",
  "retirement-started", "retirement-complete", "cleanup-deploy-required",
  "cleanup-runtime-verified", "cleaned",
];
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const fingerprint = (value) => sha256(value).slice(0, 16);
const safeId = (value) => /^[A-Za-z0-9._-]{8,128}$/.test(value);
const versionId = (value) => /^[A-Za-z0-9+=/:._-]{7,256}$/.test(value);
const fullSha = (value) => /^[a-f0-9]{40}$/.test(value);
const isoDate = (value) => {
  const time = new Date(String(value || "")).getTime();
  return Number.isFinite(time) ? time : null;
};
const required = (value, name) => {
  const normalized = String(value || "").trim();
  if (!normalized) throw new Error(`${name} is required`);
  return normalized;
};
const reference = (value) => {
  const normalized = required(value, "machine-verifiable reference");
  if (normalized.startsWith("deploy-log://") || normalized.includes("<") || normalized.includes(">")) {
    throw new Error("machine-verifiable reference is required");
  }
  return normalized;
};
const nowIso = (clock = Date.now) => new Date(clock()).toISOString();

const parseArgs = (argv) => {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (["--prepare", "--verify", "--cleanup", "--status", "--confirm-cleanup"].includes(arg)) {
      values.set(arg.slice(2), true);
    } else if (arg.startsWith("--")) {
      values.set(arg.slice(2), required(argv[++index], arg));
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }
  const modes = ["prepare", "verify", "cleanup", "status"].filter((mode) => values.has(mode));
  if (modes.length !== 1) throw new Error("exactly one of --prepare, --verify, --cleanup, or --status is required");
  return { mode: modes[0], values };
};

const loadConfig = (file) => {
  const config = JSON.parse(readFileSync(file, "utf8"));
  required(config.region, "config.region");
  required(config.expectedRoleArn, "config.expectedRoleArn");
  required(config.rotationId, "config.rotationId");
  required(config.sourceSha, "config.sourceSha");
  if (!safeId(config.rotationId)) throw new Error("config.rotationId is invalid");
  if (!fullSha(config.sourceSha)) throw new Error("config.sourceSha must be a full SHA-1");
  if (!Number.isSafeInteger(config.minimumGraceSeconds) || config.minimumGraceSeconds < 1) {
    throw new Error("config.minimumGraceSeconds must be a positive safe integer");
  }
  const ids = [
    config.jwt?.currentSecretId, config.jwt?.previousSecretId, config.jwt?.pendingSecretId,
    config.qr?.privateCurrentSecretId, config.qr?.privatePendingSecretId,
    config.qr?.publicCurrentSecretId, config.qr?.publicPreviousSecretId, config.qr?.publicPendingSecretId,
  ].map((value, index) => required(value, `config secret id ${index + 1}`));
  if (new Set(ids).size !== ids.length) throw new Error("rotation secret resources must be distinct");
  required(config.qr?.previousKeyVersion, "config.qr.previousKeyVersion");
  if (!fullSha(config.overlapDeploymentSha)) throw new Error("config.overlapDeploymentSha must be a full SHA");
  reference(config.verificationRef);
  return config;
};

const callerArn = () => execFileSync(
  "aws", ["sts", "get-caller-identity", "--query", "Arn", "--output", "text", "--no-cli-pager"],
  { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
).trim();

const assertIdentity = (config, resolveCaller = callerArn) => {
  const caller = resolveCaller();
  const role = required(config.expectedRoleArn, "config.expectedRoleArn").match(/^arn:aws:iam::([0-9]{12}):role\/(.+)$/);
  if (!role) throw new Error("config.expectedRoleArn must be an IAM role ARN");
  const expectedPrefix = `arn:aws:sts::${role[1]}:assumed-role/${role[2]}/`;
  if (!caller.startsWith(expectedPrefix)) throw new Error("rotation identity is not the configured release role");
  return caller;
};

const client = (config) => new SecretsManagerClient({ region: config.region });
const secretValue = async (sm, id) => {
  const result = await sm.send(new GetSecretValueCommand({ SecretId: id }));
  const value = result.SecretString ?? (result.SecretBinary ? Buffer.from(result.SecretBinary).toString("utf8") : "");
  return { value: String(value), versionId: String(result.VersionId || "") };
};
const storedMaterial = (result) => {
  if (!result.value) return { value: "", metadata: {} };
  try {
    const parsed = JSON.parse(result.value);
    if (parsed && typeof parsed === "object" && typeof parsed.value === "string") return { value: parsed.value, metadata: parsed };
  } catch {
    // Legacy raw values are accepted only as the pre-rotation source.
  }
  return { value: result.value, metadata: { legacy: true } };
};
const putMaterial = async (sm, id, material, metadata, token) => {
  const payload = JSON.stringify({ ...metadata, value: material });
  return sm.send(new PutSecretValueCommand({
    SecretId: id,
    SecretString: payload,
    ClientRequestToken: sha256(token).slice(0, 64),
  }));
};

const readState = (file) => (existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : null);
const writeState = (file, state) => {
  const temporary = `${file}.tmp-${process.pid}`;
  writeFileSync(temporary, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
  chmodSync(temporary, 0o600);
  renameSync(temporary, file);
  chmodSync(file, 0o600);
};
const statePath = (values) => path.resolve(required(values.get("state-file"), "--state-file"));
const fixturePath = (values) => path.resolve(required(values.get("fixture-file"), "--fixture-file"));
const persist = (context, state) => (context.persistState || writeState)(statePath(context.values), state);
const clockOf = (context) => context.clock || Date.now;

const slots = async (sm, config) => {
  const records = await Promise.all([
    ["jwtCurrent", config.jwt.currentSecretId], ["jwtPrevious", config.jwt.previousSecretId], ["jwtPending", config.jwt.pendingSecretId],
    ["qrPrivateCurrent", config.qr.privateCurrentSecretId], ["qrPrivatePending", config.qr.privatePendingSecretId],
    ["qrPublicCurrent", config.qr.publicCurrentSecretId], ["qrPublicPrevious", config.qr.publicPreviousSecretId], ["qrPublicPending", config.qr.publicPendingSecretId],
  ].map(async ([name, id]) => [name, { id, raw: await secretValue(sm, id) }]));
  return Object.fromEntries(records.map(([name, record]) => [name, { ...record, material: storedMaterial(record.raw) }]));
};

const isRetired = (material) => !material.value && material.metadata?.slot?.endsWith("-retired") && Boolean(isoDate(material.metadata.retiredAt));
const assertPendingOwnership = (name, material, rotationId) => {
  if (isRetired(material)) return;
  if (!material.value) {
    if (Object.keys(material.metadata || {}).length) throw new Error(`${name} pending slot has non-retired metadata`);
    return;
  }
  if (material.metadata.rotationId !== rotationId) throw new Error(`${name} pending slot is owned by another rotation`);
  if (!String(material.metadata.slot || "").startsWith("pending")) throw new Error(`${name} pending slot metadata is invalid`);
};

const assertJwtPreviousSlotAvailable = (material) => {
  if (material.value || (!isRetired(material) && Object.keys(material.metadata || {}).length)) {
    throw new Error("JWT_PREVIOUS_SLOT_NOT_RETIRED");
  }
};

const keyPair = () => generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});
const qrVersion = (publicKey) => sha256(publicKey).slice(0, 16);

const makePreviousQrFixture = (privatePem, publicPem, oldVersion, file) => {
  const payload = { qr_id: "rotation-synthetic", batch_id: null, licensee_id: "rotation", iat: 1_700_000_000, nonce: sha256(`${oldVersion}:fixture`).slice(0, 24), kid: oldVersion };
  const bytes = Buffer.from(JSON.stringify(payload));
  const signature = cryptoSign(null, createHash("sha256").update(bytes).digest(), createPrivateKey(privatePem));
  if (!cryptoVerify(null, createHash("sha256").update(bytes).digest(), createPublicKey(publicPem), signature)) throw new Error("failed to create previous QR fixture");
  writeFileSync(file, JSON.stringify({ payload, signature: signature.toString("base64url"), token: `${bytes.toString("base64url")}.${signature.toString("base64url")}` }, null, 2), { mode: 0o600 });
  chmodSync(file, 0o600);
};

const validateRuntimeProof = ({ file, proof: persistedProof, config, phase, expectedDeploymentSha, clock }) => {
  const proof = persistedProof || JSON.parse(readFileSync(path.resolve(required(file, `--${phase}-runtime-file`)), "utf8"));
  if (proof.rotationId !== config.rotationId || proof.phase !== phase) throw new Error(`${phase} runtime proof does not match this rotation`);
  if (!fullSha(expectedDeploymentSha) || proof.deploymentSha !== expectedDeploymentSha) throw new Error(`${phase} runtime proof deployment SHA is invalid`);
  if (!reference(proof.runtimeInvocationRef)) throw new Error(`${phase} runtime proof reference is invalid`);
  const observedAt = isoDate(proof.observedAt);
  if (observedAt === null || observedAt > clock()) throw new Error(`${phase} runtime proof timestamp is invalid`);
  if (proof.serviceHealthy !== true || proof.healthHttpStatus !== 200 || proof.expectedReleaseGitSha !== config.sourceSha || proof.healthReleaseGitSha !== config.sourceSha) throw new Error(`${phase} runtime proof health is invalid`);
  const healthObservedAt = isoDate(proof.healthObservedAt);
  if (healthObservedAt === null || healthObservedAt > observedAt || observedAt - healthObservedAt > 300_000) throw new Error(`${phase} runtime proof health timestamp is invalid`);
  const requiredChecks = phase === "overlap"
    ? ["jwtCurrentRuntimeVerify", "jwtPreviousRuntimeVerify", "jwtInvalidRuntimeRejected", "qrCurrentRuntimeVerify", "qrPreviousRuntimeVerify", "qrTamperMatchingKeyTest", "qrUnknownKeyRejected", "serviceHealthy"]
    : ["jwtCurrentRuntimeVerify", "jwtPreviousRuntimeRejected", "qrCurrentRuntimeVerify", "qrPreviousRuntimeRejected", "qrUnknownKeyRejected", "serviceHealthy"];
  for (const check of requiredChecks) if (proof[check] !== true) throw new Error(`${phase} runtime proof is missing ${check}`);
  return { ...proof, observedAt: new Date(observedAt).toISOString() };
};

const stateForPending = ({ config, identity, oldJwt, oldQrPublic, oldQrVersion, newJwt, newQrPublic, newQrVersion, pending }) => ({
  stateVersion: 3,
  rotationId: config.rotationId,
  sourceSha: config.sourceSha,
  operator: identity,
  phase: "prepared",
  preparedAt: nowIso(),
  jwt: { oldFingerprint: fingerprint(oldJwt), newFingerprint: fingerprint(newJwt) },
  qr: { oldPublicFingerprint: fingerprint(oldQrPublic), newPublicFingerprint: fingerprint(newQrPublic), oldKeyVersion: oldQrVersion, newKeyVersion: newQrVersion },
  pending,
});

const assertState = (state, config) => {
  if (!state || state.rotationId !== config.rotationId) throw new Error("state file belongs to another rotation");
  if (!PHASES.includes(state.phase)) throw new Error(`unsupported rotation phase: ${state.phase}`);
  if (state.sourceSha !== config.sourceSha) throw new Error("state source SHA does not match config");
};
const assertStateSlots = (state, current) => {
  if (state.jwt?.newFingerprint !== fingerprint(current.jwtCurrent.material.value)) throw new Error("current JWT does not match rotation state");
  if (state.qr?.newPublicFingerprint !== fingerprint(current.qrPublicCurrent.material.value)) throw new Error("current QR public key does not match rotation state");
  for (const [name, record, expected] of [["JWT pending", current.jwtPending, state.jwt?.newFingerprint], ["QR private pending", current.qrPrivatePending, null], ["QR public pending", current.qrPublicPending, state.qr?.newPublicFingerprint]]) {
    if (record.material.value && record.material.metadata.rotationId !== state.rotationId) throw new Error(`${name} does not belong to rotation state`);
    if (record.material.value && expected && fingerprint(record.material.value) !== expected) throw new Error(`${name} does not match rotation state`);
    if (record.material.value && record.material.metadata.materialFingerprint !== fingerprint(record.material.value)) throw new Error(`${name} fingerprint metadata is inconsistent`);
  }
  if (current.jwtPrevious.material.value && fingerprint(current.jwtPrevious.material.value) !== state.jwt?.oldFingerprint) throw new Error("previous JWT does not match rotation state");
  if (current.qrPublicPrevious.material.value && fingerprint(current.qrPublicPrevious.material.value) !== state.qr?.oldPublicFingerprint) throw new Error("previous QR public key does not match rotation state");
};

const assertPrepareLineage = (state, current) => {
  const currentFingerprint = fingerprint(current.jwtCurrent.material.value);
  const previousFingerprint = current.jwtPrevious.material.value ? fingerprint(current.jwtPrevious.material.value) : null;
  if (state.phase === "prepared") {
    const oldCurrent = currentFingerprint === state.jwt?.oldFingerprint;
    const promotedCurrent = currentFingerprint === state.jwt?.newFingerprint;
    if (!oldCurrent && !promotedCurrent) throw new Error("current JWT does not match prepared rotation lineage");
    if (previousFingerprint && previousFingerprint !== state.jwt?.oldFingerprint) throw new Error("previous JWT does not match prepared rotation lineage");
    if (promotedCurrent && previousFingerprint !== state.jwt?.oldFingerprint) throw new Error("prepared promotion is incomplete or foreign");
    return;
  }
  if (currentFingerprint !== state.jwt?.newFingerprint) throw new Error("current JWT does not match rotation state");
  if (previousFingerprint && previousFingerprint !== state.jwt?.oldFingerprint) throw new Error("previous JWT does not match rotation state");
};

const prepare = async (context) => {
  const { config, sm, values, identity } = context;
  const stateFile = statePath(values);
  const fixtureFile = fixturePath(values);
  let state = readState(stateFile);
  if (state) assertState(state, config);
  let current = await slots(sm, config);
  for (const [name, record] of [["jwt", current.jwtPending], ["QR private", current.qrPrivatePending], ["QR public", current.qrPublicPending]]) assertPendingOwnership(name, record.material, config.rotationId);
  if (state) assertPrepareLineage(state, current);

  if (!state) {
    assertJwtPreviousSlotAvailable(current.jwtPrevious.material);
    const oldJwt = current.jwtCurrent.material.value;
    const oldQrPublic = current.qrPublicPrevious.material.value || current.qrPublicCurrent.material.value;
    if (!oldJwt || !oldQrPublic || !current.qrPrivateCurrent.material.value) throw new Error("current rotation material is incomplete");
    const oldQrVersion = current.qrPublicPrevious.material.metadata.keyVersion || current.qrPublicCurrent.material.metadata.keyVersion || required(config.qr.previousKeyVersion, "config.qr.previousKeyVersion");
    let newJwt = current.jwtPending.material.value;
    let newPrivate = current.qrPrivatePending.material.value;
    let newPublic = current.qrPublicPending.material.value;
    if (newPublic && !newPrivate) throw new Error("QR public pending material exists without its private pair");
    if (!newPrivate) {
      const pair = keyPair();
      newPrivate = pair.privateKey;
      newPublic = pair.publicKey;
    } else {
      newPublic = createPublicKey(newPrivate).export({ format: "pem", type: "spki" });
      if (current.qrPublicPending.material.value && fingerprint(current.qrPublicPending.material.value) !== fingerprint(newPublic)) throw new Error("QR pending public key does not match pending private key");
    }
    if (!newJwt) newJwt = randomBytes(48).toString("base64url");
    const newQrVersion = qrVersion(newPublic);
    if (oldQrVersion === newQrVersion) throw new Error("QR key versions are not distinct");
    const pendingMetadata = {
      jwt: { rotationId: config.rotationId, family: "jwt_secrets", slot: "pending", materialFingerprint: fingerprint(newJwt) },
      qrPrivate: { rotationId: config.rotationId, family: "qr_signing_keys", slot: "pending-private", keyVersion: newQrVersion, materialFingerprint: fingerprint(newPrivate) },
      qrPublic: { rotationId: config.rotationId, family: "qr_signing_keys", slot: "pending-public", keyVersion: newQrVersion, materialFingerprint: fingerprint(newPublic) },
    };
    if (!current.jwtPending.material.value) await putMaterial(sm, config.jwt.pendingSecretId, newJwt, pendingMetadata.jwt, `${config.rotationId}:jwt:pending`);
    if (!current.qrPrivatePending.material.value) await putMaterial(sm, config.qr.privatePendingSecretId, newPrivate, pendingMetadata.qrPrivate, `${config.rotationId}:qr:private-pending`);
    if (!current.qrPublicPending.material.value) await putMaterial(sm, config.qr.publicPendingSecretId, newPublic, pendingMetadata.qrPublic, `${config.rotationId}:qr:public-pending`);
    current = await slots(sm, config);
    for (const [name, record, expected] of [["JWT", current.jwtPending, newJwt], ["QR private", current.qrPrivatePending, newPrivate], ["QR public", current.qrPublicPending, newPublic]]) {
      if (fingerprint(record.material.value) !== fingerprint(expected) || record.material.metadata.rotationId !== config.rotationId) throw new Error(`${name} pending material could not be resumed safely`);
    }
    state = stateForPending({
      config, identity, oldJwt, oldQrPublic, oldQrVersion, newJwt, newQrPublic: newPublic, newQrVersion,
      pending: {
        jwtVersionId: current.jwtPending.raw.versionId,
        qrPrivateVersionId: current.qrPrivatePending.raw.versionId,
        qrPublicVersionId: current.qrPublicPending.raw.versionId,
      },
    });
    const fixture = {
      payload: null,
      signature: null,
      token: null,
      jwtCurrentToken: jwt.sign({ rotationId: config.rotationId, slot: "current" }, newJwt, { algorithm: "HS256", noTimestamp: true }),
      jwtPreviousToken: jwt.sign({ rotationId: config.rotationId, slot: "previous" }, oldJwt, { algorithm: "HS256", noTimestamp: true }),
    };
    makePreviousQrFixture(current.qrPrivateCurrent.material.value, oldQrPublic, oldQrVersion, fixtureFile);
    const qrFixture = JSON.parse(readFileSync(fixtureFile, "utf8"));
    writeFileSync(fixtureFile, JSON.stringify({ ...qrFixture, jwtCurrentToken: fixture.jwtCurrentToken, jwtPreviousToken: fixture.jwtPreviousToken }, null, 2), { mode: 0o600 });
    chmodSync(fixtureFile, 0o600);
    persist(context, state);
  }

  assertState(state, config);
  current = await slots(sm, config);
  if (state.phase === "prepared") assertPrepareLineage(state, current);
  const pendingJwt = current.jwtPending.material;
  const pendingPrivate = current.qrPrivatePending.material;
  const pendingPublic = current.qrPublicPending.material;
  if (fingerprint(pendingJwt.value) !== state.jwt.newFingerprint || fingerprint(pendingPublic.value) !== state.qr.newPublicFingerprint || !pendingPrivate.value || pendingJwt.metadata.materialFingerprint !== fingerprint(pendingJwt.value) || pendingPrivate.metadata.materialFingerprint !== fingerprint(pendingPrivate.value) || pendingPublic.metadata.materialFingerprint !== fingerprint(pendingPublic.value)) throw new Error("pending rotation material does not match state");
  if (state.phase === "prepared") {
    const currentJwt = current.jwtCurrent.material;
    const currentQrPublic = current.qrPublicCurrent.material;
    const previousJwt = current.jwtPrevious.material;
    const previousQrPublic = current.qrPublicPrevious.material;
    if (previousJwt.value && fingerprint(previousJwt.value) !== state.jwt.oldFingerprint) throw new Error("JWT previous slot is owned by another value");
    if (previousQrPublic.value && fingerprint(previousQrPublic.value) !== state.qr.oldPublicFingerprint) throw new Error("QR previous slot is owned by another value");
    if (!previousJwt.value || isRetired(previousJwt)) await putMaterial(sm, config.jwt.previousSecretId, currentJwt.value, { rotationId: config.rotationId, family: "jwt_secrets", slot: "previous", materialFingerprint: state.jwt.oldFingerprint }, `${config.rotationId}:jwt:previous`);
    if (!previousQrPublic.value || isRetired(previousQrPublic)) await putMaterial(sm, config.qr.publicPreviousSecretId, currentQrPublic.value, { rotationId: config.rotationId, family: "qr_signing_keys", slot: "previous", keyVersion: state.qr.oldKeyVersion, materialFingerprint: state.qr.oldPublicFingerprint }, `${config.rotationId}:qr:previous`);
    if (fingerprint(currentJwt.value) !== state.jwt.newFingerprint) await putMaterial(sm, config.jwt.currentSecretId, pendingJwt.value, { rotationId: config.rotationId, family: "jwt_secrets", slot: "current", materialFingerprint: state.jwt.newFingerprint }, `${config.rotationId}:jwt:current`);
    if (fingerprint(current.qrPrivateCurrent.material.value) !== fingerprint(pendingPrivate.value)) await putMaterial(sm, config.qr.privateCurrentSecretId, pendingPrivate.value, { rotationId: config.rotationId, family: "qr_signing_keys", slot: "current-private", keyVersion: state.qr.newKeyVersion, materialFingerprint: fingerprint(pendingPrivate.value) }, `${config.rotationId}:qr:current-private`);
    if (fingerprint(currentQrPublic.value) !== state.qr.newPublicFingerprint) await putMaterial(sm, config.qr.publicCurrentSecretId, pendingPublic.value, { rotationId: config.rotationId, family: "qr_signing_keys", slot: "current-public", keyVersion: state.qr.newKeyVersion, materialFingerprint: state.qr.newPublicFingerprint }, `${config.rotationId}:qr:current-public`);
    state.phase = "overlap-deploy-required";
    state.overlapPreparedAt = nowIso(clockOf(context));
    persist(context, state);
  }
  console.log(JSON.stringify({ mode: "prepare", phase: state.phase, rotationId: state.rotationId, operator: identity, fixtureFile, stateFile, deploymentRequired: state.phase === "overlap-deploy-required", prepareCrashResumable: true }));
};

const verify = async (context) => {
  const { config, values } = context;
  const file = required(values.get("runtime-verification-file"), "--runtime-verification-file");
  const stateFile = statePath(values);
  const state = readState(stateFile);
  assertState(state, config);
  if (!["overlap-deploy-required", "overlap-ready"].includes(state.phase)) throw new Error("rotation must require an overlap deployment before verification");
  const proof = validateRuntimeProof({ file, config, phase: "overlap", expectedDeploymentSha: config.overlapDeploymentSha, clock: clockOf(context) });
  const overlapReadyAt = proof.observedAt;
  const cleanupEligibleAt = new Date(isoDate(overlapReadyAt) + config.minimumGraceSeconds * 1000).toISOString();
  state.phase = "overlap-ready";
  state.overlapReadyAt = state.overlapReadyAt || overlapReadyAt;
  state.cleanupEligibleAt = state.cleanupEligibleAt || cleanupEligibleAt;
  state.overlapRuntime = { deploymentSha: proof.deploymentSha, runtimeInvocationRef: proof.runtimeInvocationRef, serviceHealthy: true };
  persist(context, state);
  state.phase = "verified";
  state.verifiedAt = nowIso(clockOf(context));
  state.verification = {
    runtimeInvocationRef: proof.runtimeInvocationRef,
    jwtCurrentRuntimeVerify: true,
    jwtPreviousRuntimeVerify: true,
    jwtInvalidRuntimeRejected: true,
    qrCurrentRuntimeVerify: true,
    qrPreviousRuntimeVerify: true,
    qrTamperMatchingKeyTest: true,
    qrUnknownKeyRejected: true,
    serviceHealthy: true,
  };
  persist(context, state);
  console.log(JSON.stringify({ mode: "verify", phase: state.phase, rotationId: state.rotationId, overlapReadyAt: state.overlapReadyAt, cleanupEligibleAt: state.cleanupEligibleAt, jwtPreviousRuntimeVerify: true, qrTamperMatchingKeyTest: true }));
};

const retirementPayload = (config, family, slot, retirementTimestamp) => ({
  rotationId: config.rotationId, family, slot: `${slot}-retired`, retiredAt: retirementTimestamp,
});
const retireSlot = async (sm, record, config, family, slot, retirementTimestamp) => {
  const expected = retirementPayload(config, family, slot, retirementTimestamp);
  if (isRetired(record.material)) {
    if (record.material.metadata.rotationId !== config.rotationId || record.material.metadata.slot !== expected.slot || record.material.metadata.retiredAt !== retirementTimestamp) throw new Error(`${slot} retirement metadata conflicts with this rotation`);
    return record.raw.versionId;
  }
  if (!record.material.value && Object.keys(record.material.metadata || {}).length) throw new Error(`${slot} contains non-retired metadata`);
  const result = await putMaterial(sm, record.id, "", expected, `${config.rotationId}:${family}:${slot}:retired`);
  return String(result.VersionId || "");
};
const retirementRecords = (current) => [
  ["jwtPrevious", "jwt_secrets", "previous"], ["qrPublicPrevious", "qr_signing_keys", "previous"],
  ["jwtPending", "jwt_secrets", "pending"], ["qrPrivatePending", "qr_signing_keys", "pending-private"], ["qrPublicPending", "qr_signing_keys", "pending-public"],
];
const assertRetired = (current, config, timestamp) => {
  for (const [name, family, slot] of retirementRecords(current)) {
    const material = current[name].material;
    if (!isRetired(material) || material.metadata.rotationId !== config.rotationId || material.metadata.retiredAt !== timestamp || material.metadata.slot !== `${slot}-retired`) throw new Error(`${slot} was not retired by this rotation`);
  }
};

const evidenceFor = (state, config, cleanupRuntime, current) => ({
  evidenceVersion: 2, rotationId: config.rotationId, recordedAt: state.overlapReadyAt, sourceSha: config.sourceSha,
  approvedBy: required(config.approvedBy, "config.approvedBy"), approverRole: required(config.approverRole, "config.approverRole"),
  reason: required(config.reason, "config.reason"), ticket: required(config.ticket, "config.ticket"), environment: "production",
  cleanupWindowComplete: true, cleanupCompletedAt: state.cleanupCompletedAt, cleanupVerifiedBy: required(state.cleanupVerifiedBy, "state.cleanupVerifiedBy"), cleanupEvidenceRef: reference(state.cleanupEvidenceRef),
  overlapReadyAt: state.overlapReadyAt, verifiedAt: state.verifiedAt, cleanupEligibleAt: state.cleanupEligibleAt, retirementTimestamp: state.retirementTimestamp,
  cleanupDeploymentSha: state.cleanupDeploymentSha, cleanupDeploymentObservedAt: cleanupRuntime.observedAt,
  proofs: {
    previousJwtSlotRetired: true, previousQrPublicSlotRetired: true, jwtPendingRetired: true, qrPrivatePendingRetired: true, qrPublicPendingRetired: true,
    cleanupDeploymentAfterRetirement: new Date(cleanupRuntime.observedAt).getTime() > new Date(state.retirementTimestamp).getTime(),
    cleanupRuntimeVerified: true, jwtPreviousRuntimeRejected: true, qrPreviousRuntimeRejected: true,
    jwtCurrentRuntimeVerify: true, qrCurrentRuntimeVerify: true, qrUnknownKeyRejected: true, serviceHealthy: true,
  },
  linkedDeployShas: [required(config.overlapDeploymentSha, "config.overlapDeploymentSha"), state.cleanupDeploymentSha],
  verificationRefs: [reference(config.verificationRef), reference(state.cleanupEvidenceRef), state.verification.runtimeInvocationRef, cleanupRuntime.runtimeInvocationRef],
  families: [
    { name: "jwt_secrets", rotatedAt: state.overlapReadyAt, operator: required(state.cleanupVerifiedBy, "state.cleanupVerifiedBy"), method: "dual-slot", currentVersionId: current.jwtCurrent.raw.versionId, previousVersionId: current.jwtPrevious.raw.versionId, verificationRef: reference(config.verificationRef) },
    { name: "qr_signing_keys", rotatedAt: state.overlapReadyAt, operator: required(state.cleanupVerifiedBy, "state.cleanupVerifiedBy"), method: "dual-slot", currentVersionId: current.qrPublicCurrent.raw.versionId, previousVersionId: current.qrPublicPrevious.raw.versionId, currentKeyVersion: state.qr.newKeyVersion, previousKeyVersion: state.qr.oldKeyVersion, verificationRef: reference(config.verificationRef) },
  ],
});

const assertPersistedCleanupRuntime = (state, config, cleanupDeploymentSha, clock, cleanupEvidenceRef, identity) => {
  if (!state.cleanupRuntime || typeof state.cleanupRuntime !== "object") throw new Error("state.cleanupRuntime is required to resume cleanup");
  if (state.cleanupDeploymentSha !== cleanupDeploymentSha) throw new Error("cleanup deployment SHA does not match persisted runtime state");
  const retirementTimestamp = isoDate(required(state.retirementTimestamp, "state.retirementTimestamp"));
  if (retirementTimestamp === null || retirementTimestamp > clock()) throw new Error("state.retirementTimestamp is invalid");
  const cleanupRuntime = validateRuntimeProof({ proof: state.cleanupRuntime, config, phase: "cleanup", expectedDeploymentSha: state.cleanupDeploymentSha, clock });
  if (isoDate(cleanupRuntime.observedAt) <= retirementTimestamp) throw new Error("cleanup deployment must occur after retirement writes");
  const cleanupCompletedAt = isoDate(state.cleanupCompletedAt || cleanupRuntime.observedAt);
  if (cleanupCompletedAt === null || cleanupCompletedAt < isoDate(cleanupRuntime.observedAt) || cleanupCompletedAt > clock()) throw new Error("state.cleanupCompletedAt is invalid");
  reference(state.cleanupEvidenceRef || cleanupEvidenceRef);
  required(state.cleanupVerifiedBy || identity, "state.cleanupVerifiedBy");
  return cleanupRuntime;
};

const finalizeCleanup = async (context, state, cleanupRuntime) => {
  const { config, sm, values } = context;
  const alreadyCleaned = state.phase === "cleaned";
  const current = await slots(sm, config);
  assertStateSlots(state, current);
  assertRetired(current, config, state.retirementTimestamp);
  if (!alreadyCleaned) {
    state.phase = "cleaned";
    persist(context, state);
  }
  const evidence = evidenceFor(state, config, cleanupRuntime, current);
  if (values.get("evidence-out")) writeState(path.resolve(values.get("evidence-out")), evidence);
  console.log(JSON.stringify({ mode: "cleanup", phase: state.phase, rotationId: config.rotationId, cleanupDeploymentAfterRetirement: true, cleanupRuntimeVerified: true, ...(alreadyCleaned ? { idempotent: true } : {}), evidenceFile: values.get("evidence-out") || null }));
};

const cleanup = async (context) => {
  const { config, sm, values, identity } = context;
  if (!values.has("confirm-cleanup")) throw new Error("--confirm-cleanup is required for cleanup");
  const stateFile = statePath(values);
  const state = readState(stateFile);
  assertState(state, config);
  const cleanupDeploymentSha = required(values.get("cleanup-deployment-sha"), "--cleanup-deployment-sha");
  if (!fullSha(cleanupDeploymentSha)) throw new Error("--cleanup-deployment-sha must be a full SHA");
  const cleanupEvidenceRef = ["cleanup-runtime-verified", "cleaned"].includes(state.phase)
    ? (values.get("cleanup-evidence-ref") ? reference(values.get("cleanup-evidence-ref")) : null)
    : reference(values.get("cleanup-evidence-ref"));
  const clock = clockOf(context);
  if (["verified", "grace-wait"].includes(state.phase)) {
    const eligibleAt = isoDate(state.cleanupEligibleAt);
    const verifiedAt = isoDate(state.verifiedAt);
    const overlapReadyAt = isoDate(state.overlapReadyAt);
    if (eligibleAt === null || verifiedAt === null || overlapReadyAt === null || verifiedAt < overlapReadyAt) throw new Error("cleanup timing state is invalid");
    if (clock() < eligibleAt) throw new Error("cleanup grace window has not expired");
    state.phase = "grace-wait";
    state.retirementTimestamp = state.retirementTimestamp || nowIso(clock);
    persist(context, state);
    state.phase = "retirement-started";
    persist(context, state);
  }
  if (["retirement-started", "retirement-complete"].includes(state.phase)) {
    const retirementTimestamp = required(state.retirementTimestamp, "state.retirementTimestamp");
    if (isoDate(retirementTimestamp) === null || isoDate(retirementTimestamp) > clock()) throw new Error("state.retirementTimestamp is invalid");
    const current = await slots(sm, config);
    for (const [name, family, slot] of retirementRecords(current)) await retireSlot(sm, current[name], config, family, slot, retirementTimestamp);
    const retired = await slots(sm, config);
    assertRetired(retired, config, retirementTimestamp);
    state.phase = "retirement-complete";
    persist(context, state);
    state.phase = "cleanup-deploy-required";
    state.cleanupDeploymentSha = cleanupDeploymentSha;
    persist(context, state);
  }
  if (state.phase !== "cleanup-deploy-required" && state.phase !== "cleanup-runtime-verified" && state.phase !== "cleaned") throw new Error("cleanup state transition is invalid");
  if (state.phase === "cleanup-deploy-required") {
    if (state.cleanupDeploymentSha !== cleanupDeploymentSha) throw new Error("cleanup deployment SHA does not match retirement state");
    if (!values.get("cleanup-runtime-file")) {
      console.log(JSON.stringify({ mode: "cleanup", phase: state.phase, rotationId: config.rotationId, deploymentRequired: true }));
      return;
    }
    if (!cleanupEvidenceRef) throw new Error("--cleanup-evidence-ref is required when finalizing cleanup");
    const runtimeFile = required(values.get("cleanup-runtime-file"), "--cleanup-runtime-file");
    const proof = validateRuntimeProof({ file: runtimeFile, config, phase: "cleanup", expectedDeploymentSha: cleanupDeploymentSha, clock });
    if (isoDate(proof.observedAt) <= isoDate(state.retirementTimestamp)) throw new Error("cleanup deployment must occur after retirement writes");
    state.cleanupRuntime = proof;
    state.cleanupEvidenceRef = cleanupEvidenceRef;
    state.cleanupVerifiedBy = identity;
    state.cleanupCompletedAt = state.cleanupCompletedAt || nowIso(clock);
    state.phase = "cleanup-runtime-verified";
    persist(context, state);
    await finalizeCleanup(context, state, proof);
    return;
  }
  if (state.phase === "cleanup-runtime-verified") {
    if (cleanupEvidenceRef && state.cleanupEvidenceRef && cleanupEvidenceRef !== state.cleanupEvidenceRef) throw new Error("cleanup evidence reference does not match persisted runtime state");
    const proof = assertPersistedCleanupRuntime(state, config, cleanupDeploymentSha, clock, cleanupEvidenceRef, identity);
    const hydrated = !state.cleanupCompletedAt || !state.cleanupEvidenceRef || !state.cleanupVerifiedBy;
    if (!state.cleanupCompletedAt) state.cleanupCompletedAt = proof.observedAt;
    if (!state.cleanupEvidenceRef) state.cleanupEvidenceRef = cleanupEvidenceRef;
    if (!state.cleanupVerifiedBy) state.cleanupVerifiedBy = identity;
    if (hydrated) persist(context, state);
    await finalizeCleanup(context, state, proof);
    return;
  }
  if (state.phase === "cleaned") {
    if (cleanupEvidenceRef && state.cleanupEvidenceRef && cleanupEvidenceRef !== state.cleanupEvidenceRef) throw new Error("cleanup evidence reference does not match persisted runtime state");
    const proof = assertPersistedCleanupRuntime(state, config, cleanupDeploymentSha, clock, cleanupEvidenceRef, identity);
    const hydrated = !state.cleanupCompletedAt || !state.cleanupEvidenceRef || !state.cleanupVerifiedBy;
    if (!state.cleanupCompletedAt) state.cleanupCompletedAt = proof.observedAt;
    if (!state.cleanupEvidenceRef) state.cleanupEvidenceRef = cleanupEvidenceRef;
    if (!state.cleanupVerifiedBy) state.cleanupVerifiedBy = identity;
    if (hydrated) persist(context, state);
    await finalizeCleanup(context, state, proof);
  }
};

const status = async ({ config, sm, values, identity }) => {
  const current = await slots(sm, config);
  const state = readState(statePath(values));
  if (state) {
    assertState(state, config);
    if (state.phase === "prepared") assertPrepareLineage(state, current);
    if (["overlap-deploy-required", "overlap-ready", "verified", "grace-wait", "retirement-started", "retirement-complete", "cleanup-deploy-required", "cleanup-runtime-verified", "cleaned"].includes(state.phase)) assertStateSlots(state, current);
  }
  const records = Object.fromEntries(Object.entries(current).map(([name, record]) => [name, {
    id: record.id, versionId: record.raw.versionId, populated: Boolean(record.material.value),
    rotationId: record.material.metadata.rotationId || null, slot: record.material.metadata.slot || "legacy",
  }]));
  console.log(JSON.stringify({ mode: "status", operator: identity, phase: state?.phase || null, records }));
};

const main = async () => {
  const { mode, values } = parseArgs(process.argv.slice(2));
  const config = loadConfig(path.resolve(required(values.get("config"), "--config")));
  const identity = assertIdentity(config);
  const sm = client(config);
  const context = { config, sm, values, identity };
  if (mode === "prepare") return prepare(context);
  if (mode === "verify") return verify(context);
  if (mode === "cleanup") return cleanup(context);
  return status(context);
};

export { assertIdentity, cleanup, prepare, status, verify, validateRuntimeProof, writeState };

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(`Rotation coordinator failed: ${String(error?.message || error)}`);
    process.exitCode = 1;
  });
}

import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign as cryptoSign, verify as cryptoVerify } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import jwt from "jsonwebtoken";
import {
  GetSecretValueCommand,
  PutSecretValueCommand,
  SecretsManagerClient,
} from "@aws-sdk/client-secrets-manager";

const required = (value, name) => {
  const normalized = String(value || "").trim();
  if (!normalized) throw new Error(`${name} is required`);
  return normalized;
};
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const fingerprint = (value) => sha256(value).slice(0, 16);
const isoNow = () => new Date().toISOString();
const safeId = (value) => /^[A-Za-z0-9._-]{8,128}$/.test(value);
const versionId = (value) => /^[A-Za-z0-9+=/:._-]{7,256}$/.test(value);
const fullSha = (value) => /^[a-f0-9]{40}$/.test(value);
const reference = (value) => {
  const normalized = String(value || "").trim();
  if (!normalized || normalized.startsWith("deploy-log://") || normalized.includes("<") || normalized.includes(">")) {
    throw new Error("machine-verifiable reference is required");
  }
  return normalized;
};

const parseArgs = (argv) => {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--prepare" || arg === "--verify" || arg === "--cleanup" || arg === "--status" || arg === "--confirm-cleanup") {
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
  const ids = [
    config.jwt?.currentSecretId, config.jwt?.previousSecretId, config.jwt?.pendingSecretId,
    config.qr?.privateCurrentSecretId, config.qr?.privatePendingSecretId,
    config.qr?.publicCurrentSecretId, config.qr?.publicPreviousSecretId, config.qr?.publicPendingSecretId,
  ].map((value, index) => required(value, `config secret id ${index + 1}`));
  if (new Set(ids).size !== ids.length) throw new Error("rotation secret resources must be distinct");
  required(config.qr?.previousKeyVersion, "config.qr.previousKeyVersion");
  return config;
};

const callerArn = () => {
  const raw = execFileSync("aws", ["sts", "get-caller-identity", "--query", "Arn", "--output", "text", "--no-cli-pager"], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  return raw;
};

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
    // Legacy raw secret values are accepted only as the pre-rotation source.
  }
  return { value: result.value, metadata: { legacy: true } };
};
const putMaterial = async (sm, id, material, metadata, token) => {
  const payload = JSON.stringify({ ...metadata, value: material });
  return sm.send(new PutSecretValueCommand({ SecretId: id, SecretString: payload, ClientRequestToken: sha256(token).slice(0, 64) }));
};
const emptyPrevious = async (sm, id, config, family) => putMaterial(sm, id, "", {
  rotationId: config.rotationId, family, slot: "previous-retired", retiredAt: isoNow(),
}, `${config.rotationId}:${family}:previous-retired`);

const keyPair = () => generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});
const qrVersion = (publicKey) => sha256(publicKey).slice(0, 16);
const readState = (file) => (existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : null);
const writeState = (file, state) => {
  writeFileSync(file, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
  chmodSync(file, 0o600);
};
const statePath = (values) => path.resolve(required(values.get("state-file"), "--state-file"));
const fixturePath = (values) => path.resolve(required(values.get("fixture-file"), "--fixture-file"));

const makePreviousQrFixture = (privatePem, publicPem, oldVersion, file) => {
  const payload = { qr_id: "rotation-synthetic", batch_id: null, licensee_id: "rotation", iat: Math.floor(Date.now() / 1000), nonce: sha256(`${oldVersion}:fixture`).slice(0, 24), kid: oldVersion };
  const bytes = Buffer.from(JSON.stringify(payload));
  const signature = cryptoSign(null, createHash("sha256").update(bytes).digest(), createPrivateKey(privatePem));
  if (!cryptoVerify(null, createHash("sha256").update(bytes).digest(), createPublicKey(publicPem), signature)) throw new Error("failed to create previous QR fixture");
  writeFileSync(file, JSON.stringify({ payload, signature: signature.toString("base64url") }, null, 2), { mode: 0o600 });
  chmodSync(file, 0o600);
};

const verifyPreviousQrFixture = (fixture, publicPem, expectedVersion) => {
  const parsed = JSON.parse(readFileSync(fixture, "utf8"));
  if (parsed?.payload?.kid !== expectedVersion || typeof parsed.signature !== "string") throw new Error("previous QR fixture is malformed");
  const bytes = Buffer.from(JSON.stringify(parsed.payload));
  return cryptoVerify(null, createHash("sha256").update(bytes).digest(), createPublicKey(publicPem), Buffer.from(parsed.signature, "base64url"));
};

const ensureNoUnexpectedPending = (slots, config) => {
  for (const [name, slot] of Object.entries(slots)) {
    if (slot.value && (!slot.metadata || slot.metadata.rotationId !== config.rotationId)) {
      throw new Error(`${name} pending slot is owned by another rotation`);
    }
  }
};

const prepare = async ({ config, sm, values, identity }) => {
  const stateFile = statePath(values);
  const fixtureFile = fixturePath(values);
  const priorState = readState(stateFile);
  if (priorState && priorState.rotationId !== config.rotationId) throw new Error("state file belongs to another rotation");

  const ids = config;
  const [jwtCurrentRaw, jwtPreviousRaw, jwtPendingRaw, qrPrivateCurrentRaw, qrPrivatePendingRaw, qrPublicCurrentRaw, qrPublicPreviousRaw, qrPublicPendingRaw] = await Promise.all([
    secretValue(sm, ids.jwt.currentSecretId), secretValue(sm, ids.jwt.previousSecretId), secretValue(sm, ids.jwt.pendingSecretId),
    secretValue(sm, ids.qr.privateCurrentSecretId), secretValue(sm, ids.qr.privatePendingSecretId),
    secretValue(sm, ids.qr.publicCurrentSecretId), secretValue(sm, ids.qr.publicPreviousSecretId), secretValue(sm, ids.qr.publicPendingSecretId),
  ]);
  const slots = {
    jwtPending: storedMaterial(jwtPendingRaw), qrPrivatePending: storedMaterial(qrPrivatePendingRaw), qrPublicPending: storedMaterial(qrPublicPendingRaw),
  };
  if (!priorState) ensureNoUnexpectedPending(slots, config);

  let state = priorState;
  if (!state) {
    const oldJwt = storedMaterial(jwtCurrentRaw);
    const oldQrPrivate = storedMaterial(qrPrivateCurrentRaw);
    const oldQrPublic = storedMaterial(qrPublicCurrentRaw);
    if (!oldJwt.value || !oldQrPrivate.value || !oldQrPublic.value) throw new Error("current rotation material is incomplete");
    const pair = keyPair();
    const newQrVersion = qrVersion(pair.publicKey);
    const oldQrVersion = oldQrPublic.metadata.keyVersion || required(config.qr.previousKeyVersion, "config.qr.previousKeyVersion");
    if (!versionId(oldQrVersion) || !versionId(newQrVersion) || oldQrVersion === newQrVersion) throw new Error("QR key versions are invalid or not distinct");
    const newJwt = randomBytes(48).toString("base64url");
    await putMaterial(sm, ids.jwt.pendingSecretId, newJwt, { rotationId: config.rotationId, family: "jwt_secrets", slot: "pending" }, `${config.rotationId}:jwt:pending`);
    await putMaterial(sm, ids.qr.privatePendingSecretId, pair.privateKey, { rotationId: config.rotationId, family: "qr_signing_keys", slot: "pending-private", keyVersion: newQrVersion }, `${config.rotationId}:qr:private-pending`);
    await putMaterial(sm, ids.qr.publicPendingSecretId, pair.publicKey, { rotationId: config.rotationId, family: "qr_signing_keys", slot: "pending-public", keyVersion: newQrVersion }, `${config.rotationId}:qr:public-pending`);
    state = {
      evidenceVersion: 2, rotationId: config.rotationId, sourceSha: config.sourceSha, preparedAt: isoNow(), phase: "pending-ready", operator: identity,
      jwt: { oldFingerprint: fingerprint(oldJwt.value), newFingerprint: fingerprint(newJwt) },
      qr: { oldPublicFingerprint: fingerprint(oldQrPublic.value), newPublicFingerprint: fingerprint(pair.publicKey), oldKeyVersion: oldQrVersion, newKeyVersion: newQrVersion },
    };
    writeState(stateFile, state);
    makePreviousQrFixture(oldQrPrivate.value, oldQrPublic.value, oldQrVersion, fixtureFile);
  }

  const pendingJwt = storedMaterial(await secretValue(sm, ids.jwt.pendingSecretId));
  const pendingPrivate = storedMaterial(await secretValue(sm, ids.qr.privatePendingSecretId));
  const pendingPublic = storedMaterial(await secretValue(sm, ids.qr.publicPendingSecretId));
  if (fingerprint(pendingJwt.value) !== state.jwt.newFingerprint || fingerprint(pendingPublic.value) !== state.qr.newPublicFingerprint) throw new Error("pending rotation material does not match state");

  const currentJwt = storedMaterial(jwtCurrentRaw);
  const currentQrPublic = storedMaterial(qrPublicCurrentRaw);
  const previousJwt = storedMaterial(jwtPreviousRaw);
  const previousQrPublic = storedMaterial(qrPublicPreviousRaw);
  if (previousJwt.value && fingerprint(previousJwt.value) !== state.jwt.oldFingerprint) throw new Error("JWT previous slot is owned by another value");
  if (previousQrPublic.value && fingerprint(previousQrPublic.value) !== state.qr.oldPublicFingerprint) throw new Error("QR previous slot is owned by another value");
  if (!previousJwt.value) await putMaterial(sm, ids.jwt.previousSecretId, currentJwt.value, { rotationId: config.rotationId, family: "jwt_secrets", slot: "previous" }, `${config.rotationId}:jwt:previous`);
  if (!previousQrPublic.value) await putMaterial(sm, ids.qr.publicPreviousSecretId, currentQrPublic.value, { rotationId: config.rotationId, family: "qr_signing_keys", slot: "previous", keyVersion: state.qr.oldKeyVersion }, `${config.rotationId}:qr:previous-public`);
  if (fingerprint(currentJwt.value) !== state.jwt.newFingerprint) await putMaterial(sm, ids.jwt.currentSecretId, pendingJwt.value, { rotationId: config.rotationId, family: "jwt_secrets", slot: "current" }, `${config.rotationId}:jwt:current`);
  if (fingerprint(storedMaterial(qrPrivateCurrentRaw).value) !== fingerprint(pendingPrivate.value)) await putMaterial(sm, ids.qr.privateCurrentSecretId, pendingPrivate.value, { rotationId: config.rotationId, family: "qr_signing_keys", slot: "current-private", keyVersion: state.qr.newKeyVersion }, `${config.rotationId}:qr:current-private`);
  if (fingerprint(currentQrPublic.value) !== state.qr.newPublicFingerprint) await putMaterial(sm, ids.qr.publicCurrentSecretId, pendingPublic.value, { rotationId: config.rotationId, family: "qr_signing_keys", slot: "current-public", keyVersion: state.qr.newKeyVersion }, `${config.rotationId}:qr:current-public`);
  state.phase = "overlap-ready";
  state.overlapReadyAt = state.overlapReadyAt || isoNow();
  writeState(stateFile, state);
  console.log(JSON.stringify({ mode: "prepare", phase: state.phase, rotationId: state.rotationId, operator: identity, fixtureFile, stateFile, deploymentRequired: true }));
};

const verify = async ({ config, sm, values, identity }) => {
  const stateFile = statePath(values);
  const fixtureFile = fixturePath(values);
  const state = readState(stateFile);
  if (!state || state.phase !== "overlap-ready") throw new Error("rotation must be overlap-ready before verification");
  const [jwtCurrent, jwtPrevious, qrPrivateCurrent, qrPublicCurrent, qrPublicPrevious] = await Promise.all([
    secretValue(sm, config.jwt.currentSecretId), secretValue(sm, config.jwt.previousSecretId), secretValue(sm, config.qr.privateCurrentSecretId), secretValue(sm, config.qr.publicCurrentSecretId), secretValue(sm, config.qr.publicPreviousSecretId),
  ]);
  const jwtCurrentValue = storedMaterial(jwtCurrent).value;
  const jwtPreviousValue = storedMaterial(jwtPrevious).value;
  const jwtToken = jwt.sign({ rotationId: config.rotationId }, jwtCurrentValue, { algorithm: "HS256" });
  jwt.verify(jwtToken, jwtCurrentValue, { algorithms: ["HS256"] });
  const previousToken = jwt.sign({ rotationId: config.rotationId }, jwtPreviousValue, { algorithm: "HS256" });
  jwt.verify(previousToken, jwtPreviousValue, { algorithms: ["HS256"] });
  let currentTokenAcceptedByPrevious = false;
  try {
    jwt.verify(jwtToken, jwtPreviousValue, { algorithms: ["HS256"] });
    currentTokenAcceptedByPrevious = true;
  } catch {
    // Expected: current material must not verify with the previous secret.
  }
  if (currentTokenAcceptedByPrevious) throw new Error("JWT previous verification accepted current material");
  const currentPrivate = createPrivateKey(storedMaterial(qrPrivateCurrent).value);
  const currentPublic = createPublicKey(storedMaterial(qrPublicCurrent).value);
  const previousPublic = createPublicKey(storedMaterial(qrPublicPrevious).value);
  const data = Buffer.from(`rotation:${config.rotationId}`);
  const currentSignature = cryptoSign(null, data, currentPrivate);
  if (!cryptoVerify(null, data, currentPublic, currentSignature)) throw new Error("QR current verification failed");
  if (verifyPreviousQrFixture(fixtureFile, storedMaterial(qrPublicPrevious).value, state.qr.oldKeyVersion) !== true) throw new Error("QR previous verification failed");
  if (cryptoVerify(null, Buffer.from(`${data}:tampered`), previousPublic, currentSignature)) throw new Error("QR tamper verification passed");
  const verification = { rotationId: config.rotationId, sourceSha: config.sourceSha, verifiedAt: isoNow(), operator: identity, jwtCurrent: true, jwtPrevious: true, qrCurrent: true, qrPrevious: true, tamperRejected: true };
  if (values.get("verification-out")) writeState(path.resolve(values.get("verification-out")), verification);
  console.log(JSON.stringify({ mode: "verify", ...verification, verificationFile: values.get("verification-out") || null }));
};

const cleanup = async ({ config, sm, values, identity }) => {
  if (!values.has("confirm-cleanup")) throw new Error("--confirm-cleanup is required for cleanup");
  const state = readState(statePath(values));
  if (!state) throw new Error("rotation must be overlap-ready before cleanup");
  if (state.phase === "cleaned") {
    console.log(JSON.stringify({ mode: "cleanup", phase: "cleaned", rotationId: state.rotationId, idempotent: true }));
    return;
  }
  if (state.phase !== "overlap-ready") throw new Error("rotation must be overlap-ready before cleanup");
  const verificationFile = required(values.get("verification-file"), "--verification-file");
  const verification = JSON.parse(readFileSync(verificationFile, "utf8"));
  if (verification.rotationId !== config.rotationId || verification.jwtPrevious !== true || verification.qrPrevious !== true) throw new Error("verification evidence does not match this rotation");
  const cleanupDeploymentSha = values.get("cleanup-deployment-sha");
  if (!fullSha(cleanupDeploymentSha)) throw new Error("--cleanup-deployment-sha must be a full SHA");
  const cleanupEvidenceRef = reference(values.get("cleanup-evidence-ref"));
  const [jwtCurrent, jwtPrevious, qrCurrent, qrPrevious] = await Promise.all([
    secretValue(sm, config.jwt.currentSecretId), secretValue(sm, config.jwt.previousSecretId),
    secretValue(sm, config.qr.publicCurrentSecretId), secretValue(sm, config.qr.publicPreviousSecretId),
  ]);
  for (const [label, record] of [["jwt current", jwtCurrent], ["jwt previous", jwtPrevious], ["qr current", qrCurrent], ["qr previous", qrPrevious]]) {
    if (!versionId(record.versionId)) throw new Error(`${label} secret version ID is unavailable`);
  }
  await emptyPrevious(sm, config.jwt.previousSecretId, config, "jwt_secrets");
  await emptyPrevious(sm, config.qr.publicPreviousSecretId, config, "qr_signing_keys");
  state.phase = "cleaned";
  state.cleanupCompletedAt = isoNow();
  state.cleanupDeploymentSha = cleanupDeploymentSha;
  state.cleanupEvidenceRef = cleanupEvidenceRef;
  writeState(statePath(values), state);
  const evidence = {
    evidenceVersion: 2, rotationId: config.rotationId, recordedAt: state.overlapReadyAt, sourceSha: config.sourceSha,
    approvedBy: required(config.approvedBy, "config.approvedBy"), approverRole: required(config.approverRole, "config.approverRole"),
    reason: required(config.reason, "config.reason"), ticket: required(config.ticket, "config.ticket"), environment: "production",
    cleanupWindowComplete: true, cleanupCompletedAt: state.cleanupCompletedAt, cleanupVerifiedBy: identity,
    cleanupEvidenceRef, linkedDeployShas: [required(config.overlapDeploymentSha, "config.overlapDeploymentSha"), cleanupDeploymentSha],
    verificationRefs: [reference(config.verificationRef), cleanupEvidenceRef],
    families: [
      { name: "jwt_secrets", rotatedAt: state.overlapReadyAt, operator: identity, method: "dual-slot", currentVersionId: jwtCurrent.versionId, previousVersionId: jwtPrevious.versionId, verificationRef: reference(config.verificationRef) },
      { name: "qr_signing_keys", rotatedAt: state.overlapReadyAt, operator: identity, method: "dual-slot", currentVersionId: qrCurrent.versionId, previousVersionId: qrPrevious.versionId, currentKeyVersion: state.qr.newKeyVersion, previousKeyVersion: state.qr.oldKeyVersion, verificationRef: reference(config.verificationRef) },
    ],
  };
  if (values.get("evidence-out")) writeState(path.resolve(values.get("evidence-out")), evidence);
  console.log(JSON.stringify({ mode: "cleanup", phase: state.phase, rotationId: config.rotationId, evidenceFile: values.get("evidence-out") || null }));
};

const status = async ({ config, sm, identity }) => {
  const ids = [config.jwt.currentSecretId, config.jwt.previousSecretId, config.jwt.pendingSecretId, config.qr.privateCurrentSecretId, config.qr.privatePendingSecretId, config.qr.publicCurrentSecretId, config.qr.publicPreviousSecretId, config.qr.publicPendingSecretId];
  const records = await Promise.all(ids.map(async (id) => {
    const result = await secretValue(sm, id);
    const material = storedMaterial(result);
    return { id, versionId: result.versionId, populated: Boolean(material.value), rotationId: material.metadata.rotationId || null, slot: material.metadata.slot || "legacy" };
  }));
  console.log(JSON.stringify({ mode: "status", operator: identity, records }));
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

export { assertIdentity, cleanup, prepare, status, verify };

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(`Rotation coordinator failed: ${String(error?.message || error)}`);
    process.exitCode = 1;
  });
}

import assert from "node:assert/strict";
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign as signSignature, verify as verifySignature } from "node:crypto";
import { createRequire } from "node:module";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { bootstrapInitialDualSlotRotation, deriveLegacyRotationBaseline, INITIAL_DUAL_SLOT_NAMES, assertInitialDualSlotBindings } from "../aws/production-initial-dual-slot-bootstrap.mjs";
import { buildProductionRotationConfig, rotationBindingsToPostPrepareTaskBindings, rotationBindingsToTaskBindings } from "../aws/production-cutover-runtime-bootstrap.mjs";
import { buildOverlapTaskDefinition } from "../aws/production-overlap-task-definition.mjs";
import { prepare } from "../../backend/scripts/security/rotate-production-signing-material.mjs";

const jwt = createRequire(path.resolve("backend/package.json"))("jsonwebtoken");

const sourceSha = "96a4be6f0edcd626285c6a1bd8062a4008175d25";
const rotationId = "rotation-initial-20260812";
const legacy = {
  jwt: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/jwt-wBQNqk",
  qrPrivate: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/qr_sign_private_key-BcQFPO",
  qrPublic: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/qr_sign_public_key-v7Xeex",
};
const taskDefinition = {
  taskDefinition: {
    taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:47",
    containerDefinitions: [{
      name: "backend",
      environment: [{ name: "QR_SIGN_ACTIVE_KEY_VERSION", value: "2026-04-20" }],
      secrets: [
        { name: "JWT_SECRET", valueFrom: legacy.jwt },
        { name: "QR_SIGN_PRIVATE_KEY", valueFrom: legacy.qrPrivate },
        { name: "QR_SIGN_PUBLIC_KEY", valueFrom: legacy.qrPublic },
      ],
    }],
  },
};

const arn = (name) => `arn:aws:secretsmanager:eu-west-2:368992683803:secret:${name}-AbCd12`;

function fakeSecrets({ failCreateAt = null } = {}) {
  const states = new Map();
  const calls = [];
  const controls = { failCreateAt };
  const send = async (command) => {
    const name = command.constructor.name;
    const input = command.input;
    calls.push({ name, input: { ...input, SecretString: input.SecretString ? "[redacted]" : undefined } });
    if (name === "DescribeSecretCommand") {
      const state = states.get(input.SecretId);
      if (!state) throw Object.assign(new Error("not found"), { name: "ResourceNotFoundException" });
      return { Name: input.SecretId, ARN: state.arn, VersionIdsToStages: state.secretString ? { version: ["AWSCURRENT"] } : {} };
    }
    if (name === "CreateSecretCommand") {
      if (input.Name === controls.failCreateAt) throw new Error("CreateSecret denied");
      if (states.has(input.Name)) throw Object.assign(new Error("exists"), { name: "ResourceExistsException" });
      states.set(input.Name, { arn: arn(input.Name), secretString: null });
      return { Name: input.Name, ARN: arn(input.Name) };
    }
    if (name === "GetSecretValueCommand") {
      const state = [...states.values()].find((candidate) => candidate.arn === input.SecretId);
      if (!state?.secretString) throw Object.assign(new Error("no current version"), { name: "ResourceNotFoundException" });
      return { SecretString: state.secretString, VersionId: "version" };
    }
    if (name === "PutSecretValueCommand") {
      const state = [...states.values()].find((candidate) => candidate.arn === input.SecretId);
      if (!state) throw new Error("unknown write target");
      state.secretString = input.SecretString;
      return { ARN: input.SecretId, VersionId: "version" };
    }
    throw new Error(`unexpected command ${name}`);
  };
  return { states, calls, send, controls };
}

function tempOutput() {
  const directory = fsTemp();
  return { directory, file: path.join(directory, "rotation-bindings.json") };
}
function fsTemp() { return mkdtempSync(path.join(os.tmpdir(), "mscqr-initial-dual-slot-")); }

test("clean legacy topology creates exact dual-slot resources and identifier-only manifest", async () => {
  const fixture = fakeSecrets(); const output = tempOutput();
  try {
    const result = await bootstrapInitialDualSlotRotation({ send: fixture.send, taskDefinition, sourceSha, rotationId, outputFile: output.file });
    assert.equal(result.created.length, 7);
    assert.equal(result.secretValueWrites, 7);
    assert.equal(result.pendingMaterialGenerated, true);
    const manifest = readFileSync(result.bindingFile, "utf8");
    assert.doesNotMatch(manifest, /BEGIN .*PRIVATE KEY|"value"|SecretString|AccessKeyId|SessionToken/i);
    assert.equal(Object.keys(INITIAL_DUAL_SLOT_NAMES).length, 7);
    assert.equal(result.bindings.jwt.currentSecretId, legacy.jwt);
    assert.equal(result.bindings.qr.publicCurrentSecretId, legacy.qrPublic);
    assert.equal(result.bindings.qr.previousKeyVersion, "2026-04-20");
    assert.deepEqual(result.bindings.ecs, rotationBindingsToTaskBindings(result.bindings));
    assert.match(result.bindings.ecs.JWT_SECRET_PREVIOUS, /:value::$/);
    assert.equal(result.bindings.ecs.JWT_SECRET_CURRENT, legacy.jwt);
    assert.equal(fixture.calls.filter(({ name, input }) => ["GetSecretValueCommand", "PutSecretValueCommand", "DescribeSecretCommand"].includes(name) && /:value::$/.test(input.SecretId || "")).length, 0);
    assert.equal(fixture.calls.filter(({ name }) => name === "DeleteSecretCommand").length, 0);
  } finally { rmSync(output.directory, { recursive: true, force: true }); }
});

test("rerun is idempotent and does not rewrite a matching manifest or material", async () => {
  const fixture = fakeSecrets(); const output = tempOutput();
  try {
    const first = await bootstrapInitialDualSlotRotation({ send: fixture.send, taskDefinition, sourceSha, rotationId, outputFile: output.file });
    const callsAfterFirst = fixture.calls.length;
    const second = await bootstrapInitialDualSlotRotation({ send: fixture.send, taskDefinition, sourceSha, rotationId, outputFile: output.file });
    assert.equal(second.created.length, 0);
    assert.equal(second.secretValueWrites, 0);
    assert.equal(second.evidenceSha256, first.evidenceSha256);
    assert.equal(fixture.calls.slice(callsAfterFirst).filter(({ name }) => name === "CreateSecretCommand").length, 0);
    assert.equal(fixture.calls.slice(callsAfterFirst).filter(({ name }) => name === "PutSecretValueCommand").length, 0);
  } finally { rmSync(output.directory, { recursive: true, force: true }); }
});

test("partial resource creation fails closed and safely converges on retry without deletes", async () => {
  const first = fakeSecrets({ failCreateAt: INITIAL_DUAL_SLOT_NAMES.jwtPending }); const output = tempOutput();
  try {
    await assert.rejects(() => bootstrapInitialDualSlotRotation({ send: first.send, taskDefinition, sourceSha, rotationId, outputFile: output.file }), /CreateSecret denied/);
    assert.equal(first.calls.some(({ name }) => name === "DeleteSecretCommand"), false);
    first.controls.failCreateAt = null;
    const second = await bootstrapInitialDualSlotRotation({ send: first.send, taskDefinition, sourceSha, rotationId, outputFile: output.file });
    assert.equal(second.valid, true);
    assert.equal(second.created.length, 6);
  } finally { rmSync(output.directory, { recursive: true, force: true }); }
});

test("legacy current ARN mismatch is rejected before any resource write", async () => {
  const fixture = fakeSecrets(); const output = tempOutput();
  try {
    const altered = structuredClone(taskDefinition);
    altered.taskDefinition.containerDefinitions[0].secrets[0].valueFrom = legacy.qrPublic;
    await assert.rejects(() => bootstrapInitialDualSlotRotation({ send: fixture.send, taskDefinition: altered, sourceSha, rotationId, outputFile: output.file }), /distinct|invalid/);
    assert.equal(fixture.calls.length, 0);
  } finally { rmSync(output.directory, { recursive: true, force: true }); }
});

test("malformed and duplicate slot bindings are rejected", () => {
  const base = {
    sourceSha, rotationId,
    jwt: { currentSecretId: legacy.jwt, previousSecretId: arn("jwt-prev"), pendingSecretId: arn("jwt-pending") },
    qr: { privateCurrentSecretId: legacy.qrPrivate, privatePendingSecretId: arn("qr-private-pending"), publicCurrentSecretId: legacy.qrPublic, publicPreviousSecretId: arn("qr-public-previous"), publicPendingSecretId: arn("qr-public-pending"), currentKeyVersionSecretId: arn("qr-current-version"), previousKeyVersionSecretId: arn("qr-previous-version"), previousKeyVersion: "2026-04-20" },
  };
  assert.equal(assertInitialDualSlotBindings(base), true);
  assert.throws(() => assertInitialDualSlotBindings({ ...base, jwt: { ...base.jwt, pendingSecretId: base.jwt.previousSecretId } }), /distinct/);
  assert.throws(() => assertInitialDualSlotBindings({ ...base, jwt: { ...base.jwt, pendingSecretId: "not-an-arn" } }), /production secret ARNs/);
  assert.throws(() => assertInitialDualSlotBindings({ ...base, jwt: { ...base.jwt, pendingSecretId: base.jwt.currentSecretId } }), /distinct/);
  assert.throws(() => assertInitialDualSlotBindings({ ...base, jwt: { ...base.jwt, previousSecretId: base.jwt.pendingSecretId } }), /distinct/);
});

test("existing pending metadata and key-pair drift fail closed", async () => {
  const fixture = fakeSecrets(); const output = tempOutput();
  try {
    const first = await bootstrapInitialDualSlotRotation({ send: fixture.send, taskDefinition, sourceSha, rotationId, outputFile: output.file });
    const pendingArn = first.bindings.qr.privatePendingSecretId;
    const pending = [...fixture.states.values()].find(({ arn: value }) => value === pendingArn);
    pending.secretString = JSON.stringify({ rotationId, sourceSha: "a".repeat(40), family: "qr_signing_keys", slot: "pending-private", materialFingerprint: "bad", value: "not-a-key" });
    rmSync(output.file);
    await assert.rejects(() => bootstrapInitialDualSlotRotation({ send: fixture.send, taskDefinition, sourceSha, rotationId, outputFile: output.file }), /inconsistent pending|malformed/);
  } finally { rmSync(output.directory, { recursive: true, force: true }); }
});

test("generated bindings satisfy the existing cutover coordinator config contract", async () => {
  const fixture = fakeSecrets(); const output = tempOutput();
  try {
    const result = await bootstrapInitialDualSlotRotation({ send: fixture.send, taskDefinition, sourceSha, rotationId, outputFile: output.file });
    const config = buildProductionRotationConfig({
      sourceSha, rotationId, liveCurrentKeyVersion: "2026-04-20",
      approval: { ticket: "MSCQR-PROD-CUTOVER-2026-08-12", approvedBy: "approved", approverRole: "release", reason: "rotation", verificationRef: "https://example.invalid/ref", minimumGraceSeconds: 2592000 },
      bindings: result.bindings,
    });
    assert.equal(config.jwt.currentSecretId, legacy.jwt);
    assert.equal(config.qr.previousKeyVersion, "2026-04-20");
    assert.notEqual(config.jwt.currentSecretId, config.jwt.pendingSecretId);
    assert.notEqual(config.jwt.previousSecretId, config.jwt.pendingSecretId);
  } finally { rmSync(output.directory, { recursive: true, force: true }); }
});

test("legacy current baseline derivation never reads secret values", () => {
  const baseline = deriveLegacyRotationBaseline(taskDefinition);
  assert.deepEqual(baseline, { jwtCurrent: legacy.jwt, qrPrivateCurrent: legacy.qrPrivate, qrPublicCurrent: legacy.qrPublic, qrCurrentVersion: "2026-04-20" });
});

test("FULL_INITIAL_MIGRATION_SIMULATION keeps envelopes out of ECS and rotates QR key/version atomically", async () => {
  const fixture = fakeSecrets(); const output = tempOutput(); const directory = fsTemp();
  const legacyKeys = generateKeyPairSync("ed25519", { privateKeyEncoding: { format: "pem", type: "pkcs8" }, publicKeyEncoding: { format: "pem", type: "spki" } });
  try {
    fixture.states.set(legacy.jwt, { arn: legacy.jwt, secretString: "legacy-jwt-material" });
    fixture.states.set(legacy.qrPrivate, { arn: legacy.qrPrivate, secretString: legacyKeys.privateKey });
    fixture.states.set(legacy.qrPublic, { arn: legacy.qrPublic, secretString: legacyKeys.publicKey });
    const bootstrapped = await bootstrapInitialDualSlotRotation({ send: fixture.send, taskDefinition, sourceSha, rotationId, outputFile: output.file });
    const config = buildProductionRotationConfig({
      sourceSha, rotationId, liveCurrentKeyVersion: "2026-04-20",
      approval: { ticket: "MSCQR-PROD-CUTOVER-2026-08-12", approvedBy: "approved", approverRole: "release", reason: "rotation", verificationRef: "https://example.invalid/ref", minimumGraceSeconds: 2592000 },
      bindings: bootstrapped.bindings,
    });
    const stateFile = path.join(directory, "state.json"); const fixtureFile = path.join(directory, "fixture.json");
    await prepare({ config, sm: fixture, identity: "arn:aws:sts::368992683803:assumed-role/release/test", inventoryEvidenceSha256: null, values: new Map([["state-file", stateFile], ["fixture-file", fixtureFile]]) });
    const state = JSON.parse(readFileSync(stateFile, "utf8"));
    assert.equal(state.phase, "overlap-deploy-required");
    const stored = (id) => {
      const record = fixture.states.get(id) || [...fixture.states.values()].find(({ arn }) => arn === id);
      return JSON.parse(record.secretString);
    };
    const promoted = {
      jwtCurrent: stored(config.jwt.currentSecretId),
      qrPrivateCurrent: stored(config.qr.privateCurrentSecretId),
      qrPublicCurrent: stored(config.qr.publicCurrentSecretId),
      qrCurrentVersion: stored(config.qr.currentKeyVersionSecretId),
      qrPublicPrevious: stored(config.qr.publicPreviousSecretId),
      qrPreviousVersion: stored(config.qr.previousKeyVersionSecretId),
    };
    assert.equal(promoted.qrCurrentVersion.value, state.qr.newKeyVersion);
    assert.equal(promoted.qrPreviousVersion.value, state.qr.oldKeyVersion);
    assert.equal(promoted.qrPublicCurrent.keyVersion, promoted.qrCurrentVersion.value);
    assert.equal(promoted.qrPublicPrevious.keyVersion, promoted.qrPreviousVersion.value);
    assert.notEqual(promoted.qrCurrentVersion.value, promoted.qrPreviousVersion.value);

    const rotationEcs = rotationBindingsToPostPrepareTaskBindings(config);
    const artifact = Object.fromEntries(["private", "public", "active", "registry"].map((name) => [`ARTIFACT_SIGN_${name === "private" ? "PRIVATE_KEY_CURRENT" : name === "public" ? "PUBLIC_KEY_CURRENT" : name === "active" ? "ACTIVE_KEY_VERSION" : "PUBLIC_KEYS_JSON"}`, `arn:aws:secretsmanager:eu-west-2:368992683803:secret:artifact-${name}`]));
    const task = buildOverlapTaskDefinition({ backendImage: "368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:" + "a".repeat(64), releaseSha: sourceSha, backendLogGroup: "/ecs/rotation", postPrepare: true, secretBindings: { ...rotationEcs, ...artifact, ROTATION_INVENTORY_RLS_ROLE: "mscqr_prod_rls_read" } });
    const taskSecrets = Object.fromEntries(task.taskDefinition.containerDefinitions[0].secrets.map(({ name, valueFrom }) => [name, valueFrom]));
    for (const name of ["JWT_SECRET_CURRENT", "QR_SIGN_PRIVATE_KEY_CURRENT", "QR_SIGN_PUBLIC_KEY_CURRENT", "QR_SIGN_ACTIVE_KEY_VERSION", "QR_SIGN_PUBLIC_KEY_PREVIOUS", "QR_SIGN_PREVIOUS_KEY_VERSION"]) assert.match(taskSecrets[name], /:value::$/);
    const injected = (name) => {
      const base = taskSecrets[name].replace(/:value::$/, "");
      const record = fixture.states.get(base) || [...fixture.states.values()].find(({ arn }) => arn === base);
      return JSON.parse(record.secretString).value;
    };
    assert.doesNotMatch(injected("JWT_SECRET_CURRENT"), /^\{/);
    assert.ok(createPublicKey(injected("QR_SIGN_PUBLIC_KEY_CURRENT")));
    assert.ok(createPublicKey(injected("QR_SIGN_PUBLIC_KEY_PREVIOUS")));
    const token = jwt.sign({ rotationId, slot: "current" }, injected("JWT_SECRET_CURRENT"), { algorithm: "HS256", noTimestamp: true });
    assert.equal(jwt.verify(token, injected("JWT_SECRET_CURRENT"), { algorithms: ["HS256"] }).rotationId, rotationId);
    const currentPayload = Buffer.from(JSON.stringify({ rotationId, kid: injected("QR_SIGN_ACTIVE_KEY_VERSION") }));
    const currentSignature = signSignature(null, createHash("sha256").update(currentPayload).digest(), createPrivateKey(injected("QR_SIGN_PRIVATE_KEY_CURRENT")));
    assert.equal(verifySignature(null, createHash("sha256").update(currentPayload).digest(), createPublicKey(injected("QR_SIGN_PUBLIC_KEY_CURRENT")), currentSignature), true);
    const previousPayload = Buffer.from(JSON.stringify({ rotationId, kid: injected("QR_SIGN_PREVIOUS_KEY_VERSION") }));
    const previousSignature = signSignature(null, createHash("sha256").update(previousPayload).digest(), createPrivateKey(legacyKeys.privateKey));
    assert.equal(verifySignature(null, createHash("sha256").update(previousPayload).digest(), createPublicKey(injected("QR_SIGN_PUBLIC_KEY_PREVIOUS")), previousSignature), true);

    const rollback = { qrPublic: legacyKeys.publicKey, qrVersion: "2026-04-20" };
    assert.equal(createHash("sha256").update(rollback.qrPublic).digest("hex").slice(0, 16) !== state.qr.newKeyVersion, true);
    assert.equal(rollback.qrVersion, state.qr.oldKeyVersion);
  } finally { rmSync(output.directory, { recursive: true, force: true }); rmSync(directory, { recursive: true, force: true }); }
});

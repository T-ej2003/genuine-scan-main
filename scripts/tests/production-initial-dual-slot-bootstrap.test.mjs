import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { bootstrapInitialDualSlotRotation, deriveLegacyRotationBaseline, INITIAL_DUAL_SLOT_NAMES, assertInitialDualSlotBindings } from "../aws/production-initial-dual-slot-bootstrap.mjs";
import { buildProductionRotationConfig, rotationBindingsToTaskBindings } from "../aws/production-cutover-runtime-bootstrap.mjs";

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

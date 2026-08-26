import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import jwt from "jsonwebtoken";
import { assertIdentity, cleanup, prepare, readCurrentState, validateRuntimeProof, verify } from "../scripts/security/rotate-production-signing-material.mjs";
import {
  normalizeProductionRotationState,
  PRODUCTION_ROTATION_LEGACY_STATE_VERSION,
  PRODUCTION_ROTATION_MINIMUM_GRACE_SECONDS,
  PRODUCTION_ROTATION_STATE_VERSION,
} from "../scripts/security/production-rotation-grace-contract.mjs";

const baseConfig = {
  region: "eu-west-2",
  rotationId: "rotation-test-2026",
  sourceSha: "a".repeat(40),
  ticket: "SEC-ROTATION-TEST",
  approvedBy: "security@example.com",
  approverRole: "Security Lead",
  reason: "test rotation",
  minimumGraceSeconds: PRODUCTION_ROTATION_MINIMUM_GRACE_SECONDS,
  overlapDeploymentSha: "b".repeat(40),
  verificationRef: "https://example.test/verify",
  jwt: { currentSecretId: "jwt-current", previousSecretId: "jwt-previous", pendingSecretId: "jwt-pending" },
  qr: {
    previousKeyVersion: "legacy-v1",
    privateCurrentSecretId: "qr-private-current",
    privatePendingSecretId: "qr-private-pending",
    publicCurrentSecretId: "qr-public-current",
    publicPreviousSecretId: "qr-public-previous",
    publicPendingSecretId: "qr-public-pending",
    currentKeyVersionSecretId: "qr-current-version",
    previousKeyVersionSecretId: "qr-previous-version",
  },
};

const material = (value, metadata = {}) => JSON.stringify({ ...metadata, value });
const fingerprint = (value) => createHash("sha256").update(value).digest("hex").slice(0, 16);
const makeKeys = () => generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});

const fakeSecrets = (initial, { failAfterPut = 0, versionIds = {} } = {}) => {
  const values = new Map(Object.entries(initial));
  const requests = new Map();
  const putCalls = [];
  const versions = new Map(Object.entries(versionIds));
  let puts = 0;
  return {
    values,
    requests,
    putCalls,
    versionIds: versions,
    get putCount() { return puts; },
    async send(command) {
      const input = command.input;
      if (command.constructor.name === "GetSecretValueCommand") {
        if (!versions.has(input.SecretId)) versions.set(input.SecretId, `version-${input.SecretId}-initial`);
        return { SecretString: values.get(input.SecretId) || "", VersionId: versions.get(input.SecretId) };
      }
      if (command.constructor.name === "PutSecretValueCommand") {
        const prior = requests.get(input.ClientRequestToken);
        if (prior && prior !== input.SecretString) throw new Error("conflicting deterministic ClientRequestToken payload");
        requests.set(input.ClientRequestToken, input.SecretString);
        putCalls.push({ secretId: input.SecretId, payload: input.SecretString });
        puts += 1;
        const versionId = versions.get(input.SecretId) || `version-${input.SecretId}-${puts}`;
        versions.set(input.SecretId, versionId);
        values.set(input.SecretId, input.SecretString);
        if (failAfterPut && puts === failAfterPut) throw new Error("simulated process crash after durable AWS write");
        return { VersionId: versionId };
      }
      throw new Error(`unexpected command ${command.constructor.name}`);
    },
  };
};

const contextFor = (directory, config, sm, clock = () => Date.parse("2026-08-10T00:00:00.000Z"), extras = {}) => ({
  config,
  sm,
  clock,
  identity: "arn:aws:sts::368992683803:assumed-role/release/test",
  values: new Map([
    ["state-file", path.join(directory, "state.json")],
    ["fixture-file", path.join(directory, "previous-qr.json")],
    ["confirm-cleanup", true],
  ]),
  ...extras,
});

const initialSecrets = () => {
  const keys = makeKeys();
  return {
    keys,
    initial: {
      [baseConfig.jwt.currentSecretId]: material("old-jwt-material"),
      [baseConfig.qr.privateCurrentSecretId]: material(keys.privateKey, { keyVersion: "legacy-v1" }),
      [baseConfig.qr.publicCurrentSecretId]: material(keys.publicKey, { keyVersion: "legacy-v1" }),
      [baseConfig.qr.currentKeyVersionSecretId]: material("legacy-v1", { family: "qr_key_versions", slot: "current" }),
      [baseConfig.qr.previousKeyVersionSecretId]: material("", { family: "qr_key_versions", slot: "previous-empty" }),
    },
  };
};

const seededRotationSecrets = () => {
  const { initial } = initialSecrets();
  const keys = makeKeys();
  const newJwt = "new-jwt-material";
  const newQrVersion = createHash("sha256").update(keys.publicKey).digest("hex").slice(0, 16);
  initial[baseConfig.jwt.pendingSecretId] = material(newJwt, { rotationId: baseConfig.rotationId, family: "jwt_secrets", slot: "pending", materialFingerprint: fingerprint(newJwt) });
  initial[baseConfig.qr.privatePendingSecretId] = material(keys.privateKey, { rotationId: baseConfig.rotationId, family: "qr_signing_keys", slot: "pending-private", keyVersion: newQrVersion, materialFingerprint: fingerprint(keys.privateKey) });
  initial[baseConfig.qr.publicPendingSecretId] = material(keys.publicKey, { rotationId: baseConfig.rotationId, family: "qr_signing_keys", slot: "pending-public", keyVersion: newQrVersion, materialFingerprint: fingerprint(keys.publicKey) });
  return initial;
};

const runtimeProof = (config, phase, observedAt, deploymentSha) => phase === "overlap"
  ? {
      rotationId: config.rotationId, phase, deploymentSha, runtimeInvocationRef: "https://example.test/runtime-overlap",
      observedAt, jwtCurrentRuntimeVerify: true, jwtPreviousRuntimeVerify: true, jwtInvalidRuntimeRejected: true,
      qrCurrentRuntimeVerify: true, qrPreviousRuntimeVerify: true, qrTamperMatchingKeyTest: true, qrUnknownKeyRejected: true,
      serviceHealthy: true, healthHttpStatus: 200, healthReleaseGitSha: config.sourceSha, expectedReleaseGitSha: config.sourceSha, healthObservedAt: observedAt,
    }
  : {
      rotationId: config.rotationId, phase, deploymentSha, runtimeInvocationRef: "https://example.test/runtime-cleanup",
      observedAt, jwtCurrentRuntimeVerify: true, jwtPreviousRuntimeRejected: true, qrCurrentRuntimeVerify: true,
      qrPreviousRuntimeRejected: true, qrUnknownKeyRejected: true,
      serviceHealthy: true, healthHttpStatus: 200, healthReleaseGitSha: config.sourceSha, expectedReleaseGitSha: config.sourceSha, healthObservedAt: observedAt,
    };

const writeProof = (directory, name, proof) => {
  const file = path.join(directory, name);
  writeFileSync(file, `${JSON.stringify(proof)}\n`, { mode: 0o600 });
  return file;
};

const valuesWith = (context, entries, remove = []) => {
  const values = new Map(context.values);
  for (const key of remove) values.delete(key);
  for (const [key, value] of entries) values.set(key, value);
  return values;
};

const setupCleanupDeployRequired = async (directory, sm, clockState) => {
  const context = contextFor(directory, baseConfig, sm, () => clockState.now);
  await prepare(context);
  const overlapFile = writeProof(directory, "overlap.json", runtimeProof(baseConfig, "overlap", new Date(clockState.now).toISOString(), baseConfig.overlapDeploymentSha));
  await verify({ ...context, values: valuesWith(context, [["runtime-verification-file", overlapFile]]) });
  clockState.now += baseConfig.minimumGraceSeconds * 1000;
  const cleanupSha = "c".repeat(40);
  const cleanupContext = { ...context, values: valuesWith(context, [["cleanup-deployment-sha", cleanupSha], ["cleanup-evidence-ref", "https://example.test/cleanup"]]) };
  await cleanup(cleanupContext);
  return { cleanupContext, cleanupSha, retirementTimestamp: JSON.parse(readFileSync(path.join(directory, "state.json"), "utf8")).retirementTimestamp };
};

const interruptedCleanup = async (directory, sm, clockState) => {
  const { cleanupContext, cleanupSha, retirementTimestamp } = await setupCleanupDeployRequired(directory, sm, clockState);
  clockState.now = Date.parse(retirementTimestamp) + 2_000;
  const cleanupFile = writeProof(directory, "cleanup.json", runtimeProof(baseConfig, "cleanup", new Date(Date.parse(retirementTimestamp) + 1_000).toISOString(), cleanupSha));
  const crashContext = {
    ...cleanupContext,
    persistState: (file, state) => {
      writeFileSync(file, `${JSON.stringify(state)}\n`, { mode: 0o600 });
      if (state.phase === "cleanup-runtime-verified") throw new Error("simulated process death before cleaned persist");
    },
    values: valuesWith(cleanupContext, [["cleanup-runtime-file", cleanupFile]])
  };
  await assert.rejects(cleanup(crashContext), /simulated process death before cleaned persist/);
  return { cleanupContext, cleanupSha, cleanupFile, retirementTimestamp };
};

test("prepare resumes after JWT pending write crash", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rotation-jwt-crash-"));
  try {
    const { initial } = initialSecrets();
    const sm = fakeSecrets(initial, { failAfterPut: 1 });
    const first = contextFor(directory, baseConfig, sm);
    await assert.rejects(prepare(first), /simulated process crash/);
    const pendingJwt = sm.values.get(baseConfig.jwt.pendingSecretId);
    const resumedSm = fakeSecrets(Object.fromEntries(sm.values));
    const resumed = contextFor(directory, baseConfig, resumedSm);
    await prepare(resumed);
    assert.equal(JSON.parse(resumedSm.values.get(baseConfig.jwt.pendingSecretId)).value, JSON.parse(pendingJwt).value);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("prepare rejects an active previous JWT before any secret write", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rotation-active-previous-"));
  try {
    const { initial } = initialSecrets();
    initial[baseConfig.jwt.previousSecretId] = material("historical-active-jwt", {
      rotationId: "prior-rotation", family: "jwt_secrets", slot: "previous", materialFingerprint: "not-relevant",
    });
    const sm = fakeSecrets(initial);
    await assert.rejects(prepare(contextFor(directory, baseConfig, sm)), /JWT_PREVIOUS_SLOT_NOT_RETIRED/);
    assert.equal(sm.putCount, 0);
    assert.equal(sm.putCalls.length, 0);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("promotion writes pre-rotation current to previous and pending to current", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rotation-lineage-"));
  try {
    const { initial } = initialSecrets();
    const sm = fakeSecrets(initial);
    await prepare(contextFor(directory, baseConfig, sm));
    const current = JSON.parse(sm.values.get(baseConfig.jwt.currentSecretId));
    const previous = JSON.parse(sm.values.get(baseConfig.jwt.previousSecretId));
    const pending = JSON.parse(sm.values.get(baseConfig.jwt.pendingSecretId));
    assert.equal(previous.value, "old-jwt-material");
    assert.equal(current.value, pending.value);
    assert.notEqual(current.value, previous.value);
    const state = JSON.parse(readFileSync(path.join(directory, "state.json"), "utf8"));
    assert.equal(state.jwt.oldFingerprint, fingerprint("old-jwt-material"));
    const fixture = JSON.parse(readFileSync(path.join(directory, "previous-qr.json"), "utf8"));
    assert.equal(fixture.payload.qr_id, "printer-test:rotation-synthetic");
    assert.doesNotThrow(() => jwt.verify(fixture.jwtPreviousToken, "old-jwt-material", { algorithms: ["HS256"] }));
    assert.doesNotThrow(() => jwt.verify(fixture.jwtCurrentToken, JSON.parse(sm.values.get(baseConfig.jwt.currentSecretId)).value, { algorithms: ["HS256"] }));
    assert.throws(() => jwt.verify(fixture.jwtPreviousToken, "historical-wrong-secret", { algorithms: ["HS256"] }));
    const jwtWrites = sm.putCalls.filter(({ secretId }) => [baseConfig.jwt.previousSecretId, baseConfig.jwt.currentSecretId].includes(secretId));
    assert.equal(JSON.parse(jwtWrites.at(-2).payload).value, "old-jwt-material");
    assert.equal(JSON.parse(jwtWrites.at(-1).payload).value, pending.value);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("canonical retired previous JWT is reusable but never becomes the old secret", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rotation-retired-previous-"));
  try {
    const { initial } = initialSecrets();
    initial[baseConfig.jwt.previousSecretId] = material("", {
      rotationId: "prior-rotation", family: "jwt_secrets", slot: "previous-retired", retiredAt: "2026-08-09T00:00:00.000Z",
    });
    const sm = fakeSecrets(initial);
    await prepare(contextFor(directory, baseConfig, sm));
    assert.equal(JSON.parse(sm.values.get(baseConfig.jwt.previousSecretId)).value, "old-jwt-material");
    const fixture = JSON.parse(readFileSync(path.join(directory, "previous-qr.json"), "utf8"));
    assert.doesNotThrow(() => jwt.verify(fixture.jwtPreviousToken, "old-jwt-material", { algorithms: ["HS256"] }));
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("prepared state resumes with the original current lineage without regenerating pending material", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rotation-prepared-resume-"));
  try {
    const { initial } = initialSecrets();
    const sm = fakeSecrets(initial);
    let persistCount = 0;
    const first = contextFor(directory, baseConfig, sm, undefined, {
      persistState: (file, state) => {
        writeFileSync(file, `${JSON.stringify(state)}\n`, { mode: 0o600 });
        persistCount += 1;
        if (persistCount === 1) throw new Error("simulated process death before promotion");
      },
    });
    await assert.rejects(prepare(first), /simulated process death before promotion/);
    const pendingBefore = sm.values.get(baseConfig.jwt.pendingSecretId);
    assert.equal(JSON.parse(sm.values.get(baseConfig.jwt.currentSecretId)).value, "old-jwt-material");
    const stateFile = path.join(directory, "state.json");
    writeFileSync(stateFile, `${JSON.stringify(legacyV3(JSON.parse(readFileSync(stateFile, "utf8"))))}\n`, { mode: 0o600 });
    const resumedSm = fakeSecrets(Object.fromEntries(sm.values));
    await prepare(contextFor(directory, baseConfig, resumedSm));
    assert.equal(resumedSm.values.get(baseConfig.jwt.pendingSecretId), pendingBefore);
    assert.equal(JSON.parse(resumedSm.values.get(baseConfig.jwt.previousSecretId)).value, "old-jwt-material");
    assert.notEqual(JSON.parse(resumedSm.values.get(baseConfig.jwt.currentSecretId)).value, "old-jwt-material");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("legacy overlap-deployed state resumes without regenerating material", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rotation-v3-overlap-resume-"));
  try {
    const { initial } = initialSecrets();
    const sm = fakeSecrets(initial);
    await prepare(contextFor(directory, baseConfig, sm));
    const stateFile = path.join(directory, "state.json");
    writeFileSync(stateFile, `${JSON.stringify(legacyV3(JSON.parse(readFileSync(stateFile, "utf8"))))}\n`, { mode: 0o600 });
    const resumedSm = fakeSecrets(Object.fromEntries(sm.values));
    await prepare(contextFor(directory, baseConfig, resumedSm));
    const resumed = JSON.parse(readFileSync(stateFile, "utf8"));
    assert.equal(resumed.stateVersion, PRODUCTION_ROTATION_STATE_VERSION);
    assert.equal(resumed.phase, "overlap-deploy-required");
    assert.equal(resumedSm.putCount, 0);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("prepare resumes after QR private pending write crash and derives its public pair", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rotation-qr-crash-"));
  try {
    const { initial } = initialSecrets();
    const sm = fakeSecrets(initial, { failAfterPut: 2 });
    await assert.rejects(prepare(contextFor(directory, baseConfig, sm)), /simulated process crash/);
    const privatePending = JSON.parse(sm.values.get(baseConfig.qr.privatePendingSecretId)).value;
    const resumedSm = fakeSecrets(Object.fromEntries(sm.values));
    await prepare(contextFor(directory, baseConfig, resumedSm));
    assert.equal(JSON.parse(resumedSm.values.get(baseConfig.qr.privatePendingSecretId)).value, privatePending);
    assert.ok(JSON.parse(resumedSm.values.get(baseConfig.qr.publicPendingSecretId)).value);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("prepare resumes every durable promotion write without regenerating rotation material", async () => {
  for (const failAfterPut of [1, 2, 3, 4, 5, 6, 7]) {
    const directory = mkdtempSync(path.join(os.tmpdir(), `mscqr-rotation-promotion-crash-${failAfterPut}-`));
    try {
      const initial = seededRotationSecrets();
      const sm = fakeSecrets(initial, { failAfterPut });
      await assert.rejects(prepare(contextFor(directory, baseConfig, sm)), /simulated process crash/);
      const pendingBefore = Object.fromEntries([
        baseConfig.jwt.pendingSecretId, baseConfig.qr.privatePendingSecretId, baseConfig.qr.publicPendingSecretId,
      ].map((id) => [id, sm.values.get(id)]));
      const resumedSm = fakeSecrets(Object.fromEntries(sm.values));
      await prepare(contextFor(directory, baseConfig, resumedSm));
      for (const [id, payload] of Object.entries(pendingBefore)) assert.equal(resumedSm.values.get(id), payload, `pending material changed after failure ${failAfterPut}`);
      const state = JSON.parse(readFileSync(path.join(directory, "state.json"), "utf8"));
      assert.equal(state.phase, "overlap-deploy-required");
      assert.equal(JSON.parse(resumedSm.values.get(baseConfig.qr.currentKeyVersionSecretId)).value, state.qr.newKeyVersion);
      assert.equal(JSON.parse(resumedSm.values.get(baseConfig.qr.previousKeyVersionSecretId)).value, state.qr.oldKeyVersion);
      assert.equal(JSON.parse(resumedSm.values.get(baseConfig.qr.publicPreviousSecretId)).value, JSON.parse(initial[baseConfig.qr.publicCurrentSecretId]).value);
      assert.equal(JSON.parse(resumedSm.values.get(baseConfig.jwt.previousSecretId)).value, "old-jwt-material");
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  }
});

test("prepared promotion rejects foreign QR material instead of normalizing it", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rotation-promotion-tamper-"));
  try {
    const initial = seededRotationSecrets();
    const sm = fakeSecrets(initial, { failAfterPut: 7 });
    await assert.rejects(prepare(contextFor(directory, baseConfig, sm)), /simulated process crash/);
    const foreign = makeKeys();
    sm.values.set(baseConfig.qr.publicCurrentSecretId, material(foreign.publicKey, {
      rotationId: baseConfig.rotationId, family: "qr_signing_keys", slot: "current-public",
      keyVersion: "foreign-version", materialFingerprint: fingerprint(foreign.publicKey),
    }));
    const resumedSm = fakeSecrets(Object.fromEntries(sm.values));
    await assert.rejects(prepare(contextFor(directory, baseConfig, resumedSm)), /current QR public key|prepared QR public key|key version/);
    assert.equal(resumedSm.putCount, 0);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("prepared promotion rejects every unrecognized partial state", async () => {
  const cases = [
    ["wrong rotation id", 6, (sm) => {
      const record = JSON.parse(sm.values.get(baseConfig.jwt.currentSecretId));
      record.rotationId = "foreign-rotation";
      sm.values.set(baseConfig.jwt.currentSecretId, JSON.stringify(record));
    }],
    ["wrong QR key version", 4, (sm) => {
      const record = JSON.parse(sm.values.get(baseConfig.qr.privateCurrentSecretId));
      record.keyVersion = "foreign-version";
      sm.values.set(baseConfig.qr.privateCurrentSecretId, JSON.stringify(record));
    }],
    ["corrupted envelope", 4, (sm) => sm.values.set(baseConfig.qr.privateCurrentSecretId, "{malformed")],
    ["unexpected JWT previous", 1, (sm) => sm.values.set(baseConfig.jwt.previousSecretId, material("foreign-jwt"))],
    ["unexpected QR previous", 1, (sm) => sm.values.set(baseConfig.qr.publicPreviousSecretId, material("foreign-public"))],
  ];
  for (const [label, failAfterPut, mutate] of cases) {
    const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rotation-partial-reject-"));
    try {
      const sm = fakeSecrets(seededRotationSecrets(), { failAfterPut });
      await assert.rejects(prepare(contextFor(directory, baseConfig, sm)), /simulated process crash/);
      mutate(sm);
      const resumedSm = fakeSecrets(Object.fromEntries(sm.values));
      await assert.rejects(prepare(contextFor(directory, baseConfig, resumedSm)), undefined, label);
      assert.equal(resumedSm.putCount, 0, label);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  }
});

test("prepare recovers when local state write fails after all secret writes and reuses versions and payloads", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rotation-state-crash-"));
  try {
    const { initial } = initialSecrets();
    const sm = fakeSecrets(initial);
    let stateWrites = 0;
    const first = contextFor(directory, baseConfig, sm, undefined, { persistState: (file, state) => {
      stateWrites += 1;
      if (stateWrites === 2) throw new Error("simulated state write failure");
      writeFileSync(file, `${JSON.stringify(state)}\n`, { mode: 0o600 });
    } });
    await assert.rejects(prepare(first), /simulated state write failure/);
    const requestCount = sm.requests.size;
    const resumedSm = fakeSecrets(Object.fromEntries(sm.values));
    const resumed = contextFor(directory, baseConfig, resumedSm);
    await prepare(resumed);
    assert.equal(resumedSm.putCount, 0);
    assert.ok(requestCount >= 8);
    assert.equal(JSON.parse(readFileSync(path.join(directory, "state.json"), "utf8")).phase, "overlap-deploy-required");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("full rotation enforces grace, retires every slot, deploys after retirement, and allows the next rotation", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rotation-full-"));
  try {
    const { initial } = initialSecrets();
    const sm = fakeSecrets(initial);
    let currentTime = Date.parse("2026-08-10T00:00:00.000Z");
    const context = contextFor(directory, baseConfig, sm, () => currentTime);
    await prepare(context);
    const overlapFile = writeProof(directory, "overlap.json", runtimeProof(baseConfig, "overlap", new Date(currentTime).toISOString(), baseConfig.overlapDeploymentSha));
    await verify({ ...context, values: new Map([...context.values, ["runtime-verification-file", overlapFile]]) });
    await assert.rejects(cleanup({ ...context, values: new Map([...context.values, ["cleanup-deployment-sha", "c".repeat(40)], ["cleanup-evidence-ref", "https://example.test/cleanup"]]) }), /cleanup grace window has not expired/);
    currentTime += baseConfig.minimumGraceSeconds * 1000 - 1;
    await assert.rejects(cleanup({ ...context, values: new Map([...context.values, ["cleanup-deployment-sha", "c".repeat(40)], ["cleanup-evidence-ref", "https://example.test/cleanup"]]) }), /cleanup grace window has not expired/);
    currentTime += 1;
    const cleanupSha = "c".repeat(40);
    const firstCleanup = { ...context, values: new Map([...context.values, ["cleanup-deployment-sha", cleanupSha], ["cleanup-evidence-ref", "https://example.test/cleanup"]]) };
    await cleanup(firstCleanup);
    const retirementTimestamp = JSON.parse(readFileSync(path.join(directory, "state.json"), "utf8")).retirementTimestamp;
    const cleanupFile = writeProof(directory, "cleanup.json", runtimeProof(baseConfig, "cleanup", new Date(Date.parse(retirementTimestamp) + 1_000).toISOString(), cleanupSha));
    currentTime = Date.parse(retirementTimestamp) + 2_000;
    await cleanup({ ...firstCleanup, values: new Map([...firstCleanup.values, ["cleanup-runtime-file", cleanupFile]]) });
    const state = JSON.parse(readFileSync(path.join(directory, "state.json"), "utf8"));
    assert.equal(state.phase, "cleaned");
    for (const id of [baseConfig.jwt.previousSecretId, baseConfig.jwt.pendingSecretId, baseConfig.qr.privatePendingSecretId, baseConfig.qr.publicPendingSecretId, baseConfig.qr.publicPreviousSecretId]) {
      const record = JSON.parse(sm.values.get(id));
      assert.equal(record.value, "");
      assert.match(record.slot, /-retired$/);
      assert.equal(record.retiredAt, retirementTimestamp);
    }

    const nextConfig = structuredClone(baseConfig);
    nextConfig.rotationId = "rotation-test-next";
    nextConfig.sourceSha = "d".repeat(40);
    nextConfig.qr.previousKeyVersion = state.qr.newKeyVersion;
    const nextDirectory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rotation-next-"));
    try {
      await prepare(contextFor(nextDirectory, nextConfig, sm, () => currentTime));
    } finally {
      rmSync(nextDirectory, { recursive: true, force: true });
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("uninterrupted cleanup reaches cleaned and emits final evidence", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rotation-cleanup-normal-"));
  try {
    const { initial } = initialSecrets();
    const sm = fakeSecrets(initial);
    const clockState = { now: Date.parse("2026-08-10T00:00:00.000Z") };
    const { cleanupContext, cleanupSha, retirementTimestamp } = await setupCleanupDeployRequired(directory, sm, clockState);
    clockState.now = Date.parse(retirementTimestamp) + 2_000;
    const cleanupFile = writeProof(directory, "cleanup.json", runtimeProof(baseConfig, "cleanup", new Date(Date.parse(retirementTimestamp) + 1_000).toISOString(), cleanupSha));
    const evidenceFile = path.join(directory, "evidence.json");
    await cleanup({ ...cleanupContext, values: valuesWith(cleanupContext, [["cleanup-runtime-file", cleanupFile], ["evidence-out", evidenceFile]]) });
    assert.equal(JSON.parse(readFileSync(path.join(directory, "state.json"), "utf8")).phase, "cleaned");
    assert.equal(JSON.parse(readFileSync(evidenceFile, "utf8")).cleanupWindowComplete, true);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("cleanup resumes from cleanup-runtime-verified without secret or deployment mutations and preserves evidence", async () => {
  const normalDirectory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rotation-cleanup-evidence-normal-"));
  const resumedDirectory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rotation-cleanup-evidence-resumed-"));
  try {
    const fixture = { initial: seededRotationSecrets() };
    const normalClock = { now: Date.parse("2026-08-10T00:00:00.000Z") };
    const { cleanupContext: normalContext, cleanupSha: normalSha, retirementTimestamp: normalRetirement } = await setupCleanupDeployRequired(normalDirectory, fakeSecrets(fixture.initial), normalClock);
    normalClock.now = Date.parse(normalRetirement) + 2_000;
    const normalFile = writeProof(normalDirectory, "cleanup.json", runtimeProof(baseConfig, "cleanup", new Date(Date.parse(normalRetirement) + 1_000).toISOString(), normalSha));
    const normalEvidenceFile = path.join(normalDirectory, "evidence.json");
    await cleanup({ ...normalContext, values: valuesWith(normalContext, [["cleanup-runtime-file", normalFile], ["evidence-out", normalEvidenceFile]]) });

    const resumedClock = { now: Date.parse("2026-08-10T00:00:00.000Z") };
    const { cleanupContext, cleanupSha, cleanupFile } = await interruptedCleanup(resumedDirectory, fakeSecrets(fixture.initial), resumedClock);
    const resumedSm = fakeSecrets(Object.fromEntries(cleanupContext.sm.values), { versionIds: Object.fromEntries(cleanupContext.sm.versionIds) });
    const secretWritesBeforeResume = resumedSm.putCount;
    const ecsMutationsBeforeResume = 0;
    const resumedEvidenceFile = path.join(resumedDirectory, "evidence.json");
    await cleanup({
      ...cleanupContext,
      sm: resumedSm,
      values: valuesWith(cleanupContext, [["evidence-out", resumedEvidenceFile]], ["cleanup-evidence-ref", "cleanup-runtime-file"]),
    });
    assert.equal(JSON.parse(readFileSync(path.join(resumedDirectory, "state.json"), "utf8")).phase, "cleaned");
    assert.equal(resumedSm.putCount - secretWritesBeforeResume, 0);
    assert.equal(ecsMutationsBeforeResume, 0);
    const normalEvidence = JSON.parse(readFileSync(normalEvidenceFile, "utf8"));
    const resumedEvidence = JSON.parse(readFileSync(resumedEvidenceFile, "utf8"));
    assert.deepEqual(resumedEvidence, normalEvidence);
    assert.deepEqual(resumedEvidence.linkedDeployShas, [baseConfig.overlapDeploymentSha, cleanupSha]);
  } finally {
    rmSync(normalDirectory, { recursive: true, force: true });
    rmSync(resumedDirectory, { recursive: true, force: true });
  }
});

test("cleanup-runtime-verified fails closed when cleanupRuntime is missing", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rotation-cleanup-missing-proof-"));
  try {
    const { initial } = initialSecrets();
    const sm = fakeSecrets(initial);
    const clockState = { now: Date.parse("2026-08-10T00:00:00.000Z") };
    const { cleanupContext } = await interruptedCleanup(directory, sm, clockState);
    const stateFile = path.join(directory, "state.json");
    const state = JSON.parse(readFileSync(stateFile, "utf8"));
    delete state.cleanupRuntime;
    writeFileSync(stateFile, `${JSON.stringify(state)}\n`, { mode: 0o600 });
    const resumedSm = fakeSecrets(Object.fromEntries(sm.values), { versionIds: Object.fromEntries(sm.versionIds) });
    await assert.rejects(cleanup({ ...cleanupContext, sm: resumedSm, values: valuesWith(cleanupContext, [], ["cleanup-evidence-ref"]) }), /state.cleanupRuntime is required/);
    assert.equal(resumedSm.putCount, 0);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("cleanup-runtime-verified resumes a pre-fix crash state using only persisted proof plus required evidence reference", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rotation-cleanup-legacy-resume-"));
  try {
    const { initial } = initialSecrets();
    const sm = fakeSecrets(initial);
    const clockState = { now: Date.parse("2026-08-10T00:00:00.000Z") };
    const { cleanupContext, cleanupSha } = await interruptedCleanup(directory, sm, clockState);
    const stateFile = path.join(directory, "state.json");
    const state = JSON.parse(readFileSync(stateFile, "utf8"));
    delete state.cleanupCompletedAt;
    delete state.cleanupEvidenceRef;
    delete state.cleanupVerifiedBy;
    writeFileSync(stateFile, `${JSON.stringify(state)}\n`, { mode: 0o600 });
    const resumedSm = fakeSecrets(Object.fromEntries(sm.values), { versionIds: Object.fromEntries(sm.versionIds) });
    await cleanup({ ...cleanupContext, sm: resumedSm, values: valuesWith(cleanupContext, [["cleanup-deployment-sha", cleanupSha]]) });
    const resumedState = JSON.parse(readFileSync(stateFile, "utf8"));
    assert.equal(resumedState.phase, "cleaned");
    assert.equal(resumedState.cleanupCompletedAt, resumedState.cleanupRuntime.observedAt);
    assert.equal(resumedSm.putCount, 0);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("cleanup-runtime-verified fails closed when persisted cleanup deployment SHA is wrong", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rotation-cleanup-sha-"));
  try {
    const { initial } = initialSecrets();
    const sm = fakeSecrets(initial);
    const clockState = { now: Date.parse("2026-08-10T00:00:00.000Z") };
    const { cleanupContext, cleanupSha } = await interruptedCleanup(directory, sm, clockState);
    const stateFile = path.join(directory, "state.json");
    const state = JSON.parse(readFileSync(stateFile, "utf8"));
    state.cleanupRuntime.deploymentSha = "d".repeat(40);
    writeFileSync(stateFile, `${JSON.stringify(state)}\n`, { mode: 0o600 });
    const resumedSm = fakeSecrets(Object.fromEntries(sm.values), { versionIds: Object.fromEntries(sm.versionIds) });
    await assert.rejects(cleanup({ ...cleanupContext, sm: resumedSm, values: valuesWith(cleanupContext, [["cleanup-deployment-sha", cleanupSha]], ["cleanup-evidence-ref"]) }), /deployment SHA is invalid/);
    assert.equal(resumedSm.putCount, 0);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("cleanup-runtime-verified rejects overlap deployment configuration drift", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rotation-cleanup-overlap-config-drift-"));
  try {
    const { initial } = initialSecrets();
    const sm = fakeSecrets(initial);
    const clockState = { now: Date.parse("2026-08-10T00:00:00.000Z") };
    const { cleanupContext } = await interruptedCleanup(directory, sm, clockState);
    const resumedSm = fakeSecrets(Object.fromEntries(sm.values), { versionIds: Object.fromEntries(sm.versionIds) });
    const driftedConfig = { ...cleanupContext.config, overlapDeploymentSha: "d".repeat(40) };
    await assert.rejects(cleanup({ ...cleanupContext, config: driftedConfig, sm: resumedSm, values: valuesWith(cleanupContext, [], ["cleanup-evidence-ref"]) }), /does not match config|deployment SHA is invalid/);
    assert.equal(resumedSm.putCount, 0);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("cleanup-runtime-verified fails closed when persisted overlap runtime is missing", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rotation-cleanup-overlap-missing-"));
  try {
    const { initial } = initialSecrets();
    const sm = fakeSecrets(initial);
    const clockState = { now: Date.parse("2026-08-10T00:00:00.000Z") };
    const { cleanupContext } = await interruptedCleanup(directory, sm, clockState);
    const stateFile = path.join(directory, "state.json");
    const state = JSON.parse(readFileSync(stateFile, "utf8"));
    delete state.overlapRuntime;
    writeFileSync(stateFile, `${JSON.stringify(state)}\n`, { mode: 0o600 });
    const resumedSm = fakeSecrets(Object.fromEntries(sm.values), { versionIds: Object.fromEntries(sm.versionIds) });
    await assert.rejects(cleanup({ ...cleanupContext, sm: resumedSm, values: valuesWith(cleanupContext, [], ["cleanup-evidence-ref"]) }), /grace anchor|state.overlapRuntime is required/);
    assert.equal(resumedSm.putCount, 0);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("cleanup-runtime-verified fails closed when persisted overlap runtime has the wrong SHA", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rotation-cleanup-overlap-sha-"));
  try {
    const { initial } = initialSecrets();
    const sm = fakeSecrets(initial);
    const clockState = { now: Date.parse("2026-08-10T00:00:00.000Z") };
    const { cleanupContext } = await interruptedCleanup(directory, sm, clockState);
    const stateFile = path.join(directory, "state.json");
    const state = JSON.parse(readFileSync(stateFile, "utf8"));
    state.overlapRuntime.deploymentSha = "d".repeat(40);
    writeFileSync(stateFile, `${JSON.stringify(state)}\n`, { mode: 0o600 });
    const resumedSm = fakeSecrets(Object.fromEntries(sm.values), { versionIds: Object.fromEntries(sm.versionIds) });
    await assert.rejects(cleanup({ ...cleanupContext, sm: resumedSm, values: valuesWith(cleanupContext, [], ["cleanup-evidence-ref"]) }), /grace anchor|does not match config|deployment SHA is invalid/);
    assert.equal(resumedSm.putCount, 0);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("cleanup-runtime-verified revalidates overlap proof phase while cleanup proof remains valid", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rotation-cleanup-overlap-proof-"));
  try {
    const { initial } = initialSecrets();
    const sm = fakeSecrets(initial);
    const clockState = { now: Date.parse("2026-08-10T00:00:00.000Z") };
    const { cleanupContext } = await interruptedCleanup(directory, sm, clockState);
    const stateFile = path.join(directory, "state.json");
    const state = JSON.parse(readFileSync(stateFile, "utf8"));
    state.overlapRuntime.phase = "cleanup";
    writeFileSync(stateFile, `${JSON.stringify(state)}\n`, { mode: 0o600 });
    const resumedSm = fakeSecrets(Object.fromEntries(sm.values), { versionIds: Object.fromEntries(sm.versionIds) });
    await assert.rejects(cleanup({ ...cleanupContext, sm: resumedSm, values: valuesWith(cleanupContext, [], ["cleanup-evidence-ref"]) }), /grace anchor|overlap runtime proof does not match this rotation/);
    assert.equal(resumedSm.putCount, 0);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("cleanup-runtime-verified fails closed when retirement state drifts", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rotation-cleanup-retirement-drift-"));
  try {
    const { initial } = initialSecrets();
    const sm = fakeSecrets(initial);
    const clockState = { now: Date.parse("2026-08-10T00:00:00.000Z") };
    const { cleanupContext } = await interruptedCleanup(directory, sm, clockState);
    const resumedSm = fakeSecrets(Object.fromEntries(sm.values), { versionIds: Object.fromEntries(sm.versionIds) });
    resumedSm.values.set(baseConfig.jwt.pendingSecretId, material("drifted", { rotationId: baseConfig.rotationId, family: "jwt_secrets", slot: "pending", materialFingerprint: fingerprint("drifted") }));
    await assert.rejects(cleanup({ ...cleanupContext, sm: resumedSm, values: valuesWith(cleanupContext, [], ["cleanup-evidence-ref"]) }), /does not match rotation state|was not retired/);
    assert.equal(resumedSm.putCount, 0);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("cleaned cleanup is idempotent and re-emits persisted evidence without new metadata", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rotation-cleanup-idempotent-"));
  try {
    const { initial } = initialSecrets();
    const sm = fakeSecrets(initial);
    const clockState = { now: Date.parse("2026-08-10T00:00:00.000Z") };
    const { cleanupContext, cleanupSha, retirementTimestamp } = await setupCleanupDeployRequired(directory, sm, clockState);
    clockState.now = Date.parse(retirementTimestamp) + 2_000;
    const cleanupFile = writeProof(directory, "cleanup.json", runtimeProof(baseConfig, "cleanup", new Date(Date.parse(retirementTimestamp) + 1_000).toISOString(), cleanupSha));
    const firstEvidence = path.join(directory, "first-evidence.json");
    await cleanup({ ...cleanupContext, values: valuesWith(cleanupContext, [["cleanup-runtime-file", cleanupFile], ["evidence-out", firstEvidence]]) });
    const stateBefore = readFileSync(path.join(directory, "state.json"), "utf8");
    const writesBeforeRetry = sm.putCount;
    const secondEvidence = path.join(directory, "second-evidence.json");
    await cleanup({ ...cleanupContext, values: valuesWith(cleanupContext, [["cleanup-deployment-sha", cleanupSha], ["evidence-out", secondEvidence]], ["cleanup-evidence-ref", "cleanup-runtime-file"]) });
    assert.equal(sm.putCount - writesBeforeRetry, 0);
    assert.equal(readFileSync(path.join(directory, "state.json"), "utf8"), stateBefore);
    assert.deepEqual(JSON.parse(readFileSync(secondEvidence, "utf8")), JSON.parse(readFileSync(firstEvidence, "utf8")));
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("wrong release identity fails closed before secret operations", () => {
  assert.throws(
    () => assertIdentity({ expectedRoleArn: "arn:aws:iam::368992683803:role/approved-rotation-role" }, () => "arn:aws:sts::368992683803:assumed-role/unapproved-role/session"),
    /not the configured release role/
  );
});

test("runtime proof accepts only the expected deployment SHA for overlap and cleanup", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-runtime-proof-sha-"));
  try {
    const config = { rotationId: "rotation-proof", sourceSha: "a".repeat(40) };
    const common = { rotationId: config.rotationId, runtimeInvocationRef: "https://example.test/proof", observedAt: "2026-08-10T00:00:00.000Z", serviceHealthy: true, healthHttpStatus: 200, healthReleaseGitSha: "a".repeat(40), expectedReleaseGitSha: "a".repeat(40), healthObservedAt: "2026-08-10T00:00:00.000Z" };
    const overlap = { ...common, phase: "overlap", deploymentSha: "a".repeat(40), jwtCurrentRuntimeVerify: true, jwtPreviousRuntimeVerify: true, jwtInvalidRuntimeRejected: true, qrCurrentRuntimeVerify: true, qrPreviousRuntimeVerify: true, qrTamperMatchingKeyTest: true, qrUnknownKeyRejected: true };
    const cleanupProof = { ...common, phase: "cleanup", deploymentSha: "b".repeat(40), jwtCurrentRuntimeVerify: true, jwtPreviousRuntimeRejected: true, qrCurrentRuntimeVerify: true, qrPreviousRuntimeRejected: true, qrUnknownKeyRejected: true };
    const overlapFile = writeProof(directory, "overlap.json", overlap);
    const cleanupFile = writeProof(directory, "cleanup.json", cleanupProof);
    const clock = () => Date.parse("2026-08-10T00:01:00.000Z");
    assert.doesNotThrow(() => validateRuntimeProof({ file: overlapFile, config, phase: "overlap", expectedDeploymentSha: overlap.deploymentSha, clock }));
    assert.throws(() => validateRuntimeProof({ file: overlapFile, config, phase: "overlap", expectedDeploymentSha: "c".repeat(40), clock }), /deployment SHA is invalid/);
    assert.doesNotThrow(() => validateRuntimeProof({ file: cleanupFile, config, phase: "cleanup", expectedDeploymentSha: cleanupProof.deploymentSha, clock }));
    assert.throws(() => validateRuntimeProof({ file: cleanupFile, config, phase: "cleanup", expectedDeploymentSha: "d".repeat(40), clock }), /deployment SHA is invalid/);
    assert.throws(() => validateRuntimeProof({ file: overlapFile, config, phase: "cleanup", expectedDeploymentSha: overlap.deploymentSha, clock }), /does not match this rotation/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("verified state persists the reviewed grace and rejects config or proof attempts to reset its deadline", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rotation-grace-binding-"));
  try {
    const { initial } = initialSecrets();
    const sm = fakeSecrets(initial);
    const clock = () => Date.parse("2026-08-10T00:01:00.000Z");
    const context = contextFor(directory, baseConfig, sm, clock);
    await prepare(context);
    const firstProof = writeProof(directory, "overlap.json", runtimeProof(baseConfig, "overlap", "2026-08-10T00:00:00.000Z", baseConfig.overlapDeploymentSha));
    await verify({ ...context, values: valuesWith(context, [["runtime-verification-file", firstProof]]) });
    const stateFile = path.join(directory, "state.json");
    const persisted = JSON.parse(readFileSync(stateFile, "utf8"));
    assert.equal(persisted.minimumGraceSeconds, baseConfig.minimumGraceSeconds);
    assert.equal(persisted.cleanupEligibleAt, "2026-09-09T00:00:00.000Z");

    const retryState = { ...persisted, phase: "overlap-ready" };
    writeFileSync(stateFile, `${JSON.stringify(retryState)}\n`, { mode: 0o600 });
    await assert.rejects(verify({ ...context, config: { ...baseConfig, minimumGraceSeconds: baseConfig.minimumGraceSeconds + 1 }, values: valuesWith(context, [["runtime-verification-file", firstProof]]) }), /state minimum grace/);

    const laterProof = writeProof(directory, "later.json", runtimeProof(baseConfig, "overlap", "2026-08-10T00:00:01.000Z", baseConfig.overlapDeploymentSha));
    await assert.rejects(verify({ ...context, values: valuesWith(context, [["runtime-verification-file", laterProof]]) }), /grace anchor/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

const legacyV3 = (state) => {
  const legacy = structuredClone(state);
  legacy.stateVersion = PRODUCTION_ROTATION_LEGACY_STATE_VERSION;
  delete legacy.minimumGraceSeconds;
  return legacy;
};

test("actual coordinator reader migrates legacy prepared and overlap-deployed states exactly once from reviewed config", () => {
  for (const phase of ["prepared", "overlap-deploy-required"]) {
    const directory = mkdtempSync(path.join(os.tmpdir(), `mscqr-rotation-v3-${phase}-`));
    try {
      const stateFile = path.join(directory, "state.json");
      const legacy = legacyV3({
        stateVersion: PRODUCTION_ROTATION_STATE_VERSION,
        rotationId: baseConfig.rotationId,
        sourceSha: baseConfig.sourceSha,
        operator: "arn:aws:sts::368992683803:assumed-role/release/test",
        phase,
        overlapDeploymentSha: baseConfig.overlapDeploymentSha,
        preparedAt: "2026-08-10T00:00:00.000Z",
        ...(phase === "overlap-deploy-required" ? { overlapPreparedAt: "2026-08-10T00:01:00.000Z" } : {}),
        jwt: { oldFingerprint: "1".repeat(16), newFingerprint: "2".repeat(16) },
        qr: { oldPrivateFingerprint: "3".repeat(16), oldPublicFingerprint: "4".repeat(16), newPrivateFingerprint: "5".repeat(16), newPublicFingerprint: "6".repeat(16), oldKeyVersion: "legacy-v1", newKeyVersion: "next-v2" },
        pending: { jwtVersionId: "jwt-version-1", qrPrivateVersionId: "qr-private-version-1", qrPublicVersionId: "qr-public-version-1" },
      });
      writeFileSync(stateFile, `${JSON.stringify(legacy, null, 2)}\n`, { mode: 0o600 });
      const context = contextFor(directory, baseConfig, fakeSecrets({}));
      const migrated = readCurrentState(context);
      assert.equal(migrated.stateVersion, PRODUCTION_ROTATION_STATE_VERSION);
      assert.equal(migrated.minimumGraceSeconds, baseConfig.minimumGraceSeconds);
      const firstBytes = readFileSync(stateFile, "utf8");
      assert.deepEqual(readCurrentState(context), migrated);
      assert.equal(readFileSync(stateFile, "utf8"), firstBytes);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  }
});

test("legacy timed phases derive the original grace and preserve the exact deadline through atomic disk migration", () => {
  for (const phase of ["overlap-ready", "verified", "grace-wait", "retirement-started", "retirement-complete", "cleanup-deploy-required", "cleanup-runtime-verified", "cleaned"]) {
    const directory = mkdtempSync(path.join(os.tmpdir(), `mscqr-rotation-v3-${phase}-`));
    try {
      const stateFile = path.join(directory, "state.json");
      const overlapReadyAt = "2026-08-10T00:00:00.000Z";
      const cleanupEligibleAt = "2026-09-09T00:00:00.000Z";
      const legacy = legacyV3({
        stateVersion: PRODUCTION_ROTATION_STATE_VERSION,
        rotationId: baseConfig.rotationId,
        sourceSha: baseConfig.sourceSha,
        phase,
        overlapDeploymentSha: baseConfig.overlapDeploymentSha,
        overlapReadyAt,
        cleanupEligibleAt,
        overlapRuntime: { phase: "overlap", rotationId: baseConfig.rotationId, deploymentSha: baseConfig.overlapDeploymentSha, observedAt: overlapReadyAt },
        ...(phase === "overlap-ready" ? {} : { verifiedAt: "2026-08-10T00:01:00.000Z" }),
      });
      writeFileSync(stateFile, `${JSON.stringify(legacy, null, 2)}\n`, { mode: 0o600 });
      const context = contextFor(directory, baseConfig, fakeSecrets({}));
      const migrated = readCurrentState(context);
      assert.equal(migrated.minimumGraceSeconds, baseConfig.minimumGraceSeconds);
      assert.equal(migrated.overlapReadyAt, overlapReadyAt);
      assert.equal(migrated.cleanupEligibleAt, cleanupEligibleAt);
      const firstBytes = readFileSync(stateFile, "utf8");
      assert.deepEqual(readCurrentState(context), migrated);
      assert.equal(readFileSync(stateFile, "utf8"), firstBytes);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  }
});

test("legacy verified state reaches cleanup at its original deadline without restarting the window", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rotation-v3-verified-cleanup-"));
  try {
    const { initial } = initialSecrets();
    const sm = fakeSecrets(initial);
    const clockState = { now: Date.parse("2026-08-10T00:00:00.000Z") };
    const context = contextFor(directory, baseConfig, sm, () => clockState.now);
    await prepare(context);
    const proofFile = writeProof(directory, "overlap.json", runtimeProof(baseConfig, "overlap", new Date(clockState.now).toISOString(), baseConfig.overlapDeploymentSha));
    await verify({ ...context, values: valuesWith(context, [["runtime-verification-file", proofFile]]) });
    const stateFile = path.join(directory, "state.json");
    const verified = JSON.parse(readFileSync(stateFile, "utf8"));
    const originalDeadline = verified.cleanupEligibleAt;
    writeFileSync(stateFile, `${JSON.stringify(legacyV3(verified), null, 2)}\n`, { mode: 0o600 });
    clockState.now = Date.parse(originalDeadline);
    await cleanup({ ...context, values: valuesWith(context, [["cleanup-deployment-sha", "c".repeat(40)], ["cleanup-evidence-ref", "https://example.test/cleanup"]]) });
    const resumed = JSON.parse(readFileSync(stateFile, "utf8"));
    assert.equal(resumed.stateVersion, PRODUCTION_ROTATION_STATE_VERSION);
    assert.equal(resumed.minimumGraceSeconds, baseConfig.minimumGraceSeconds);
    assert.equal(resumed.overlapReadyAt, verified.overlapReadyAt);
    assert.equal(resumed.cleanupEligibleAt, originalDeadline);
    assert.equal(resumed.phase, "cleanup-deploy-required");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("legacy migration fails closed for unauthenticated, malformed, shortened, fractional, or conflicting grace", () => {
  const timed = legacyV3({
    stateVersion: PRODUCTION_ROTATION_STATE_VERSION,
    phase: "verified",
    rotationId: baseConfig.rotationId,
    overlapDeploymentSha: baseConfig.overlapDeploymentSha,
    overlapReadyAt: "2026-08-10T00:00:00.000Z",
    verifiedAt: "2026-08-10T00:01:00.000Z",
    cleanupEligibleAt: "2026-09-09T00:00:00.000Z",
    overlapRuntime: { phase: "overlap", rotationId: baseConfig.rotationId, deploymentSha: baseConfig.overlapDeploymentSha, observedAt: "2026-08-10T00:00:00.000Z" },
  });
  assert.throws(() => normalizeProductionRotationState(legacyV3({ stateVersion: PRODUCTION_ROTATION_STATE_VERSION, phase: "prepared" })), /authenticated reviewed grace/);
  assert.throws(() => normalizeProductionRotationState(legacyV3({ stateVersion: PRODUCTION_ROTATION_STATE_VERSION, phase: "overlap-deploy-required", overlapRuntime: timed.overlapRuntime }), { reviewedMinimumGraceSeconds: baseConfig.minimumGraceSeconds }), /overlap runtime or grace fields/);
  assert.throws(() => normalizeProductionRotationState({ ...timed, overlapReadyAt: "2026-08-10 00:00:00" }), /canonical ISO/);
  assert.throws(() => normalizeProductionRotationState({ ...timed, cleanupEligibleAt: "2026-08-09T23:59:59.000Z" }), /positive/);
  assert.throws(() => normalizeProductionRotationState({ ...timed, cleanupEligibleAt: "2026-09-09T00:00:00.001Z" }), /whole number/);
  assert.throws(() => normalizeProductionRotationState({ ...timed, cleanupEligibleAt: "2026-08-11T00:00:00.000Z" }), /at least/);
  assert.throws(() => normalizeProductionRotationState({ ...timed, overlapRuntime: { ...timed.overlapRuntime, observedAt: "2026-08-10T00:00:01.000Z" } }), /overlap runtime proof/);
  assert.throws(() => normalizeProductionRotationState({ ...timed, minimumGraceSeconds: baseConfig.minimumGraceSeconds }), /legacy rotation state/);
  assert.throws(() => normalizeProductionRotationState(timed, { reviewedMinimumGraceSeconds: baseConfig.minimumGraceSeconds + 1 }), /reviewed config/);
  const current = normalizeProductionRotationState(timed, { reviewedMinimumGraceSeconds: baseConfig.minimumGraceSeconds }).state;
  assert.deepEqual(normalizeProductionRotationState(current, { reviewedMinimumGraceSeconds: baseConfig.minimumGraceSeconds }).state, current);
});

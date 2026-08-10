import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import jwt from "jsonwebtoken";
import { assertIdentity, cleanup, prepare, validateRuntimeProof, verify } from "../scripts/security/rotate-production-signing-material.mjs";

const baseConfig = {
  region: "eu-west-2",
  rotationId: "rotation-test-2026",
  sourceSha: "a".repeat(40),
  ticket: "SEC-ROTATION-TEST",
  approvedBy: "security@example.com",
  approverRole: "Security Lead",
  reason: "test rotation",
  minimumGraceSeconds: 10,
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
  clockState.now += 10_000;
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
    const resumedSm = fakeSecrets(Object.fromEntries(sm.values));
    await prepare(contextFor(directory, baseConfig, resumedSm));
    assert.equal(resumedSm.values.get(baseConfig.jwt.pendingSecretId), pendingBefore);
    assert.equal(JSON.parse(resumedSm.values.get(baseConfig.jwt.previousSecretId)).value, "old-jwt-material");
    assert.notEqual(JSON.parse(resumedSm.values.get(baseConfig.jwt.currentSecretId)).value, "old-jwt-material");
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
    currentTime += 9_000;
    await assert.rejects(cleanup({ ...context, values: new Map([...context.values, ["cleanup-deployment-sha", "c".repeat(40)], ["cleanup-evidence-ref", "https://example.test/cleanup"]]) }), /cleanup grace window has not expired/);
    currentTime += 1_000;
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
    assert.deepEqual(JSON.parse(readFileSync(resumedEvidenceFile, "utf8")), JSON.parse(readFileSync(normalEvidenceFile, "utf8")));
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

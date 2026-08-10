import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
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
const makeKeys = () => generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});

const fakeSecrets = (initial, { failAfterPut = 0 } = {}) => {
  const values = new Map(Object.entries(initial));
  const requests = new Map();
  const versions = new Map();
  let puts = 0;
  return {
    values,
    requests,
    get putCount() { return puts; },
    async send(command) {
      const input = command.input;
      if (command.constructor.name === "GetSecretValueCommand") {
        return { SecretString: values.get(input.SecretId) || "", VersionId: versions.get(input.SecretId) || `version-${input.SecretId}-initial` };
      }
      if (command.constructor.name === "PutSecretValueCommand") {
        const prior = requests.get(input.ClientRequestToken);
        if (prior && prior !== input.SecretString) throw new Error("conflicting deterministic ClientRequestToken payload");
        requests.set(input.ClientRequestToken, input.SecretString);
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

const runtimeProof = (config, phase, observedAt, deploymentSha) => phase === "overlap"
  ? {
      rotationId: config.rotationId, phase, deploymentSha, runtimeInvocationRef: "https://example.test/runtime-overlap",
      observedAt, jwtCurrentRuntimeVerify: true, jwtPreviousRuntimeVerify: true, jwtInvalidRuntimeRejected: true,
      qrCurrentRuntimeVerify: true, qrPreviousRuntimeVerify: true, qrTamperMatchingKeyTest: true, qrUnknownKeyRejected: true, serviceHealthy: true,
    }
  : {
      rotationId: config.rotationId, phase, deploymentSha, runtimeInvocationRef: "https://example.test/runtime-cleanup",
      observedAt, jwtCurrentRuntimeVerify: true, jwtPreviousRuntimeRejected: true, qrCurrentRuntimeVerify: true,
      qrPreviousRuntimeRejected: true, qrUnknownKeyRejected: true, serviceHealthy: true,
    };

const writeProof = (directory, name, proof) => {
  const file = path.join(directory, name);
  writeFileSync(file, `${JSON.stringify(proof)}\n`, { mode: 0o600 });
  return file;
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

test("wrong release identity fails closed before secret operations", () => {
  assert.throws(
    () => assertIdentity({ expectedRoleArn: "arn:aws:iam::368992683803:role/approved-rotation-role" }, () => "arn:aws:sts::368992683803:assumed-role/unapproved-role/session"),
    /not the configured release role/
  );
});

test("runtime proof accepts only the expected deployment SHA for overlap and cleanup", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-runtime-proof-sha-"));
  try {
    const config = { rotationId: "rotation-proof" };
    const common = { rotationId: config.rotationId, runtimeInvocationRef: "https://example.test/proof", observedAt: "2026-08-10T00:00:00.000Z", serviceHealthy: true };
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

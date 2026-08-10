import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { assertIdentity, prepare, verify, cleanup } from "../scripts/security/rotate-production-signing-material.mjs";

const config = {
  region: "eu-west-2",
  rotationId: "rotation-test-2026",
  sourceSha: "a".repeat(40),
  ticket: "SEC-ROTATION-TEST",
  approvedBy: "security@example.com",
  approverRole: "Security Lead",
  reason: "test rotation",
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
const fakeSecrets = (initial) => {
  const values = new Map(Object.entries(initial));
  let version = 0;
  return {
    values,
    async send(command) {
      const input = command.input;
      if (command.constructor.name === "GetSecretValueCommand") {
        return { SecretString: values.get(input.SecretId) || "", VersionId: `version-${input.SecretId}` };
      }
      if (command.constructor.name === "PutSecretValueCommand") {
        values.set(input.SecretId, input.SecretString);
        version += 1;
        return { VersionId: `version-${input.SecretId}-${version}` };
      }
      throw new Error(`unexpected command ${command.constructor.name}`);
    },
  };
};

test("prepare, verify, and cleanup are resumable and cleanup is idempotent", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rotation-test-"));
  const stateFile = path.join(directory, "state.json");
  const fixtureFile = path.join(directory, "previous-qr.json");
  const verificationFile = path.join(directory, "verification.json");
  const evidenceFile = path.join(directory, "evidence.json");
  const oldJwt = "old-jwt-material";
  const keys = await import("node:crypto").then(({ generateKeyPairSync }) => generateKeyPairSync("ed25519", {
    privateKeyEncoding: { format: "pem", type: "pkcs8" },
    publicKeyEncoding: { format: "pem", type: "spki" },
  }));
  const sm = fakeSecrets({
    [config.jwt.currentSecretId]: material(oldJwt),
    [config.qr.privateCurrentSecretId]: material(keys.privateKey, { keyVersion: "legacy-v1" }),
    [config.qr.publicCurrentSecretId]: material(keys.publicKey, { keyVersion: "legacy-v1" }),
  });
  const values = new Map([
    ["state-file", stateFile],
    ["fixture-file", fixtureFile],
    ["confirm-cleanup", true],
  ]);
  const context = { config, sm, values, identity: "arn:aws:sts::368992683803:assumed-role/release/test" };
  const output = [];
  const originalLog = console.log;
  console.log = (line) => output.push(String(line));
  try {
    await prepare(context);
    const firstState = readFileSync(stateFile, "utf8");
    const interrupted = JSON.parse(firstState);
    interrupted.phase = "pending-ready";
    writeFileSync(stateFile, `${JSON.stringify(interrupted, null, 2)}\n`);
    await prepare(context);
    assert.equal(JSON.parse(readFileSync(stateFile, "utf8")).phase, "overlap-ready");
    const resumedState = readFileSync(stateFile, "utf8");
    await prepare(context);
    assert.equal(readFileSync(stateFile, "utf8"), resumedState);
    await verify({ ...context, values: new Map([...values, ["verification-out", verificationFile]]) });
    await cleanup({ ...context, values: new Map([...values, ["verification-file", verificationFile], ["cleanup-deployment-sha", "c".repeat(40)], ["cleanup-evidence-ref", "https://example.test/cleanup"], ["evidence-out", evidenceFile]]) });
    const cleaned = readFileSync(stateFile, "utf8");
    await cleanup({ ...context, values: new Map([...values, ["verification-file", verificationFile], ["cleanup-deployment-sha", "c".repeat(40)], ["cleanup-evidence-ref", "https://example.test/cleanup"], ["evidence-out", evidenceFile]]) });
    assert.equal(readFileSync(stateFile, "utf8"), cleaned);
    assert.equal(output.some((line) => line.includes(oldJwt)), false);
  } finally {
    console.log = originalLog;
    rmSync(directory, { recursive: true, force: true });
  }
});

test("wrong release identity fails closed before secret operations", () => {
  assert.throws(
    () => assertIdentity({ expectedRoleArn: "arn:aws:iam::368992683803:role/approved-rotation-role" }, () => "arn:aws:sts::368992683803:assumed-role/unapproved-role/session"),
    /not the configured release role/
  );
});

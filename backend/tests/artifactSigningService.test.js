const assert = require("node:assert/strict");
const { createHash, generateKeyPairSync, sign } = require("node:crypto");

const { signArtifactPayload, validateArtifactSigningConfiguration, verifyArtifactPayload } = require("../dist/services/artifactSigningService.js");

const pair = () => generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});

const original = { ...process.env };
const current = pair();
const historical = pair();
const payload = "{\"artifact\":\"rotation-test\"}";

try {
  process.env.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT = current.privateKey;
  process.env.ARTIFACT_SIGN_PUBLIC_KEY_CURRENT = current.publicKey;
  process.env.ARTIFACT_SIGN_ACTIVE_KEY_VERSION = "v2";
  process.env.ARTIFACT_SIGN_PUBLIC_KEYS_JSON = JSON.stringify({ v1: historical.publicKey, v2: current.publicKey });

  validateArtifactSigningConfiguration();
  const currentEnvelope = signArtifactPayload(payload);
  assert.deepEqual({ algorithm: currentEnvelope.algorithm, keyVersion: currentEnvelope.keyVersion }, { algorithm: "Ed25519", keyVersion: "v2" });
  assert.equal(verifyArtifactPayload(payload, currentEnvelope), true);
  assert.equal(verifyArtifactPayload(`${payload}!`, currentEnvelope), false);
  assert.equal(verifyArtifactPayload(payload, { ...currentEnvelope, signature: `${currentEnvelope.signature}x` }), false);
  assert.equal(verifyArtifactPayload(payload, { ...currentEnvelope, keyVersion: "unknown" }), false);
  assert.equal(verifyArtifactPayload(payload, { ...currentEnvelope, algorithm: "hmac-sha256" }), false);

  const historicalSignature = sign(null, createHash("sha256").update(payload).digest(), historical.privateKey).toString("base64url");
  assert.equal(verifyArtifactPayload(payload, { algorithm: "Ed25519", keyVersion: "v1", signature: historicalSignature }), true);
  assert.equal(verifyArtifactPayload(payload, { algorithm: "Ed25519", keyVersion: "v1", signature: sign(null, createHash("sha256").update(payload).digest(), pair().privateKey).toString("base64url") }), false);

  delete process.env.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT;
  delete process.env.ARTIFACT_SIGN_PUBLIC_KEY_CURRENT;
  delete process.env.ARTIFACT_SIGN_ACTIVE_KEY_VERSION;
  delete process.env.ARTIFACT_SIGN_PUBLIC_KEYS_JSON;
  process.env.JWT_SECRET = "legacy-jwt-fixture";
  process.env.QR_SIGN_HMAC_SECRET = "legacy-qr-fixture";
  assert.throws(() => signArtifactPayload(payload), /ARTIFACT_SIGN_/);
  assert.equal(verifyArtifactPayload(payload, currentEnvelope), false);
} finally {
  for (const key of Object.keys(process.env)) if (!(key in original)) delete process.env[key];
  Object.assign(process.env, original);
}

console.log("artifact signing tests passed");

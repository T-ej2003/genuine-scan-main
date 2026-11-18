const assert = require("node:assert/strict");
const { createHash, generateKeyPairSync, sign } = require("node:crypto");
const jwt = require("jsonwebtoken");

const { getJwtSecret, verifyJwtWithCurrentOrPrevious } = require("../dist/utils/security.js");
const { signQrPayload, verifyQrToken } = require("../dist/services/qrTokenService.js");
const { verifyProductionRotationCleanupRuntime, verifyProductionRotationRuntime } = require("../dist/security/productionRotationRuntime.js");

const keys = () => generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});
const payload = (kid) => ({ qr_id: "rotation-test", batch_id: null, licensee_id: "rotation", iat: 1_700_000_000, nonce: "rotation-nonce", kid });
const restore = { ...process.env };

try {
  process.env.JWT_SECRET_CURRENT = "jwt-current";
  process.env.JWT_SECRET_PREVIOUS = "jwt-previous";
  assert.equal(getJwtSecret(), "jwt-current");
  assert.equal(verifyJwtWithCurrentOrPrevious("old", (secret) => {
    if (secret === "jwt-previous") return "previous-ok";
    throw new Error("not previous");
  }), "previous-ok");
  process.env.JWT_SECRET_PREVIOUS = "jwt-current";
  assert.throws(() => getJwtSecretSetForTest(), /different/);
  process.env.JWT_SECRET_PREVIOUS = "jwt-previous";

  const old = keys();
  const current = keys();
  const artifact = keys();
  const artifactHistorical = keys();
  process.env.QR_SIGN_PRIVATE_KEY_CURRENT = current.privateKey;
  process.env.QR_SIGN_PUBLIC_KEY_CURRENT = current.publicKey;
  process.env.QR_SIGN_ACTIVE_KEY_VERSION = "current-v2";
  process.env.QR_SIGN_PUBLIC_KEY_PREVIOUS = old.publicKey;
  process.env.QR_SIGN_PREVIOUS_KEY_VERSION = "old-v1";
  process.env.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT = artifact.privateKey;
  process.env.ARTIFACT_SIGN_PUBLIC_KEY_CURRENT = artifact.publicKey;
  process.env.ARTIFACT_SIGN_ACTIVE_KEY_VERSION = "artifact-v1";
  process.env.ARTIFACT_SIGN_PUBLIC_KEYS_JSON = JSON.stringify({ "artifact-old": artifactHistorical.publicKey, "artifact-v1": artifact.publicKey });
  delete process.env.QR_SIGN_PRIVATE_KEY;
  delete process.env.QR_SIGN_PUBLIC_KEY;
  const currentToken = signQrPayload(payload("current-v2"));
  assert.equal(verifyQrToken(currentToken).signing.keyVersion, "current-v2");

  process.env.QR_SIGN_PRIVATE_KEY_CURRENT = old.privateKey;
  process.env.QR_SIGN_PUBLIC_KEY_CURRENT = old.publicKey;
  process.env.QR_SIGN_ACTIVE_KEY_VERSION = "old-v1";
  delete process.env.QR_SIGN_PUBLIC_KEY_PREVIOUS;
  delete process.env.QR_SIGN_PREVIOUS_KEY_VERSION;
  const oldToken = signQrPayload(payload("old-v1"));

  process.env.QR_SIGN_PRIVATE_KEY_CURRENT = current.privateKey;
  process.env.QR_SIGN_PUBLIC_KEY_CURRENT = current.publicKey;
  process.env.QR_SIGN_ACTIVE_KEY_VERSION = "current-v2";
  process.env.QR_SIGN_PUBLIC_KEY_PREVIOUS = old.publicKey;
  process.env.QR_SIGN_PREVIOUS_KEY_VERSION = "old-v1";
  assert.equal(verifyQrToken(oldToken).signing.keyVersion, "old-v1");
  delete process.env.QR_SIGN_PUBLIC_KEY_PREVIOUS;
  delete process.env.QR_SIGN_PREVIOUS_KEY_VERSION;
  assert.throws(() => verifyQrToken(oldToken), /could not be verified/,
    "retired label keys must fail closed when their public key is unavailable");
  process.env.QR_SIGN_PUBLIC_KEYS_JSON = JSON.stringify({ "old-v1": old.publicKey });
  assert.equal(verifyQrToken(oldToken).signing.keyVersion, "old-v1",
    "retained public keys keep old physical labels verifiable without retaining signing authority");
  process.env.QR_SIGN_PUBLIC_KEYS_JSON = JSON.stringify({ family: "qr_signing_keys", slot: "previous-retired", value: "", retainedPublicKeys: { "old-v1": old.publicKey } });
  assert.equal(verifyQrToken(oldToken).signing.keyVersion, "old-v1", "the existing previous-key secret carries the durable public archive after retirement");
  process.env.QR_SIGN_PUBLIC_KEYS_JSON = JSON.stringify({ family: "qr_signing_keys", slot: "previous-retired", value: "", retainedPublicKeys: {} });
  assert.throws(() => verifyQrToken(oldToken), /could not be verified/, "revoking an archived key blocks its labels");
  process.env.QR_SIGN_PUBLIC_KEYS_JSON = JSON.stringify({ family: "qr_signing_keys", slot: "previous-retired", value: "", retainedPublicKeys: { "old-v1": old.privateKey } });
  assert.throws(() => verifyQrToken(oldToken), /must not contain private keys/);
  const newest = keys();
  process.env.QR_SIGN_PRIVATE_KEY_CURRENT = newest.privateKey;
  process.env.QR_SIGN_PUBLIC_KEY_CURRENT = newest.publicKey;
  process.env.QR_SIGN_ACTIVE_KEY_VERSION = "newest-v3";
  process.env.QR_SIGN_PUBLIC_KEY_PREVIOUS = current.publicKey;
  process.env.QR_SIGN_PREVIOUS_KEY_VERSION = "current-v2";
  process.env.QR_SIGN_PUBLIC_KEYS_JSON = JSON.stringify({ family: "qr_signing_keys", slot: "previous", value: current.publicKey, retainedPublicKeys: { "old-v1": old.publicKey } });
  assert.equal(verifyQrToken(oldToken).signing.keyVersion, "old-v1", "two rotations preserve signed historical labels");
  assert.equal(verifyQrToken(currentToken).signing.keyVersion, "current-v2");
  process.env.QR_SIGN_PRIVATE_KEY_CURRENT = current.privateKey;
  process.env.QR_SIGN_PUBLIC_KEY_CURRENT = current.publicKey;
  process.env.QR_SIGN_ACTIVE_KEY_VERSION = "current-v2";
  delete process.env.QR_SIGN_PUBLIC_KEY_PREVIOUS;
  delete process.env.QR_SIGN_PREVIOUS_KEY_VERSION;
  process.env.QR_SIGN_PUBLIC_KEYS_JSON = JSON.stringify({ "old-v1": old.publicKey });
  assert.throws(() => verifyQrToken(`${oldToken.slice(0, -1)}x`), /could not be verified/);
  process.env.QR_SIGN_PUBLIC_KEYS_JSON = JSON.stringify({ "old-v1": current.publicKey });
  assert.throws(() => verifyQrToken(oldToken), /must not alias an existing public key/);
  process.env.QR_SIGN_PUBLIC_KEYS_JSON = JSON.stringify({ "old-v1": old.privateKey });
  assert.throws(() => verifyQrToken(oldToken), /must not contain private keys/);
  process.env.QR_SIGN_PUBLIC_KEYS_JSON = JSON.stringify({ "old-v1": Buffer.from(old.privateKey).toString("base64") });
  assert.throws(() => verifyQrToken(oldToken), /must not contain private keys/);
  delete process.env.QR_SIGN_PUBLIC_KEYS_JSON;
  process.env.QR_SIGN_PUBLIC_KEY_PREVIOUS = old.publicKey;
  process.env.QR_SIGN_PREVIOUS_KEY_VERSION = "old-v1";
  assert.throws(() => signQrPayload(payload("old-v1")), /active key version/);
  assert.throws(() => verifyQrToken(`${oldToken.slice(0, -1)}x`), /could not be verified/);
  assert.throws(() => verifyQrToken(signQrPayload(payload("unknown"))), /active key version/);

  const preparedCurrentJwtToken = jwt.sign({ rotationId: "prepared-new-current" }, "jwt-current", { algorithm: "HS256" });
  const preparedPreviousJwtToken = jwt.sign({ rotationId: "prepared-old-current" }, "jwt-previous", { algorithm: "HS256" });
  const artifactHistoricalPayload = JSON.stringify({ artifact: "historical-runtime-fixture" });
  const artifactHistoricalSignature = {
    algorithm: "Ed25519",
    keyVersion: "artifact-old",
    signature: sign(null, createHash("sha256").update(artifactHistoricalPayload).digest(), artifactHistorical.privateKey).toString("base64url"),
  };
  const healthEvidence = { serviceHealthy: true, healthHttpStatus: 200, healthReleaseGitSha: "a".repeat(40), expectedReleaseGitSha: "a".repeat(40), healthObservedAt: new Date().toISOString() };
  const overlapRuntime = verifyProductionRotationRuntime({ currentJwtToken: preparedCurrentJwtToken, previousJwtToken: preparedPreviousJwtToken, qrFixtureToken: oldToken, historicalContinuity: "VERIFIED_PREVIOUS_QR", artifactHistoricalPayload, artifactHistoricalSignature, healthEvidence });
  assert.deepEqual(overlapRuntime, {
    jwtCurrentRuntimeVerify: true,
    jwtPreviousRuntimeVerify: true,
    jwtInvalidRuntimeRejected: true,
    qrCurrentRuntimeVerify: true,
    qrPreviousRuntimeVerify: true,
    historicalContinuity: "VERIFIED_PREVIOUS_QR",
    legacyQrKeypairUnrecoverable: false,
    qrPreviousSlotAbsent: false,
    qrTamperMatchingKeyTest: true,
    qrUnknownKeyRejected: true,
    artifactCurrentRuntimeVerify: true,
    artifactHistoricalRuntimeVerify: true,
    serviceHealthy: true,
    healthHttpStatus: 200,
    healthReleaseGitSha: "a".repeat(40),
    expectedReleaseGitSha: "a".repeat(40),
    healthObservedAt: healthEvidence.healthObservedAt,
  });
  delete process.env.JWT_SECRET_PREVIOUS;
  assert.throws(() => verifyProductionRotationRuntime({ currentJwtToken: preparedCurrentJwtToken, previousJwtToken: preparedPreviousJwtToken, qrFixtureToken: oldToken, historicalContinuity: "VERIFIED_PREVIOUS_QR", healthEvidence }), /JWT_SECRET_PREVIOUS/);
  process.env.JWT_SECRET_PREVIOUS = "jwt-previous";

  process.env.JWT_SECRET_CURRENT = "wrong-current";
  assert.throws(() => verifyProductionRotationRuntime({ currentJwtToken: preparedCurrentJwtToken, previousJwtToken: preparedPreviousJwtToken, qrFixtureToken: oldToken, historicalContinuity: "VERIFIED_PREVIOUS_QR", healthEvidence }), /invalid signature|Invalid token|current/i);
  process.env.JWT_SECRET_CURRENT = "jwt-current";
  process.env.JWT_SECRET_PREVIOUS = "wrong-previous";
  assert.throws(() => verifyProductionRotationRuntime({ currentJwtToken: preparedCurrentJwtToken, previousJwtToken: preparedPreviousJwtToken, qrFixtureToken: oldToken, historicalContinuity: "VERIFIED_PREVIOUS_QR", healthEvidence }), /invalid signature|Invalid token|previous/i);
  process.env.JWT_SECRET_PREVIOUS = "jwt-previous";

  delete process.env.QR_SIGN_PUBLIC_KEY_PREVIOUS;
  delete process.env.QR_SIGN_PREVIOUS_KEY_VERSION;
  const initialMigrationRuntime = verifyProductionRotationRuntime({ currentJwtToken: preparedCurrentJwtToken, previousJwtToken: preparedPreviousJwtToken, qrFixtureToken: currentToken, historicalContinuity: "LEGACY_QR_KEYPAIR_UNRECOVERABLE", healthEvidence });
  assert.equal(initialMigrationRuntime.qrPreviousRuntimeVerify, false);
  assert.equal(initialMigrationRuntime.legacyQrKeypairUnrecoverable, true);
  assert.equal(initialMigrationRuntime.qrPreviousSlotAbsent, true);
  process.env.QR_SIGN_PUBLIC_KEY_PREVIOUS = old.publicKey;
  process.env.QR_SIGN_PREVIOUS_KEY_VERSION = "old-v1";
  assert.throws(() => verifyProductionRotationRuntime({ currentJwtToken: preparedCurrentJwtToken, previousJwtToken: preparedPreviousJwtToken, qrFixtureToken: currentToken, historicalContinuity: "LEGACY_QR_KEYPAIR_UNRECOVERABLE", healthEvidence }), /must not be trusted/);

  delete process.env.JWT_SECRET_PREVIOUS;
  delete process.env.QR_SIGN_PUBLIC_KEY_PREVIOUS;
  delete process.env.QR_SIGN_PREVIOUS_KEY_VERSION;
  const cleanupRuntime = verifyProductionRotationCleanupRuntime({ currentJwtToken: preparedCurrentJwtToken, previousJwtToken: preparedPreviousJwtToken, qrFixtureToken: oldToken, historicalContinuity: "VERIFIED_PREVIOUS_QR", artifactHistoricalPayload, artifactHistoricalSignature, healthEvidence });
  assert.equal(cleanupRuntime.jwtPreviousRuntimeRejected, true);
  assert.equal(cleanupRuntime.qrPreviousRuntimeRejected, true);
  assert.equal(cleanupRuntime.jwtCurrentRuntimeVerify, true);
  assert.equal(cleanupRuntime.qrCurrentRuntimeVerify, true);
  assert.equal(cleanupRuntime.artifactHistoricalRuntimeVerify, true);

  assert.throws(() => verifyProductionRotationRuntime({ currentJwtToken: preparedCurrentJwtToken, previousJwtToken: preparedPreviousJwtToken, qrFixtureToken: oldToken, historicalContinuity: "VERIFIED_PREVIOUS_QR", healthEvidence: { ...healthEvidence, serviceHealthy: false } }), /health/i);
  assert.throws(() => verifyProductionRotationRuntime({ currentJwtToken: preparedCurrentJwtToken, previousJwtToken: preparedPreviousJwtToken, qrFixtureToken: oldToken, historicalContinuity: "VERIFIED_PREVIOUS_QR", healthEvidence: { ...healthEvidence, healthHttpStatus: 500 } }), /health/i);
  assert.throws(() => verifyProductionRotationRuntime({ currentJwtToken: preparedCurrentJwtToken, previousJwtToken: preparedPreviousJwtToken, qrFixtureToken: oldToken, historicalContinuity: "VERIFIED_PREVIOUS_QR", healthEvidence: { ...healthEvidence, healthReleaseGitSha: "b".repeat(40) } }), /health/i);
  assert.throws(() => verifyProductionRotationRuntime({ currentJwtToken: preparedCurrentJwtToken, previousJwtToken: preparedPreviousJwtToken, qrFixtureToken: oldToken, historicalContinuity: "VERIFIED_PREVIOUS_QR", healthEvidence: { ...healthEvidence, healthObservedAt: new Date(Date.now() - 301_000).toISOString() } }), /health/i);
} finally {
  for (const key of Object.keys(process.env)) {
    if (!(key in restore)) delete process.env[key];
  }
  Object.assign(process.env, restore);
}

function getJwtSecretSetForTest() {
  delete require.cache[require.resolve("../dist/utils/secretConfig.js")];
  const { getJwtSecretSet } = require("../dist/utils/secretConfig.js");
  return getJwtSecretSet();
}

console.log("rotation dual-slot runtime tests passed");

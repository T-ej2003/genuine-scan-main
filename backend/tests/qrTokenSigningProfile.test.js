const assert = require("assert");

process.env.QR_SIGN_HMAC_SECRET_CURRENT = "qr-token-signing-profile-secret";
delete process.env.QR_SIGN_PRIVATE_KEY;
delete process.env.QR_SIGN_PUBLIC_KEY;
delete process.env.QR_SIGN_ACTIVE_KEY_VERSION;
delete process.env.QR_SIGN_KMS_KEY_REF;
delete process.env.QR_SIGN_KMS_VERIFY_KEY_REF;

const {
  getQrSigningProfile,
  signQrPayload,
  verifyQrToken,
} = require("../dist/services/qrTokenService");

const signingProfile = getQrSigningProfile();
const token = signQrPayload({
  qr_id: "qr-signing-profile-1",
  batch_id: "batch-signing-profile-1",
  licensee_id: "lic-signing-profile-1",
  iat: Math.floor(Date.now() / 1000),
  nonce: "nonce-signing-profile-1",
});

const verified = verifyQrToken(token);

assert.strictEqual(signingProfile.mode, "hmac", "test profile should use HMAC mode when only the HMAC secret is configured");
assert.ok(verified.payload.kid, "signed QR payload should carry a key version");
assert.strictEqual(
  verified.payload.kid,
  signingProfile.keyVersion,
  "signQrPayload should inject the active signing key version when payload.kid is omitted"
);
assert.strictEqual(verified.signing.mode, "hmac");
assert.strictEqual(verified.signing.keyVersion, signingProfile.keyVersion);
assert.strictEqual(verified.signing.payloadKeyVersion, verified.payload.kid);

console.log("qr token signing profile tests passed");

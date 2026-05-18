const assert = require("assert");

process.env.QR_SIGN_PROVIDER = "managed";
process.env.QR_SIGN_KMS_KEY_REF = "kms://projects/mscqr/locations/global/keyRings/platform/cryptoKeys/qr-sign";
process.env.QR_SIGN_KMS_VERIFY_KEY_REF = "kms://projects/mscqr/locations/global/keyRings/platform/cryptoKeys/qr-sign/cryptoKeyVersions/1";
const TEST_KEY_VERSION = "v1";
process.env.QR_SIGN_ACTIVE_KEY_VERSION = TEST_KEY_VERSION;
delete process.env.QR_SIGN_PRIVATE_KEY;
delete process.env.QR_SIGN_PUBLIC_KEY;
delete process.env.QR_SIGN_HMAC_SECRET;
delete process.env.QR_SIGN_HMAC_SECRET_CURRENT;

const {
  clearManagedQrSignerBridge,
  getQrSigningProfile,
  registerManagedQrSignerBridge,
  signQrPayload,
  verifyQrToken,
} = require("../dist/services/qrTokenService");

clearManagedQrSignerBridge();

assert.throws(
  () => getQrSigningProfile(),
  /no managed signer bridge is registered/i,
  "managed signing should fail closed when no bridge is registered"
);

registerManagedQrSignerBridge({
  keyVersion: TEST_KEY_VERSION,
  keyRef: "kms://projects/mscqr/locations/global/keyRings/platform/cryptoKeys/qr-sign/cryptoKeyVersions/1",
  sign(payloadHash) {
    return Buffer.from(`managed:${payloadHash.toString("hex")}`, "utf8");
  },
  verify({ payloadHash, signature }) {
    const expected = Buffer.from(`managed:${payloadHash.toString("hex")}`, "utf8");
    return {
      valid: expected.equals(signature),
      keyVersion: TEST_KEY_VERSION,
      keyRef: "kms://projects/mscqr/locations/global/keyRings/platform/cryptoKeys/qr-sign/cryptoKeyVersions/1",
    };
  },
});

const profile = getQrSigningProfile();
assert.strictEqual(profile.mode, "ed25519");
assert.strictEqual(profile.provider, "kms-bridge");
assert.strictEqual(profile.keyVersion, TEST_KEY_VERSION);

const token = signQrPayload({
  qr_id: "qr-managed-1",
  batch_id: "batch-managed-1",
  licensee_id: "lic-managed-1",
  iat: Math.floor(Date.now() / 1000),
  nonce: "nonce-managed-1",
});

const verified = verifyQrToken(token);
assert.strictEqual(verified.signing.provider, "kms-bridge");
assert.strictEqual(verified.signing.keyVersion, TEST_KEY_VERSION);
assert.strictEqual(verified.signing.payloadKeyVersion, TEST_KEY_VERSION);

clearManagedQrSignerBridge();

console.log("managed QR signer bridge tests passed");

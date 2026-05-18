const assert = require("assert");
const { generateKeyPairSync } = require("crypto");

delete process.env.QR_SIGN_HMAC_SECRET;
delete process.env.QR_SIGN_HMAC_SECRET_CURRENT;
delete process.env.QR_SIGN_PROVIDER;
delete process.env.QR_SIGN_KMS_KEY_REF;
delete process.env.QR_SIGN_KMS_VERIFY_KEY_REF;

const {
  signQrPayload,
  validateQrSigningConfiguration,
  verifyQrToken,
} = require("../dist/services/qrTokenService");

const payload = {
  qr_id: "qr-key-normalization-1",
  batch_id: "batch-key-normalization-1",
  licensee_id: "licensee-key-normalization-1",
  manufacturer_id: "manufacturer-key-normalization-1",
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
  nonce: "nonce-key-normalization-1",
};

const TEST_KEY_VERSION = "v1";

const setEd25519Keys = (transform = (value) => value) => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  process.env.QR_SIGN_PRIVATE_KEY = transform(privateKey.export({ type: "pkcs8", format: "pem" }).toString());
  process.env.QR_SIGN_PUBLIC_KEY = transform(publicKey.export({ type: "spki", format: "pem" }).toString());
  process.env.QR_SIGN_ACTIVE_KEY_VERSION = TEST_KEY_VERSION;
};

const assertRoundTrip = (message) => {
  const profile = validateQrSigningConfiguration();
  const token = signQrPayload(payload);
  const verified = verifyQrToken(token);
  assert.strictEqual(profile.mode, "ed25519", message);
  assert.strictEqual(verified.payload.qr_id, payload.qr_id, message);
  assert.strictEqual(verified.signing.keyVersion, TEST_KEY_VERSION, message);
};

setEd25519Keys((value) => JSON.stringify(value.replace(/\n/g, "\\n")));
assertRoundTrip("Quoted escaped PEM keys should import and sign");

setEd25519Keys((value) => Buffer.from(value, "utf8").toString("base64"));
assertRoundTrip("Base64-wrapped PEM keys should import and sign");

process.env.QR_SIGN_PRIVATE_KEY = "not a pem key";
process.env.QR_SIGN_PUBLIC_KEY = "not a pem key";
let failed = false;
try {
  signQrPayload(payload);
} catch (error) {
  failed = true;
  assert.strictEqual(error.code, "QR_SIGNING_CONFIGURATION_INVALID");
  assert(error.safeCryptoMetadata, "Invalid key errors should carry safe crypto metadata");
  assert.strictEqual(error.safeCryptoMetadata.errorCode, "ERR_OSSL_UNSUPPORTED");
}
assert(failed, "Invalid QR signing key material should fail with a precise configuration error");

const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
process.env.QR_SIGN_PRIVATE_KEY = rsa.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
process.env.QR_SIGN_PUBLIC_KEY = rsa.publicKey.export({ type: "spki", format: "pem" }).toString();
failed = false;
try {
  signQrPayload(payload);
} catch (error) {
  failed = true;
  assert.strictEqual(error.code, "QR_SIGNING_KEY_TYPE_UNSUPPORTED");
  assert.strictEqual(error.safeCryptoMetadata.privateKeyType, "rsa");
}
assert(failed, "RSA keys must not be accepted for Ed25519 QR signing");

console.log("qr token key normalization tests passed");

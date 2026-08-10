const assert = require("node:assert/strict");
const { generateKeyPairSync } = require("node:crypto");

const { getJwtSecret, verifyJwtWithCurrentOrPrevious } = require("../dist/utils/security.js");
const { signQrPayload, verifyQrToken } = require("../dist/services/qrTokenService.js");

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
  process.env.QR_SIGN_PRIVATE_KEY_CURRENT = current.privateKey;
  process.env.QR_SIGN_PUBLIC_KEY_CURRENT = current.publicKey;
  process.env.QR_SIGN_ACTIVE_KEY_VERSION = "current-v2";
  process.env.QR_SIGN_PUBLIC_KEY_PREVIOUS = old.publicKey;
  process.env.QR_SIGN_PREVIOUS_KEY_VERSION = "old-v1";
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
  assert.throws(() => signQrPayload(payload("old-v1")), /active key version/);
  assert.throws(() => verifyQrToken(`${oldToken.slice(0, -1)}x`), /could not be verified/);
  assert.throws(() => verifyQrToken(signQrPayload(payload("unknown"))), /active key version/);
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

const assert = require("assert");

process.env.QR_SIGN_HMAC_SECRET_CURRENT = "internal-release-signing-profile-test-secret";
process.env.QR_SIGN_PROVIDER = "env";
delete process.env.QR_SIGN_PRIVATE_KEY;
delete process.env.QR_SIGN_PUBLIC_KEY;
delete process.env.QR_SIGN_KMS_KEY_REF;
delete process.env.QR_SIGN_KMS_VERIFY_KEY_REF;

const { internalReleaseMetadata } = require("../dist/controllers/healthController");

const req = {};
const res = {
  payload: null,
  json(value) {
    this.payload = value;
    return this;
  },
};

internalReleaseMetadata(req, res);

assert.strictEqual(res.payload?.success, true, "internal release metadata should be successful");
assert(res.payload?.gitSha, "internal release metadata should include gitSha");
assert(res.payload?.signing, "internal release metadata should include signing profile");
assert.strictEqual(res.payload.signing.provider, "env");
assert(["hmac", "ed25519"].includes(res.payload.signing.mode), "signing mode should be hmac or ed25519");
assert(res.payload.signing.keyVersion, "internal release metadata should include signing key version");

console.log("internal release metadata signing profile test passed");

const { generateKeyPairSync } = require("crypto");
const { signQrPayload, verifyQrToken } = require("../dist/services/qrTokenService");
const { evaluateScanPolicy } = require("../dist/services/scanPolicy");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const setupKeys = () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  process.env.QR_SIGN_PRIVATE_KEY = privateKey
    .export({ type: "pkcs8", format: "pem" })
    .toString()
    .replace(/\n/g, "\\n");
  process.env.QR_SIGN_PUBLIC_KEY = publicKey
    .export({ type: "spki", format: "pem" })
    .toString()
    .replace(/\n/g, "\\n");
};

const run = () => {
  setupKeys();

  const payload = {
    qr_id: "test-qr-id",
    batch_id: "batch-id",
    licensee_id: "licensee-id",
    manufacturer_id: "m-id",
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
    nonce: "nonce-1",
  };

  const token = signQrPayload(payload);
  const verified = verifyQrToken(token).payload;
  assert(verified.qr_id === payload.qr_id, "Token verification should succeed");

  // signature verification failure
  const tampered = token.slice(0, -1) + (token.slice(-1) === "a" ? "b" : "a");
  let threw = false;
  try {
    verifyQrToken(tampered);
  } catch {
    threw = true;
  }
  assert(threw, "Tampered token should fail signature verification");

  // scan policy checks
  const firstScan = evaluateScanPolicy("PRINTED");
  assert(firstScan.allowRedeem, "Printed QR should allow redeem");

  const secondScan = evaluateScanPolicy("REDEEMED");
  assert(secondScan.outcome === "ALREADY_REDEEMED", "Second scan should be flagged as already redeemed");

  const prePrint = evaluateScanPolicy("ACTIVATED");
  assert(prePrint.outcome === "SUSPICIOUS", "Scan before print confirm should be suspicious");

  const blocked = evaluateScanPolicy("BLOCKED");
  assert(blocked.outcome === "BLOCKED", "Blocked QR should be invalid");

  console.log("scan security tests passed");
};

run();

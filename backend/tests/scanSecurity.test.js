const { generateKeyPairSync } = require("crypto");
const { signQrPayload, verifyQrToken } = require("../dist/services/qrTokenService");
const { evaluateScanPolicy } = require("../dist/services/scanPolicy");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const setupKeys = () => {
  delete process.env.QR_SIGN_HMAC_SECRET;
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

const setupHmac = () => {
  delete process.env.QR_SIGN_PRIVATE_KEY;
  delete process.env.QR_SIGN_PUBLIC_KEY;
  process.env.QR_SIGN_HMAC_SECRET = "scan-security-test-hmac-secret";
};

const assertThrows = (fn, message) => {
  let threw = false;
  try {
    fn();
  } catch {
    threw = true;
  }
  assert(threw, message);
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
  assertThrows(() => verifyQrToken(tampered), "Tampered token should fail signature verification");
  assertThrows(() => verifyQrToken(`${token}.x`), "Token with extra segments should fail");
  assertThrows(() => verifyQrToken("$$$.@@@"), "Invalid base64url encoding should fail");

  // HMAC fallback checks
  setupHmac();
  const hmacToken = signQrPayload(payload);
  const hmacVerified = verifyQrToken(hmacToken).payload;
  assert(hmacVerified.qr_id === payload.qr_id, "HMAC token verification should succeed");
  const hmacTampered = hmacToken.slice(0, -1) + (hmacToken.slice(-1) === "a" ? "b" : "a");
  assertThrows(() => verifyQrToken(hmacTampered), "Tampered HMAC token should fail");

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

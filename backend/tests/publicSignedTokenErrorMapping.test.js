const assert = require("node:assert/strict");
const path = require("node:path");

const distRoot = path.resolve(__dirname, "../dist");
const mockModule = (relativePath, exportsValue) => {
  const resolved = require.resolve(path.join(distRoot, relativePath));
  require.cache[resolved] = { id: resolved, filename: resolved, loaded: true, exports: exportsValue };
};

const repositoryModule = require("../dist/rls-waves/session-b/b02/publicBoundaryRepository");
const qrTokenModule = require("../dist/services/qrTokenService");
let scenario = "success";

mockModule("rls-waves/session-b/b01/runtimeClients.js", { getB01PreAuthPrisma: () => ({}) });
mockModule("rls-waves/session-b/b02/publicBoundaryRepository.js", {
  PublicSignedTokenRejectedError: repositoryModule.PublicSignedTokenRejectedError,
  verifyRawQr: async () => null,
  verifySignedQr: async () => {
    if (scenario === "expired") throw new repositoryModule.PublicSignedTokenRejectedError();
    if (["sql-domain", "revoked", "wrong-qr"].includes(scenario)) {
      throw { code: "P2010", meta: { code: "P0001", message: "ERROR: PUBLIC_SIGNED_TOKEN_INVALID\nCONTEXT: hidden SQL" } };
    }
    if (scenario === "direct-domain") throw new Error("PUBLIC_SIGNED_TOKEN_INVALID");
    if (scenario === "unknown-p2010") {
      throw { code: "P2010", meta: { code: "P0001", message: "ERROR: UNREVIEWED_DATABASE_ERROR\nCONTEXT: hidden SQL" } };
    }
    return {
      result: "AUTHENTIC",
      messageKey: "verification.first_scan",
      nextAction: "SAVE_OR_REPORT",
      verificationMethod: "SIGNED_LABEL",
      maskedCode: "********0001",
      brandName: "MSCQR",
      brandWebsite: null,
      brandSupportEmail: null,
      brandSupportPhone: null,
      manufacturerName: null,
      manufacturerWebsite: null,
      printedAt: null,
      firstVerifiedAt: new Date(),
      latestVerifiedAt: new Date(),
      ownershipClaimAvailable: true,
      reportSessionAvailable: true,
      sessionStartToken: "session-start-token",
    };
  },
});
mockModule("services/qrTokenService.js", {
  QrTokenVerificationError: qrTokenModule.QrTokenVerificationError,
  hashToken: () => "a".repeat(64),
  isPrinterTestQrId: () => false,
  verifyQrToken: () => {
    if (scenario === "malformed" || scenario === "bad-signature") throw new qrTokenModule.QrTokenVerificationError();
    if (scenario === "dependency") throw new Error("signing provider unavailable: do not expose");
    return {
      payload: {
        qr_id: "60000000-0000-4000-8000-000000000001",
        licensee_id: "60000000-0000-4000-8000-000000000002",
        batch_id: "60000000-0000-4000-8000-000000000003",
        manufacturer_id: null,
        nonce: "nonce-value",
        epoch: 1,
        kid: "v1",
        iat: Math.floor(Date.now() / 1000) - 1,
        exp: Math.floor(Date.now() / 1000) + 60,
      },
      signing: { keyVersion: "v1" },
    };
  },
});
mockModule("controllers/verify/shared.js", {
  deriveRequestDeviceFingerprint: () => "device",
  hashIp: () => "b".repeat(64),
  hashToken: () => "c".repeat(64),
  normalizeCode: (value) => String(value || "").trim(),
});

const { verifyQRCode } = require("../dist/controllers/verify/verificationHandlers");

const run = async (nextScenario) => {
  scenario = nextScenario;
  const res = {
    statusCode: 200,
    body: null,
    status(code) { this.statusCode = code; return this; },
    json(payload) { this.body = payload; return this; },
  };
  await verifyQRCode({
    params: {},
    query: { t: "signed-token-value" },
    ip: "192.0.2.1",
    get: () => "",
    requestId: "signed-token-error-test",
    customer: null,
  }, res);
  return res;
};

(async () => {
  for (const rejected of [
    "malformed", "bad-signature", "expired", "revoked", "wrong-qr", "sql-domain", "direct-domain",
  ]) {
    const res = await run(rejected);
    assert.equal(res.statusCode, 400, rejected);
    assert.deepEqual(res.body, { success: false, error: "Request could not be verified." });
    assert.doesNotMatch(JSON.stringify(res.body), /P2010|P0001|SQL|signature|token|CONTEXT/i);
  }
  for (const unavailable of ["dependency", "unknown-p2010"]) {
    const res = await run(unavailable);
    assert.equal(res.statusCode, 503, unavailable);
    assert.deepEqual(res.body, {
      success: false,
      degraded: true,
      code: "PUBLIC_VERIFICATION_UNAVAILABLE",
      error: "Verification is temporarily unavailable.",
    });
    assert.doesNotMatch(JSON.stringify(res.body), /P2010|P0001|SQL|provider|CONTEXT/i);
  }
  assert.equal((await run("success")).statusCode, 200);
  console.log("public signed-token error mapping test passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});

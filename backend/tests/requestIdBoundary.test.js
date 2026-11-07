const assert = require("node:assert/strict");
const { createBackendApp } = require("../dist/app");
const { logger } = require("../dist/utils/logger");
const { hashToken } = require("../dist/utils/security");
const tokenService = require("../dist/services/auth/tokenService");
const canonicalAuth = require("../dist/rls-waves/session-b/b01/canonicalAuthContext");
const { sealCookieToken } = require("../dist/services/auth/cookieTokenProtectionService");

const valid = "aaaa5fab-7f42-474f-8014-e735a1fa8803";
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const originalWarn = logger.warn;
const completions = [];
logger.warn = (message, meta) => { if (message === "HTTP request completed") completions.push(meta); };

(async () => {
  const server = await new Promise((resolve) => {
    const listener = createBackendApp().listen(0, "127.0.0.1", () => resolve(listener));
  });
  try {
    const url = `http://127.0.0.1:${server.address().port}/api/dashboard/stats`;
    for (const supplied of [valid, "not-a-uuid", "aaaa5fab-7f42-774f-8014-e735a1fa8803", "x".repeat(129), " "]) {
      const response = await fetch(url, { headers: { "x-request-id": supplied } });
      const observed = response.headers.get("x-request-id");
      assert.equal(response.status, 401, "the protected dashboard route still requires authentication");
      assert.match(observed, uuid);
      if (supplied === valid) assert.equal(observed, valid);
      else assert.notEqual(observed, supplied);
      const meta = completions.at(-1);
      assert.equal(meta.requestId, observed);
      const safeRejected = /^[A-Za-z0-9._:-]{1,128}$/.test(supplied) && supplied !== valid;
      assert.equal(meta.rejectedClientRequestIdRef,
        safeRejected ? hashToken(`client-request-id:${supplied}`) : null);
    }

    const originalVerify = tokenService.verifyAccessToken;
    const originalSession = canonicalAuth.withDatabaseAuthenticatedSession;
    let boundaryInput;
    tokenService.verifyAccessToken = () => ({
      userId: "11111111-1111-4111-8111-111111111111",
      sessionId: "22222222-2222-4222-8222-222222222222",
      role: "MANUFACTURER",
    });
    canonicalAuth.withDatabaseAuthenticatedSession = async (_claims, input) => {
      boundaryInput = input;
      throw new Error("boundary probe stops before database access");
    };
    try {
      const response = await fetch(url, { headers: {
        authorization: "Bearer fixture-access-token",
        "x-database-session-capability": sealCookieToken("A".repeat(43), "auth.database-session"),
        "x-request-id": "x".repeat(129),
      } });
      assert.equal(response.status, 401);
      assert.match(boundaryInput.requestId, uuid, "hydration receives the server UUID instead of the oversized header");
      assert.equal(boundaryInput.capability, "A".repeat(43));
      assert.equal(boundaryInput.purpose, "auth-session-hydration");
    } finally {
      tokenService.verifyAccessToken = originalVerify;
      canonicalAuth.withDatabaseAuthenticatedSession = originalSession;
    }
  } finally {
    logger.warn = originalWarn;
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
  console.log("request ID boundary tests passed");
})().catch((error) => { console.error(error); process.exit(1); });

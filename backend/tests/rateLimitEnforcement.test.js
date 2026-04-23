const assert = require("assert");
const express = require("express");

process.env.PUBLIC_VERIFY_RATE_LIMIT_PER_MIN = "3";

const { loginIpLimiter, loginActorLimiter } = require("../dist/routes/modules/authRoutes");
const {
  verifyCodeIpLimiter,
  verifyCodeActorLimiter,
  verifyClaimRouteLimiter,
  verifyClaimIpLimiter,
  verifyClaimActorLimiter,
  gatewayJobRouteLimiter,
  gatewayJobIpLimiter,
  gatewayJobActorLimiter,
  printMutationRouteLimiter,
  printMutationIpLimiter,
  printMutationActorLimiter,
} = require("../dist/routes/index");

const startServer = (app) =>
  new Promise((resolve) => {
    const server = app.listen(0, "127.0.0.1", () => {
      const address = server.address();
      resolve({
        server,
        baseUrl: `http://127.0.0.1:${address.port}`,
      });
    });
  });

const stopServer = (server) =>
  new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) reject(error);
      else resolve();
    });
  });

const assertRateLimitAfter = async ({
  app,
  path,
  method = "POST",
  body,
  headers,
  allowed,
  description,
}) => {
  const { server, baseUrl } = await startServer(app);
  try {
    for (let index = 0; index < allowed; index += 1) {
      const response = await fetch(`${baseUrl}${path}`, {
        method,
        headers: {
          ...(body ? { "content-type": "application/json" } : {}),
          ...(headers || {}),
        },
        body: body ? JSON.stringify(body) : undefined,
      });

      assert.strictEqual(response.status, 200, `${description} should allow request ${index + 1}`);
    }

    const limited = await fetch(`${baseUrl}${path}`, {
      method,
      headers: {
        ...(body ? { "content-type": "application/json" } : {}),
        ...(headers || {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    });

    assert.strictEqual(limited.status, 429, `${description} should rate-limit the ${allowed + 1}th request`);
  } finally {
    await stopServer(server);
  }
};

const loginApp = express();
loginApp.use(express.json());
loginApp.post("/auth/login", loginIpLimiter, loginActorLimiter, (_req, res) => res.status(200).json({ success: true }));

const verifyCodeApp = express();
verifyCodeApp.get("/verify/:code", verifyCodeIpLimiter, verifyCodeActorLimiter, (_req, res) => res.status(200).json({ success: true }));

const verifyClaimApp = express();
verifyClaimApp.use(express.json());
verifyClaimApp.post(
  "/verify/:code/claim",
  verifyClaimRouteLimiter,
  verifyClaimIpLimiter,
  verifyClaimActorLimiter,
  (_req, res) => res.status(200).json({ success: true })
);

const gatewayJobApp = express();
gatewayJobApp.use(express.json());
gatewayJobApp.post(
  "/print-gateway/direct/claim",
  gatewayJobRouteLimiter,
  gatewayJobIpLimiter,
  gatewayJobActorLimiter,
  (_req, res) => res.status(200).json({ success: true })
);

const printMutationApp = express();
printMutationApp.use(express.json());
printMutationApp.post(
  "/manufacturer/print-jobs",
  printMutationRouteLimiter,
  printMutationIpLimiter,
  printMutationActorLimiter,
  (_req, res) => res.status(200).json({ success: true })
);

(async () => {
  await assertRateLimitAfter({
    app: loginApp,
    path: "/auth/login",
    body: { email: "limit@example.com" },
    allowed: 10,
    description: "auth login",
  });

  await assertRateLimitAfter({
    app: verifyCodeApp,
    path: "/verify/AADS00000020171?device=device-a",
    method: "GET",
    allowed: 20,
    description: "public verify code lookup",
  });

  await assertRateLimitAfter({
    app: verifyClaimApp,
    path: "/verify/AADS00000020171/claim",
    body: { token: "ownership-transfer-token" },
    allowed: 12,
    description: "ownership-sensitive claim flow",
  });

  await assertRateLimitAfter({
    app: gatewayJobApp,
    path: "/print-gateway/direct/claim",
    headers: { "x-printer-gateway-id": "gateway-1" },
    body: { gatewayId: "gateway-1" },
    allowed: 90,
    description: "gateway job claim",
  });

  await assertRateLimitAfter({
    app: printMutationApp,
    path: "/manufacturer/print-jobs",
    body: { printerId: "printer-1" },
    allowed: 40,
    description: "manufacturer print mutation",
  });

  console.log("rate limit enforcement tests passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});

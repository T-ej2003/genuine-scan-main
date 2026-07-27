import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import http from "node:http";
import test from "node:test";

import {
  calculateTotpBoundaryWaitMs,
  decodeBase32Secret,
  generateTotpCode,
} from "../lib/staging-smoke-totp.mjs";

const RFC_TOTP_SECRET = ["GEZD", "GNBV", "GY3T", "QOJQ", "GEZD", "GNBV", "GY3T", "QOJQ"].join("");

const startHtml503Server = async () => {
  const server = http.createServer((req, res) => {
    if (req.url === "/api/health/ready") {
      res.writeHead(503, { "content-type": "text/html; charset=utf-8" });
      res.end("<html><body><h1>503 Service Temporarily Unavailable</h1></body></html>");
      return;
    }

    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ success: false, error: "unexpected smoke path" }));
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    close: () => new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve()))),
  };
};

const startMfaBootstrapServer = async () => {
  let submittedMfaCode = null;
  const server = http.createServer(async (req, res) => {
    const json = (status, payload) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(payload));
    };

    if (req.url === "/api/health/ready") return json(200, { success: true, status: "ready" });
    if (req.url === "/api/health/live") return json(200, { success: true, status: "live" });
    if (req.url === "/api/auth/login" && req.method === "POST") {
      req.resume();
      return json(200, {
        success: true,
        data: {
          auth: {
            sessionStage: "MFA_BOOTSTRAP",
          },
        },
      });
    }
    if (req.url === "/api/auth/mfa/challenge/begin" && req.method === "POST") {
      req.resume();
      return json(200, { success: true, data: { ticket: "smoke-ticket" } });
    }
    if (req.url === "/api/auth/mfa/challenge/complete" && req.method === "POST") {
      let body = "";
      for await (const chunk of req) body += chunk;
      submittedMfaCode = JSON.parse(body).code;
      return json(200, { success: true, data: { auth: { sessionStage: "ACTIVE" } } });
    }
    if (req.url === "/api/auth/me") return json(200, { success: true, data: { user: { role: "ADMIN" } } });
    if (req.url === "/api/internal/release") return json(403, { success: false, error: "admin only" });

    return json(404, { success: false, error: "unexpected smoke path" });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    close: () => new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve()))),
    submittedMfaCode: () => submittedMfaCode,
  };
};

const runSmoke = (baseUrl, env) =>
  new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["scripts/smoke-release.mjs"], {
      cwd: process.cwd(),
      env: {
        ...process.env,
        SMOKE_BASE_URL: baseUrl,
        SMOKE_API_BASE_URL: `${baseUrl}/api`,
        SMOKE_ALLOW_LOCAL_DEFAULT: "false",
        SMOKE_ADMIN_MFA_CODE: "",
        SMOKE_ADMIN_MFA_SECRET: "",
        ...env,
      },
    });

    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", reject);
    child.on("close", (status) => resolve({ status, stdout, stderr }));
  });

test("Base32 decoding accepts canonical padded input and rejects malformed input", () => {
  assert.equal(decodeBase32Secret(["MZX", "W6==="].join("")).toString("utf8"), "foo");
  assert.throws(() => decodeBase32Secret("MZXW6!=="), /valid Base32 secret/);
  assert.throws(() => decodeBase32Secret("A"), /valid Base32 secret/);
});

test("six-digit SHA1 TOTP matches the RFC 6238 vector", () => {
  assert.equal(generateTotpCode(RFC_TOTP_SECRET, 59_000), "287082");
});

test("TOTP boundary wait calculation crosses only the final three-second edge", () => {
  assert.equal(calculateTotpBoundaryWaitMs(27_000), 0);
  assert.equal(calculateTotpBoundaryWaitMs(27_001), 3_000);
  assert.equal(calculateTotpBoundaryWaitMs(29_999), 2);
  assert.equal(calculateTotpBoundaryWaitMs(30_000), 0);
});

test("pull request smoke records HTML 503 readiness as degraded instead of release-blocking", async () => {
  const server = await startHtml503Server();
  try {
    const result = await runSmoke(server.baseUrl, {
      GITHUB_EVENT_NAME: "pull_request",
      SMOKE_REQUIRED: "false",
      ALLOW_STAGING_SMOKE_DEGRADED_ON_PR: "true",
    });

    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.match(result.stdout, /PR smoke degraded\/unavailable; not release-blocking/);
    assert.match(result.stdout, /status=503/);
    assert.match(result.stdout, /content-type=text\/html/);
    assert.match(result.stdout, /503 Service Temporarily Unavailable/);
  } finally {
    await server.close();
  }
});

test("pull request smoke soft-skips MFA bootstrap when smoke MFA code is not configured", async () => {
  const server = await startMfaBootstrapServer();
  try {
    const result = await runSmoke(server.baseUrl, {
      GITHUB_EVENT_NAME: "pull_request",
      SMOKE_REQUIRED: "false",
      ALLOW_STAGING_SMOKE_DEGRADED_ON_PR: "true",
      SMOKE_LOGIN_EMAIL: "admin@example.com",
      SMOKE_LOGIN_PASSWORD: "correct-horse-battery-staple",
      SMOKE_ADMIN_MFA_CODE: "",
      SMOKE_ADMIN_MFA_SECRET: "",
    });

    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.match(result.stdout, /PASS ready health/);
    assert.match(result.stdout, /PASS live health/);
    assert.match(result.stdout, /PASS login/);
    assert.match(result.stdout, /SKIP admin MFA bootstrap completion/);
    assert.match(result.stdout, /SMOKE_REQUIRED=false/);
  } finally {
    await server.close();
  }
});

test("static MFA code overrides the TOTP secret", async () => {
  const server = await startMfaBootstrapServer();
  const malformedSecret = ["must", "not", "be", "decoded"].join("-");
  try {
    const result = await runSmoke(server.baseUrl, {
      GITHUB_EVENT_NAME: "workflow_dispatch",
      SMOKE_REQUIRED: "true",
      SMOKE_LOGIN_EMAIL: "admin@example.com",
      SMOKE_LOGIN_PASSWORD: "correct-horse-battery-staple",
      SMOKE_ADMIN_MFA_CODE: "654321",
      SMOKE_ADMIN_MFA_SECRET: malformedSecret,
    });

    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.equal(server.submittedMfaCode() === "654321", true);
    assert.equal(`${result.stdout}${result.stderr}`.includes(malformedSecret), false);
  } finally {
    await server.close();
  }
});

test("strict smoke retains the missing-MFA failure", async () => {
  const server = await startMfaBootstrapServer();
  try {
    const result = await runSmoke(server.baseUrl, {
      GITHUB_EVENT_NAME: "workflow_dispatch",
      SMOKE_REQUIRED: "true",
      SMOKE_LOGIN_EMAIL: "admin@example.com",
      SMOKE_LOGIN_PASSWORD: "correct-horse-battery-staple",
    });

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Set SMOKE_ADMIN_MFA_CODE or SMOKE_ADMIN_MFA_SECRET/);
    assert.equal(server.submittedMfaCode() === null, true);
  } finally {
    await server.close();
  }
});

test("TOTP secret supplies the MFA challenge code when no static code is configured", async () => {
  const server = await startMfaBootstrapServer();
  try {
    const result = await runSmoke(server.baseUrl, {
      GITHUB_EVENT_NAME: "workflow_dispatch",
      SMOKE_REQUIRED: "true",
      SMOKE_LOGIN_EMAIL: "admin@example.com",
      SMOKE_LOGIN_PASSWORD: "correct-horse-battery-staple",
      SMOKE_ADMIN_MFA_SECRET: RFC_TOTP_SECRET,
    });

    const submittedCode = server.submittedMfaCode();
    const now = Date.now();
    const acceptedCodes = [-30_000, 0, 30_000].map((offset) => generateTotpCode(RFC_TOTP_SECRET, now + offset));
    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.equal(acceptedCodes.includes(submittedCode), true);
    assert.equal(`${result.stdout}${result.stderr}`.includes(RFC_TOTP_SECRET), false);
    assert.equal(`${result.stdout}${result.stderr}`.includes(submittedCode), false);
  } finally {
    await server.close();
  }
});

test("malformed TOTP secret fails closed without leaking its value", async () => {
  const server = await startMfaBootstrapServer();
  const malformedSecret = ["malformed", "seed", "must", "stay", "redacted"].join("-");
  try {
    const result = await runSmoke(server.baseUrl, {
      GITHUB_EVENT_NAME: "workflow_dispatch",
      SMOKE_REQUIRED: "true",
      SMOKE_LOGIN_EMAIL: "admin@example.com",
      SMOKE_LOGIN_PASSWORD: "correct-horse-battery-staple",
      SMOKE_ADMIN_MFA_SECRET: malformedSecret,
    });

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /SMOKE_ADMIN_MFA_SECRET must be a valid Base32 secret/);
    assert.equal(`${result.stdout}${result.stderr}`.includes(malformedSecret), false);
    assert.equal(server.submittedMfaCode() === null, true);
  } finally {
    await server.close();
  }
});

test("strict smoke still fails HTML 503 readiness responses", async () => {
  const server = await startHtml503Server();
  try {
    const result = await runSmoke(server.baseUrl, {
      GITHUB_EVENT_NAME: "workflow_dispatch",
      SMOKE_REQUIRED: "true",
      ALLOW_STAGING_SMOKE_DEGRADED_ON_PR: "false",
    });

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Smoke request expected JSON but received HTML/);
    assert.match(result.stderr, /Status=503/);
  } finally {
    await server.close();
  }
});

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import http from "node:http";
import test from "node:test";

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

const runSmoke = (baseUrl, env) =>
  new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["scripts/smoke-release.mjs"], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      ...env,
      SMOKE_BASE_URL: baseUrl,
      SMOKE_API_BASE_URL: `${baseUrl}/api`,
      SMOKE_ALLOW_LOCAL_DEFAULT: "false",
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

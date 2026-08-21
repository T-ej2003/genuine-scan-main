import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "../..");
const smoke = path.join(root, "scripts/aws/verify-production-smoke.sh");
const sourceSha = "565f78be803558feb40a543ead464c5410738960";
const ready = JSON.stringify({
  success: true,
  status: "ready",
  timestamp: "2026-08-21T00:00:00.000Z",
  release: { gitSha: sourceSha },
  dependencies: {
    database: { configured: true, ready: true },
    redis: { configured: true, ready: true },
    objectStorage: { configured: true, ready: true },
  },
});

function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "production-smoke-readiness-"));
  const curl = path.join(directory, "curl");
  const log = path.join(directory, "urls.log");
  fs.writeFileSync(curl, `#!/bin/sh
set -eu
output=""
url=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) output="$2"; shift 2 ;;
    --write-out) shift 2 ;;
    --silent|--show-error|--disable) shift ;;
    --proto) shift 2 ;;
    *) url="$1"; shift ;;
  esac
done
printf '%s' "$MOCK_CURL_BODY" > "$output"
printf '%s\n' "$url" >> "$MOCK_CURL_LOG"
printf '%s' "\${MOCK_CURL_STATUS:-200}"
`, { mode: 0o700 });
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return { directory, log };
}

function runSmoke(t, body, paths, overrides = {}) {
  const { directory, log } = fixture(t);
  const env = {
    ...process.env,
    PATH: `${directory}:${process.env.PATH}`,
    PUBLIC_BASE_URL: "https://www.mscqr.com",
    MOCK_CURL_BODY: body,
    MOCK_CURL_LOG: log,
    ...(paths ? { SMOKE_PATHS: paths } : {}),
    ...overrides,
  };
  const run = () => execFileSync("bash", [smoke], { cwd: root, env, encoding: "utf8", stdio: "pipe" });
  return { run, urls: () => fs.readFileSync(log, "utf8").trim().split("\n") };
}

test("normal and recovery smoke use the one public Nginx-proxied readiness path", (t) => {
  const normal = runSmoke(t, ready);
  normal.run();
  assert.deepEqual(normal.urls(), [
    "https://www.mscqr.com/",
    "https://www.mscqr.com/login",
    "https://www.mscqr.com/api/health/ready",
  ]);

  const nginx = fs.readFileSync(path.join(root, "nginx.ecs-frontend.conf"), "utf8");
  const workflow = fs.readFileSync(path.join(root, ".github/workflows/release-gate.yml"), "utf8");
  const verifier = fs.readFileSync(smoke, "utf8");
  assert.match(nginx, /location ~ \^\/api\/health\/\?\(\.\*\)\$/);
  assert.match(nginx, /rewrite \^\/api\/health\/\?\(\.\*\)\$ \/health\/\$1 break;/);
  assert.doesNotMatch(nginx, /location[^\n]*\/health\/ready/);
  assert.match(workflow, /--health-url "\$\{\{ env\.PUBLIC_BASE_URL \}\}\/api\/health\/ready"/);
  assert.deepEqual([...workflow.matchAll(/SMOKE_PATHS:\s*([^\n]+)/g)].map((match) => match[1].trim()), ["/api/health/ready"]);
  assert.doesNotMatch(workflow, /`\/health\/ready` passed/);
  assert.match(verifier, /\[\[ "\$path" == "\/api\/health\/ready" \]\]/);
  assert.doesNotMatch(verifier, /--location|\s-L(?:\s|\\)/);
  assert.match(verifier, /--disable/);
});

test("public readiness rejects frontend HTML, malformed JSON, and degraded HTTP-200 payloads", (t) => {
  for (const body of [
    "<!doctype html><html><body>frontend</body></html>",
    "not-json",
    JSON.stringify({ ...JSON.parse(ready), success: false, status: "degraded" }),
  ]) {
    const smokeRun = runSmoke(t, body, "/api/health/ready");
    assert.throws(smokeRun.run);
  }
});

test("healthy canonical public readiness JSON passes semantic verification", (t) => {
  const smokeRun = runSmoke(t, ready, "/api/health/ready");
  assert.match(smokeRun.run(), /Verified https:\/\/www\.mscqr\.com\/api\/health\/ready returned HTTP 200/);
});

test("foreign origins and redirects fail closed", (t) => {
  const foreign = runSmoke(t, ready, "/api/health/ready", { PUBLIC_BASE_URL: "https://example.invalid" });
  assert.throws(foreign.run);

  for (const location of ["https://evil.invalid/api/health/ready", "https://www.mscqr.com/api/health/ready"]) {
    const redirected = runSmoke(t, ready, "/api/health/ready", { MOCK_CURL_STATUS: "302", MOCK_LOCATION: location });
    assert.throws(redirected.run);
  }
});

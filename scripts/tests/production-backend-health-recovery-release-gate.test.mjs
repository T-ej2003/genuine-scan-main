import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import yaml from "js-yaml";
import {
  CONFIRM_ENV,
  CONFIRM_VALUE,
  DATABASE_ENV,
  runCertification,
} from "../rls/certify-full-database.mjs";

const workflow = fs.readFileSync(".github/workflows/release-gate.yml", "utf8");
const parsedWorkflow = yaml.load(workflow);
const rateLimitEnforcementTest = fs.readFileSync("backend/tests/rateLimitEnforcement.test.js", "utf8");

test("release gate exposes one bounded backend health recovery mode", () => {
  assert.match(workflow, /- backend-health-recovery/);
  assert.match(workflow, /backend-health-recovery\)[\s\S]*BACKEND_RECOVERY_CURRENT_TASK_DEFINITION_ARN[\s\S]*BACKEND_RECOVERY_IMAGE_AUTHORIZATION_SHA256[\s\S]*BACKEND_RECOVERY_APPROVAL_SHA256/);
  const recoveryCase = workflow.match(/backend-health-recovery\)([\s\S]*?)\n\s*;;/u)?.[1] || "";
  assert.doesNotMatch(recoveryCase, /check:rotation-evidence-freshness/);
  assert.match(workflow, /Execute governed legacy backend health recovery[\s\S]*recover-production-backend-health\.mjs[\s\S]*--execute/);
  assert.match(workflow, /Upload backend health recovery evidence\n\s*if: \$\{\{ always\(\) && inputs\.release_mode == 'backend-health-recovery' \}\}[\s\S]*backend-health-recovery-evidence[\s\S]*if-no-files-found: ignore/);
  assert.match(workflow, /--health-url "\$\{\{ env\.PUBLIC_BASE_URL \}\}\/api\/health\/ready"/);
  assert.match(workflow, /deploy-production-ecs:[\s\S]*environment: production/);
  assert.match(workflow, /Authenticate production environment approval boundary[\s\S]*approval_dir="\$RUNNER_TEMP\/production-environment-approval"[\s\S]*! -d "\$approval_dir" \|\| -L "\$approval_dir"[\s\S]*install -d -m 700 -- "\$approval_dir"[\s\S]*stat -c '%a'[\s\S]*stat -c '%u'[\s\S]*production-github-environment-approval\.mjs[\s\S]*--environment production[\s\S]*--workflow-ref "\$GITHUB_WORKFLOW_REF"[\s\S]*--event-name "\$GITHUB_EVENT_NAME"[\s\S]*--workflow-run-id "\$GITHUB_RUN_ID"/);
  assert.doesNotMatch(workflow, /evidence_file="\$RUNNER_TEMP\/production-environment-approval\.json"/);
  assert.match(workflow, /Generate and verify checksum-bound production RLS package[\s\S]*approval_dir="\$\(dirname "\$\{\{ steps\.production-environment-approval\.outputs\.evidence_file \}\}"\)"[\s\S]*stat -c '%a'[\s\S]*production-rls-approval\.json/);
  assert.doesNotMatch(workflow, /approval_file="\$RUNNER_TEMP\/production-rls-approval\.json"/);
  assert.doesNotMatch(workflow, /production-github-environment-approval\.mjs[^\n]*--github-token/);
  assert.match(workflow, /--environment-approval "\$\{\{ steps\.production-environment-approval\.outputs\.evidence_file \}\}"[\s\S]*--environment-approval-sha256 "\$\{\{ steps\.production-environment-approval\.outputs\.evidence_sha256 \}\}"/);
  assert.ok(workflow.indexOf("Authenticate production environment approval boundary") < workflow.indexOf("Configure AWS credentials via OIDC"));
});

test("backend recovery cannot enter rotation, frontend, worker, or normal release steps", () => {
  assert.doesNotMatch(workflow, /if: \$\{\{ inputs\.release_mode != 'normal' \}\}/);
  assert.match(workflow, /Deploy rotation transition backend ECS service\n\s*if: \$\{\{ inputs\.release_mode == 'rotation-overlap' \|\| inputs\.release_mode == 'rotation-cleanup' \}\}/);
  assert.match(workflow, /Deploy frontend ECS service\n\s*if: \$\{\{ inputs\.release_mode == 'normal'/);
  assert.match(workflow, /Deploy worker ECS service\n\s*if: \$\{\{ inputs\.release_mode == 'normal'/);
});

test("backend validation closes its shared Redis client before advancing", () => {
  assert.match(workflow, /REDIS_URL: redis:\/\/127\.0\.0\.1:6379\/0/);
  assert.match(rateLimitEnforcementTest, /closeRedisConnections/);
  assert.match(rateLimitEnforcementTest, /\.finally\(closeRedisConnections\)/);
});

test("release gate certifies the same disposable PostgreSQL database used by integration", () => {
  const steps = parsedWorkflow.jobs["deploy-production-ecs"].steps;
  const integration = steps.find((step) => step.name === "Disposable integration tests").run;
  const certification = steps.find((step) => step.name === "Full RLS verification and PostgreSQL 18.4 certification").run;
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-release-gate-rls-"));
  const bin = path.join(directory, "bin");
  const githubEnv = path.join(directory, "github-env");
  const invocations = path.join(directory, "npm-invocations");
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, "npm"), `#!/bin/sh\nprintf '%s\\t%s\\t%s\\t%s\\n' "$*" "\${${CONFIRM_ENV}:-}" "\${${DATABASE_ENV}:-}" "\${P2_TEST_DATABASE_ADMIN_URL:-}" >> "$INVOCATION_LOG"\n`);
  fs.chmodSync(path.join(bin, "npm"), 0o700);

  const env = {
    ...process.env,
    PATH: `${bin}:${process.env.PATH}`,
    GITHUB_ENV: githubEnv,
    INVOCATION_LOG: invocations,
    P2_TEST_DB_PROTOCOL: "postgresql",
    P2_TEST_DB_USER: "mscqr_rls_cert_admin",
    P2_TEST_DB_HOST: "127.0.0.1",
    P2_TEST_DB_PORT: "5432",
    P2_TEST_DB_NAME: "mscqr_p2_integration_test",
  };

  try {
    const integrationResult = spawnSync("bash", ["-e"], { input: integration, env, encoding: "utf8" });
    assert.equal(integrationResult.status, 0, integrationResult.stderr);
    const [name, adminUrl] = fs.readFileSync(githubEnv, "utf8").trim().split("=");
    assert.equal(name, "P2_TEST_DATABASE_ADMIN_URL");
    assert.equal(adminUrl, "postgresql://mscqr_rls_cert_admin@127.0.0.1:5432/mscqr_p2_integration_test");
    assert.equal(parsedWorkflow.jobs["deploy-production-ecs"].services.postgres.env.POSTGRES_USER, "mscqr_rls_cert_admin");
    assert.match(parsedWorkflow.jobs["deploy-production-ecs"].services.postgres.options, /pg_isready -U mscqr_rls_cert_admin/);

    const certificationResult = spawnSync("bash", ["-e"], {
      input: certification,
      env: { ...env, [name]: adminUrl },
      encoding: "utf8",
    });
    assert.equal(certificationResult.status, 0, certificationResult.stderr);
    const calls = fs.readFileSync(invocations, "utf8").trim().split("\n").map((line) => line.split("\t"));
    assert.deepEqual(calls.map(([command]) => command), ["run test:integration:ci", "run rls:full-verify", "run rls:full-certify"]);
    assert.deepEqual(calls.at(-1), ["run rls:full-certify", CONFIRM_VALUE, adminUrl, adminUrl]);
    assert.doesNotMatch(certification, /\|\|\s*true/);

    assert.throws(() => runCertification(adminUrl, {}), /Set MSCQR_FULL_RLS_CERTIFICATION_CONFIRM/);
    assert.throws(() => runCertification("", { [CONFIRM_ENV]: CONFIRM_VALUE }), /valid local PostgreSQL admin URL/);
    assert.throws(
      () => runCertification("postgresql://postgres@production.example.com/mscqr_full_rls_ci", { [CONFIRM_ENV]: CONFIRM_VALUE }),
      /loopback-local/
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

const parseRedisCommand = (buffer) => {
  const headerEnd = buffer.indexOf("\r\n");
  if (headerEnd < 0 || buffer[0] !== 42) return null;
  const count = Number(buffer.subarray(1, headerEnd));
  const parts = [];
  let offset = headerEnd + 2;
  for (let index = 0; index < count; index += 1) {
    const lengthEnd = buffer.indexOf("\r\n", offset);
    if (lengthEnd < 0 || buffer[offset] !== 36) return null;
    const length = Number(buffer.subarray(offset + 1, lengthEnd));
    const valueEnd = lengthEnd + 2 + length;
    if (buffer.length < valueEnd + 2) return null;
    parts.push(buffer.subarray(lengthEnd + 2, valueEnd).toString());
    offset = valueEnd + 2;
  }
  return { parts, rest: buffer.subarray(offset) };
};

test("Redis-backed incident tests advance and exit naturally", async () => {
  const build = spawnSync("npm", ["--prefix", "backend", "run", "build"], { encoding: "utf8" });
  assert.equal(build.status, 0, build.stderr || build.stdout);

  const counters = new Map();
  const expiries = new Map();
  const sockets = new Set();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    let pending = Buffer.alloc(0);
    socket.on("data", (chunk) => {
      pending = Buffer.concat([pending, chunk]);
      for (let parsed; (parsed = parseRedisCommand(pending)); pending = parsed.rest) {
        const [rawCommand, key, rawValue] = parsed.parts;
        const command = rawCommand.toUpperCase();
        if (command === "INCR") {
          const value = (counters.get(key) || 0) + 1;
          counters.set(key, value);
          socket.write(`:${value}\r\n`);
        } else if (command === "PTTL") {
          socket.write(`:${expiries.has(key) ? Math.max(0, expiries.get(key) - Date.now()) : -1}\r\n`);
        } else if (command === "PEXPIRE") {
          expiries.set(key, Date.now() + Number(rawValue));
          socket.write(":1\r\n");
        } else if (command === "INFO") {
          const info = "# Server\r\nredis_version:8.0.0\r\n";
          socket.write(`$${Buffer.byteLength(info)}\r\n${info}\r\n`);
        } else if (command === "PING") {
          socket.write("+PONG\r\n");
        } else {
          socket.write("+OK\r\n");
          if (command === "QUIT") socket.end();
        }
      }
    });
  });

  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const port = server.address().port;
  const child = spawn("bash", ["-c", `"${process.execPath}" tests/incidentMvp.test.js && "${process.execPath}" tests/incidentPdfExport.test.js`], {
    cwd: "backend",
    detached: true,
    env: { ...process.env, REDIS_URL: `redis://127.0.0.1:${port}/0`, REDIS_TLS: "false" },
  });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  let timedOut = false;
  const watchdog = setTimeout(() => {
    timedOut = true;
    process.kill(-child.pid, "SIGTERM");
  }, 15_000);

  try {
    const [code, signal] = await once(child, "close");
    assert.equal(timedOut, false, "incident test chain did not terminate naturally");
    assert.equal(signal, null, `incident test chain was terminated by ${signal}`);
    assert.equal(code, 0, stderr || stdout);
    assert.match(stdout, /incident MVP tests passed/);
    assert.match(stdout, /incident PDF export tests passed/);
  } finally {
    clearTimeout(watchdog);
    for (const socket of sockets) socket.destroy();
    server.close();
    await once(server, "close");
  }
});

test("release gate heredocs parse and backend recovery lifecycle validation executes", () => {
  const heredocSteps = Object.values(parsedWorkflow.jobs).flatMap((job) => job.steps || []).filter((step) => step.run?.includes("<<"));
  for (const step of heredocSteps) {
    const parsed = spawnSync("bash", ["-n"], { input: step.run, encoding: "utf8" });
    assert.equal(parsed.status, 0, `${step.name}: ${parsed.stderr}`);
  }

  const lifecycle = parsedWorkflow.jobs["resolve-deploy-target"].steps.find((step) => step.name === "Validate production release lifecycle mode").run;
  const image = JSON.stringify({ valid: true });
  const approval = JSON.stringify({ approvedBy: "T-ej2003" });
  const env = {
    ...process.env,
    RELEASE_MODE: "backend-health-recovery",
    BACKEND_RECOVERY_CURRENT_TASK_DEFINITION_ARN: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:47",
    BACKEND_RECOVERY_IMAGE_DIGEST: `sha256:${"a".repeat(64)}`,
    BACKEND_RECOVERY_IMAGE_AUTHORIZATION_JSON: image,
    BACKEND_RECOVERY_IMAGE_AUTHORIZATION_SHA256: createHash("sha256").update(image).digest("hex"),
    BACKEND_RECOVERY_APPROVAL_JSON: approval,
    BACKEND_RECOVERY_APPROVAL_SHA256: createHash("sha256").update(approval).digest("hex"),
  };
  assert.equal(spawnSync("bash", ["-e"], { input: lifecycle, env }).status, 0);
  assert.notEqual(spawnSync("bash", ["-e"], { input: lifecycle, env: { ...env, BACKEND_RECOVERY_APPROVAL_SHA256: "0".repeat(64) } }).status, 0);
  assert.notEqual(spawnSync("bash", ["-e"], { input: lifecycle, env: { ...env, RELEASE_MODE: "unsupported" } }).status, 0);
});

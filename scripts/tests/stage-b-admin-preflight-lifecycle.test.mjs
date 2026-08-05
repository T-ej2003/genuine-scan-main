import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  classifyStageBAdminPreflightDeadline,
  runStageBAdminPreflightLifecycle,
  STAGE_B_ADMIN_PREFLIGHT_TIMEOUT_SECONDS,
  STAGE_B_ADMIN_PREFLIGHT_TIMEOUT_MS,
} from "../aws/stage-b-admin-preflight-lifecycle.mjs";
import { STAGE_B_DEPLOYMENT_EVIDENCE_TTL_SECONDS } from "../aws/stage-b-evidence-freshness.mjs";

const temp = () => fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-admin-lifecycle-test-"));
const canonicalizeJson = (value) => Array.isArray(value)
  ? `[${value.map(canonicalizeJson).join(",")}]`
  : value && typeof value === "object"
    ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalizeJson(value[key])}`).join(",")}}`
    : JSON.stringify(value);
const hash = (value) => import("node:crypto").then(({ createHash }) => createHash("sha256").update(value).digest("hex"));
const validPair = async (reportPath, signaturePath) => {
  const report = { status: "valid", nested: { source: "fixture" } };
  const reportSha256 = await hash(Buffer.from(canonicalizeJson(report)));
  fs.writeFileSync(reportPath, `${JSON.stringify(report)}\n`, { mode: 0o600 });
  fs.writeFileSync(signaturePath, `${JSON.stringify({ reportSha256 })}\n`, { mode: 0o600 });
};
const fakeProcessOps = { kill: () => undefined };

function fakeSpawn({ reportPath, signaturePath, code = 0, delayMs = 5, stderr = "", publish = true, closeOnKill = true }) {
  return () => {
    const child = new EventEmitter();
    child.pid = 73001;
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    let timer = setTimeout(async () => {
      if (publish) await validPair(reportPath, signaturePath);
      child.stdout.emit("data", Buffer.from("safe producer output\n"));
      child.stderr.emit("data", Buffer.from(stderr));
      child.emit("close", code, null);
    }, delayMs);
    child.kill = (signal) => {
      clearTimeout(timer);
      child.killedSignal = signal;
      if (closeOnKill) queueMicrotask(() => child.emit("close", null, signal));
      return true;
    };
    return child;
  };
}

function paths() {
  const directory = temp();
  return { directory, repositoryRoot: process.cwd(), lifecycleDirectory: path.join(directory, "lifecycle"), outputPath: path.join(directory, "administrator-capability.json"), signaturePath: path.join(directory, "administrator-capability.signature.json") };
}

test("the 1200-second producer deadline is separate from the 3600-second evidence TTL", () => {
  assert.equal(STAGE_B_ADMIN_PREFLIGHT_TIMEOUT_SECONDS, 1200);
  assert.equal(STAGE_B_ADMIN_PREFLIGHT_TIMEOUT_MS, 1200000);
  assert.equal(STAGE_B_DEPLOYMENT_EVIDENCE_TTL_SECONDS, 3600);
  assert.notEqual(STAGE_B_ADMIN_PREFLIGHT_TIMEOUT_SECONDS, STAGE_B_DEPLOYMENT_EVIDENCE_TTL_SECONDS);
  assert.equal(classifyStageBAdminPreflightDeadline({ active: true, elapsedSeconds: 1199 }), "RUNNING");
  assert.equal(classifyStageBAdminPreflightDeadline({ active: true, elapsedSeconds: 1200 }), "TIMED_OUT");
  assert.equal(classifyStageBAdminPreflightDeadline({ active: false, elapsedSeconds: 1200 }), null);
});

test("delayed publication remains RUNNING until the exact producer exits, then succeeds", async () => {
  const fixture = paths();
  const promise = runStageBAdminPreflightLifecycle({ ...fixture, producerPath: "/reviewed/run-production-green-stage-b-preflight.mjs", cwd: "/reviewed", spawn: fakeSpawn({ reportPath: fixture.outputPath, signaturePath: fixture.signaturePath, delayMs: 30 }), processOps: fakeProcessOps, timeoutMs: 500 });
  await new Promise((resolve) => setTimeout(resolve, 5));
  const running = JSON.parse(fs.readFileSync(path.join(fixture.lifecycleDirectory, "lifecycle.json"), "utf8"));
  assert.equal(running.state, "RUNNING");
  assert.equal(fs.existsSync(fixture.outputPath), false);
  const result = await promise;
  assert.equal(result.state, "SUCCEEDED");
  assert.equal(result.exitCode, 0);
  assert.equal(fs.statSync(path.join(fixture.lifecycleDirectory, "lifecycle.json")).mode & 0o777, 0o600);
});

test("a second invocation is rejected while the first PID is active", async () => {
  const fixture = paths();
  const first = runStageBAdminPreflightLifecycle({ ...fixture, producerPath: "/reviewed/producer.mjs", cwd: "/reviewed", spawn: fakeSpawn({ reportPath: fixture.outputPath, signaturePath: fixture.signaturePath, delayMs: 40 }), processOps: fakeProcessOps, timeoutMs: 500 });
  await new Promise((resolve) => setTimeout(resolve, 5));
  await assert.rejects(() => runStageBAdminPreflightLifecycle({ ...fixture, producerPath: "/reviewed/producer.mjs", cwd: "/reviewed", spawn: fakeSpawn({ reportPath: fixture.outputPath, signaturePath: fixture.signaturePath }), processOps: fakeProcessOps, timeoutMs: 500 }), /already running/);
  assert.equal((await first).state, "SUCCEEDED");
});

test("producer exit failure preserves exit code and stderr without publishing a pair", async () => {
  const fixture = paths();
  const result = await runStageBAdminPreflightLifecycle({ ...fixture, producerPath: "/reviewed/producer.mjs", cwd: "/reviewed", spawn: fakeSpawn({ reportPath: fixture.outputPath, signaturePath: fixture.signaturePath, code: 7, stderr: "AccessDenied: safe summary\n", publish: false }), processOps: fakeProcessOps, timeoutMs: 500 });
  assert.equal(result.state, "FAILED");
  assert.equal(result.exitCode, 7);
  assert.match(fs.readFileSync(result.stderr.path, "utf8"), /AccessDenied/);
  assert.equal(fs.existsSync(fixture.outputPath), false);
  assert.equal(fs.existsSync(fixture.signaturePath), false);
});

test("ExpiredToken remains a hard producer failure", async () => {
  const fixture = paths();
  const result = await runStageBAdminPreflightLifecycle({ ...fixture, producerPath: "/reviewed/producer.mjs", cwd: "/reviewed", spawn: fakeSpawn({ reportPath: fixture.outputPath, signaturePath: fixture.signaturePath, code: 1, stderr: "ExpiredToken: The security token included in the request is expired\n", publish: false }), processOps: fakeProcessOps, timeoutMs: 500 });
  assert.equal(result.state, "FAILED");
  assert.equal(result.failureClass, "PRODUCER_EXIT");
  assert.match(fs.readFileSync(result.stderr.path, "utf8"), /ExpiredToken/);
});

test("exit zero without a complete pair fails transactionally", async () => {
  const fixture = paths();
  const result = await runStageBAdminPreflightLifecycle({ ...fixture, producerPath: "/reviewed/producer.mjs", cwd: "/reviewed", spawn: fakeSpawn({ reportPath: fixture.outputPath, signaturePath: fixture.signaturePath, publish: false }), processOps: fakeProcessOps, timeoutMs: 500 });
  assert.equal(result.state, "FAILED");
  assert.equal(result.failureClass, "TRANSACTIONAL_PUBLICATION");
});

test("an active producer that reaches the deadline is terminated and classified TIMED_OUT", async () => {
  const fixture = paths();
  const result = await runStageBAdminPreflightLifecycle({ ...fixture, producerPath: "/reviewed/producer.mjs", cwd: "/reviewed", spawn: fakeSpawn({ reportPath: fixture.outputPath, signaturePath: fixture.signaturePath, delayMs: 100, closeOnKill: true }), processOps: fakeProcessOps, timeoutMs: 10, terminationGraceMs: 10 });
  assert.equal(result.state, "TIMED_OUT");
  assert.equal(result.timeout, true);
  assert.equal(result.signal, "SIGTERM");
  assert.equal(fs.existsSync(fixture.outputPath), false);
});

test("retry is allowed only after a terminal failure and lifecycle metadata stays secret-free", async () => {
  const fixture = paths();
  await runStageBAdminPreflightLifecycle({ ...fixture, producerPath: "/reviewed/producer.mjs", cwd: "/reviewed", spawn: fakeSpawn({ reportPath: fixture.outputPath, signaturePath: fixture.signaturePath, code: 1, stderr: "AWS_SESSION_TOKEN=secret-value\n", publish: false }), processOps: fakeProcessOps, timeoutMs: 500 });
  const result = await runStageBAdminPreflightLifecycle({ ...fixture, producerPath: "/reviewed/producer.mjs", cwd: "/reviewed", spawn: fakeSpawn({ reportPath: fixture.outputPath, signaturePath: fixture.signaturePath }), processOps: fakeProcessOps, timeoutMs: 500, retry: true });
  assert.equal(result.state, "SUCCEEDED");
  const lifecycle = fs.readFileSync(path.join(fixture.lifecycleDirectory, "lifecycle.json"), "utf8");
  const stderr = fs.readFileSync(path.join(fixture.lifecycleDirectory, "stderr.log"), "utf8");
  assert.doesNotMatch(lifecycle, /secret-value/);
  assert.doesNotMatch(stderr, /secret-value/);
  assert.equal(fs.statSync(path.join(fixture.lifecycleDirectory, "stderr.log")).mode & 0o777, 0o600);
});

test("the lifecycle launcher has no apply or credential persistence seam", () => {
  const source = fs.readFileSync(new URL("../aws/run-stage-b-administrator-preflight.mjs", import.meta.url), "utf8");
  assert.match(source, /run-production-green-stage-b-preflight\.mjs/);
  assert.doesNotMatch(source, /terraform|apply|AWS_SESSION_TOKEN|AWS_SECRET_ACCESS_KEY/);
});

test("credential-session documentation is explicit without inventing a root lifetime", () => {
  const runbook = fs.readFileSync(new URL("../../documents/security/rls-program/PRODUCTION_GREEN_STAGE_B_INFRASTRUCTURE_RUNBOOK.md", import.meta.url), "utf8");
  assert.match(runbook, /get-session-token --duration-seconds 129600/);
  assert.match(runbook, /assume-role --duration-seconds 3600/);
  assert.match(runbook, /root administrator `aws login --profile default` session is externally controlled/);
  assert.match(runbook, /ExpiredToken/);
});

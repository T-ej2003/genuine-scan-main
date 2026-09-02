import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import crypto from "node:crypto";
import {
  classifyStageBAdminPreflightDeadline,
  runStageBAdminPreflightLifecycle,
  STAGE_B_ADMIN_PREFLIGHT_TIMEOUT_SECONDS,
  STAGE_B_ADMIN_PREFLIGHT_TIMEOUT_MS,
} from "../aws/stage-b-admin-preflight-lifecycle.mjs";
import { buildPermissionReportBinding, PERMISSION_REPORT_BINDING_DOMAIN, PERMISSION_REPORT_BINDING_SCHEMA_VERSION, PERMISSION_REPORT_HASH_DOMAIN, PERMISSION_REPORT_SIGNING_ALGORITHM, PERMISSION_REPORT_SIGNING_KEY_ARN, PERMISSION_REPORT_SIGNATURE_SCHEMA_VERSION, signedPermissionReportBindingSha256 } from "../aws/validate-production-green-stage-b-permissions.mjs";
import { STAGE_B_DEPLOYMENT_EVIDENCE_TTL_SECONDS } from "../aws/stage-b-evidence-freshness.mjs";

const temp = () => fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-admin-lifecycle-test-"));
const canonicalizeJson = (value) => Array.isArray(value)
  ? `[${value.map(canonicalizeJson).join(",")}]`
  : value && typeof value === "object"
    ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalizeJson(value[key])}`).join(",")}}`
    : JSON.stringify(value);
const hash = (value) => crypto.createHash("sha256").update(value).digest("hex");
const validPair = async (reportPath, signaturePath) => {
  const report = { status: "valid", nested: { source: "fixture" } };
  const reportBytes = Buffer.from(`${JSON.stringify(report, null, 2)}\n`);
  const canonicalPayloadSha256 = hash(Buffer.from(canonicalizeJson(report)));
  const reportFileSha256 = hash(reportBytes);
  const bindingPayload = buildPermissionReportBinding({ report, canonicalPayloadSha256, reportFileSha256, keyArn: PERMISSION_REPORT_SIGNING_KEY_ARN, signingAlgorithm: PERMISSION_REPORT_SIGNING_ALGORITHM });
  const signature = { schemaVersion: PERMISSION_REPORT_SIGNATURE_SCHEMA_VERSION, hashDomain: PERMISSION_REPORT_HASH_DOMAIN, bindingDomain: PERMISSION_REPORT_BINDING_DOMAIN, bindingSchemaVersion: PERMISSION_REPORT_BINDING_SCHEMA_VERSION, evidenceKind: report.evidenceKind, phase: report.phase, purpose: report.purpose, accountId: "368992683803", region: "eu-west-2", keyId: PERMISSION_REPORT_SIGNING_KEY_ARN, keyArn: PERMISSION_REPORT_SIGNING_KEY_ARN, signingAlgorithm: PERMISSION_REPORT_SIGNING_ALGORITHM, canonicalPayloadSha256, reportFileSha256, signedBindingSha256: signedPermissionReportBindingSha256(bindingPayload), signatureBase64: "AQ==", signedAt: "2026-08-01T12:00:00.000Z" };
  const signatureBytes = Buffer.from(`${JSON.stringify(signature, null, 2)}\n`);
  fs.writeFileSync(reportPath, reportBytes, { mode: 0o600 });
  fs.writeFileSync(signaturePath, signatureBytes, { mode: 0o600 });
};
const fakeProcessOps = { kill: () => undefined };

function fakeSpawn({ reportPath, signaturePath, code = 0, delayMs = 5, stderr = "", publish = true, publishPair = validPair, closeOnKill = true, onStart = () => undefined }) {
  return (_, args) => {
    onStart();
    const stagedReportPath = args[args.indexOf("--output") + 1] || reportPath;
    const stagedSignaturePath = args[args.indexOf("--signature-output") + 1] || signaturePath;
    const child = new EventEmitter();
    child.pid = 73001;
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    let timer = setTimeout(async () => {
      if (publish) await publishPair(stagedReportPath, stagedSignaturePath);
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
const stagingEntries = (fixture) => fs.readdirSync(fixture.directory).filter((entry) => entry.startsWith(".stage-b-admin-preflight-"));

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
  assert.deepEqual(stagingEntries(fixture), []);
});

test("pre-existing report and signature are preserved and producer is not started", async () => {
  const fixture = paths(); let starts = 0;
  const reportBytes = Buffer.from("existing-report\n"); const signatureBytes = Buffer.from("existing-signature\n");
  fs.writeFileSync(fixture.outputPath, reportBytes, { mode: 0o600 }); fs.writeFileSync(fixture.signaturePath, signatureBytes, { mode: 0o600 });
  const result = await runStageBAdminPreflightLifecycle({ ...fixture, producerPath: "/reviewed/producer.mjs", cwd: "/reviewed", spawn: fakeSpawn({ reportPath: fixture.outputPath, signaturePath: fixture.signaturePath, onStart: () => { starts += 1; } }), processOps: fakeProcessOps, timeoutMs: 500 });
  assert.equal(result.failureClass, "PREEXISTING_OUTPUT"); assert.equal(starts, 0);
  assert.deepEqual(fs.readFileSync(fixture.outputPath), reportBytes); assert.deepEqual(fs.readFileSync(fixture.signaturePath), signatureBytes);
});

test("invalid output paths fail before spawn", async () => {
  for (const mutation of [
    (fixture) => ({ ...fixture, outputPath: "relative-report.json" }),
    (fixture) => ({ ...fixture, outputPath: path.join(fixture.repositoryRoot, "operator-owned-report.json") }),
    (fixture) => ({ ...fixture, outputPath: fixture.signaturePath }),
  ]) {
    const fixture = mutation(paths()); let starts = 0;
    const result = await runStageBAdminPreflightLifecycle({ ...fixture, producerPath: "/reviewed/producer.mjs", cwd: "/reviewed", spawn: fakeSpawn({ reportPath: fixture.outputPath, signaturePath: fixture.signaturePath, onStart: () => { starts += 1; } }), processOps: fakeProcessOps, timeoutMs: 500 });
    assert.equal(result.failureClass, "INVALID_OUTPUT_PATH"); assert.equal(starts, 0);
  }
});

test("symlink output paths fail before spawn", async () => {
  const fixture = paths(); const target = path.join(fixture.directory, "unrelated.txt"); fs.writeFileSync(target, "untouched\n", { mode: 0o600 }); fs.symlinkSync(target, fixture.outputPath); let starts = 0;
  const result = await runStageBAdminPreflightLifecycle({ ...fixture, producerPath: "/reviewed/producer.mjs", cwd: "/reviewed", spawn: fakeSpawn({ reportPath: fixture.outputPath, signaturePath: fixture.signaturePath, onStart: () => { starts += 1; } }), processOps: fakeProcessOps, timeoutMs: 500 });
  assert.equal(result.failureClass, "INVALID_OUTPUT_PATH"); assert.equal(starts, 0); assert.equal(fs.readFileSync(target, "utf8"), "untouched\n"); assert.equal(fs.lstatSync(fixture.outputPath).isSymbolicLink(), true);
});

test("lifecycle records canonical, raw report, and raw signature hash domains", async () => {
  const fixture = paths();
  const result = await runStageBAdminPreflightLifecycle({ ...fixture, producerPath: "/reviewed/producer.mjs", cwd: "/reviewed", spawn: fakeSpawn({ reportPath: fixture.outputPath, signaturePath: fixture.signaturePath }), processOps: fakeProcessOps, timeoutMs: 500 });
  assert.equal(result.state, "SUCCEEDED");
  const reportBytes = fs.readFileSync(fixture.outputPath);
  const signatureBytes = fs.readFileSync(fixture.signaturePath);
  const report = JSON.parse(reportBytes);
  const canonicalPayloadSha256 = hash(Buffer.from(canonicalizeJson(report)));
  assert.equal(result.report.canonicalPayloadSha256, canonicalPayloadSha256);
  assert.equal(result.report.reportFileSha256, hash(reportBytes));
  assert.equal(result.signature.signatureFileSha256, hash(signatureBytes));
  assert.notEqual(result.report.canonicalPayloadSha256, result.report.reportFileSha256);
  assert.equal("reportSha256" in result.report, false);
  assert.equal(fs.lstatSync(fixture.outputPath).isFile(), true); assert.equal(fs.lstatSync(fixture.signaturePath).isFile(), true);
  assert.equal(fs.statSync(fixture.outputPath).mode & 0o777, 0o600); assert.equal(fs.statSync(fixture.signaturePath).mode & 0o777, 0o600);
});

test("a modified report after signing fails raw-file binding and leaves no final pair", async () => {
  const fixture = paths();
  const publishModified = async (reportPath, signaturePath) => {
    await validPair(reportPath, signaturePath);
    fs.appendFileSync(reportPath, " \n");
  };
  const result = await runStageBAdminPreflightLifecycle({ ...fixture, producerPath: "/reviewed/producer.mjs", cwd: "/reviewed", spawn: fakeSpawn({ reportPath: fixture.outputPath, signaturePath: fixture.signaturePath, publishPair: publishModified }), processOps: fakeProcessOps, timeoutMs: 500 });
  assert.equal(result.state, "FAILED");
  assert.equal(result.failureClass, "TRANSACTIONAL_PUBLICATION");
  assert.equal(fs.existsSync(fixture.outputPath), false);
  assert.equal(fs.existsSync(fixture.signaturePath), false);
});

test("report-only and signature-only publication fail closed and are cleaned", async () => {
  for (const publishPair of [
    async (reportPath) => fs.writeFileSync(reportPath, "{\"status\":\"valid\"}\n", { mode: 0o600 }),
    async (_, signaturePath) => fs.writeFileSync(signaturePath, "{}\n", { mode: 0o600 }),
  ]) {
    const fixture = paths();
    const result = await runStageBAdminPreflightLifecycle({ ...fixture, producerPath: "/reviewed/producer.mjs", cwd: "/reviewed", spawn: fakeSpawn({ reportPath: fixture.outputPath, signaturePath: fixture.signaturePath, publishPair }), processOps: fakeProcessOps, timeoutMs: 500 });
    assert.equal(result.state, "FAILED");
    assert.equal(result.failureClass, "TRANSACTIONAL_PUBLICATION");
    assert.equal(fs.existsSync(fixture.outputPath), false);
    assert.equal(fs.existsSync(fixture.signaturePath), false);
    assert.deepEqual(stagingEntries(fixture), []);
  }
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
  const unrelatedPath = path.join(fixture.directory, "unrelated.txt"); fs.writeFileSync(unrelatedPath, "preserve\n", { mode: 0o600 });
  const result = await runStageBAdminPreflightLifecycle({ ...fixture, producerPath: "/reviewed/producer.mjs", cwd: "/reviewed", spawn: fakeSpawn({ reportPath: fixture.outputPath, signaturePath: fixture.signaturePath, code: 7, stderr: "AccessDenied: safe summary\n", publish: false }), processOps: fakeProcessOps, timeoutMs: 500 });
  assert.equal(result.state, "FAILED");
  assert.equal(result.exitCode, 7);
  assert.match(fs.readFileSync(result.stderr.path, "utf8"), /AccessDenied/);
  assert.equal(fs.existsSync(fixture.outputPath), false);
  assert.equal(fs.existsSync(fixture.signaturePath), false);
  assert.equal(fs.readFileSync(unrelatedPath, "utf8"), "preserve\n"); assert.deepEqual(stagingEntries(fixture), []);
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
  assert.deepEqual(stagingEntries(fixture), []);
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
  assert.match(runbook, /--source-sha <exact-protected-main-sha>/);
  assert.match(runbook, /static plan fixture never supplies the live temporary-KMS absence-evidence identity/);
});

test("plan-bound permission runbook documents every mandatory artifact input", () => {
  const runbook = fs.readFileSync(new URL("../../documents/security/rls-program/PRODUCTION_GREEN_STAGE_B_INFRASTRUCTURE_RUNBOOK.md", import.meta.url), "utf8");
  const start = runbook.indexOf("npm run stage-b:plan-bound-permission-preflight");
  const end = runbook.indexOf("```", start + 1);
  assert.notEqual(start, -1);
  assert.notEqual(end, -1);
  const command = runbook.slice(start, end);
  for (const option of ["--plan-json", "--canonical-plan-json", "--saved-plan", "--plan-approval-report", "--plan-approval-report-sha256", "--reference-audit", "--manifest", "--output", "--signature-output", "--lifecycle-directory"]) {
    assert.match(command, new RegExp(`${option}\\s+<[^>]+>`));
  }
});

test("release preflight documentation passes the authenticated image authorization", () => {
  const runbook = fs.readFileSync(new URL("../../documents/ops/iam/PRODUCTION_GREEN_STAGE_B_PROVIDER_RECOVERY_2026-07-29.md", import.meta.url), "utf8");
  assert.match(runbook, /--image-authorization <absolute-private-image-authorization>/);
  assert.match(runbook, /--image-authorization-sha256 <exact-image-authorization-file-sha256>/);
  assert.match(runbook, /Image evidence is the signed publication report consumed to derive the/);
  assert.match(runbook, /image authorization is the authenticated current-source artifact consumed by release/);
});

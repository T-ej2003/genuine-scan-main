import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import yaml from "js-yaml";
import { spawnSync } from "node:child_process";
import { startProductionB03BrokerExecution, parseB03StartArguments, runB03StartCli } from "../aws/apply-production-b03-incremental-release.mjs";
import { STAGE_B } from "../aws/production-green-stage-b-contract.mjs";

const sourceSha = "4".repeat(40), image = `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:${"a".repeat(64)}`;
const taskDefinitionArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-b03-incremental:7";
const request = { operation: "b03-incremental", approvalId: `APR-B03-${sourceSha}-${"a".repeat(16)}`, sourceSha, approvalSha256: "b".repeat(64) };
function fixture({ proof = {}, start = {}, metadata = {}, authorize, authenticateSource, now } = {}) {
  const calls = [];
  const input = { sourceSha, request, environment: {}, now: now || (() => new Date("2026-10-28T12:05:00Z")),
    authenticateSource: authenticateSource || (async () => {}), authorize: authorize || (async () => ({ backend: image })),
    runner: args => {
      assert.deepEqual(args.slice(0, 2), ["lambda", "invoke"]);
      assert.equal(args[args.indexOf("--function-name") + 1], STAGE_B.brokerAliasArn);
      const event = JSON.parse(fs.readFileSync(args[args.indexOf("--payload") + 1].slice(8), "utf8"));
      assert.deepEqual(Object.keys(event).sort(), ["approvalId", "approvalSha256", "operation", "sourceSha"]);
      calls.push(event);
      const validation = event.operation === "validate-b03-approval";
      const response = validation ? { status: "validated", approvalId: request.approvalId, sourceSha,
        approvalSha256: request.approvalSha256, approvalContractSha256: "c".repeat(64), taskDefinitionArn,
        backendImage: image, packageSha256: "d".repeat(64), expiresAt: "2026-10-28T12:30:00Z", ...proof }
        : { status: "started", schemaVersion: 1, environment: "production", event: "b03-broker-start", mode: "b03-incremental",
          approvalId: request.approvalId, taskDefinitionArn, approvalContractSha256: "c".repeat(64), requestSha256: "e".repeat(64),
          taskArn: `arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/${"f".repeat(32)}`, nonce: "a".repeat(32), ...start };
      fs.writeFileSync(args[args.indexOf("--payload") + 2], JSON.stringify(response));
      return JSON.stringify({ StatusCode: 200, ExecutedVersion: "22", ...(typeof metadata === "function" ? metadata(validation) : metadata) });
    } };
  return { input, calls };
}

test("Release Gate start validates published approval then invokes only the fixed broker operation", async () => {
  const { input, calls } = fixture();
  const result = await startProductionB03BrokerExecution(input);
  assert.equal(result.status, "STARTED_UNVERIFIED"); assert.equal(result.initiation.taskDefinitionArn, taskDefinitionArn);
  assert.deepEqual(calls.map(c => c.operation), ["validate-b03-approval", "b03-incremental"]);
  assert.deepEqual(calls[1], request);
});

test("B03 start requires the existing production OIDC authorization boundary", async () => {
  const { input, calls } = fixture();
  await assert.rejects(startProductionB03BrokerExecution({ ...input, authorize: undefined }));
  assert.equal(calls.length, 0);
});

for (const [name, change] of Object.entries({
  missing: () => undefined,
  "wrong source": r => ({ ...r, sourceSha: "5".repeat(40) }),
  command: r => ({ ...r, overrides: { command: ["sh"] } }),
  environment: r => ({ ...r, environment: [] }),
  "task role": r => ({ ...r, taskRoleArn: "other" }),
  "execution role": r => ({ ...r, executionRoleArn: "other" }),
  "task definition": r => ({ ...r, taskDefinitionArn: "other" }),
})) test(`B03 start rejects ${name} before any broker call`, async () => {
  const { input, calls } = fixture();
  await assert.rejects(startProductionB03BrokerExecution({ ...input, request: change(request) })); assert.equal(calls.length, 0);
});

for (const [name, options] of Object.entries({
  "missing approval": { authorize: async () => { throw new Error("approval absent"); } },
  "untrusted task": { proof: { taskDefinitionArn: taskDefinitionArn.replace("b03-incremental", "unrelated") } },
  "untrusted image": { proof: { backendImage: image.replace("a".repeat(64), "0".repeat(64)) } },
  "source mismatch": { proof: { sourceSha: "5".repeat(40) } },
  "artifact mismatch": { proof: { approvalSha256: "0".repeat(64) } },
  expired: { proof: { expiresAt: "2026-10-28T12:00:00Z" } },
  "mutable broker": { metadata: { ExecutedVersion: "$LATEST" } },
  "broker error": { metadata: { FunctionError: "Unhandled" } },
})) test(`B03 validation rejects ${name} without requesting execution`, async () => {
  const { input, calls } = fixture(options);
  await assert.rejects(startProductionB03BrokerExecution(input)); assert.ok(calls.length <= 1);
});

for (const [name, options] of Object.entries({
  "task substitution": { start: { taskDefinitionArn: taskDefinitionArn.replace(":7", ":8") } },
  "contract substitution": { start: { approvalContractSha256: "0".repeat(64) } },
  "unexpected status": { start: { status: "completed" } },
  "unexpected fields": { start: { overrides: {} } },
  "alias changed": { metadata: validation => ({ ExecutedVersion: validation ? "22" : "23" }) },
})) test(`B03 initiation rejects ${name} and never retries automatically`, async () => {
  const { input, calls } = fixture(options);
  await assert.rejects(startProductionB03BrokerExecution(input)); assert.equal(calls.length, 2);
});

test("source change or expiry between proof and start blocks execution", async () => {
  let checks = 0;
  const a = fixture({ authenticateSource: async () => { if (++checks === 2) throw new Error("main advanced"); } });
  await assert.rejects(startProductionB03BrokerExecution(a.input)); assert.equal(a.calls.length, 1);
  let ticks = 0;
  const b = fixture({ now: () => new Date(++ticks === 1 ? "2026-10-28T12:05:00Z" : "2026-10-28T13:00:00Z") });
  await assert.rejects(startProductionB03BrokerExecution(b.input)); assert.equal(b.calls.length, 1);
});

test("canonical CLI transports a compact reference and writes initiation only", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "b03-cli-test-"));
  try {
    const authorization = Buffer.from('{"synthetic":true}');
    for (const [name, value] of Object.entries({ auth: authorization, approval: Buffer.from('{}'), request: Buffer.from(JSON.stringify(request)) })) fs.writeFileSync(path.join(directory, name), value);
    const args = ["--mode", "start", "--source-sha", sourceSha, "--authorization", path.join(directory, "auth"),
      "--authorization-sha256", crypto.createHash("sha256").update(authorization).digest("hex"), "--approval-evidence", path.join(directory, "approval"),
      "--b03-request", path.join(directory, "request"), "--release-train-run-id", "123", "--output", path.join(directory, "start.json")];
    const f = fixture();
    await runB03StartCli(args, { start: input => startProductionB03BrokerExecution({ ...f.input, ...input }) });
    assert.equal(JSON.parse(fs.readFileSync(path.join(directory, "start.json"))).status, "STARTED_UNVERIFIED");
    for (const bad of [[...args, "--task-definition-arn", taskDefinitionArn], args.map(v => v === "--b03-request" ? "--overrides" : v)]) assert.throws(() => parseB03StartArguments(bad));
    fs.unlinkSync(path.join(directory, "start.json"));
    fs.writeFileSync(path.join(directory, "auth"), "tampered");
    await assert.rejects(runB03StartCli(args, { start: async () => assert.fail("hash mismatch must not launch") }));
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test("completion CLI requires a bounded independent reference and never starts SQL", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "b03-completion-cli-"));
  try {
    const authorization = Buffer.from("{}"), reference = { sourceSha, runId: "1" };
    for (const [name, value] of Object.entries({ auth: authorization, approval: Buffer.from("{}"), request: Buffer.from(JSON.stringify(request)), verifier: Buffer.from(JSON.stringify(reference)) }))
      fs.writeFileSync(path.join(directory, name), value);
    const args = ["--mode", "complete", "--source-sha", sourceSha, "--authorization", path.join(directory, "auth"),
      "--authorization-sha256", crypto.createHash("sha256").update(authorization).digest("hex"), "--approval-evidence", path.join(directory, "approval"),
      "--b03-request", path.join(directory, "request"), "--release-train-run-id", "123", "--compatibility-reference", path.join(directory, "verifier"),
      "--output", path.join(directory, "complete.json")];
    await runB03StartCli(args, { start: async () => assert.fail("completion cannot relaunch SQL"), complete: async input => {
      assert.deepEqual(input.compatibilityReference, reference); return { status: "VERIFIED" };
    } });
    assert.equal(JSON.parse(fs.readFileSync(path.join(directory, "complete.json"))).status, "VERIFIED");
    assert.throws(() => parseB03StartArguments(args.filter((_, i) => i !== args.indexOf("--compatibility-reference") && i !== args.indexOf("--compatibility-reference") + 1)));
    fs.writeFileSync(path.join(directory, "verifier"), "x".repeat(2049));
    await assert.rejects(runB03StartCli(args, { complete: async () => assert.fail("oversized reference reached completion") }), /compact independent verification reference/);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test("Release Train forwards B03 references; Gate starts or completes only through the broker", () => {
  const train = yaml.load(fs.readFileSync(".github/workflows/release-train.yml", "utf8"));
  const gate = yaml.load(fs.readFileSync(".github/workflows/release-gate.yml", "utf8"));
  assert.equal(train.on.workflow_dispatch.inputs.b03_approval_reference_json.type, "string");
  assert.equal(train.on.workflow_dispatch.inputs.b03_compatibility_reference_json.type, "string");
  assert.equal(gate.on.workflow_dispatch.inputs.b03_approval_reference_json.type, "string");
  assert.equal(gate.on.workflow_dispatch.inputs.b03_compatibility_reference_json.type, "string");
  const trainSteps = Object.values(train.jobs).flatMap(j => j.steps || []);
  assert.ok(trainSteps.some(s => s.run?.includes('["b03_approval_reference_json", process.env.B03_APPROVAL_REFERENCE_JSON]')));
  assert.ok(trainSteps.some(s => s.run?.includes('["b03_compatibility_reference_json", process.env.B03_COMPATIBILITY_REFERENCE_JSON]')));
  const steps = Object.values(gate.jobs).flatMap(j => j.steps || []);
  const execute = steps.find(s => s.run?.includes("apply-production-b03-incremental-release.mjs"));
  assert.equal(execute.env.B03_APPROVAL_REFERENCE_JSON, "${{ inputs.b03_approval_reference_json }}");
  assert.equal(execute.env.B03_COMPATIBILITY_REFERENCE_JSON, "${{ inputs.b03_compatibility_reference_json }}");
  assert.match(execute.run, /b03_mode=start/); assert.match(execute.run, /b03_mode=complete/);
  assert.match(execute.run, /--mode "\$b03_mode"/); assert.match(execute.run, /--b03-request/);
  const branch = execute.run.slice(execute.run.indexOf('if [[ "$DATABASE_INSTALL_MODE"'), execute.run.indexOf('elif [[ "$DATABASE_INSTALL_MODE"'));
  assert.doesNotMatch(branch, /aws ecs|--task-definition-arn|--overrides/);
  assert.match(branch, /b03_output="\$PRODUCTION_RLS_RELEASE_RECEIPT_PATH"/);
  assert.match(branch, /--compatibility-reference/);
  assert.match(branch, /if \[\[ "\$b03_mode" == start \]\]; then[\s\S]*exit 1/);
  assert.equal(spawnSync("bash", ["-n"], { input: execute.run, encoding: "utf8" }).status, 0);
  const source = fs.readFileSync("scripts/aws/apply-production-b03-incremental-release.mjs", "utf8");
  assert.doesNotMatch(source, /["']ecs["']\s*,\s*["'](?:run-task|register-task-definition)["']/);
  assert.doesNotMatch(source, /["']secretsmanager["']\s*,\s*["']get-secret-value["']/);
});

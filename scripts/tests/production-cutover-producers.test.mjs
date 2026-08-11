import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPairSync } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { verifyArtifactSigningDomain } from "../aws/production-artifact-signing-domain.mjs";
import { createProductionRuntimeInventoryAdapter, PRODUCTION_RUNTIME_INVENTORY_COMMAND } from "../aws/production-runtime-inventory-adapter.mjs";
import { createProductionOverlapDeploymentAdapter } from "../aws/production-cutover-production-adapters.mjs";
import { loadApprovedArtifactSigningBindings } from "../aws/production-artifact-signing-secrets-adapter.mjs";
import { assertNoOnboardingEvidenceLeak } from "../security/production-strict-onboarding.mjs";
import { createProductionInteractiveEcsExecRunner } from "../aws/production-ecs-exec-command.mjs";

const digest = `sha256:${"b".repeat(64)}`;
const taskArn = "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/one";
const expected = { expectedClusterArn: "arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main", expectedTaskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:1", expectedImageDigest: digest, serviceName: "mscqr-backend-servi-euw2", containerName: "backend" };

test("runtime inventory uses one exact tagged task and fixed aggregate command", async () => {
  let finalDescribe;
  let executed;
  const task = { taskArn, clusterArn: expected.expectedClusterArn, taskDefinitionArn: expected.expectedTaskDefinitionArn, lastStatus: "RUNNING", group: "service:mscqr-backend-servi-euw2", containers: [{ name: "backend", imageDigest: digest }], tags: [{ key: "MSCQRExecTarget", value: "production-backend" }], managedAgents: [{ name: "ExecuteCommandAgent", lastStatus: "RUNNING" }] };
  const adapter = createProductionRuntimeInventoryAdapter({ expected, ecs: {
    describeService: async () => ({ enableExecuteCommand: true }),
    listTasks: async () => ({ taskArns: [taskArn] }),
    describeTasks: async ({ taskArns }) => { finalDescribe = taskArns; return { tasks: [task] }; },
    executeCommand: async (value) => { executed = value; return JSON.stringify({ refreshSessions: { count: 0 }, adminSessions: { count: 0 }, customerSessions: { count: 0 }, customerVerificationState: { count: 0 }, activeInvites: { count: 0 }, resetTokens: { count: 0 }, emailVerification: { count: 0 }, qrArtifacts: { count: 0 }, printerTestQrArtifacts: { status: "NOT_APPLICABLE", reason: "fixture" }, artifactRecords: { count: 0 }, legacyComplianceArtifacts: { count: 0 }, legacyImmutableAuditArtifacts: { status: "NOT_APPLICABLE", reason: "fixture" }, oauthState: { status: "NOT_APPLICABLE", reason: "fixture" }, oauthExchange: { status: "NOT_APPLICABLE", reason: "fixture" }, printedQrCompatibility: { status: "NOT_APPLICABLE", reason: "fixture" } }); },
  } });
  const result = await adapter({ taskDefinitionArn: expected.expectedTaskDefinitionArn });
  const value = result.inventory;
  assert.equal(value.refreshSessions.count, 0);
  assert.equal(result.taskArn, taskArn);
  assert.deepEqual(finalDescribe, [taskArn]);
  assert.deepEqual(executed, { taskArn, container: "backend", command: PRODUCTION_RUNTIME_INVENTORY_COMMAND });
});

test("artifact signing rejects mismatched pair and never accepts sensitive evidence", async () => {
  const current = generateKeyPairSync("ed25519", { privateKeyEncoding: { format: "pem", type: "pkcs8" }, publicKeyEncoding: { format: "pem", type: "spki" } });
  const other = generateKeyPairSync("ed25519", { privateKeyEncoding: { format: "pem", type: "pkcs8" }, publicKeyEncoding: { format: "pem", type: "spki" } });
  const bindings = Object.fromEntries(["ARTIFACT_SIGN_PRIVATE_KEY_CURRENT", "ARTIFACT_SIGN_PUBLIC_KEY_CURRENT", "ARTIFACT_SIGN_ACTIVE_KEY_VERSION", "ARTIFACT_SIGN_PUBLIC_KEYS_JSON"].map((name) => [name, name]));
  const values = { ARTIFACT_SIGN_PRIVATE_KEY_CURRENT: current.privateKey, ARTIFACT_SIGN_PUBLIC_KEY_CURRENT: other.publicKey, ARTIFACT_SIGN_ACTIVE_KEY_VERSION: "v1", ARTIFACT_SIGN_PUBLIC_KEYS_JSON: JSON.stringify({ v1: current.publicKey }) };
  await assert.rejects(() => verifyArtifactSigningDomain({ bindings, readSecret: async (ref) => values[ref] }), /inconsistent|match/i);
  assert.throws(() => assertNoOnboardingEvidenceLeak({ token: "x" }), /sensitive/);
});

test("artifact secret bindings are loaded only from reviewed IAM configuration", () => {
  assert.throws(() => loadApprovedArtifactSigningBindings("/tmp/unreviewed-artifact-bindings.json"), /repository-reviewed IAM configuration/);
});

test("production AWS commands carry the reviewed region and process identity", () => {
  // The runner delegates to execFileSync in production; the source contract
  // test below keeps the region/profile binding explicit without invoking AWS.
  const source = fs.readFileSync("scripts/aws/production-cutover-production-adapters.mjs", "utf8");
  assert.match(source, /AWS_DEFAULT_REGION: region/);
  assert.match(source, /args\.includes\("--region"\)/);
  assert.match(source, /AWS_PROFILE: profile/);
});

test("production inventory targets the stable backend, not the pending overlap revision", () => {
  const source = fs.readFileSync("scripts/aws/production-cutover-production-adapters.mjs", "utf8");
  assert.match(source, /expectedTaskDefinitionArn: config\.inventoryTaskDefinitionArn \|\| config\.expectedCurrentTaskDefinitionArn/);
});

test("interactive ECS Exec adapter uses the exact revalidated ARN and process runner", async () => {
  let invocation;
  const run = createProductionInteractiveEcsExecRunner({ spawn: (command, args) => {
    invocation = { command, args };
    return { status: 0, stdout: "MSCQR_FIXTURE_READY\r\n{" + "\"ok\":true}" };
  } });
  const transcript = await run({ cluster: "mscqr-prod-euw2-main", taskArn, container: "backend", command: "node /app/scripts/production-rotation-state-inventory.mjs" });
  assert.match(transcript, /\"ok\":true/);
  assert.equal(invocation.command, "python3");
  assert.equal(invocation.args[invocation.args.indexOf("--task") + 1], taskArn);
  assert.equal(invocation.args[invocation.args.indexOf("--command") + 1], "sh -c 'printf MSCQR_FIXTURE_READY; node /app/scripts/production-rotation-state-inventory.mjs'");
});

test("production overlap adapter invokes the governed deploy wrapper with exact mutation bindings", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-overlap-adapter-test-"));
  const readinessFile = path.join(directory, "readiness.json");
  const taskDefinitionArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:9";
  let invocation;
  try {
    const adapter = createProductionOverlapDeploymentAdapter({
      deployScript: path.join(directory, "deploy-ecs-service.sh"),
      readinessFile,
      sourceSha: "a".repeat(40),
      rotationId: "rotation-test-1",
      rotationStateSha256: "c".repeat(64),
      readinessSha256: "d".repeat(64),
      imageDigest: digest,
      expectedCurrentTaskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:47",
      runScript: (_script, _args, options) => {
        invocation = options;
        fs.writeFileSync(options.env.METADATA_FILE, JSON.stringify({ newTaskDefinitionArn: taskDefinitionArn }));
      },
    });
    const result = await adapter.run({ taskDefinitionArn });
    assert.equal(result.updateServiceCount, 1);
    assert.equal(invocation.env.MSCQR_GOVERNED_ORCHESTRATOR, "1");
    assert.equal(invocation.env.PROPAGATE_TAGS, "TASK_DEFINITION");
    assert.equal(invocation.env.ENABLE_EXECUTE_COMMAND, "true");
    assert.equal(invocation.env.EXISTING_TASK_DEFINITION_ARN, taskDefinitionArn);
    assert.equal(invocation.env.OVERLAP_READINESS_EVIDENCE_SHA256, "d".repeat(64));
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";
import {
  STAGING_DATABASE_ROLE_CONTEXT as C,
  assertDatabaseRoleOperatorIdentity,
} from "../lib/staging-database-role-credentials-core.mjs";

const command = process.argv[2];
const modes = Object.freeze({
  apply: "rls-shared-apply",
  verify: "rls-shared-verify",
  rollback: "rls-shared-rollback",
});
const helperArnPattern = new RegExp(`^arn:aws:ecs:${C.region}:${C.accountId}:task-definition/mscqr-staging-database-role-admin:[0-9]+$`);
const helperImagePattern = new RegExp(`^${C.accountId}\\.dkr\\.ecr\\.${C.region}\\.amazonaws\\.com/mscqr-backend@sha256:[a-f0-9]{64}$`);
const canaryArn = `arn:aws:ecs:${C.region}:${C.accountId}:task-definition/mscqr-staging-backend:9`;
const brokerArn = `arn:aws:lambda:${C.region}:${C.accountId}:function:${C.brokerFunction}:reviewed`;
const root = path.resolve(import.meta.dirname, "../..");
const sha256File = (name) => crypto.createHash("sha256").update(fs.readFileSync(path.join(root, name))).digest("hex");
const brokerBinding = Object.freeze({
  executorContractSha256: sha256File("documents/security/rls-program/staging-full-rls-executor-contract.json"),
  brokerSourceSha256: sha256File("infra/terraform/staging-api/lambda/database-role-executor-broker/index.mjs"),
});
export const APPLY_BLOCK_REASON = "Shared RLS apply is blocked: stable revision 7 has contextless User access and the reviewed User policies do not support legacy admin INSERT, DELETE, or cross-user UPDATE.";
const APPLY_CONFIRMATION = "MSCQR_APPLY_STAGING_RLS_SHARED_BATCH_PHASE";
const ROLLBACK_CONFIRMATION = "MSCQR_ROLLBACK_STAGING_RLS_SHARED_BATCH_PHASE";

const run = (args) => {
  const result = spawnSync("aws", [...args, "--region", C.region, "--output", "json"], {
    encoding: "utf8",
    env: { ...process.env, AWS_REGION: C.region, AWS_DEFAULT_REGION: C.region },
    maxBuffer: 8 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.error || result.status !== 0) throw new Error(`AWS ${args[0]} ${args[1]} failed; output suppressed.`);
  try { return result.stdout ? JSON.parse(result.stdout) : {}; }
  catch { throw new Error(`AWS ${args[0]} ${args[1]} returned invalid JSON.`); }
};
const routeFlags = (definition) => Object.fromEntries(
  (definition.containerDefinitions?.[0]?.environment || [])
    .filter(({ name }) => C.routeFlags.includes(name))
    .map(({ name, value }) => [name, value])
);
const assertFlags = (actual, expected, label) => {
  for (const name of C.routeFlags) if (actual[name] !== expected[name]) throw new Error(`${label} has an unsafe ${name} value.`);
};

export function validateLocalGate(mode, env = process.env) {
  if (!Object.hasOwn(modes, mode)) throw new Error("Command must be apply, verify, or rollback.");
  if ((env.AWS_REGION || env.AWS_DEFAULT_REGION || C.region) !== C.region) throw new Error(`AWS region must be ${C.region}.`);
  if (env.MSCQR_STAGING_VPC_EXECUTOR !== "disposable-ecs-admin-task") throw new Error("Reviewed disposable ECS admin executor must be selected.");
  if (!helperArnPattern.test(env.MSCQR_STAGING_DB_ADMIN_TASK_DEFINITION_ARN || "")) throw new Error("Exact reviewed staging database-role admin task definition ARN is required.");
  if (!helperImagePattern.test(env.MSCQR_STAGING_RLS_HELPER_IMAGE_REF || "")) throw new Error("Exact immutable staging RLS helper image digest reference is required.");
  if (mode === "apply" && env.MSCQR_CONFIRM_STAGING_RLS_SHARED_BATCH_PHASE !== APPLY_CONFIRMATION) throw new Error(`Set MSCQR_CONFIRM_STAGING_RLS_SHARED_BATCH_PHASE=${APPLY_CONFIRMATION}.`);
  if (mode === "apply") throw new Error(APPLY_BLOCK_REASON);
  if (mode === "rollback" && env.MSCQR_CONFIRM_STAGING_RLS_SHARED_BATCH_PHASE_ROLLBACK !== ROLLBACK_CONFIRMATION) throw new Error(`Set MSCQR_CONFIRM_STAGING_RLS_SHARED_BATCH_PHASE_ROLLBACK=${ROLLBACK_CONFIRMATION}.`);
  return modes[mode];
}

export function assertSharedBrokerConfiguration(configuration, helperArn, binding = brokerBinding) {
  const version = String(configuration?.Version || "");
  const variables = configuration?.Environment?.Variables || {};
  if (!/^[1-9][0-9]*$/.test(version)
      || variables.BROKER_CLUSTER_ARN !== `arn:aws:ecs:${C.region}:${C.accountId}:cluster/${C.cluster}`
      || variables.BROKER_TASK_DEFINITION_ARN !== helperArn
      || variables.BROKER_EXECUTOR_CONTRACT_SHA256 !== binding.executorContractSha256
      || variables.BROKER_SOURCE_SHA256 !== binding.brokerSourceSha256) {
    throw new Error("Reviewed broker alias configuration does not match the shared-RLS helper.");
  }
  return version;
}

export function assertSharedBrokerLaunch(metadata, started, { reviewedVersion, helperArn, binding = brokerBinding }) {
  const expectedKeys = ["brokerSourceSha256", "executorContractSha256", "status", "taskArn", "taskDefinitionArn"];
  const taskArnPrefix = `arn:aws:ecs:${C.region}:${C.accountId}:task/${C.cluster}/`;
  if (metadata?.FunctionError || metadata?.StatusCode !== 200 || String(metadata?.ExecutedVersion || "") !== reviewedVersion
      || Object.keys(started || {}).sort().join(",") !== expectedKeys.join(",")
      || started.status !== "started" || started.taskDefinitionArn !== helperArn
      || typeof started.taskArn !== "string" || !started.taskArn.startsWith(taskArnPrefix)
      || Object.entries(binding).some(([name, value]) => started[name] !== value)) {
    throw new Error("Broker refused or executed outside the reviewed shared-RLS helper binding.");
  }
  return started.taskArn;
}

export function assertReviewedTopology({ service, stableDefinition, canaryDefinition, helperDefinition, helperArn, helperImageRef }) {
  if (service.taskDefinition !== `arn:aws:ecs:${C.region}:${C.accountId}:task-definition/mscqr-staging-backend:7`
      || service.desiredCount !== service.runningCount || service.runningCount < 1
      || (service.deployments || []).some((deployment) => deployment.status !== "PRIMARY" || deployment.taskDefinition !== service.taskDefinition)) {
    throw new Error("Stable ECS revision 7 must remain the only serving deployment.");
  }
  const allFalse = Object.fromEntries(C.routeFlags.map((name) => [name, "false"]));
  assertFlags(routeFlags(stableDefinition), allFalse, "Stable revision 7");
  assertFlags(routeFlags(canaryDefinition), {
    MSCQR_STAGING_RLS_BATCHES_READ_ENABLED: "true",
    MSCQR_STAGING_RLS_BATCH_ALLOCATION_MAP_ENABLED: "false",
    MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED: "false",
  }, "Canary revision 9");
  if (helperDefinition.taskDefinitionArn !== helperArn || helperDefinition.family !== "mscqr-staging-database-role-admin"
      || helperDefinition.networkMode !== "awsvpc" || helperDefinition.containerDefinitions?.length !== 1) {
    throw new Error("Helper task definition is outside the reviewed staging admin family.");
  }
  const container = helperDefinition.containerDefinitions[0];
  if (container.name !== "db-admin" || container.readonlyRootFilesystem !== true
      || container.image !== helperImageRef
      || !(container.command || []).join(" ").includes("staging-database-role-vpc-executor.mjs")) {
    throw new Error("Helper task does not use the reviewed VPC executor entrypoint.");
  }
  const logOptions = container.logConfiguration?.options || {};
  if (container.logConfiguration?.logDriver !== "awslogs"
      || logOptions["awslogs-group"] !== "/ecs/mscqr-staging-backend"
      || logOptions["awslogs-stream-prefix"] !== "database-role-admin") {
    throw new Error("Helper task does not use the reviewed CloudWatch log destination.");
  }
  assertFlags(routeFlags(helperDefinition), allFalse, "Database admin helper");
  const dbSecrets = (container.secrets || []).filter(({ name }) => name === "DATABASE_URL");
  if (dbSecrets.length !== 1
      || !/:secret:mscqr\/staging\/database-url-[A-Za-z0-9]+$/.test(dbSecrets[0].valueFrom || "")
      || /\/app-|\/rls-read-|\/migrator-/i.test(dbSecrets[0].valueFrom || "")) {
    throw new Error("Helper must receive only the staging administrative DATABASE_URL secret.");
  }
  return true;
}

const expectedSqlEvidence = Object.freeze({
  apply: {
    status: "staging_shared_batch_rls_applied",
    protectedTableCount: 10,
    candidateSelectPolicyCount: 10,
    sharedPolicyCount: 7,
    authFunctionCount: 2,
    printerTablesChanged: false,
    batchPoliciesChanged: false,
  },
  verify: {
    status: "staging_shared_batch_rls_verified",
    database: C.databaseName,
    protectedTables: 10,
    candidateSelectPolicies: 10,
    sharedPolicies: 7,
    authFunctions: 2,
    emptyContextSharedQueries: "fail_closed",
    rlsReadWrites: "denied",
    appSharedCrud: "preserved",
    printerProtectedTables: 0,
  },
  rollback: {
    status: "staging_shared_batch_rls_rolled_back",
    sharedProtectedTableCount: 0,
    preservedBatchProtectedTableCount: 6,
    preservedBatchPolicyCount: 6,
    printerTablesChanged: false,
    runtimeTableGrantsChanged: false,
  },
});

export function parseSqlEvidence(mode, events) {
  const expected = expectedSqlEvidence[mode];
  const records = (events || []).flatMap(({ message = "" }) => String(message).split("\n")).flatMap((line) => {
    try { return [JSON.parse(line)]; } catch { return []; }
  });
  const evidence = records.findLast((record) => record?.phase === "complete"
    && record?.mechanism === "brokered-disposable-ecs-admin-psql-task"
    && record?.status === expected?.status);
  if (!evidence) throw new Error("CloudWatch did not contain the reviewed SQL completion evidence.");
  for (const [key, value] of Object.entries(expected)) {
    if (evidence[key] !== value) throw new Error(`SQL evidence has an unsafe ${key} value.`);
  }
  return evidence;
}

export function taskEvidence(mode, task, helperArn, helperDefinition, helperImageRef, loadLogEvents) {
  const container = task?.containers?.find(({ name }) => name === "db-admin");
  if (!task || task.lastStatus !== "STOPPED" || task.taskDefinitionArn !== helperArn || !container) {
    throw new Error("Reviewed shared RLS helper did not reach a corroborated stopped state.");
  }
  const definition = helperDefinition?.containerDefinitions?.find(({ name }) => name === "db-admin");
  const logOptions = definition?.logConfiguration?.options || {};
  const taskId = task.taskArn?.split("/").at(-1);
  const logStream = container.logStreamName || (logOptions["awslogs-stream-prefix"] && taskId
    ? `${logOptions["awslogs-stream-prefix"]}/db-admin/${taskId}` : null);
  const expectedDigest = helperImageRef.split("@")[1];
  if (!logOptions["awslogs-group"] || !logStream || container.imageDigest !== expectedDigest) {
    throw new Error("Stopped helper task does not match the reviewed image digest or log destination.");
  }
  const evidence = {
    status: container.exitCode === 0 ? `staging_shared_batch_rls_${mode}_task_passed` : "staging_shared_batch_rls_task_failed",
    mode,
    database: C.databaseName,
    region: C.region,
    cluster: C.cluster,
    serviceTaskDefinitionRevision: 7,
    canaryTaskDefinitionRevision: 9,
    helperTaskDefinitionArn: helperArn,
    taskArn: task.taskArn,
    exitCode: container.exitCode,
    cloudWatchLogGroup: logOptions["awslogs-group"] || null,
    cloudWatchLogStream: logStream,
    helperImageDigest: container.imageDigest,
    secretsPrinted: false,
    ecsServiceUpdated: false,
  };
  if (container.exitCode !== 0) throw Object.assign(new Error("Shared RLS SQL task exited non-zero; inspect the printed CloudWatch log stream."), { evidence });
  const sqlEvidence = parseSqlEvidence(mode, loadLogEvents(logOptions["awslogs-group"], logStream));
  return { ...evidence, sqlEvidenceValidated: true, ...sqlEvidence };
}

export function execute(mode = command) {
  const brokerMode = validateLocalGate(mode);
  const identity = run(["sts", "get-caller-identity"]);
  assertDatabaseRoleOperatorIdentity(identity, { ...process.env, AWS_REGION: C.region });
  const helperArn = process.env.MSCQR_STAGING_DB_ADMIN_TASK_DEFINITION_ARN;
  const helperImageRef = process.env.MSCQR_STAGING_RLS_HELPER_IMAGE_REF;
  const service = run(["ecs", "describe-services", "--cluster", C.cluster, "--services", C.service]).services?.[0];
  const stableDefinition = run(["ecs", "describe-task-definition", "--task-definition", service?.taskDefinition]).taskDefinition;
  const canaryDefinition = run(["ecs", "describe-task-definition", "--task-definition", canaryArn]).taskDefinition;
  const helperDefinition = run(["ecs", "describe-task-definition", "--task-definition", helperArn]).taskDefinition;
  assertReviewedTopology({ service, stableDefinition, canaryDefinition, helperDefinition, helperArn, helperImageRef });
  const brokerConfiguration = run(["lambda", "get-function-configuration", "--function-name", brokerArn]);
  const reviewedVersion = assertSharedBrokerConfiguration(brokerConfiguration, helperArn);

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-staging-shared-rls-"));
  fs.chmodSync(directory, 0o700);
  try {
    const request = path.join(directory, "broker-request.json");
    const response = path.join(directory, "broker-response.json");
    const confirmation = mode === "apply" ? APPLY_CONFIRMATION : mode === "rollback" ? ROLLBACK_CONFIRMATION : undefined;
    const payload = { mode: brokerMode, ...(confirmation ? { confirmation } : {}) };
    fs.writeFileSync(request, JSON.stringify(payload), { mode: 0o600, flag: "wx" });
    const metadata = run([
      "lambda", "invoke", "--function-name", brokerArn,
      "--cli-binary-format", "raw-in-base64-out", "--payload", `fileb://${request}`, response,
    ]);
    let started;
    try { started = JSON.parse(fs.readFileSync(response, "utf8")); }
    catch { throw new Error("Broker returned invalid task metadata."); }
    const taskArn = assertSharedBrokerLaunch(metadata, started, { reviewedVersion, helperArn });
    run(["ecs", "wait", "tasks-stopped", "--cluster", C.cluster, "--tasks", taskArn]);
    const task = run(["ecs", "describe-tasks", "--cluster", C.cluster, "--tasks", taskArn]).tasks?.[0];
    return taskEvidence(mode, task, helperArn, helperDefinition, helperImageRef, (logGroup, logStream) =>
      run(["logs", "get-log-events", "--log-group-name", logGroup, "--log-stream-name", logStream, "--start-from-head"]).events || []);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(import.meta.filename)) {
  try { console.log(JSON.stringify(execute(), null, 2)); }
  catch (error) {
    if (error.evidence) console.error(JSON.stringify(error.evidence, null, 2));
    else console.error(JSON.stringify({ status: "blocked", reason: error.message, secretsPrinted: false }, null, 2));
    process.exitCode = 2;
  }
}

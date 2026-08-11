#!/usr/bin/env node
import { readFileSync, statSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { assertSelectedTargetTask, requireExecuteCommandEnabled, selectAndRevalidateExactTarget } from "./ecs-exec-target-selection.mjs";
import { ECS_EXEC_OPERATOR_CALLER_PATTERN, ECS_EXEC_OPERATOR_ROLE_ARN, ECS_EXEC_OPERATOR_TASK_TAG_KEY, ECS_EXEC_OPERATOR_TASK_TAG_VALUE } from "./production-ecs-exec-operator-contract.mjs";

const ROOT = path.resolve(import.meta.dirname, "../..");
const PTY_HELPER = path.join(ROOT, "scripts/aws/ecs-exec-fixture-pty.py");
const args = new Map();
for (let index = 0; index < process.argv.slice(2).length; index += 1) {
  const value = process.argv.slice(2)[index];
  if (!value.startsWith("--")) throw new Error("invalid verifier argument");
  const next = process.argv.slice(2)[index + 1];
  if (!next || next.startsWith("--")) throw new Error(`missing value for ${value}`);
  args.set(value.slice(2), next);
  index += 1;
}

const required = (name) => {
  const value = String(args.get(name) || "").trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
};
const fullSha = (value, name) => {
  if (!/^[a-f0-9]{40}$/.test(value)) throw new Error(`${name} must be a full SHA`);
  return value;
};
const safeReference = (value, name) => {
  if (!/^[A-Za-z0-9._:/-]+$/.test(value)) throw new Error(`${name} contains unsupported characters`);
  return value;
};
const safeIdentifier = (value, name) => {
  if (!/^[A-Za-z0-9._-]{1,128}$/.test(value)) throw new Error(`${name} contains unsupported characters`);
  return value;
};
const shellQuote = (value) => `'${String(value).replaceAll("'", "'\\''")}'`;
const region = safeReference(args.get("region") || "eu-west-2", "region");
const cluster = safeReference(args.get("cluster") || "mscqr-prod-euw2-main", "cluster");
const service = safeReference(args.get("service") || "mscqr-backend-servi-euw2", "service");
const container = safeReference(args.get("container") || "backend", "container");
const phase = safeReference(args.get("phase") || process.env.ROTATION_RUNTIME_PHASE || "", "phase");
if (!new Set(["overlap", "cleanup"]).has(phase)) throw new Error("phase must be overlap or cleanup");
const fixtureFile = path.resolve(required("fixture-file"));
const proofOutput = path.resolve(required("proof-output"));
const expectedTaskDefinition = safeReference(required("task-definition"), "task-definition");
const expectedImageDigest = required("image-digest");
if (!/^sha256:[a-f0-9]{64}$/.test(expectedImageDigest)) throw new Error("image-digest must be an immutable digest");
const expectedDeploymentSha = fullSha(args.get("deployment-sha") || process.env.ROTATION_DEPLOYMENT_SHA || "", "deployment-sha");
const expectedReleaseSha = fullSha(args.get("release-sha") || args.get("expected-release-sha") || process.env.ROTATION_RELEASE_GIT_SHA || "", "release-sha");
const rotationId = safeIdentifier(args.get("rotation-id") || process.env.ROTATION_ID || "", "rotation-id");
const invocationRef = safeIdentifier(args.get("invocation-ref") || process.env.ROTATION_RUNTIME_INVOCATION_REF || "", "invocation-ref");
const healthUrl = required("health-url");
const parsedHealthUrl = new URL(healthUrl);
if (parsedHealthUrl.protocol !== "https:") throw new Error("health-url must use HTTPS");

const fixtureMode = statSync(fixtureFile).mode & 0o777;
if (fixtureMode !== 0o600) throw new Error("fixture-file must have mode 0600");
const fixtureBytes = readFileSync(fixtureFile);

const awsJson = (awsArgs) => {
  const result = spawnSync("aws", [...awsArgs, "--region", region, "--output", "json"], {
    cwd: ROOT,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
    maxBuffer: 8 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) throw new Error("AWS read-only discovery failed");
  try {
    return JSON.parse(result.stdout || "{}");
  } catch {
    throw new Error("AWS discovery returned invalid JSON");
  }
};

const callerArn = awsJson(["sts", "get-caller-identity"]).Arn;
if (!new RegExp(ECS_EXEC_OPERATOR_CALLER_PATTERN).test(callerArn || "")) throw new Error(`ECS Exec verifier requires ${ECS_EXEC_OPERATOR_ROLE_ARN}; deployment identities are not accepted`);

const serviceResult = awsJson(["ecs", "describe-services", "--cluster", cluster, "--services", service]);
const serviceRecord = serviceResult.services?.[0];
if (!serviceRecord || serviceResult.failures?.length || serviceRecord.serviceName !== service) throw new Error("expected ECS service was not found");
requireExecuteCommandEnabled(serviceRecord);
const clusterResult = awsJson(["ecs", "describe-clusters", "--clusters", cluster]);
const clusterRecord = clusterResult.clusters?.[0];
if (!clusterRecord || clusterResult.failures?.length || clusterRecord.status !== "ACTIVE" || typeof clusterRecord.clusterArn !== "string") throw new Error("expected ECS cluster was not found");
const expectedPrimaryDeployment = serviceRecord.deployments?.some((deployment) => deployment.status === "PRIMARY" && deployment.taskDefinition === expectedTaskDefinition);
if (!expectedPrimaryDeployment) throw new Error("expected task definition is not the primary service deployment");

const taskDefinition = awsJson(["ecs", "describe-task-definition", "--task-definition", expectedTaskDefinition]).taskDefinition;
const taskContainer = taskDefinition?.containerDefinitions?.find((entry) => entry.name === container);
const releaseSha = taskContainer?.environment?.find((entry) => entry.name === "RELEASE_GIT_SHA")?.value;
const taskImage = taskContainer?.image || "";
if (releaseSha !== expectedReleaseSha || !taskImage.endsWith(`@${expectedImageDigest}`)) throw new Error("target task definition release or image does not match the expected identity");

const listed = awsJson(["ecs", "list-tasks", "--cluster", cluster, "--service-name", service, "--desired-status", "RUNNING"]);
const taskArns = listed.taskArns || [];
if (!taskArns.length) throw new Error("expected service has no running tasks");
const described = awsJson(["ecs", "describe-tasks", "--cluster", cluster, "--tasks", ...taskArns, "--include", "TAGS"]);
if (described.failures?.length || !Array.isArray(described.tasks)) throw new Error("ECS task discovery returned an invalid response");
const expectedTarget = { expectedClusterArn: clusterRecord.clusterArn, expectedTaskDefinitionArn: expectedTaskDefinition, expectedImageDigest, serviceName: service, containerName: container, expectedTaskTagKey: ECS_EXEC_OPERATOR_TASK_TAG_KEY, expectedTaskTagValue: ECS_EXEC_OPERATOR_TASK_TAG_VALUE };
const selection = selectAndRevalidateExactTarget({ tasks: described.tasks, finalTasks: described.tasks, ...expectedTarget });
const targetTask = selection.selectedTask;
assertSelectedTargetTask({ task: targetTask, expectedClusterArn: clusterRecord.clusterArn, expectedTaskDefinitionArn: expectedTaskDefinition, expectedImageDigest, serviceName: service, containerName: container, expectedTaskTagKey: ECS_EXEC_OPERATOR_TASK_TAG_KEY, expectedTaskTagValue: ECS_EXEC_OPERATOR_TASK_TAG_VALUE });
// Re-read exactly the selected ARN with tags immediately before the mutation.
// Never replace a validated task with a later list result or operator input.
const finalTargetResponse = awsJson(["ecs", "describe-tasks", "--cluster", cluster, "--tasks", targetTask.taskArn, "--include", "TAGS"]);
if (finalTargetResponse.failures?.length || !Array.isArray(finalTargetResponse.tasks)) throw new Error("final ECS Exec target revalidation returned an invalid response");
const finalTargetTask = selectAndRevalidateExactTarget({ tasks: described.tasks, finalTasks: finalTargetResponse.tasks, ...expectedTarget }).finalTask;

const remoteProofPath = `/app/uploads/.mscqr-rotation-proof-${rotationId}.json`;
const remoteCommand = [
  "stty -echo",
  "trap 'rm -f " + shellQuote(remoteProofPath) + "; stty echo' EXIT HUP INT TERM",
  "printf MSCQR_FIXTURE_READY",
  `ROTATION_RUNTIME_PHASE=${shellQuote(phase)} ROTATION_ID=${shellQuote(rotationId)} ROTATION_DEPLOYMENT_SHA=${shellQuote(expectedDeploymentSha)} ROTATION_RUNTIME_INVOCATION_REF=${shellQuote(invocationRef)} node /app/scripts/security/verify-production-rotation-runtime.mjs --fixture-stdin --output ${shellQuote(remoteProofPath)} --health-url ${shellQuote(healthUrl)} --expected-release-sha ${shellQuote(expectedReleaseSha)}`,
  "status=$?",
  `if [ \"$status\" -eq 0 ]; then printf '\\nMSCQR_PROOF_BEGIN\\n'; cat ${shellQuote(remoteProofPath)}; printf '\\nMSCQR_PROOF_END\\n'; fi`,
  "exit $status",
].join("; ");

const pty = spawnSync("python3", [
  PTY_HELPER,
  "--input-file",
  fixtureFile,
  "150",
  String(2 * 1024 * 1024),
  "--",
  "aws",
  "ecs",
  "execute-command",
  "--region",
  region,
  "--cluster",
  cluster,
  "--task",
  finalTargetTask.taskArn,
  "--container",
  container,
  "--interactive",
  "--command",
  `sh -c ${shellQuote(remoteCommand)}`,
], { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], maxBuffer: 4 * 1024 * 1024 });
const transcript = String(pty.stdout || "");
if (transcript.includes(fixtureBytes.toString("utf8"))) throw new Error("fixture appeared in the ECS Exec transcript");
if (pty.error || pty.status !== 0) throw new Error("ECS Exec runtime verifier failed");
const cleanTranscript = transcript.replace(/\x1B\[[0-?]*[ -/]*[@-~]/g, "");
const begin = cleanTranscript.indexOf("MSCQR_PROOF_BEGIN");
const end = cleanTranscript.indexOf("MSCQR_PROOF_END", begin + 1);
if (begin < 0 || end < 0) throw new Error("ECS Exec proof markers were not found");
let proof;
try {
  proof = JSON.parse(cleanTranscript.slice(begin + "MSCQR_PROOF_BEGIN".length, end).trim());
} catch {
  throw new Error("ECS Exec returned malformed runtime proof");
}
if (proof.rotationId !== rotationId || proof.phase !== phase || proof.deploymentSha !== expectedDeploymentSha || proof.runtimeInvocationRef !== invocationRef || proof.healthReleaseGitSha !== expectedReleaseSha) {
  throw new Error("runtime proof is not bound to the requested deployment");
}
if (proof.artifactCurrentRuntimeVerify !== true) throw new Error("runtime proof artifact signing check failed");
if (proof.artifactHistoricalRuntimeVerify !== true) throw new Error("runtime proof historical artifact verification is required");

const finalProof = {
  ...proof,
  targetTaskArn: finalTargetTask.taskArn,
  selectedTaskArn: targetTask.taskArn,
  matchingTaskCount: selection.matchingTaskCount,
  targetTaskDefinitionArn: finalTargetTask.taskDefinitionArn,
  targetImageDigest: expectedImageDigest,
  expectedReleaseSha,
  targetService: service,
  targetCluster: cluster,
};
writeFileSync(proofOutput, `${JSON.stringify(finalProof, null, 2)}\n`, { mode: 0o600, flag: "wx" });
console.log(JSON.stringify({
  phase,
  rotationId,
  targetTaskArn: finalTargetTask.taskArn,
  selectedTaskArn: targetTask.taskArn,
  matchingTaskCount: selection.matchingTaskCount,
  targetTaskDefinitionArn: targetTask.taskDefinitionArn,
  targetImageDigest: expectedImageDigest,
  deploymentSha: expectedDeploymentSha,
  runtimeInvocationRef: invocationRef,
  serviceHealthy: proof.serviceHealthy === true,
}));

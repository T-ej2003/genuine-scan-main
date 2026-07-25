#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { GREEN_EXECUTOR_MODES, PRODUCTION_GREEN } from "../../backend/scripts/production-full-rls-green-executor.mjs";

const ACCOUNT = "368992683803";
const REGION = "eu-west-2";
const CLUSTER_ARN = `arn:aws:ecs:${REGION}:${ACCOUNT}:cluster/mscqr-prod-euw2-main`;
const APPLY_MODES = Object.freeze([
  "full-rls-capability-preflight",
  "full-rls-admin-bootstrap",
  "full-rls-role-provision",
  "full-rls-role-verify",
  "full-rls-admin-ownership",
  "full-rls-runtime-policy",
  "full-rls-verification",
]);
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const parseArray = (raw, pattern, label) => {
  const values = JSON.parse(raw || "[]");
  if (!Array.isArray(values) || values.length === 0 || values.some((value) => typeof value !== "string" || !pattern.test(value))) {
    throw new Error(`${label} is outside the protected production contract.`);
  }
  return values;
};

export function validateProductionReleaseEnvironment(env = process.env) {
  const config = {
    releaseSha: env.RELEASE_GIT_SHA,
    sourceContractSha256: env.MSCQR_FULL_RLS_SOURCE_CONTRACT_SHA256,
    packageChecksumSha256: env.MSCQR_FULL_RLS_PACKAGE_CHECKSUM_SHA256,
    executorImage: env.PRODUCTION_RLS_EXECUTOR_IMAGE,
    backendImage: env.PRODUCTION_BACKEND_IMAGE,
    workerImage: env.PRODUCTION_WORKER_IMAGE,
    frontendImage: env.PRODUCTION_FRONTEND_IMAGE,
    clusterArn: env.PRODUCTION_RLS_CLUSTER_ARN,
    taskRoleArn: env.PRODUCTION_RLS_TASK_ROLE_ARN,
    executionRoleArn: env.PRODUCTION_RLS_EXECUTION_ROLE_ARN,
    adminSecretArn: env.PRODUCTION_RLS_ADMIN_SECRET_ARN,
    receiptBucket: env.PRODUCTION_RLS_RECEIPT_BUCKET,
    subnets: parseArray(env.PRODUCTION_RLS_PRIVATE_SUBNETS_JSON, /^subnet-[a-f0-9]+$/, "Production executor subnets"),
    securityGroups: parseArray(env.PRODUCTION_RLS_SECURITY_GROUPS_JSON, /^sg-[a-f0-9]+$/, "Production executor security groups"),
  };
  if (!/^[a-f0-9]{40}$/.test(config.releaseSha || "")
      || !/^[a-f0-9]{64}$/.test(config.sourceContractSha256 || "")
      || !/^[a-f0-9]{64}$/.test(config.packageChecksumSha256 || "")
      || config.clusterArn !== CLUSTER_ARN
      || !new RegExp(`^arn:aws:iam::${ACCOUNT}:role/mscqr-production-full-rls-green-executor-task$`).test(config.taskRoleArn || "")
      || !new RegExp(`^arn:aws:iam::${ACCOUNT}:role/mscqr-production-ecs-execution-role$`).test(config.executionRoleArn || "")
      || !new RegExp(`^arn:aws:secretsmanager:${REGION}:${ACCOUNT}:secret:mscqr/production/rls-green/phase2/database-url/admin-[A-Za-z0-9]{6}$`).test(config.adminSecretArn || "")
      || !PRODUCTION_GREEN.receiptBucketPattern.test(config.receiptBucket || "")) {
    throw new Error("Production release binding is incomplete or outside the reviewed identity.");
  }
  for (const image of [config.executorImage, config.backendImage, config.workerImage, config.frontendImage]) {
    if (!new RegExp(`^${ACCOUNT}\\.dkr\\.ecr\\.${REGION}\\.amazonaws\\.com/mscqr-(?:backend|worker|web)@sha256:[a-f0-9]{64}$`).test(image || "")) {
      throw new Error("Production image binding must use an approved immutable ECR digest.");
    }
  }
  return config;
}

export function buildTaskDefinition(mode, config) {
  if (!GREEN_EXECUTOR_MODES.includes(mode)) throw new Error("Production executor mode is not reviewed.");
  const confirmation = PRODUCTION_GREEN.confirmations[mode];
  return {
    family: `mscqr-production-full-rls-green-${mode.replace("full-rls-", "")}`,
    taskRoleArn: config.taskRoleArn,
    executionRoleArn: config.executionRoleArn,
    networkMode: "awsvpc",
    requiresCompatibilities: ["FARGATE"],
    cpu: "256",
    memory: "512",
    runtimePlatform: { operatingSystemFamily: "LINUX", cpuArchitecture: "X86_64" },
    containerDefinitions: [{
      name: "full-rls-green",
      image: config.executorImage,
      essential: true,
      command: ["node", "scripts/production-full-rls-green-executor.mjs"],
      environment: [
        { name: "MSCQR_FULL_RLS_MODE", value: mode },
        { name: "MSCQR_FULL_RLS_SOURCE_CONTRACT_SHA256", value: config.sourceContractSha256 },
        { name: "MSCQR_FULL_RLS_PACKAGE_CHECKSUM_SHA256", value: config.packageChecksumSha256 },
        { name: "MSCQR_FULL_RLS_RECEIPT_BUCKET", value: config.receiptBucket },
        { name: "RELEASE_GIT_SHA", value: config.releaseSha },
        ...(confirmation ? [{ name: "MSCQR_FULL_RLS_CONFIRMATION", value: confirmation }] : []),
      ],
      secrets: [{ name: "DATABASE_URL", valueFrom: config.adminSecretArn }],
      readonlyRootFilesystem: true,
      privileged: false,
      user: "node",
      linuxParameters: { initProcessEnabled: true, capabilities: { add: [], drop: ["ALL"] }, devices: [], tmpfs: [] },
      logConfiguration: {
        logDriver: "awslogs",
        options: {
          "awslogs-group": "/ecs/mscqr-production/full-rls-green",
          "awslogs-region": REGION,
          "awslogs-stream-prefix": mode,
        },
      },
    }],
    tags: [
      { key: "Environment", value: "production" },
      { key: "ReleaseSha", value: config.releaseSha },
      { key: "SourceContractSha256", value: config.sourceContractSha256 },
      { key: "PackageChecksumSha256", value: config.packageChecksumSha256 },
    ],
  };
}

const defaultAws = (args) => {
  const result = spawnSync("aws", [...args, "--region", REGION, "--output", "json"], { encoding: "utf8" });
  if (result.status !== 0) throw new Error("Protected production executor command failed; provider detail suppressed.");
  return result.stdout.trim() ? JSON.parse(result.stdout) : {};
};

const registerTask = (mode, config, aws, directory) => {
  const file = path.join(directory, `${mode}.json`);
  fs.writeFileSync(file, JSON.stringify(buildTaskDefinition(mode, config)), { mode: 0o600, flag: "wx" });
  const response = aws(["ecs", "register-task-definition", "--cli-input-json", `file://${file}`]);
  const arn = response.taskDefinition?.taskDefinitionArn;
  const expected = `arn:aws:ecs:${REGION}:${ACCOUNT}:task-definition/mscqr-production-full-rls-green-${mode.replace("full-rls-", "")}:`;
  if (typeof arn !== "string" || !arn.startsWith(expected)) throw new Error("Registered production task identity is invalid.");
  return arn;
};

const runTask = (taskDefinition, config, aws) => {
  const startedAt = Date.now();
  const response = aws([
    "ecs", "run-task",
    "--cluster", config.clusterArn,
    "--task-definition", taskDefinition,
    "--launch-type", "FARGATE",
    "--count", "1",
    "--network-configuration", `awsvpcConfiguration={subnets=[${config.subnets.join(",")}],securityGroups=[${config.securityGroups.join(",")}],assignPublicIp=DISABLED}`,
  ]);
  if ((response.failures || []).length || response.tasks?.length !== 1) throw new Error("Production executor did not launch exactly one task.");
  const taskArn = response.tasks[0]?.taskArn;
  if (typeof taskArn !== "string" || !taskArn.startsWith(`${config.clusterArn.replace(":cluster/", ":task/")}/`)) {
    throw new Error("Production executor task identity is invalid.");
  }
  aws(["ecs", "wait", "tasks-stopped", "--cluster", config.clusterArn, "--tasks", taskArn]);
  const described = aws(["ecs", "describe-tasks", "--cluster", config.clusterArn, "--tasks", taskArn]);
  if (described.tasks?.length !== 1 || described.tasks[0]?.containers?.length !== 1 || described.tasks[0].containers[0]?.exitCode !== 0) {
    throw new Error("Production executor task failed; task detail suppressed.");
  }
  return startedAt;
};

const readReceipt = (mode, config, aws, directory, startedAt) => {
  const prefix = `rls-receipts/${config.releaseSha}/${mode}/`;
  const listed = aws(["s3api", "list-objects-v2", "--bucket", config.receiptBucket, "--prefix", prefix]);
  const item = [...(listed.Contents || [])].sort((left, right) => String(right.LastModified).localeCompare(String(left.LastModified)))[0];
  if (!item?.Key?.startsWith(prefix)) throw new Error("Production executor receipt is missing.");
  const file = path.join(directory, `${mode}-receipt.json`);
  aws(["s3api", "get-object", "--bucket", config.receiptBucket, "--key", item.Key, file]);
  const value = JSON.parse(fs.readFileSync(file, "utf8"));
  const receiptSha256 = value.receiptSha256;
  delete value.receiptSha256;
  if (value.environment !== "production"
      || value.mode !== mode
      || value.status !== "passed"
      || value.releaseSha !== config.releaseSha
      || value.sourceContractSha256 !== config.sourceContractSha256
      || value.packageChecksumSha256 !== config.packageChecksumSha256
      || Date.parse(value.completedAt || 0) < startedAt - 300_000
      || receiptSha256 !== sha256(`${JSON.stringify(value)}\n`)) {
    throw new Error("Production executor receipt binding is invalid.");
  }
  return { mode, receiptSha256, catalogueSha256: value.catalogueSha256 };
};

export async function applyProductionFullRlsRelease({
  env = process.env,
  aws = defaultAws,
  outputPath = env.PRODUCTION_RLS_RELEASE_RECEIPT_PATH,
} = {}) {
  const config = validateProductionReleaseEnvironment(env);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-production-rls-"));
  const receipts = [];
  let mutationStarted = false;
  try {
    const tasks = Object.fromEntries(GREEN_EXECUTOR_MODES.map((mode) => [mode, registerTask(mode, config, aws, directory)]));
    for (const mode of APPLY_MODES) {
      mutationStarted ||= Boolean(PRODUCTION_GREEN.confirmations[mode]);
      const startedAt = runTask(tasks[mode], config, aws);
      receipts.push(readReceipt(mode, config, aws, directory, startedAt));
    }
    const bundle = {
      schemaVersion: 1,
      environment: "production",
      releaseSha: config.releaseSha,
      sourceContractSha256: config.sourceContractSha256,
      packageChecksumSha256: config.packageChecksumSha256,
      images: {
        executor: config.executorImage,
        backend: config.backendImage,
        worker: config.workerImage,
        frontend: config.frontendImage,
      },
      receipts,
    };
    bundle.receiptBundleSha256 = sha256(`${JSON.stringify(bundle)}\n`);
    if (!outputPath) throw new Error("Production release receipt output path is required.");
    fs.writeFileSync(outputPath, `${JSON.stringify(bundle, null, 2)}\n`, { mode: 0o600, flag: "wx" });
    process.stdout.write(`${JSON.stringify({ status: "verified", releaseSha: config.releaseSha, receiptBundleSha256: bundle.receiptBundleSha256 })}\n`);
    return bundle;
  } catch (error) {
    if (mutationStarted) {
      try {
        const rollbackTask = registerTask("full-rls-rollback", config, aws, directory);
        const startedAt = runTask(rollbackTask, config, aws);
        readReceipt("full-rls-rollback", config, aws, directory, startedAt);
      } catch {
        throw new Error("Production package failed and exact rollback could not be verified.");
      }
    }
    throw error;
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  applyProductionFullRlsRelease().catch(() => {
    process.stderr.write('{"status":"blocked","reason":"production-full-rls-release-failed"}\n');
    process.exitCode = 1;
  });
}

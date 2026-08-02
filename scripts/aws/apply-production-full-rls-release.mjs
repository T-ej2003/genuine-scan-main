#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { PRODUCTION_GREEN } from "../../backend/scripts/production-full-rls-green-executor.mjs";
import { STAGE_B } from "./production-green-stage-b-contract.mjs";

const ACCOUNT = STAGE_B.account;
const REGION = STAGE_B.region;
const CLUSTER_ARN = STAGE_B.clusterArn;
const BROKER_ARN = STAGE_B.brokerAliasArn;
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

export function validateProductionReleaseEnvironment(env = process.env) {
  const config = {
    releaseSha: env.RELEASE_GIT_SHA,
    sourceContractSha256: env.MSCQR_FULL_RLS_SOURCE_CONTRACT_SHA256,
    migrationSetDigest: env.MSCQR_FULL_RLS_MIGRATION_SET_DIGEST,
    packageChecksumSha256: env.MSCQR_FULL_RLS_PACKAGE_CHECKSUM_SHA256,
    approvalId: env.PRODUCTION_RLS_APPROVAL_ID,
    brokerArn: env.PRODUCTION_RLS_BROKER_ARN,
    executorImage: env.PRODUCTION_RLS_EXECUTOR_IMAGE,
    backendImage: env.PRODUCTION_BACKEND_IMAGE,
    workerImage: env.PRODUCTION_WORKER_IMAGE,
    canaryImage: env.PRODUCTION_RLS_CANARY_IMAGE,
    frontendTaskDefinition: env.PRODUCTION_FRONTEND_TASK_DEFINITION,
    clusterArn: env.PRODUCTION_RLS_CLUSTER_ARN,
    receiptBucket: env.PRODUCTION_RLS_RECEIPT_BUCKET,
  };
  if (!/^[a-f0-9]{40}$/.test(config.releaseSha || "")
      || !/^[a-f0-9]{64}$/.test(config.sourceContractSha256 || "")
      || !/^[a-f0-9]{64}$/.test(config.migrationSetDigest || "")
      || !/^[a-f0-9]{64}$/.test(config.packageChecksumSha256 || "")
      || !/^[A-Za-z0-9][A-Za-z0-9._:/-]{5,127}$/.test(config.approvalId || "")
      || config.clusterArn !== CLUSTER_ARN
      || config.brokerArn !== BROKER_ARN
      || config.frontendTaskDefinition !== "mscqr-frontend:20"
      || !PRODUCTION_GREEN.receiptBucketPattern.test(config.receiptBucket || "")) {
    throw new Error("Production release binding is incomplete or outside the reviewed identity.");
  }
  for (const image of [config.executorImage, config.backendImage, config.workerImage, config.canaryImage]) {
    if (!new RegExp(`^${ACCOUNT}\\.dkr\\.ecr\\.${REGION}\\.amazonaws\\.com/mscqr-(?:backend|worker)@sha256:[a-f0-9]{64}$`).test(image || "")) {
      throw new Error("Production image binding must use an approved immutable ECR digest.");
    }
  }
  return config;
}

const defaultAws = (args) => {
  const result = spawnSync("aws", [...args, "--region", REGION, "--output", "json"], { encoding: "utf8" });
  if (result.status !== 0) throw new Error("Protected production broker command failed; provider detail suppressed.");
  return result.stdout.trim() ? JSON.parse(result.stdout) : {};
};

const invokeBroker = (mode, config, aws, directory) => {
  const requestPath = path.join(directory, `${mode}-broker-request.json`);
  const responsePath = path.join(directory, `${mode}-broker-response.json`);
  fs.writeFileSync(requestPath, JSON.stringify({ mode, approvalId: config.approvalId }), { mode: 0o600, flag: "wx" });
  const invoked = aws([
    "lambda", "invoke",
    "--function-name", STAGE_B.brokerFunctionArn,
    "--qualifier", STAGE_B.brokerAliasQualifier,
    "--cli-binary-format", "raw-in-base64-out",
    "--payload", `fileb://${requestPath}`,
    responsePath,
  ]);
  if (invoked.FunctionError) throw new Error("Production approval broker rejected the activation request.");
  const response = JSON.parse(fs.readFileSync(responsePath, "utf8"));
  if (response.status !== "started" || response.mode !== mode || response.approvalId !== config.approvalId) {
    throw new Error("Production approval broker response binding is invalid.");
  }
  return response.taskArn;
};

const waitForTask = (taskArn, config, aws) => {
  if (typeof taskArn !== "string" || !taskArn.startsWith(`${config.clusterArn.replace(":cluster/", ":task/")}/`)) {
    throw new Error("Production executor task identity is invalid.");
  }
  aws(["ecs", "wait", "tasks-stopped", "--cluster", config.clusterArn, "--tasks", taskArn]);
  const described = aws(["ecs", "describe-tasks", "--cluster", config.clusterArn, "--tasks", taskArn]);
  if (described.tasks?.length !== 1 || described.tasks[0]?.containers?.length !== 1 || described.tasks[0].containers[0]?.exitCode !== 0) {
    throw new Error("Production executor task failed; task detail suppressed.");
  }
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
      || value.migrationSetDigest !== config.migrationSetDigest
      || value.packageChecksumSha256 !== config.packageChecksumSha256
      || value.approvalId !== config.approvalId
      || Date.parse(value.completedAt || 0) < startedAt - 300_000
      || receiptSha256 !== sha256(`${JSON.stringify(value)}\n`)) {
    throw new Error("Production executor receipt binding is invalid.");
  }
  return {
    mode,
    receiptSha256,
    catalogueSha256: value.catalogueSha256,
    approvalContractSha256: value.approvalContractSha256,
  };
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
    for (const mode of APPLY_MODES) {
      mutationStarted ||= Boolean(PRODUCTION_GREEN.confirmations[mode]);
      const startedAt = Date.now();
      const taskArn = invokeBroker(mode, config, aws, directory);
      waitForTask(taskArn, config, aws);
      receipts.push(readReceipt(mode, config, aws, directory, startedAt));
    }
    const canaryTaskArn = invokeBroker("full-rls-application-canary", config, aws, directory);
    waitForTask(canaryTaskArn, config, aws);
    if (new Set(receipts.map((item) => item.approvalContractSha256)).size !== 1) {
      throw new Error("Production executor receipts do not share one approval contract.");
    }
    const bundle = {
      schemaVersion: 2,
      environment: "production",
      releaseSha: config.releaseSha,
      sourceContractSha256: config.sourceContractSha256,
      migrationSetDigest: config.migrationSetDigest,
      packageChecksumSha256: config.packageChecksumSha256,
      approvalId: config.approvalId,
      approvalContractSha256: receipts[0].approvalContractSha256,
      applicationCanary: "passed",
      images: {
        executor: config.executorImage,
        backend: config.backendImage,
        worker: config.workerImage,
        canary: config.canaryImage,
        frontendTaskDefinition: config.frontendTaskDefinition,
      },
      receipts,
    };
    bundle.receiptBundleSha256 = sha256(`${JSON.stringify(bundle)}\n`);
    if (!outputPath) throw new Error("Production release receipt output path is required.");
    fs.writeFileSync(outputPath, `${JSON.stringify(bundle, null, 2)}\n`, { mode: 0o600, flag: "wx" });
    process.stdout.write(`${JSON.stringify({ status: "verified", releaseSha: config.releaseSha, receiptBundleSha256: bundle.receiptBundleSha256 })}\n`);
    return bundle;
  } catch {
    if (mutationStarted) {
      try {
        const startedAt = Date.now();
        const taskArn = invokeBroker("full-rls-rollback", config, aws, directory);
        waitForTask(taskArn, config, aws);
        readReceipt("full-rls-rollback", config, aws, directory, startedAt);
      } catch {
        throw new Error("Production package failed and exact rollback could not be verified.");
      }
    }
    throw new Error("Production full-RLS activation failed; detail suppressed.");
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

import { PrismaClient } from "@prisma/client";
import { GetObjectCommand, PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { KMSClient, VerifyCommand } from "@aws-sdk/client-kms";
import { pathToFileURL } from "node:url";
import { signRdsIamToken, taskRoleCredentials } from "./victoria-rds-iam-token.mjs";
import { consumeVictoriaRecoveryNonce, verifyVictoriaRecoveryAuthorization, victoriaRecoveryImplementationSha256, VICTORIA_RECOVERY_IDENTITY } from "../../scripts/aws/victoria-recovery-authorization.mjs";
import { validateVictoriaRecoveryResult } from "../../scripts/aws/victoria-recovery-result.mjs";

const REGION = "eu-west-2";
const TASK_FAMILY = "mscqr-production-victoria-recovery";
const { operation: OPERATION, email: TARGET_EMAIL, database: TARGET_DATABASE } = VICTORIA_RECOVERY_IDENTITY;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{4}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const required = (value, name) => {
  if (typeof value !== "string" || !value.trim()) throw new Error(`${name}_MISSING`);
  return value.trim();
};

async function readAuthorization(s3, bucket, key) {
  const response = await s3.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
  const text = await response.Body.transformToString();
  const value = JSON.parse(text);
  if (Buffer.byteLength(text) > 16_384 || value?.operation !== OPERATION || value?.targetEmail !== TARGET_EMAIL
      || value?.targetDatabase !== TARGET_DATABASE || key !== `authorizations/${value?.nonce}.json`) {
    throw new Error("AUTHORIZATION_OBJECT_BINDING_INVALID");
  }
  return value;
}

async function taskIdentity() {
  const endpoint = required(process.env.ECS_CONTAINER_METADATA_URI_V4, "ECS_CONTAINER_METADATA_URI_V4");
  const response = await fetch(`${endpoint}/task`, { signal: AbortSignal.timeout(3000) });
  if (!response.ok) throw new Error("ECS_TASK_METADATA_UNAVAILABLE");
  const task = await response.json();
  const container = task.Containers?.find(({ Name }) => Name === "recovery");
  if (!container?.ImageID || !container.Image || task.Family !== TASK_FAMILY || !Number.isSafeInteger(Number(task.Revision))) throw new Error("ECS_TASK_IDENTITY_INVALID");
  const digest = String(container.ImageID).match(/(?:@)?sha256:([a-f0-9]{64})$/)?.[1];
  const image = `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-victoria-recovery@sha256:${digest || ""}`;
  if (!digest || container.Image !== image) throw new Error("ECS_IMAGE_DIGEST_UNAVAILABLE");
  return {
    image,
    taskDefinition: `arn:aws:ecs:eu-west-2:368992683803:task-definition/${task.Family}:${task.Revision}`,
  };
}

async function verifyKms({ keyId, message, signature }) {
  const client = new KMSClient({ region: REGION });
  try {
    const response = await client.send(new VerifyCommand({
      KeyId: keyId, Message: message, MessageType: "RAW", Signature: signature,
      SigningAlgorithm: "RSASSA_PSS_SHA_256",
    }));
    return response.SignatureValid === true;
  } finally {
    client.destroy();
  }
}

async function run() {
  const bucket = required(process.env.VICTORIA_RECOVERY_EVIDENCE_BUCKET, "VICTORIA_RECOVERY_EVIDENCE_BUCKET");
  const key = required(process.env.VICTORIA_RECOVERY_AUTHORIZATION_KEY, "VICTORIA_RECOVERY_AUTHORIZATION_KEY");
  const signingKeyArn = required(process.env.VICTORIA_RECOVERY_SIGNING_KEY_ARN, "VICTORIA_RECOVERY_SIGNING_KEY_ARN");
  const sourceSha = required(process.env.GIT_SHA, "GIT_SHA");
  if (!UUID.test(key.match(/^authorizations\/([^/]+)\.json$/)?.[1] || "")) throw new Error("AUTHORIZATION_OBJECT_KEY_INVALID");

  const aws = new S3Client({ region: REGION });
  const authorization = await readAuthorization(aws, bucket, key);
  const identity = await taskIdentity();
  const verified = await verifyVictoriaRecoveryAuthorization(authorization, {
    sourceSha,
    implementationSha256: victoriaRecoveryImplementationSha256(),
    executorImage: identity.image,
    executorTaskDefinition: identity.taskDefinition,
    signingKeyArn,
    operator: authorization.operator,
    approvedBy: authorization.approvedBy,
    approvalWorkflowRunId: authorization.approvalWorkflowRunId,
    approvalWorkflowRunAttempt: authorization.approvalWorkflowRunAttempt,
  }, { verify: verifyKms });
  await consumeVictoriaRecoveryNonce(verified, {
    putIfAbsent: async ({ key, body }) => {
      try {
        await aws.send(new PutObjectCommand({ Bucket: bucket, Key: key, Body: body, IfNoneMatch: "*", ServerSideEncryption: "aws:kms" }));
        return true;
      } catch (error) {
        if (error?.$metadata?.httpStatusCode === 412 || error?.name === "PreconditionFailed" || error?.name === "ConditionalRequestConflict") return false;
        throw error;
      }
    },
  });

  const host = required(process.env.VICTORIA_RDS_HOST, "VICTORIA_RDS_HOST");
  const credentials = await taskRoleCredentials();
  const token = signRdsIamToken({ host, username: "mscqr_prod_victoria_recovery", credentials });
  const connection = new URL(`postgresql://mscqr_prod_victoria_recovery@${host}:5432/${TARGET_DATABASE}?sslmode=verify-full`);
  connection.password = token;
  const databaseUrl = connection.toString();
  const db = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
  let result = null, transactionError = null, cleanupError = null;
  try {
    result = await db.$transaction(async (tx) => {
      const rows = await tx.$queryRaw`SELECT current_database() AS database`;
      if (rows.length !== 1 || rows[0].database !== TARGET_DATABASE) throw new Error("DATABASE_IDENTITY_INVALID");
      const [row] = await tx.$queryRaw`SELECT app_ops.victoria_failed_onboarding_recovery_v1() AS result`;
      if (!row?.result || row.result.operation !== OPERATION || row.result.targetEmail !== TARGET_EMAIL
          || row.result.targetDatabase !== TARGET_DATABASE) throw new Error("RECOVERY_RESULT_INVALID");
      return row.result;
    }, { isolationLevel: "Serializable", timeout: 60_000, maxWait: 10_000 });
  } catch (error) {
    transactionError = error;
  }
  try {
    await db.$transaction(async (tx) => {
      const [row] = await tx.$queryRaw`SELECT app_ops.victoria_failed_onboarding_recovery_v1_cleanup() AS revoked`;
      if (row?.revoked !== true) throw new Error("TEMPORARY_AUTHORITY_CLEANUP_FAILED");
    }, { isolationLevel: "Serializable", timeout: 15_000, maxWait: 5_000 });
  } catch (error) {
    cleanupError = error;
  } finally {
    await db.$disconnect();
  }

  const evidence = Buffer.from(JSON.stringify({ operation: OPERATION, sourceSha, authorizationNonce: verified.nonce,
    status: cleanupError ? "authority-cleanup-failed" : transactionError ? "transaction-failed" : result.pruneComplete ? "complete" : "stopped",
    reason: cleanupError ? "TEMPORARY_AUTHORITY_CLEANUP_FAILED" : transactionError ? "DATABASE_OPERATION_FAILED" : result.reason,
    temporaryAuthorityCleanup: cleanupError === null, result }));
  validateVictoriaRecoveryResult(JSON.parse(evidence), { sourceSha, nonce: verified.nonce, requireSuccess: false });
  await aws.send(new PutObjectCommand({ Bucket: bucket, Key: `results/${verified.nonce}.json`, Body: evidence,
    ContentType: "application/json", IfNoneMatch: "*", ServerSideEncryption: "aws:kms" }));
  process.stdout.write(`${JSON.stringify({ operation: OPERATION, targetEmail: TARGET_EMAIL, targetDatabase: TARGET_DATABASE,
    pruneComplete: result?.pruneComplete === true, temporaryAuthorityCleanup: cleanupError === null,
    reason: cleanupError ? "TEMPORARY_AUTHORITY_CLEANUP_FAILED" : transactionError ? "DATABASE_OPERATION_FAILED" : result.reason,
    evidenceKey: `results/${verified.nonce}.json` })}\n`);
  aws.destroy();
  if (cleanupError) process.exitCode = 3;
  else if (transactionError || result?.pruneComplete !== true) process.exitCode = 2;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  run().catch((error) => {
    process.stderr.write(`${JSON.stringify({ operation: OPERATION, status: "failed", reason: /^[A-Z0-9_]+$/.test(error.message) ? error.message : "EXECUTOR_FAILURE" })}\n`);
    process.exitCode = 1;
  });
}

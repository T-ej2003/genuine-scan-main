#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import {
  STAGE_B,
  STAGE_B_APPROVAL_ALGORITHM,
  stageBApprovalIdForReleaseSha,
  validateStageBApproval,
} from "./production-green-stage-b-contract.mjs";

const CHECKER_CALLER = new RegExp(`^arn:aws:sts::${STAGE_B.account}:assumed-role/mscqr-production-rls-independent-checker/[A-Za-z0-9+=,.@_-]{2,64}$`);
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");

export const approvalPublicationClientRequestToken = ({ approvalId, releaseSha }) =>
  sha256(Buffer.from(`${approvalId}\n${releaseSha}`, "utf8"));

const currentSourceSha = () => String(execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" })).trim();
const assertSourceSha = (value) => {
  if (!/^[a-f0-9]{40}$/.test(value)) throw new Error("Source SHA is not an exact commit.");
  return value;
};
const assertCleanSource = () => {
  if (String(execFileSync("git", ["status", "--porcelain", "--untracked-files=no"], { encoding: "utf8" })).trim()) throw new Error("Publisher requires a clean source checkout.");
};

export async function prepareStageBApprovalPublication({ approvalBytes, expectedSourceSha, callerArn, now = new Date(), verifySignature }) {
  if (!Buffer.isBuffer(approvalBytes) || !approvalBytes.length) throw new Error("Approval artifact is missing.");
  let approval;
  try { approval = JSON.parse(approvalBytes.toString("utf8")); } catch { throw new Error("Approval artifact is not valid JSON."); }
  const sourceSha = assertSourceSha(expectedSourceSha);
  if (!CHECKER_CALLER.test(callerArn) || approval.checkerIdentity !== callerArn) throw new Error("Only the exact independent checker session may publish the approval.");
  if (approval.approvalId !== stageBApprovalIdForReleaseSha(sourceSha) || approval.releaseSha !== sourceSha) throw new Error("Approval identity is not bound to the current release.");
  if (!verifySignature) throw new Error("Approval signature verifier is required.");
  const validated = await validateStageBApproval(approval, { releaseSha: sourceSha, approvalId: stageBApprovalIdForReleaseSha(sourceSha) }, { now, verifySignature });
  return {
    approval,
    approvalBytes,
    approvalSha256: sha256(approvalBytes),
    approvalContractSha256: validated.approvalContractSha256,
    clientRequestToken: approvalPublicationClientRequestToken({ approvalId: approval.approvalId, releaseSha: sourceSha }),
  };
}

export async function publishStageBApproval({ approvalPath, expectedSourceSha = currentSourceSha(), callerArn, now = new Date(), readFile = fs.readFileSync, verifySignature, putSecretValue, assertSource = assertCleanSource }) {
  assertSource();
  const prepared = await prepareStageBApprovalPublication({ approvalBytes: readFile(approvalPath), expectedSourceSha, callerArn, now, verifySignature });
  if (!putSecretValue) throw new Error("Approval publisher requires a Secrets Manager writer.");
  const response = await putSecretValue({
    SecretId: STAGE_B.approvalSecretArn,
    SecretString: prepared.approvalBytes.toString("utf8"),
    ClientRequestToken: prepared.clientRequestToken,
  });
  if (response.ARN !== STAGE_B.approvalSecretArn || response.VersionId !== prepared.clientRequestToken || !response.VersionStages?.includes("AWSCURRENT")) throw new Error("Secrets Manager publication response is outside the reviewed contract.");
  return { status: "published", secretArn: response.ARN, versionId: response.VersionId, versionStages: response.VersionStages, approvalId: prepared.approval.approvalId, sourceSha: prepared.approval.releaseSha, approvalSha256: prepared.approvalSha256, approvalContractSha256: prepared.approvalContractSha256 };
}

const runAwsJson = (args) => JSON.parse(execFileSync("aws", [...args, "--region", STAGE_B.region, "--output", "json", "--no-cli-pager"], { encoding: "utf8" }));
const callerArn = async () => String(runAwsJson(["sts", "get-caller-identity"]).Arn || "");
const withPrivateFile = (bytes, callback) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-b-approval-publish-"));
  const filePath = path.join(directory, "payload");
  try { fs.writeFileSync(filePath, bytes, { mode: 0o600, flag: "wx" }); return callback(filePath); } finally { fs.rmSync(directory, { recursive: true, force: true }); }
};
const verifySignature = async ({ keyId, message, signature }) => withPrivateFile(message, (messagePath) => {
  const result = runAwsJson(["kms", "verify", "--key-id", keyId, "--message", `fileb://${messagePath}`, "--message-type", "RAW", "--signature", Buffer.from(signature).toString("base64"), "--signing-algorithm", STAGE_B_APPROVAL_ALGORITHM]);
  return result.SignatureValid === true;
});
const putSecretValue = async ({ SecretId, SecretString, ClientRequestToken }) => withPrivateFile(Buffer.from(SecretString, "utf8"), (secretPath) => runAwsJson(["secretsmanager", "put-secret-value", "--secret-id", SecretId, "--secret-string", `file://${secretPath}`, "--client-request-token", ClientRequestToken]));

async function run(argv = process.argv.slice(2)) {
  const index = argv.indexOf("--approval");
  if (index < 0 || !argv[index + 1] || argv[index + 1].startsWith("--") || argv.some((value) => value === "--secret-arn")) throw new Error("--approval is required and the target secret is contract-bound.");
  const identity = await callerArn();
  const result = await publishStageBApproval({ approvalPath: argv[index + 1], callerArn: identity, verifySignature, putSecretValue });
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

if (process.argv[1]?.endsWith("publish-production-green-stage-b-approval.mjs")) run().catch(() => { process.stderr.write('{"status":"blocked","reason":"approval-publication-failed"}\n'); process.exitCode = 1; });

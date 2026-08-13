#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { STAGE_B, STAGE_B_APPROVAL_PUBLICATION_VALIDATION_OPERATION, stageBApprovalIdForReleaseSha } from "./production-green-stage-b-contract.mjs";

const RELEASE_CALLER = new RegExp(`^arn:aws:sts::${STAGE_B.account}:assumed-role/mscqr-production-release-deployer/[A-Za-z0-9+=,.@_-]{2,64}$`);
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const sourceSha = () => String(execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" })).trim();
const runAwsJson = (args) => JSON.parse(execFileSync("aws", [...args, "--region", STAGE_B.region, "--output", "json", "--no-cli-pager"], { encoding: "utf8" }));
const privateFiles = (files, callback) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-b-approval-check-"));
  try {
    const paths = Object.fromEntries(Object.entries(files).map(([name, bytes]) => {
      const filePath = path.join(directory, name);
      fs.writeFileSync(filePath, bytes, { mode: 0o600, flag: "wx" });
      return [name, filePath];
    }));
    return callback(paths);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
};

export function buildApprovalPublicationValidationRequest({ approvalBytes, expectedSourceSha = sourceSha() }) {
  let approval;
  try { approval = JSON.parse(approvalBytes.toString("utf8")); } catch { throw new Error("Approval artifact is not valid JSON."); }
  if (approval.approvalId !== stageBApprovalIdForReleaseSha(expectedSourceSha) || approval.releaseSha !== expectedSourceSha) throw new Error("Local approval is not bound to the current release.");
  return { approvalId: approval.approvalId, operation: STAGE_B_APPROVAL_PUBLICATION_VALIDATION_OPERATION, sourceSha: expectedSourceSha, approvalSha256: sha256(approvalBytes) };
}

export function validateApprovalPublicationProof(response, expected) {
  if (response?.status !== "validated" || response.approvalId !== expected.approvalId || response.sourceSha !== expected.sourceSha
      || response.approvalSha256 !== expected.approvalSha256 || !/^[a-f0-9]{64}$/.test(response.approvalContractSha256 || "")) throw new Error("Broker approval publication proof is invalid.");
  return { status: response.status, approvalId: response.approvalId, sourceSha: response.sourceSha, approvalSha256: response.approvalSha256, approvalContractSha256: response.approvalContractSha256 };
}

export function checkApprovalPublication({ approvalPath, expectedSourceSha = sourceSha(), callerArn, invoke }) {
  const approvalBytes = fs.readFileSync(approvalPath);
  const request = buildApprovalPublicationValidationRequest({ approvalBytes, expectedSourceSha });
  if (!RELEASE_CALLER.test(callerArn)) throw new Error("Only the release-deployer may request broker publication proof.");
  return invoke(request, (response) => validateApprovalPublicationProof(response, request));
}

const caller = () => String(runAwsJson(["sts", "get-caller-identity"]).Arn || "");
const invoke = (request, consume) => privateFiles({ payload: Buffer.from(`${JSON.stringify(request)}\n`), response: Buffer.alloc(0) }, ({ payload, response }) => {
  const result = runAwsJson(["lambda", "invoke", "--function-name", STAGE_B.brokerAliasArn, "--invocation-type", "RequestResponse", "--cli-binary-format", "raw-in-base64-out", "--payload", `fileb://${payload}`, response]);
  if (result.FunctionError) throw new Error("Broker approval publication proof invocation failed.");
  return consume(JSON.parse(fs.readFileSync(response, "utf8")));
});

if (process.argv[1]?.endsWith("check-production-green-stage-b-approval-publication.mjs")) {
  const index = process.argv.indexOf("--approval");
  if (index < 0 || !process.argv[index + 1] || process.argv[index + 1].startsWith("--")) {
    process.stderr.write('{"status":"blocked","reason":"--approval-is-required"}\n'); process.exitCode = 1;
  } else {
    try {
      const result = checkApprovalPublication({ approvalPath: process.argv[index + 1], callerArn: caller(), invoke });
      process.stdout.write(`${JSON.stringify(result)}\n`);
    } catch {
      process.stderr.write('{"status":"blocked","reason":"approval-publication-proof-failed"}\n'); process.exitCode = 1;
    }
  }
}

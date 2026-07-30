#!/usr/bin/env node
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import {
  STAGE_B,
  STAGE_B_APPROVAL_FIELDS,
  STAGE_B_APPROVAL_ALGORITHM,
  canonicalStageBApproval,
  stageBApprovalSha256,
  validateStageBApproval,
  validateStageBApprovalPayload,
} from "./production-green-stage-b-contract.mjs";

const option = (name) => {
  const index = process.argv.indexOf(name);
  return index < 0 ? "" : String(process.argv[index + 1] || "").trim();
};
const required = (name) => option(name) || (() => { throw new Error(`${name} is required.`); })();
const aws = (args) => {
  const result = spawnSync("aws", [...args, "--region", STAGE_B.region, "--output", "json"], { encoding: "utf8" });
  if (result.status !== 0) throw new Error("Stage B approval signing failed; provider detail suppressed.");
  return JSON.parse(result.stdout || "{}");
};
const exactInput = (input) => Object.keys(input || {}).sort().join(",") === [...STAGE_B_APPROVAL_FIELDS].sort().join(",");

export async function prepareStageBApproval(input, { now = new Date() } = {}) {
  if (!exactInput(input)) throw new Error("Stage B approval input fields do not match schema version 2.");
  if (input.signatureAlgorithm !== STAGE_B_APPROVAL_ALGORITHM) throw new Error("Stage B approval signing algorithm is outside the reviewed contract.");
  await validateStageBApprovalPayload(input, undefined, { now });
  return { approval: Object.fromEntries(STAGE_B_APPROVAL_FIELDS.map((field) => [field, input[field]])), approvalContractSha256: stageBApprovalSha256(input) };
}

export async function signStageBApproval(input, {
  now = new Date(),
  caller = async () => aws(["sts", "get-caller-identity"]),
  sign = async ({ message }) => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-b-approval-"));
    const messagePath = path.join(directory, "approval.json");
    try {
      fs.writeFileSync(messagePath, message, { mode: 0o600, flag: "wx" });
      return aws(["kms", "sign", "--key-id", STAGE_B.approvalKmsKeyArn, "--message", `fileb://${messagePath}`, "--message-type", "RAW", "--signing-algorithm", STAGE_B_APPROVAL_ALGORITHM]).Signature;
    } finally { fs.rmSync(directory, { recursive: true, force: true }); }
  },
  verifySignature = async ({ message, signature }) => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-b-approval-"));
    const messagePath = path.join(directory, "approval.json");
    try {
      fs.writeFileSync(messagePath, message, { mode: 0o600, flag: "wx" });
      return aws(["kms", "verify", "--key-id", STAGE_B.approvalKmsKeyArn, "--message", `fileb://${messagePath}`, "--message-type", "RAW", "--signature", Buffer.from(signature).toString("base64"), "--signing-algorithm", STAGE_B_APPROVAL_ALGORITHM]).SignatureValid === true;
    } finally { fs.rmSync(directory, { recursive: true, force: true }); }
  },
} = {}) {
  const prepared = await prepareStageBApproval(input, { now });
  const identity = String((await caller()).Arn || "");
  if (identity !== prepared.approval.checkerIdentity) throw new Error("Only the exact independent checker session may sign the Stage B approval.");
  const message = Buffer.from(canonicalStageBApproval(prepared.approval));
  const signatureBase64 = String(await sign({ keyId: STAGE_B.approvalKmsKeyArn, message }) || "");
  const artifact = { ...prepared.approval, signatureBase64 };
  await validateStageBApproval(artifact, undefined, { now, verifySignature });
  return { artifact, approvalContractSha256: prepared.approvalContractSha256 };
}

async function run() {
  const input = JSON.parse(fs.readFileSync(required("--input"), "utf8"));
  const signing = process.argv.includes("--sign");
  if (!signing) {
    const prepared = await prepareStageBApproval(input);
    process.stdout.write(`${JSON.stringify({ status: "validated", schemaVersion: 2, approvalContractSha256: prepared.approvalContractSha256 })}\n`);
    return;
  }
  const output = path.resolve(required("--output"));
  const { artifact, approvalContractSha256 } = await signStageBApproval(input);
  fs.writeFileSync(output, `${JSON.stringify(artifact, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  process.stdout.write(`${JSON.stringify({ status: "signed", schemaVersion: 2, approvalContractSha256 })}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  run().catch(() => { process.stderr.write('{"status":"blocked","reason":"stage-b-approval-failed"}\n'); process.exitCode = 1; });
}

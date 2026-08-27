#!/usr/bin/env node
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
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
import { createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";

const option = (name) => {
  const index = process.argv.indexOf(name);
  return index < 0 ? "" : String(process.argv[index + 1] || "").trim();
};
const required = (name) => option(name) || (() => { throw new Error(`${name} is required.`); })();
const exactInput = (input) => Object.keys(input || {}).sort().join(",") === [...STAGE_B_APPROVAL_FIELDS].sort().join(",");
const awsJson = (run, args) => JSON.parse(run([...args, "--output", "json"]) || "{}");
const withMessage = (callback) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-b-approval-"));
  const messagePath = path.join(directory, "approval.json");
  try { return callback(messagePath); } finally { fs.rmSync(directory, { recursive: true, force: true }); }
};

export async function prepareStageBApproval(input, { now = new Date() } = {}) {
  if (!exactInput(input)) throw new Error("Stage B approval input fields do not match schema version 2.");
  if (input.signatureAlgorithm !== STAGE_B_APPROVAL_ALGORITHM) throw new Error("Stage B approval signing algorithm is outside the reviewed contract.");
  await validateStageBApprovalPayload(input, undefined, { now });
  return { approval: Object.fromEntries(STAGE_B_APPROVAL_FIELDS.map((field) => [field, input[field]])), approvalContractSha256: stageBApprovalSha256(input) };
}

export async function signStageBApproval(input, {
  now = new Date(),
  caller,
  sign,
  verifySignature,
} = {}) {
  if (![caller, sign, verifySignature].every((value) => typeof value === "function")) throw new Error("Stage B approval signing requires an explicit independent-checker AWS boundary.");
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
  if (required("--credential-source") !== PRODUCTION_AWS_CREDENTIAL_SOURCE.INHERITED_CHECKER_SESSION) throw new Error("Stage B approval signing requires the inherited independent-checker session credential source.");
  const runAws = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.INHERITED_CHECKER_SESSION });
  const { artifact, approvalContractSha256 } = await signStageBApproval(input, {
    caller: async () => awsJson(runAws, ["sts", "get-caller-identity"]),
    sign: async ({ message }) => withMessage((messagePath) => {
      fs.writeFileSync(messagePath, message, { mode: 0o600, flag: "wx" });
      return awsJson(runAws, ["kms", "sign", "--key-id", STAGE_B.approvalKmsKeyArn, "--message", `fileb://${messagePath}`, "--message-type", "RAW", "--signing-algorithm", STAGE_B_APPROVAL_ALGORITHM]).Signature;
    }),
    verifySignature: async ({ message, signature }) => withMessage((messagePath) => {
      fs.writeFileSync(messagePath, message, { mode: 0o600, flag: "wx" });
      return awsJson(runAws, ["kms", "verify", "--key-id", STAGE_B.approvalKmsKeyArn, "--message", `fileb://${messagePath}`, "--message-type", "RAW", "--signature", Buffer.from(signature).toString("base64"), "--signing-algorithm", STAGE_B_APPROVAL_ALGORITHM]).SignatureValid === true;
    }),
  });
  fs.writeFileSync(output, `${JSON.stringify(artifact, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  process.stdout.write(`${JSON.stringify({ status: "signed", schemaVersion: 2, approvalContractSha256 })}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  run().catch(() => { process.stderr.write('{"status":"blocked","reason":"stage-b-approval-failed"}\n'); process.exitCode = 1; });
}

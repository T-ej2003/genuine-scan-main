#!/usr/bin/env node
import fs from "node:fs";
import { createHash } from "node:crypto";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";
import {
  STAGE_B,
  stageBApprovalFields,
  STAGE_B_APPROVAL_ALGORITHM,
  canonicalStageBApproval,
  stageBApprovalSha256,
  validateStageBApproval,
  validateStageBApprovalPayload,
} from "./production-green-stage-b-contract.mjs";
import { createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { prepareB03Approval, signB03Approval, createB03SourceAuthenticator } from "./create-production-b03-approval.mjs";
import { B03_BROKER, encodeB03Approval, b03ApprovalMessage } from "../../infra/aws/terraform/lambda/production-rls-approval-broker/b03-approval.mjs";

const option = (name) => {
  const index = process.argv.indexOf(name);
  return index < 0 ? "" : String(process.argv[index + 1] || "").trim();
};
const cryptoHash = bytes => createHash("sha256").update(bytes).digest("hex");
const required = (name) => option(name) || (() => { throw new Error(`${name} is required.`); })();
const exactInput = (input) => Object.keys(input || {}).sort().join(",") === stageBApprovalFields(input).sort().join(",");
const awsJson = (run, args) => JSON.parse(run([...args, "--output", "json"]) || "{}");
const withMessage = (callback) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-b-approval-"));
  const messagePath = path.join(directory, "approval.json");
  try { return callback(messagePath); } finally { fs.rmSync(directory, { recursive: true, force: true }); }
};

export async function prepareStageBApproval(input, options = {}) {
  const { now = new Date() } = options;
  if (input.operation === B03_BROKER.mode) {
    const request = await prepareB03Approval(input, options);
    return { approval: request.approval, approvalContractSha256: cryptoHash(b03ApprovalMessage(request.approval)) };
  }
  if (!exactInput(input)) throw new Error("Stage B approval input fields do not match schema version 2.");
  if (input.signatureAlgorithm !== STAGE_B_APPROVAL_ALGORITHM) throw new Error("Stage B approval signing algorithm is outside the reviewed contract.");
  await validateStageBApprovalPayload(input, undefined, { now });
  return { approval: Object.fromEntries(stageBApprovalFields(input).map((field) => [field, input[field]])), approvalContractSha256: stageBApprovalSha256(input) };
}

export async function signStageBApproval(input, options = {}) {
  const { now = new Date(), caller, sign, verifySignature } = options;
  if (input.operation === B03_BROKER.mode) {
    const request = await signB03Approval(input, options);
    const artifactBytes = encodeB03Approval(request);
    return { artifact: JSON.parse(artifactBytes), artifactBytes, approvalContractSha256: cryptoHash(b03ApprovalMessage(request.approval)) };
  }
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
  if (!signing && input.operation !== B03_BROKER.mode) {
    const prepared = await prepareStageBApproval(input);
    process.stdout.write(`${JSON.stringify({ status: "validated", schemaVersion: 2, approvalContractSha256: prepared.approvalContractSha256 })}\n`);
    return;
  }
  const output = signing ? path.resolve(required("--output")) : null;
  if (required("--credential-source") !== PRODUCTION_AWS_CREDENTIAL_SOURCE.INHERITED_CHECKER_SESSION) throw new Error("Stage B approval signing requires the inherited independent-checker session credential source.");
  const runAws = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.INHERITED_CHECKER_SESSION });
  const dependencies = {
    ...(input.operation === B03_BROKER.mode ? {
      authenticateSourceAndPackage: createB03SourceAuthenticator({ input, imageAuthorization: JSON.parse(fs.readFileSync(required("--image-authorization"), "utf8")), runAws }),
      describeTaskDefinition: async task => awsJson(runAws, ["ecs", "describe-task-definition", "--task-definition", task, "--include", "TAGS"]),
    } : {}),
    caller: async () => awsJson(runAws, ["sts", "get-caller-identity"]),
    sign: async ({ message }) => withMessage((messagePath) => {
      fs.writeFileSync(messagePath, message, { mode: 0o600, flag: "wx" });
      return awsJson(runAws, ["kms", "sign", "--key-id", STAGE_B.approvalKmsKeyArn, "--message", `fileb://${messagePath}`, "--message-type", "RAW", "--signing-algorithm", STAGE_B_APPROVAL_ALGORITHM]).Signature;
    }),
    verifySignature: async ({ message, signature }) => withMessage((messagePath) => {
      fs.writeFileSync(messagePath, message, { mode: 0o600, flag: "wx" });
      return awsJson(runAws, ["kms", "verify", "--key-id", STAGE_B.approvalKmsKeyArn, "--message", `fileb://${messagePath}`, "--message-type", "RAW", "--signature", Buffer.from(signature).toString("base64"), "--signing-algorithm", STAGE_B_APPROVAL_ALGORITHM]).SignatureValid === true;
    }),
  };
  if (!signing) {
    const prepared = await prepareStageBApproval(input, dependencies);
    process.stdout.write(`${JSON.stringify({ status: "validated", approvalContractSha256: prepared.approvalContractSha256 })}\n`);
    return;
  }
  const { artifact, artifactBytes, approvalContractSha256 } = await signStageBApproval(input, dependencies);
  fs.writeFileSync(output, artifactBytes || `${JSON.stringify(artifact, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  process.stdout.write(`${JSON.stringify({ status: "signed", schemaVersion: artifact.schemaVersion,
    ...(input.operation === B03_BROKER.mode ? { operation: input.operation } : {}), approvalContractSha256 })}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  run().catch(() => { process.stderr.write('{"status":"blocked","reason":"stage-b-approval-failed"}\n'); process.exitCode = 1; });
}

#!/usr/bin/env node
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import {
  PRODUCTION_RLS_APPROVAL_ALGORITHM,
  canonicalProductionApprovalPayload,
  productionApprovalSha256,
} from "../../backend/scripts/production-rls-approval.mjs";
import { calculateCleanRoomSourceContract } from "./lib/clean-room-source-contract.mjs";
import { createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "../aws/production-credential-source-contract.mjs";

const value = (name) => {
  const index = process.argv.indexOf(name);
  return index === -1 ? "" : String(process.argv[index + 1] || "").trim();
};
const required = (name) => value(name) || (() => { throw new Error(`${name} is required.`); })();

export function buildProductionApprovalPayload({
  releaseSha,
  deploymentId,
  approvalId,
  ticketId,
  kmsKeyArn,
  checkerIdentity,
  issuedAt,
  expiresAt,
  sourceContractSha256,
  migrationSetDigest,
}) {
  return {
    schemaVersion: 1,
    environment: "production",
    releaseSha,
    deploymentId,
    greenDatabase: `mscqr_production_rls_green_${deploymentId}`,
    sourceContractSha256,
    migrationSetDigest,
    approvalId,
    ticketId,
    administratorIdentity: "mscqr_prod_admin",
    independentCheckerIdentity: checkerIdentity,
    issuedAt,
    expiresAt,
    kmsKeyArn,
    signatureAlgorithm: PRODUCTION_RLS_APPROVAL_ALGORITHM,
  };
}

export function createProductionApproval({
  outputPath,
  releaseSha,
  deploymentId,
  approvalId,
  ticketId,
  kmsKeyArn,
  expiresAt,
  awsClient,
  now = new Date(),
}) {
  if (typeof awsClient !== "function") throw new Error("Production RLS approval requires an explicit independent-checker AWS command runner.");
  const caller = awsClient(["sts", "get-caller-identity"]);
  const checkerIdentity = String(caller.Arn || "");
  const { sourceContractSha256, migrationSetDigest } = calculateCleanRoomSourceContract();
  const payload = buildProductionApprovalPayload({
    releaseSha,
    deploymentId,
    approvalId,
    ticketId,
    kmsKeyArn,
    checkerIdentity,
    issuedAt: now.toISOString(),
    expiresAt: new Date(expiresAt).toISOString(),
    sourceContractSha256,
    migrationSetDigest,
  });
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-production-approval-"));
  const messagePath = path.join(directory, "payload.json");
  try {
    fs.writeFileSync(messagePath, canonicalProductionApprovalPayload(payload), { mode: 0o600, flag: "wx" });
    const signed = awsClient([
      "kms", "sign",
      "--key-id", kmsKeyArn,
      "--message", `fileb://${messagePath}`,
      "--message-type", "RAW",
      "--signing-algorithm", PRODUCTION_RLS_APPROVAL_ALGORITHM,
    ]);
    if (!signed.Signature) throw new Error("KMS did not return an approval signature.");
    const artifact = { ...payload, signatureBase64: signed.Signature };
    fs.writeFileSync(outputPath, `${JSON.stringify(artifact, null, 2)}\n`, { mode: 0o600, flag: "wx" });
    return { approvalId, approvalContractSha256: productionApprovalSha256(payload), outputPath };
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname)) {
  try {
    if (required("--credential-source") !== PRODUCTION_AWS_CREDENTIAL_SOURCE.INHERITED_CHECKER_SESSION) throw new Error("Production RLS approval requires the inherited independent-checker session credential source.");
    const runAws = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.INHERITED_CHECKER_SESSION });
    const result = createProductionApproval({
      outputPath: path.resolve(required("--output")),
      releaseSha: required("--release-sha"),
      deploymentId: required("--deployment-id"),
      approvalId: required("--approval-id"),
      ticketId: required("--ticket-id"),
      kmsKeyArn: required("--kms-key-arn"),
      expiresAt: required("--expires-at"),
      awsClient: (args) => JSON.parse(runAws([...args, "--output", "json"])),
    });
    process.stdout.write(`${JSON.stringify({ status: "signed", approvalId: result.approvalId, approvalContractSha256: result.approvalContractSha256 })}\n`);
  } catch {
    process.stderr.write('{"status":"blocked","reason":"production-rls-approval-failed"}\n');
    process.exitCode = 1;
  }
}

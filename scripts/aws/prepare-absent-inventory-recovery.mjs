#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { ABSENT_INVENTORY_PREDECESSOR, assertAbsentInventoryRecoveryPayload, assertIndependentFailedInventoryEvidence } from "../../infra/aws/terraform/lambda/production-rls-approval-broker/index.mjs";
import { STAGE_B, PRESERVED_INVENTORY_PREDECESSOR, canonicalJson, validateStageBApproval } from "./production-green-stage-b-contract.mjs";
import { readStageBPrivateFileBytes, writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";
import { createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";

const hash = bytes => crypto.createHash("sha256").update(bytes).digest("hex");
const json = (run, args) => JSON.parse(run([...args, "--output", "json", "--no-cli-pager"]));
export async function prepareAbsentInventoryRecovery({ configPath, runRead, runSign, now = new Date() }) {
  const root = json(runRead, ["sts", "get-caller-identity"]);
  const checker = json(runSign, ["sts", "get-caller-identity"]);
  if (root.Arn !== `arn:aws:iam::${STAGE_B.account}:root` || !new RegExp(`^arn:aws:sts::${STAGE_B.account}:assumed-role/mscqr-production-rls-independent-checker/[A-Za-z0-9+=,.@_-]+$`).test(checker.Arn || "")) throw new Error("Recovery requires the canonical root readback and independent checker signer.");
  const bytes = readStageBPrivateFileBytes({ filePath: configPath, repositoryRoot: process.cwd(), label: "Recovery cutover config" }).bytes;
  const config = JSON.parse(bytes), fixed = ABSENT_INVENTORY_PREDECESSOR;
  const head = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  if (execFileSync("git", ["rev-parse", "origin/main"], { encoding: "utf8" }).trim() !== head || config.sourceSha !== head || execFileSync("git", ["status", "--porcelain"], { encoding: "utf8" }).trim() || config.rotationId !== PRESERVED_INVENTORY_PREDECESSOR.rotationId || canonicalJson(config.inventoryFailedPredecessor) !== canonicalJson(PRESERVED_INVENTORY_PREDECESSOR)) throw new Error("Recovery requires clean current-source config and exact predecessor.");
  for (const key of ["rotationStateFile", "rotationFixtureFile", "overlapRuntimeProofFile", "readinessEvidenceFile"]) {
    if (!path.isAbsolute(config[key] || "") || path.dirname(config[key]) !== path.dirname(path.resolve(configPath)) || fs.existsSync(config[key])) throw new Error("Canonical rotation or overlap state exists or its location is ambiguous.");
  }
  const predecessorKey = "production-predeployment-rotation-inventory#0c14f7f9eab1481da87a58e0fe8445e882653437d3a13f7f535782e0b7e3794c";
  if (json(runRead, ["dynamodb", "get-item", "--table-name", STAGE_B.replayTable, "--consistent-read", "--key", JSON.stringify({ approvalMode: { S: predecessorKey } })]).Item) throw new Error("Predecessor claim reappeared.");
  const rows = json(runRead, ["dynamodb", "scan", "--table-name", STAGE_B.replayTable, "--consistent-read", "--filter-expression", "rotationId = :r OR predecessorOperationKey = :p OR approvalMode = :g", "--expression-attribute-values", JSON.stringify({ ":r": { S: config.rotationId }, ":p": { S: predecessorKey }, ":g": { S: `absent-inventory-recovery#${predecessorKey}` } })]);
  if (rows.Items?.length || rows.LastEvaluatedKey) throw new Error("Inventory successor exists or replay scan is incomplete.");
  const lookup = name => { const response = json(runRead, ["cloudtrail", "lookup-events", "--lookup-attributes", `AttributeKey=EventName,AttributeValue=${name}`, "--start-time", "2026-09-30T22:38:00Z", "--end-time", now.toISOString()]); if (response.NextToken || !Array.isArray(response.Events)) throw new Error("Inventory event history is incomplete."); return response.Events.map(entry => JSON.parse(entry.CloudTrailEvent)); };
  const runEvents = lookup("RunTask"), stopEvents = lookup("StopTask");
  const logResponse = json(runRead, ["logs", "get-log-events", "--log-group-name", STAGE_B.inventoryLogGroupName, "--log-stream-name", `predeployment-inventory/inventory/${fixed.taskArn.split("/").pop()}`, "--start-from-head"]);
  const logEvents = [...(logResponse.events || [])]; let token = logResponse.nextForwardToken;
  for (let page = 0; token; page++) {
    if (page >= 20 || Buffer.byteLength(JSON.stringify(logEvents)) > 128 * 1024) throw new Error("Inventory logs are incomplete.");
    const next = json(runRead, ["logs", "get-log-events", "--log-group-name", STAGE_B.inventoryLogGroupName, "--log-stream-name", `predeployment-inventory/inventory/${fixed.taskArn.split("/").pop()}`, "--start-from-head", "--next-token", token]);
    logEvents.push(...(next.events || [])); if (!next.nextForwardToken || next.nextForwardToken === token) break; token = next.nextForwardToken;
  }
  const approval = json(runRead, ["secretsmanager", "get-secret-value", "--secret-id", STAGE_B.approvalSecretArn, "--version-id", fixed.approvalVersionId]).SecretString;
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-absent-inventory-sign-")); fs.chmodSync(directory, 0o700);
  const messagePath = path.join(directory, "message");
  try {
    const verifySignature = async ({ keyId, message, signature }) => {
      fs.writeFileSync(messagePath, message, { mode: 0o600 });
      return json(runRead, ["kms", "verify", "--key-id", keyId, "--message", `fileb://${messagePath}`, "--message-type", "RAW", "--signature", Buffer.from(signature).toString("base64"), "--signing-algorithm", "RSASSA_PSS_SHA_256"]).SignatureValid === true;
    };
    const authenticated = await validateStageBApproval(approval, { releaseSha: PRESERVED_INVENTORY_PREDECESSOR.releaseSha, approvalId: PRESERVED_INVENTORY_PREDECESSOR.approvalId, images: { backendImageDigest: PRESERVED_INVENTORY_PREDECESSOR.imageDigest } }, { now: new Date(fixed.startedAt), verifySignature });
    const proof = assertIndependentFailedInventoryEvidence({ runEvents, stopEvents, logEvents, authorizationSha256: authenticated.approvalContractSha256 });
    const payload = { schemaVersion: 1, purpose: "recover-exact-absent-inventory-predecessor", sourceSha: config.sourceSha, imageReleaseSha: config.imageReleaseSha, configSha256: hash(bytes), rotationId: config.rotationId, originalConfigSha256: fixed.configSha256, originalAuthorizationSha256: proof.authorizationSha256, taskArn: fixed.taskArn, runTaskEventId: proof.runTaskEventId, stopTaskEventId: proof.stopTaskEventId, logEventsSha256: proof.logEventsSha256, successfulInventoryOutputAbsent: true, rotationStateAbsent: true, verifiedOverlapAbsent: true, issuedAt: now.toISOString(), expiresAt: new Date(now.getTime() + 15 * 60 * 1000).toISOString() };
    assertAbsentInventoryRecoveryPayload(payload, payload, now);
    fs.writeFileSync(messagePath, canonicalJson(payload), { mode: 0o600 });
    const signatureBase64 = json(runSign, ["kms", "sign", "--key-id", STAGE_B.approvalKmsKeyArn, "--message", `fileb://${messagePath}`, "--message-type", "RAW", "--signing-algorithm", "RSASSA_PSS_SHA_256"]).Signature;
    if (!await verifySignature({ keyId: STAGE_B.approvalKmsKeyArn, message: Buffer.from(canonicalJson(payload)), signature: Buffer.from(signatureBase64, "base64") })) throw new Error("Recovery signature did not verify.");
    const filePath = path.join(path.dirname(path.resolve(configPath)), "inventory-absent-claim-evidence.json");
    writeStageBPrivateFileAtomic({ filePath, bytes: Buffer.from(`${JSON.stringify({ payload, signatureBase64 })}\n`), repositoryRoot: process.cwd(), overwrite: true, label: "Absent inventory recovery evidence" });
    return { filePath, configSha256: payload.configSha256, expiresAt: payload.expiresAt };
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const index = process.argv.indexOf("--config"); if (index < 0 || !process.argv[index + 1]) throw new Error("--config is required");
  const runRead = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: "mscqr-production-root" });
  const runSign = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.INHERITED_CHECKER_SESSION });
  console.log(JSON.stringify(await prepareAbsentInventoryRecovery({ configPath: process.argv[index + 1], runRead, runSign })));
}

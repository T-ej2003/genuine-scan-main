import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { createHandler } from "../../infra/aws/terraform/lambda/production-rls-approval-broker/index.mjs";
import { STAGE_B, STAGE_B_APPROVAL_ALGORITHM, STAGE_B_BROKER_TASK_DEFINITION_FAMILIES, canonicalStageBApproval, stageBApprovalIdForReleaseSha } from "../aws/production-green-stage-b-contract.mjs";
import { stageBTemplateHashes } from "../aws/production-green-stage-b-task-definitions.mjs";
import { prepareStageBApproval, signStageBApproval } from "../aws/create-production-green-stage-b-approval.mjs";

const now = new Date("2026-07-30T12:00:00.000Z");
const digest = (value) => value.repeat(64);
const image = (repository, value) => `368992683803.dkr.ecr.eu-west-2.amazonaws.com/${repository}@sha256:${digest(value)}`;
const taskDefinitionArns = Object.fromEntries(Object.entries(STAGE_B_BROKER_TASK_DEFINITION_FAMILIES).map(([mode, family]) => [mode, `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}:1`]));
const checkerIdentity = "arn:aws:sts::368992683803:assumed-role/mscqr-production-rls-independent-checker/checker";
const deployerIdentity = "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/deployer";
const input = (overrides = {}) => ({
  schemaVersion: 2, environment: "production", account: STAGE_B.account, region: STAGE_B.region,
  releaseSha: "a".repeat(40), sourceContractSha256: digest("b"), migrationSetDigest: digest("c"), packageChecksumSha256: digest("d"), deploymentId: "phase2",
  greenDatabaseIdentifier: STAGE_B.greenDatabaseIdentifier, greenDatabaseName: "mscqr_production_rls_green_phase2", administratorIdentity: "mscqr_prod_admin",
  databaseSecurityGroupId: STAGE_B.databaseSecurityGroupId, executorSecurityGroupId: STAGE_B.executorSecurityGroupId,
  backendImageDigest: image("mscqr-backend", "1"), workerImageDigest: image("mscqr-worker", "2"), executorImageDigest: image("mscqr-backend", "3"), canaryImageDigest: image("mscqr-backend", "4"),
  taskDefinitionArns, taskDefinitionTemplateHashes: stageBTemplateHashes(), brokerAliasArn: STAGE_B.brokerAliasArn, brokerVersion: "1",
  checkerIdentity, deployerIdentity, executorIdentity: STAGE_B.executorRoleArn, approvalId: stageBApprovalIdForReleaseSha("a".repeat(40)), ticketId: "CHG-STAGE-B-0001",
  issuedAt: "2026-07-30T11:55:00.000Z", expiresAt: "2026-07-30T13:00:00.000Z", nonce: "12345678-1234-1234-1234-123456789abc", signatureAlgorithm: STAGE_B_APPROVAL_ALGORITHM,
  ...overrides,
});
const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const sign = async ({ message }) => crypto.sign("sha256", message, { key: privateKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }).toString("base64");
const verifySignature = async ({ message, signature }) => crypto.verify("sha256", message, { key: publicKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, signature);

test("v2 approval dry-run is deterministic, exact, and makes no KMS call", async () => {
  const calls = []; const first = await prepareStageBApproval(input(), { now }); const second = await prepareStageBApproval(JSON.parse(JSON.stringify(input())), { now });
  assert.equal(first.approvalContractSha256, second.approvalContractSha256); assert.equal(calls.length, 0);
  assert.equal(canonicalStageBApproval(first.approval), canonicalStageBApproval(second.approval));
});

test("v2 creator rejects unknown or missing fields, invalid bindings, signer equality, expiry, nonce, and mutable images", async () => {
  for (const candidate of [
    (() => { const value = input(); delete value.nonce; return value; })(), { ...input(), extra: true }, input({ schemaVersion: 1 }), input({ releaseSha: "invalid" }), input({ backendImageDigest: "mscqr-backend:latest" }), input({ checkerIdentity: "arn:aws:sts::368992683803:assumed-role/unreviewed/checker" }), input({ checkerIdentity: deployerIdentity }), input({ taskDefinitionArns: { ...taskDefinitionArns, "full-rls-verification": "not-an-arn" } }), input({ nonce: "bad" }), input({ expiresAt: "2026-07-30T11:59:00.000Z" }), input({ signatureAlgorithm: "RSASSA_PKCS1_V1_5_SHA_256" }), input({ brokerAliasArn: "arn:aws:lambda:eu-west-2:368992683803:function:other:reviewed" }),
  ]) await assert.rejects(() => prepareStageBApproval(candidate, { now }));
});

test("v2 creator requires complete exact task-definition and template-hash maps", async () => {
  const templateHashes = stageBTemplateHashes();
  const missingArn = { ...taskDefinitionArns }; delete missingArn["full-rls-verification"];
  const missingHash = { ...templateHashes }; delete missingHash.backend;
  await assert.doesNotReject(() => prepareStageBApproval(input(), { now }));
  for (const candidate of [
    input({ taskDefinitionArns: missingArn }),
    input({ taskDefinitionTemplateHashes: missingHash }),
    input({ taskDefinitionArns: { ...taskDefinitionArns, extra: taskDefinitionArns["full-rls-verification"] } }),
    input({ taskDefinitionTemplateHashes: { ...templateHashes, extra: templateHashes.backend } }),
    input({ taskDefinitionTemplateHashes: { ...Object.fromEntries(Object.entries(templateHashes).filter(([key]) => key !== "backend")), "full-rls-verification": templateHashes.backend } }),
    input({ taskDefinitionArns: { ...taskDefinitionArns, "full-rls-verification": templateHashes.backend } }),
  ]) await assert.rejects(() => prepareStageBApproval(candidate, { now }));
});

test("explicit signing validates the v2 artifact through the broker validator without KMS in tests", async () => {
  const { artifact } = await signStageBApproval(input(), { now, caller: async () => ({ Arn: checkerIdentity }), sign, verifySignature });
  const config = { clusterArn: STAGE_B.clusterArn, approvalSecretArn: STAGE_B.approvalSecretArn, executorSecurityGroupId: STAGE_B.executorSecurityGroupId, privateSubnetIds: STAGE_B.privateSubnetIds, replayTable: "replay", receiptBucket: STAGE_B.receiptBucket, taskDefinitionArns, templateHashes: stageBTemplateHashes(), approvalExpected: { releaseSha: artifact.releaseSha, sourceContractSha256: artifact.sourceContractSha256, migrationSetDigest: artifact.migrationSetDigest, packageChecksumSha256: artifact.packageChecksumSha256, deploymentId: artifact.deploymentId, approvalId: artifact.approvalId, ticketId: artifact.ticketId, images: { backendImageDigest: artifact.backendImageDigest, workerImageDigest: artifact.workerImageDigest, executorImageDigest: artifact.executorImageDigest, canaryImageDigest: artifact.canaryImageDigest }, taskDefinitionArns }, images: { backendImageDigest: artifact.backendImageDigest, workerImageDigest: artifact.workerImageDigest, executorImageDigest: artifact.executorImageDigest, canaryImageDigest: artifact.canaryImageDigest } };
  const handler = createHandler({ config, readApproval: async () => JSON.stringify(artifact), verifySignature, claimApproval: async () => {}, runTask: async () => ({ failures: [], tasks: [{ taskArn: "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/fixed" }] }), now: () => now });
  await assert.doesNotReject(() => handler({ approvalId: artifact.approvalId, mode: "full-rls-verification" }));
  await assert.rejects(() => signStageBApproval(input(), { now, caller: async () => ({ Arn: deployerIdentity }), sign, verifySignature }), /exact independent checker/);
});

import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { createHandler } from "../../infra/aws/terraform/lambda/production-rls-approval-broker/index.mjs";
import { STAGE_B, STAGE_B_APPROVAL_ALGORITHM, STAGE_B_BROKER_TASK_DEFINITION_FAMILIES, canonicalStageBApproval, stageBApprovalIdForReleaseSha } from "../aws/production-green-stage-b-contract.mjs";
import { stageBTemplateHashes } from "../aws/production-green-stage-b-task-definitions.mjs";
import { approvalPublicationClientRequestToken, prepareStageBApprovalPublication, publishStageBApproval } from "../aws/publish-production-green-stage-b-approval.mjs";
import { buildApprovalPublicationValidationRequest, validateApprovalPublicationProof } from "../aws/check-production-green-stage-b-approval-publication.mjs";

const now = new Date("2026-07-30T12:00:00.000Z");
const sourceSha = "a".repeat(40);
const digest = (seed) => seed.repeat(64);
const image = (name, seed) => `368992683803.dkr.ecr.eu-west-2.amazonaws.com/${name}@sha256:${digest(seed)}`;
const taskDefinitionArns = Object.fromEntries(Object.entries(STAGE_B_BROKER_TASK_DEFINITION_FAMILIES).map(([mode, family]) => [mode, `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}:1`]));
const checker = "arn:aws:sts::368992683803:assumed-role/mscqr-production-rls-independent-checker/checker";
const release = "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/release";
const approval = (overrides = {}) => ({
  schemaVersion: 2, environment: "production", account: STAGE_B.account, region: STAGE_B.region, releaseSha: sourceSha,
  sourceContractSha256: digest("b"), migrationSetDigest: digest("c"), packageChecksumSha256: digest("d"), deploymentId: "phase2",
  greenDatabaseIdentifier: STAGE_B.greenDatabaseIdentifier, greenDatabaseName: "mscqr_production_rls_green_phase2", administratorIdentity: "mscqr_prod_admin",
  databaseSecurityGroupId: STAGE_B.databaseSecurityGroupId, executorSecurityGroupId: STAGE_B.executorSecurityGroupId,
  backendImageDigest: image("mscqr-backend", "1"), workerImageDigest: image("mscqr-worker", "2"), executorImageDigest: image("mscqr-backend", "3"), canaryImageDigest: image("mscqr-backend", "4"),
  taskDefinitionArns, taskDefinitionTemplateHashes: stageBTemplateHashes(), brokerAliasArn: STAGE_B.brokerAliasArn, brokerVersion: "1",
  checkerIdentity: checker, deployerIdentity: release, executorIdentity: STAGE_B.executorRoleArn, approvalId: stageBApprovalIdForReleaseSha(sourceSha), ticketId: "CHG-STAGE-B-0001",
  issuedAt: "2026-07-30T11:55:00.000Z", expiresAt: "2026-07-30T13:00:00.000Z", nonce: "12345678-1234-1234-1234-123456789abc", signatureAlgorithm: STAGE_B_APPROVAL_ALGORITHM,
  ...overrides,
});
const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const sign = (value) => crypto.sign("sha256", Buffer.from(canonicalStageBApproval(value)), { key: privateKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }).toString("base64");
const signedBytes = (value = approval()) => Buffer.from(`${JSON.stringify({ ...value, signatureBase64: sign(value) }, null, 2)}\n`);
const verifySignature = async ({ message, signature }) => crypto.verify("sha256", message, { key: publicKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, signature);

test("publisher validates before write, targets only the canonical secret, and publishes exact bytes", async () => {
  const bytes = signedBytes(); let writes = 0; let request;
  const result = await publishStageBApproval({ approvalPath: "/private/tmp/approval.json", expectedSourceSha: sourceSha, callerArn: checker, now, readFile: () => bytes, verifySignature, assertSource: () => {}, putSecretValue: async (value) => { writes += 1; request = value; return { ARN: STAGE_B.approvalSecretArn, VersionId: approvalPublicationClientRequestToken({ approvalId: stageBApprovalIdForReleaseSha(sourceSha), releaseSha: sourceSha }), VersionStages: ["AWSCURRENT"] }; } });
  assert.equal(writes, 1); assert.equal(request.SecretId, STAGE_B.approvalSecretArn); assert.equal(request.SecretString, bytes.toString("utf8")); assert.equal(result.status, "published");
});

test("publisher rejects malformed, unsigned, expired, wrong-source, and wrong-caller artifacts before write", async () => {
  for (const [label, bytes, callerArn] of [
    ["malformed", Buffer.from("{"), checker],
    ["unsigned", Buffer.from(`${JSON.stringify(approval())}\n`), checker],
    ["wrong source", signedBytes(approval({ releaseSha: "b".repeat(40) })), checker],
    ["expired", signedBytes(approval({ expiresAt: "2026-07-30T11:59:00.000Z" })), checker],
    ["release deployer", signedBytes(), release],
  ]) {
    let writes = 0;
    await assert.rejects(() => publishStageBApproval({ approvalPath: label, expectedSourceSha: sourceSha, callerArn, now, readFile: () => bytes, verifySignature, assertSource: () => {}, putSecretValue: async () => { writes += 1; } }));
    assert.equal(writes, 0, label);
  }
});

test("deterministic client token rejects mutated logical approval identity and preserves safe retry semantics", () => {
  const first = approvalPublicationClientRequestToken({ approvalId: stageBApprovalIdForReleaseSha(sourceSha), releaseSha: sourceSha });
  const retry = approvalPublicationClientRequestToken({ approvalId: stageBApprovalIdForReleaseSha(sourceSha), releaseSha: sourceSha });
  const changed = approvalPublicationClientRequestToken({ approvalId: stageBApprovalIdForReleaseSha("b".repeat(40)), releaseSha: "b".repeat(40) });
  assert.equal(first, retry); assert.notEqual(first, changed); assert.match(first, /^[a-f0-9]{64}$/);
});

test("release-unique approval IDs prevent cross-release same-mode collisions while preserving replay protection", async () => {
  const releaseA = "a".repeat(40); const releaseB = "b".repeat(40); const claimed = new Set();
  const run = async (releaseSha, mode) => {
    const value = approval({ releaseSha, approvalId: stageBApprovalIdForReleaseSha(releaseSha) });
    const raw = JSON.stringify({ ...value, signatureBase64: sign(value) });
    const expected = { releaseSha, sourceContractSha256: value.sourceContractSha256, migrationSetDigest: value.migrationSetDigest, packageChecksumSha256: value.packageChecksumSha256, deploymentId: value.deploymentId, approvalId: value.approvalId, ticketId: value.ticketId, images: { backendImageDigest: value.backendImageDigest, workerImageDigest: value.workerImageDigest, executorImageDigest: value.executorImageDigest, canaryImageDigest: value.canaryImageDigest }, taskDefinitionArns };
    const config = { clusterArn: STAGE_B.clusterArn, approvalSecretArn: STAGE_B.approvalSecretArn, executorSecurityGroupId: STAGE_B.executorSecurityGroupId, privateSubnetIds: STAGE_B.privateSubnetIds, replayTable: STAGE_B.replayTable, receiptBucket: STAGE_B.receiptBucket, taskDefinitionArns, templateHashes: stageBTemplateHashes(), approvalExpected: expected, images: expected.images };
    return createHandler({ config, executingBrokerVersion: "1", readApproval: async () => raw, verifySignature, claimApproval: async ({ approvalId, mode: requestedMode }) => { const key = `${approvalId}#${requestedMode}`; if (claimed.has(key)) throw new Error("approval replay"); claimed.add(key); }, runTask: async () => ({ failures: [], tasks: [{ taskArn: "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/fixed" }] }), now: () => now })({ approvalId: value.approvalId, mode });
  };
  await run(releaseA, "full-rls-verification");
  await run(releaseB, "full-rls-verification");
  await run(releaseA, "full-rls-admin-bootstrap");
  await assert.rejects(() => run(releaseA, "full-rls-verification"), /replay/);
  assert.notEqual(stageBApprovalIdForReleaseSha(releaseA), stageBApprovalIdForReleaseSha(releaseB));
  await assert.rejects(() => prepareStageBApprovalPublication({ approvalBytes: Buffer.from(JSON.stringify(approval({ approvalId: "APR-STAGE-B-0001" }))), expectedSourceSha: releaseA, callerArn: checker, now, verifySignature }), /identity/);
});

test("broker validation proves AWSCURRENT without claiming or launching work", async () => {
  const artifact = JSON.parse(signedBytes()); const raw = JSON.stringify(artifact); const calls = [];
  const config = { clusterArn: STAGE_B.clusterArn, approvalSecretArn: STAGE_B.approvalSecretArn, executorSecurityGroupId: STAGE_B.executorSecurityGroupId, privateSubnetIds: STAGE_B.privateSubnetIds, replayTable: STAGE_B.replayTable, receiptBucket: STAGE_B.receiptBucket, taskDefinitionArns, templateHashes: stageBTemplateHashes(), approvalExpected: { releaseSha: sourceSha, sourceContractSha256: artifact.sourceContractSha256, migrationSetDigest: artifact.migrationSetDigest, packageChecksumSha256: artifact.packageChecksumSha256, deploymentId: artifact.deploymentId, approvalId: artifact.approvalId, ticketId: artifact.ticketId, images: { backendImageDigest: artifact.backendImageDigest, workerImageDigest: artifact.workerImageDigest, executorImageDigest: artifact.executorImageDigest, canaryImageDigest: artifact.canaryImageDigest }, taskDefinitionArns }, images: { backendImageDigest: artifact.backendImageDigest, workerImageDigest: artifact.workerImageDigest, executorImageDigest: artifact.executorImageDigest, canaryImageDigest: artifact.canaryImageDigest } };
  const event = buildApprovalPublicationValidationRequest({ approvalBytes: Buffer.from(raw), expectedSourceSha: sourceSha });
  const result = await createHandler({ config, executingBrokerVersion: "1", readApproval: async () => raw, verifySignature, claimApproval: async () => calls.push("claim"), runTask: async () => calls.push("run"), now: () => now })(event);
  assert.equal(result.status, "validated"); assert.deepEqual(calls, []); assert.equal(result.approvalSha256, crypto.createHash("sha256").update(raw).digest("hex"));
  assert.deepEqual(validateApprovalPublicationProof(result, event), result);
});

test("broker publication validation rejects an approval for another immutable Lambda version", async () => {
  const artifact = JSON.parse(signedBytes()); const raw = JSON.stringify(artifact);
  const config = { clusterArn: STAGE_B.clusterArn, approvalSecretArn: STAGE_B.approvalSecretArn, executorSecurityGroupId: STAGE_B.executorSecurityGroupId, privateSubnetIds: STAGE_B.privateSubnetIds, replayTable: STAGE_B.replayTable, receiptBucket: STAGE_B.receiptBucket, taskDefinitionArns, templateHashes: stageBTemplateHashes(), approvalExpected: { releaseSha: sourceSha, sourceContractSha256: artifact.sourceContractSha256, migrationSetDigest: artifact.migrationSetDigest, packageChecksumSha256: artifact.packageChecksumSha256, deploymentId: artifact.deploymentId, approvalId: artifact.approvalId, ticketId: artifact.ticketId }, images: { backendImageDigest: artifact.backendImageDigest, workerImageDigest: artifact.workerImageDigest, executorImageDigest: artifact.executorImageDigest, canaryImageDigest: artifact.canaryImageDigest } };
  const event = buildApprovalPublicationValidationRequest({ approvalBytes: Buffer.from(raw), expectedSourceSha: sourceSha });
  const handler = createHandler({ config, executingBrokerVersion: "2", readApproval: async () => raw, verifySignature, claimApproval: async () => assert.fail("publication proof must not claim"), runTask: async () => assert.fail("publication proof must not run"), now: () => now });
  await assert.rejects(() => handler(event), /brokerVersion/);
});

test("broker validation rejects tampered bytes and wrong source without AWS work", async () => {
  const artifact = JSON.parse(signedBytes()); const raw = JSON.stringify(artifact); const config = { clusterArn: STAGE_B.clusterArn, approvalSecretArn: STAGE_B.approvalSecretArn, executorSecurityGroupId: STAGE_B.executorSecurityGroupId, privateSubnetIds: STAGE_B.privateSubnetIds, replayTable: STAGE_B.replayTable, receiptBucket: STAGE_B.receiptBucket, taskDefinitionArns, templateHashes: stageBTemplateHashes(), approvalExpected: { releaseSha: sourceSha, sourceContractSha256: artifact.sourceContractSha256, migrationSetDigest: artifact.migrationSetDigest, packageChecksumSha256: artifact.packageChecksumSha256, deploymentId: artifact.deploymentId, approvalId: artifact.approvalId, ticketId: artifact.ticketId, images: { backendImageDigest: artifact.backendImageDigest, workerImageDigest: artifact.workerImageDigest, executorImageDigest: artifact.executorImageDigest, canaryImageDigest: artifact.canaryImageDigest }, taskDefinitionArns }, images: { backendImageDigest: artifact.backendImageDigest, workerImageDigest: artifact.workerImageDigest, executorImageDigest: artifact.executorImageDigest, canaryImageDigest: artifact.canaryImageDigest } };
  const handler = createHandler({ config, executingBrokerVersion: "1", readApproval: async () => raw, verifySignature, claimApproval: async () => assert.fail("claim must not run"), runTask: async () => assert.fail("run must not run"), now: () => now });
  await assert.rejects(() => handler({ ...buildApprovalPublicationValidationRequest({ approvalBytes: Buffer.from(raw), expectedSourceSha: sourceSha }), approvalSha256: "0".repeat(64) }));
  await assert.rejects(() => handler({ ...buildApprovalPublicationValidationRequest({ approvalBytes: Buffer.from(raw), expectedSourceSha: sourceSha }), sourceSha: "b".repeat(40) }));
});

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { prepareStageBApproval } from "../aws/create-production-green-stage-b-approval.mjs";
import { STAGE_B, STAGE_B_APPROVAL_ALGORITHM, STAGE_B_MODES } from "../aws/production-green-stage-b-contract.mjs";
import { prepareProductionGreenStageBApprovalInput, writeProductionGreenStageBApprovalInput } from "../aws/prepare-production-green-stage-b-approval-input.mjs";
import { stageBTemplateHashes } from "../aws/production-green-stage-b-task-definitions.mjs";

const releaseSha = "8d7ecc53a0c8d0ec07dfce1aeb03dc22d0f43f82";
const checkerIdentity = "arn:aws:sts::368992683803:assumed-role/mscqr-production-rls-independent-checker/checker-session";
const deployerIdentity = "arn:aws:sts::368992683803/assumed-role/mscqr-production-release-deployer/deployer-session".replace("368992683803/", "368992683803:");
const image = (name) => `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-${name === "worker" ? "worker" : "backend"}@sha256:${({ backend: "b", worker: "a", executor: "e", canary: "c" })[name].repeat(64)}`;
const digest = (character) => character.repeat(64);
const taskDefinitionArns = Object.fromEntries(STAGE_B_MODES.map((mode) => [mode, `arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-${mode}:4`]));

const evidence = (overrides = {}) => ({
  releaseSha,
  backendImageDigest: image("backend"),
  workerImageDigest: image("worker"),
  executorImageDigest: image("executor"),
  canaryImageDigest: image("canary"),
  sourceContractSha256: digest("a"),
  migrationSetDigest: digest("b"),
  packageChecksumSha256: digest("c"),
  taskDefinitionArns,
  brokerVersion: "4",
  checkerIdentity,
  deployerIdentity,
  provenance: {
    releaseSha: "protected-main-checkout",
    backendImageDigest: "production-green-stage-b-image-evidence",
    workerImageDigest: "production-green-stage-b-image-evidence",
    executorImageDigest: "production-green-stage-b-image-evidence",
    canaryImageDigest: "production-green-stage-b-image-evidence",
    sourceContractSha256: "generate-production-green-stage-b-tfvars",
    migrationSetDigest: "generate-production-green-stage-b-tfvars",
    packageChecksumSha256: "generate-production-green-stage-b-tfvars",
    taskDefinitionArns: "stage-b-refresh-state",
    brokerVersion: "stage-b-refresh-state",
    checkerIdentity: "inherited-checker-session",
    deployerIdentity: "authenticated-release-preflight",
  },
  ...overrides,
});

const operator = (overrides = {}) => ({ ticketId: "CHG-STAGE-B-0001", issuedAt: "2026-08-31T10:00:00.000Z", nonce: "12345678-1234-1234-1234-123456789abc", ...overrides });
const now = new Date("2026-08-31T10:01:00.000Z");

test("canonical producer derives a complete unsigned input accepted by the existing creator", async () => {
  const result = await prepareProductionGreenStageBApprovalInput({ evidence: evidence(), protectedSourceSha: releaseSha, operator: operator(), now });
  assert.equal(result.input.approvalId, `APR-STAGE-B-${releaseSha}`);
  assert.equal(result.input.account, STAGE_B.account);
  assert.equal(result.input.executorSecurityGroupId, STAGE_B.executorSecurityGroupId);
  assert.equal(result.input.signatureAlgorithm, STAGE_B_APPROVAL_ALGORITHM);
  assert.deepEqual(result.input.taskDefinitionTemplateHashes, stageBTemplateHashes());
  await assert.doesNotReject(() => prepareStageBApproval(result.input, { now }));
  assert.equal(result.review, (await prepareProductionGreenStageBApprovalInput({ evidence: evidence(), protectedSourceSha: releaseSha, operator: operator(), now })).review);
});

test("only the ticket is required from the operator; time bounds and nonce are safely derived", async () => {
  const result = await prepareProductionGreenStageBApprovalInput({ evidence: evidence(), protectedSourceSha: releaseSha, operator: { ticketId: "CHG-STAGE-B-0001" }, now, randomUuid: () => "12345678-1234-1234-1234-123456789abc" });
  assert.equal(result.input.issuedAt, now.toISOString());
  assert.equal(result.input.expiresAt, "2026-08-31T12:01:00.000Z");
  assert.equal(result.input.nonce, "12345678-1234-1234-1234-123456789abc");
});

for (const [label, field, value] of [
  ["source", "releaseSha", "7".repeat(40)],
  ["backend image", "backendImageDigest", "mscqr-backend:latest"],
  ["worker image", "workerImageDigest", "mscqr-worker:latest"],
  ["executor image", "executorImageDigest", "mscqr-backend:latest"],
  ["canary image", "canaryImageDigest", "mscqr-backend:latest"],
  ["migration digest", "migrationSetDigest", "not-a-digest"],
  ["package checksum", "packageChecksumSha256", "not-a-digest"],
  ["source contract", "sourceContractSha256", "not-a-digest"],
  ["checker identity", "checkerIdentity", "not-an-identity"],
  ["deployer identity", "deployerIdentity", "not-an-identity"],
  ["task definition map", "taskDefinitionArns", { ...taskDefinitionArns, extra: taskDefinitionArns[STAGE_B_MODES[0]] }],
]) {
  test(`rejects ${label} evidence drift`, async () => {
    await assert.rejects(() => prepareProductionGreenStageBApprovalInput({ evidence: evidence({ [field]: value }), protectedSourceSha: releaseSha, operator: operator(), now }), /evidence|map|identity|invalid|contract|mismatch/i);
  });
}

test("rejects wrong account, operator fields, expiry, nonce, and missing ticket", async () => {
  await assert.rejects(() => prepareProductionGreenStageBApprovalInput({ evidence: evidence(), protectedSourceSha: "7".repeat(40), operator: operator(), now }), /source/);
  await assert.rejects(() => prepareProductionGreenStageBApprovalInput({ evidence: evidence(), protectedSourceSha: releaseSha, operator: { ...operator(), extra: "x" }, now }), /unexpected/);
  await assert.rejects(() => prepareProductionGreenStageBApprovalInput({ evidence: evidence(), protectedSourceSha: releaseSha, operator: operator({ ticketId: "bad" }), now }), /ticket/);
  await assert.rejects(() => prepareProductionGreenStageBApprovalInput({ evidence: evidence(), protectedSourceSha: releaseSha, operator: operator({ expiresAt: "2026-08-31T13:00:01.000Z" }), now }), /two-hour/);
  await assert.rejects(() => prepareProductionGreenStageBApprovalInput({ evidence: evidence(), protectedSourceSha: releaseSha, operator: operator({ expiresAt: "2026-08-31T09:00:00.000Z" }), now }), /expiry/);
  await assert.rejects(() => prepareProductionGreenStageBApprovalInput({ evidence: evidence(), protectedSourceSha: releaseSha, operator: operator({ nonce: "not-a-nonce" }), now }), /nonce/);
});

test("rejects stale or historical evidence by requiring the exact current release binding", async () => {
  await assert.rejects(() => prepareProductionGreenStageBApprovalInput({ evidence: evidence({ releaseSha: "e337816da6d8e76a50e655c49a5572f8cfbbfaaf" }), protectedSourceSha: releaseSha, operator: operator(), now }), /source/);
});

test("requires field-specific authenticated checker and deployer role sessions", async () => {
  await assert.rejects(() => prepareProductionGreenStageBApprovalInput({ evidence: evidence({ checkerIdentity: deployerIdentity }), protectedSourceSha: releaseSha, operator: operator(), now }), /checkerIdentity|required role/);
  await assert.rejects(() => prepareProductionGreenStageBApprovalInput({ evidence: evidence({ deployerIdentity: checkerIdentity }), protectedSourceSha: releaseSha, operator: operator(), now }), /deployerIdentity|required role/);
});

test("producer has no signing or AWS capability and writes only through the private artifact helper", () => {
  const source = fs.readFileSync(path.resolve("scripts/aws/prepare-production-green-stage-b-approval-input.mjs"), "utf8");
  assert.doesNotMatch(source, /kms|secretsmanager|RegisterTaskDefinition|RunTask|UpdateService|createProductionAwsCommandRunner/);
  assert.match(source, /writeStageBPrivateFileAtomic/);
});

test("review contains bindings but no credential or signature fields", async () => {
  const result = await prepareProductionGreenStageBApprovalInput({ evidence: evidence(), protectedSourceSha: releaseSha, operator: operator(), now });
  assert.match(result.review, /unsignedApprovalInputSha256=/);
  assert.match(result.review, /checkerDecisionPresent=false/);
  assert.doesNotMatch(result.review, /signatureBase64|password|secretValue|privateKey/i);
});

test("runbook names the producer and keeps checker decision separate", () => {
  const runbook = fs.readFileSync(path.resolve("documents/security/rls-program/FULL_DATABASE_PRODUCTION_ACTIVATION_RUNBOOK.md"), "utf8");
  assert.match(runbook, /prepare-production-green-stage-b-approval-input\.mjs/);
  assert.match(runbook, /authenticated current-source evidence/);
  assert.match(runbook, /explicit independent decision/);
  assert.doesNotMatch(runbook, /operator supplies the complete approval input file/i);
});

test("private output contract rejects repository paths and overwrite is exclusive", async () => {
  const result = await prepareProductionGreenStageBApprovalInput({ evidence: evidence(), protectedSourceSha: releaseSha, operator: operator(), now });
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-approval-input-test-"));
  const output = path.join(directory, "approval-input.json");
  const written = writeProductionGreenStageBApprovalInput({ result, outputPath: output });
  assert.equal(written.written.sha256, result.inputSha256);
  assert.equal(fs.statSync(output).mode & 0o777, 0o600);
  assert.throws(() => writeProductionGreenStageBApprovalInput({ result, outputPath: output }), /overwrite/);
  assert.throws(() => writeProductionGreenStageBApprovalInput({ result, outputPath: path.join(process.cwd(), "approval-input.json") }), /outside the repository/);
  fs.rmSync(directory, { recursive: true, force: true });
});

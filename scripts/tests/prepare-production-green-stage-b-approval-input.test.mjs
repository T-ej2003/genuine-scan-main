import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { prepareStageBApproval } from "../aws/create-production-green-stage-b-approval.mjs";
import { collectProductionGreenStageBApprovalEvidence } from "../aws/collect-production-green-stage-b-approval-evidence.mjs";
import { STAGE_B, STAGE_B_APPROVAL_ALGORITHM, STAGE_B_MODES } from "../aws/production-green-stage-b-contract.mjs";
import { prepareProductionGreenStageBApprovalInput, writeProductionGreenStageBApprovalInput } from "../aws/prepare-production-green-stage-b-approval-input.mjs";
import { stageBTemplateHashes } from "../aws/production-green-stage-b-task-definitions.mjs";

const releaseSha = "8d7ecc53a0c8d0ec07dfce1aeb03dc22d0f43f82";
const checkerIdentity = "arn:aws:sts::368992683803:assumed-role/mscqr-production-rls-independent-checker/checker-session";
const deployerIdentity = "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/deployer-session";
const digest = (character) => character.repeat(64);
const taskDefinitionArns = Object.fromEntries(STAGE_B_MODES.map((mode) => [mode, `arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-${mode}:4`]));
const now = new Date("2026-08-31T10:01:00.000Z");
const report = { images: { backend: { digest: `sha256:${"b".repeat(64)}` }, worker: { digest: `sha256:${"a".repeat(64)}` }, executor: { digest: `sha256:${"e".repeat(64)}` }, canary: { digest: `sha256:${"c".repeat(64)}` } } };
const authorization = { imageEvidenceSha256: digest("d"), authorizationSha256: digest("f"), imageReleaseSha: releaseSha, images: [{ service: "backend", digest: report.images.backend.digest }, { service: "worker", digest: report.images.worker.digest }, { service: "rls-executor", digest: report.images.executor.digest }, { service: "rls-canary", digest: report.images.canary.digest }] };
const live = (overrides = {}) => ({ configuration: { FunctionArn: STAGE_B.brokerAliasArn, Version: "4", Environment: { Variables: { BROKER_TASK_DEFINITIONS_JSON: JSON.stringify(taskDefinitionArns), BROKER_APPROVAL_EXPECTED_JSON: JSON.stringify({ packageChecksumSha256: digest("c") }) } } }, alias: { AliasArn: STAGE_B.brokerAliasArn, Name: STAGE_B.brokerAliasQualifier, FunctionVersion: "4" }, ...overrides });

function evidence(overrides = {}) {
  return collectProductionGreenStageBApprovalEvidence({ sourceSha: releaseSha, imageAuthorization: authorization, tfvarsPath: "/secure/t.tfvars", bindingReportPath: "/secure/t.json", releasePreflightPath: "/secure/preflight.json", checkerIdentity, live: live(overrides.live), now, validateImageAuthorization: () => {}, validateTfvarsBinding: () => ({ ...report, ...(overrides.report || {}) }), deriveContracts: () => ({ sourceContractSha256: digest("a"), migrationSetDigest: digest("b"), packageChecksumSha256: digest("c") }), readPreflight: () => ({ sourceSha: releaseSha, caller: deployerIdentity }) }).evidence;
}

test("canonical collector produces evidence accepted by the existing creator", async () => {
  const result = await prepareProductionGreenStageBApprovalInput({ evidence: evidence(), protectedSourceSha: releaseSha, operator: { ticketId: "CHG-STAGE-B-0001" }, now, randomUuid: () => "12345678-1234-1234-1234-123456789abc" });
  assert.equal(result.input.approvalId, `APR-STAGE-B-${releaseSha}`);
  assert.equal(result.input.signatureAlgorithm, STAGE_B_APPROVAL_ALGORITHM);
  assert.deepEqual(result.input.taskDefinitionTemplateHashes, stageBTemplateHashes());
  await assert.doesNotReject(() => prepareStageBApproval(result.input, { now }));
});

test("fabricated evidence and self-declared provenance cannot enter the producer", async () => {
  await assert.rejects(() => prepareProductionGreenStageBApprovalInput({ evidence: { ...evidence() }, protectedSourceSha: releaseSha, operator: { ticketId: "CHG-STAGE-B-0001" }, now }), /canonical authenticated evidence/);
});

test("same-source evidence expires instead of receiving a fresh approval lifetime", async () => {
  const collected = evidence();
  await assert.rejects(() => prepareProductionGreenStageBApprovalInput({ evidence: collected, protectedSourceSha: releaseSha, operator: { ticketId: "CHG-STAGE-B-0001" }, now: new Date("2026-08-31T11:01:00.000Z") }), /stale/);
});

for (const [label, mutate] of [
  ["backend image", () => ({ report: { images: { ...report.images, backend: { digest: `sha256:${"9".repeat(64)}` } } } })],
  ["task map", () => ({ live: { configuration: { ...live().configuration, Environment: { Variables: { ...live().configuration.Environment.Variables, BROKER_TASK_DEFINITIONS_JSON: JSON.stringify({ ...taskDefinitionArns, rogue: taskDefinitionArns[STAGE_B_MODES[0]] }) } } } } })],
  ["broker binding", () => ({ live: { alias: { ...live().alias, FunctionVersion: "5" } } })],
]) test(`collector rejects current runtime ${label} drift`, () => assert.throws(() => evidence(mutate()), /match|broker|version|binding/i));

test("only ticket is operator-controlled; time and nonce are internally derived", async () => {
  const result = await prepareProductionGreenStageBApprovalInput({ evidence: evidence(), protectedSourceSha: releaseSha, operator: { ticketId: "CHG-STAGE-B-0001" }, now, randomUuid: () => "12345678-1234-1234-1234-123456789abc" });
  assert.equal(result.input.issuedAt, now.toISOString()); assert.equal(result.input.expiresAt, "2026-08-31T12:01:00.000Z");
  await assert.rejects(() => prepareProductionGreenStageBApprovalInput({ evidence: evidence(), protectedSourceSha: releaseSha, operator: { ticketId: "CHG-STAGE-B-0001", nonce: "12345678-1234-1234-1234-123456789abc" }, now }), /unexpected/);
});

test("source exposes no caller-controlled evidence hash or time/nonce CLI switches", () => {
  const source = fs.readFileSync(path.resolve("scripts/aws/prepare-production-green-stage-b-approval-input.mjs"), "utf8");
  for (const option of ["--evidence", "--evidence-sha256", "--issued-at", "--expires-at", "--nonce"]) assert.doesNotMatch(source, new RegExp(option));
  assert.match(source, /writeStageBPrivateFilesAtomic/);
});

test("input and mandatory review are an immutable transactional pair", async () => {
  const result = await prepareProductionGreenStageBApprovalInput({ evidence: evidence(), protectedSourceSha: releaseSha, operator: { ticketId: "CHG-STAGE-B-0001" }, now, randomUuid: () => "12345678-1234-1234-1234-123456789abc" });
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-approval-input-test-")); fs.chmodSync(directory, 0o700);
  const input = path.join(directory, "input.json"); const review = path.join(directory, "review.txt");
  const written = writeProductionGreenStageBApprovalInput({ result, outputPath: input, reviewOutputPath: review });
  assert.equal(written.written.sha256, result.inputSha256); assert.match(fs.readFileSync(review, "utf8"), new RegExp(result.inputSha256));
  assert.throws(() => writeProductionGreenStageBApprovalInput({ result, outputPath: input, reviewOutputPath: path.join(directory, "other.txt") }), /overwrite/);
  assert.equal(fs.existsSync(path.join(directory, "other.txt")), false); fs.rmSync(directory, { recursive: true, force: true });
});

test("review output failure rolls back the input", async () => {
  const result = await prepareProductionGreenStageBApprovalInput({ evidence: evidence(), protectedSourceSha: releaseSha, operator: { ticketId: "CHG-STAGE-B-0001" }, now });
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-approval-input-test-")); fs.chmodSync(directory, 0o700);
  const input = path.join(directory, "input.json"); const review = path.join(directory, "review.txt"); const fake = { ...fs, renameSync(from, to) { if (to === review) throw new Error("simulated review commit failure"); return fs.renameSync(from, to); } };
  assert.throws(() => writeProductionGreenStageBApprovalInput({ result, outputPath: input, reviewOutputPath: review, fsOps: fake }), /simulated/);
  assert.equal(fs.existsSync(input), false); assert.equal(fs.existsSync(review), false); fs.rmSync(directory, { recursive: true, force: true });
});

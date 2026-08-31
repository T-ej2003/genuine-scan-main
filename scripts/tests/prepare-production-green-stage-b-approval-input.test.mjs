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
const image = (repository, character) => ({ digest: `sha256:${character.repeat(64)}`, imageReference: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/${repository}@sha256:${character.repeat(64)}` });
const report = { tfvarsSha256: digest("a"), images: { backend: image("mscqr-backend", "b"), worker: image("mscqr-worker", "a"), executor: image("mscqr-backend", "e"), canary: image("mscqr-backend", "c") } };
const authorization = { imageEvidenceSha256: digest("d"), authorizationSha256: digest("f"), imageReleaseSha: releaseSha, images: [{ service: "backend", digest: report.images.backend.digest }, { service: "worker", digest: report.images.worker.digest }, { service: "rls-executor", digest: report.images.executor.digest }, { service: "rls-canary", digest: report.images.canary.digest }] };
const brokerApprovalExpected = { releaseSha, sourceContractSha256: digest("a"), migrationSetDigest: digest("b"), packageChecksumSha256: digest("c"), deploymentId: "phase2", greenDatabaseName: "mscqr_production_rls_green_phase2", administratorIdentity: "mscqr_prod_admin", databaseSecurityGroupId: STAGE_B.databaseSecurityGroupId, executorSecurityGroupId: STAGE_B.executorSecurityGroupId };
const brokerImages = { backendImageDigest: report.images.backend.imageReference, workerImageDigest: report.images.worker.imageReference, executorImageDigest: report.images.executor.imageReference, canaryImageDigest: report.images.canary.imageReference };
const preflight = (overrides = {}) => ({ status: "ready-for-plan", sourceSha: releaseSha, caller: deployerIdentity, account: STAGE_B.account, region: STAGE_B.region, backendReady: true, stateReady: true, handoffReady: true, tfvarsReady: true, failed: [], skipped: [], requiredReads: { "ecs:DescribeTasks": "allowed" }, total: 1, allowed: 1, checkerTrust: { exact: true, mfaRequired: true }, administratorReportSha256: digest("b"), releaseReadFailures: 0, configurationFailures: 0, unmappedCalls: 0, unclassifiedCapabilities: 0, identityBoundaryViolations: 0, sourceLivePolicyMismatches: 0, administratorSimulationFailures: 0, tfvarsSha256: digest("a"), ...overrides });
const live = (overrides = {}) => ({ configuration: { FunctionArn: STAGE_B.brokerAliasArn, Version: "4", Environment: { Variables: { BROKER_TASK_DEFINITIONS_JSON: JSON.stringify(taskDefinitionArns), BROKER_TASK_TEMPLATE_HASHES_JSON: JSON.stringify(stageBTemplateHashes()), BROKER_APPROVAL_EXPECTED_JSON: JSON.stringify(brokerApprovalExpected), BROKER_IMAGES_JSON: JSON.stringify(brokerImages) } } }, alias: { AliasArn: STAGE_B.brokerAliasArn, Name: STAGE_B.brokerAliasQualifier, FunctionVersion: "4" }, ...overrides });

function evidence(overrides = {}) {
  return collectProductionGreenStageBApprovalEvidence({ sourceSha: releaseSha, imageAuthorization: authorization, tfvarsPath: "/secure/t.tfvars", bindingReportPath: "/secure/t.json", releasePreflightPath: "/secure/preflight.json", checkerIdentity, live: live(overrides.live), now, validateImageAuthorization: () => {}, validateTfvarsBinding: () => ({ ...report, ...(overrides.report || {}) }), deriveContracts: () => ({ sourceContractSha256: digest("a"), migrationSetDigest: digest("b"), packageChecksumSha256: digest("c") }), readPreflight: () => preflight(overrides.preflight) }).evidence;
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

for (const [label, overrides] of [
  ["blocked status", { preflight: { status: "blocked" } }],
  ["denied read", { preflight: { requiredReads: { "ecs:DescribeTasks": "denied" }, failed: [{ id: "read", action: "ecs:DescribeTasks" }] } }],
  ["incomplete readiness", { preflight: { tfvarsReady: false } }],
  ["wrong tfvars digest", { preflight: { tfvarsSha256: digest("c") } }],
  ["wrong binding report digest", { preflight: { bindingReportSha256: digest("c") } }],
]) test(`collector rejects ${label} preflight`, () => assert.throws(() => evidence(overrides), /preflight|tfvars|binding/i));

test("collector accepts order-independent live broker JSON", () => {
  const reverse = (value) => Object.fromEntries(Object.entries(value).reverse());
  const current = live().configuration;
  const variables = current.Environment.Variables;
  const reordered = { BROKER_IMAGES_JSON: JSON.stringify(reverse(brokerImages)), BROKER_APPROVAL_EXPECTED_JSON: JSON.stringify(reverse(brokerApprovalExpected)), BROKER_TASK_TEMPLATE_HASHES_JSON: JSON.stringify(reverse(stageBTemplateHashes())), BROKER_TASK_DEFINITIONS_JSON: JSON.stringify(reverse(taskDefinitionArns)) };
  assert.doesNotThrow(() => evidence({ live: { configuration: { ...current, Environment: { Variables: reordered } } } }));
});

for (const field of Object.keys(brokerApprovalExpected)) test(`collector rejects live broker approval ${field} drift`, () => {
  const changed = { ...brokerApprovalExpected, [field]: field === "releaseSha" ? "f".repeat(40) : field.endsWith("Sha256") ? digest("d") : `${brokerApprovalExpected[field]}-changed` };
  const variables = { ...live().configuration.Environment.Variables, BROKER_APPROVAL_EXPECTED_JSON: JSON.stringify(changed) };
  assert.throws(() => evidence({ live: { configuration: { ...live().configuration, Environment: { Variables: variables } } } }), /broker|binding|contract/i);
});

for (const field of ["backendImageDigest", "workerImageDigest", "executorImageDigest", "canaryImageDigest"]) test(`collector rejects live broker ${field} drift`, () => {
  const changed = { ...brokerImages, [field]: brokerImages[field].replace(/[a-f0-9]{64}$/, "d".repeat(64)) };
  const variables = { ...live().configuration.Environment.Variables, BROKER_IMAGES_JSON: JSON.stringify(changed) };
  assert.throws(() => evidence({ live: { configuration: { ...live().configuration, Environment: { Variables: variables } } } }), /broker|image|binding/i);
});

for (const field of STAGE_B_MODES.length ? Object.keys(stageBTemplateHashes()) : []) test(`collector rejects live broker template hash ${field} drift`, () => {
  const changed = { ...stageBTemplateHashes(), [field]: digest("d") };
  const variables = { ...live().configuration.Environment.Variables, BROKER_TASK_TEMPLATE_HASHES_JSON: JSON.stringify(changed) };
  assert.throws(() => evidence({ live: { configuration: { ...live().configuration, Environment: { Variables: variables } } } }), /broker|template|binding/i);
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

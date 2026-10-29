import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { b03Completion } from "../../infra/aws/terraform/lambda/production-rls-approval-broker/b03-completion.mjs";
import { B03_BROKER, b03ApprovalMessage, b03TaskDefinitionSha256, buildB03ExecutorDefinition, encodeB03Approval } from "../../infra/aws/terraform/lambda/production-rls-approval-broker/b03-approval.mjs";
import { canonicalSha256, STAGE_B } from "../aws/production-green-stage-b-contract.mjs";
import { calculateCleanRoomSourceContract } from "../rls/lib/clean-room-source-contract.mjs";
import { APP_ONLY } from "../aws/production-app-only-contract.mjs";
import { APP_ONLY_VERIFIER } from "../aws/production-app-only-policy.mjs";
import { buildAppOnlyVerifierDefinition } from "../aws/production-app-only-verifier-command.mjs";
import { verifyB03IndependentCatalogue, assertAuthenticatedB03Receipt } from "../aws/production-b03-completion.mjs";
import { completeProductionB03Release } from "../aws/apply-production-b03-incremental-release.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url)), sourceSha = "4".repeat(40);
const image = `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:${"a".repeat(64)}`;
const taskArn = `arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/${"a".repeat(32)}`;
const verifierTaskArn = taskArn.replace(/a{32}$/, "b".repeat(32));
const taskDefinitionArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-b03-incremental:3";
const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
function fixture() {
  const contract = calculateCleanRoomSourceContract(root);
  const requirementsBody = { schemaVersion: 1, kind: "APP_ONLY_CANONICAL_DATABASE_REQUIREMENTS", sourceSha, candidateSourceSha: sourceSha,
    sourceContractSha256: contract.sourceContractSha256, migrationSetDigest: contract.migrationSetDigest,
    canonicalPackageChecksumsSha256: "a".repeat(64), objects: Object.fromEntries(["routines", "tables", "policies", "schemas", "roles"].map(k => [k, [{ identity: k, sha256: "a".repeat(64) }]])) };
  const requirements = { ...requirementsBody, requirementsSha256: canonicalSha256(requirementsBody) };
  const catalogue = Object.fromEntries(Object.entries(requirements.objects).map(([key, value]) => [key, canonicalSha256(value)]));
  const packageBody = { schemaVersion: 1, kind: "PRODUCTION_B03_INCREMENTAL_PACKAGE", sourceSha,
    predecessorSourceSha: "d785aa7f1e154f37c0dc621082e3f6c46d5d5aec", predecessorRequirementsSha256: "a".repeat(64), successorRequirementsSha256: requirements.requirementsSha256,
    predecessorCatalogue: catalogue, successorCatalogue: catalogue, mutations: Array.from({ length: 44 }, () => ({ owner: "auth", sql: "SELECT 1" })) };
  const pkg = { ...packageBody, packageSha256: canonicalSha256(packageBody) };
  const definition = { ...buildB03ExecutorDefinition({ sourceSha, backendImage: image, package: pkg, databaseHostname: "db.example.internal" }), taskDefinitionArn, status: "ACTIVE", revision: 3 };
  const approval = { schemaVersion: 1, operation: "PRODUCTION_B03_BROKER_APPROVAL", account: STAGE_B.account, region: STAGE_B.region,
    clusterArn: STAGE_B.clusterArn, approvalId: `APR-B03-${sourceSha}-${"a".repeat(16)}`, sourceSha, backendImage: image,
    taskDefinitionArn, taskDefinitionSha256: b03TaskDefinitionSha256(definition), packageSha256: pkg.packageSha256,
    database: B03_BROKER.database, databaseHostname: "db.example.internal", predecessorCatalogue: catalogue, successorCatalogue: catalogue,
    ticketId: "CHG-20261028-001", checkerIdentity: "arn:aws:sts::368992683803:assumed-role/mscqr-production-rls-independent-checker/checker",
    issuedAt: "2026-10-29T12:00:00Z", expiresAt: "2026-10-29T12:30:00Z", nonce: "a".repeat(16), signatureBase64: "" };
  approval.signatureBase64 = crypto.sign("sha256", b03ApprovalMessage(approval), { key: privateKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }).toString("base64");
  const approvalBytes = encodeB03Approval({ operation: B03_BROKER.mode, approval, package: pkg });
  const request = { operation: "b03-completion-status", approvalId: approval.approvalId, sourceSha, approvalSha256: crypto.createHash("sha256").update(approvalBytes).digest("hex") };
  const launch = { taskArn, taskDefinitionArn, approvalId: approval.approvalId, mode: B03_BROKER.mode, event: "b03-broker-start",
    approvalContractSha256: canonicalSha256(JSON.parse(b03ApprovalMessage(approval))), requestSha256: "f".repeat(64), nonce: "a".repeat(32) };
  const launchRow = { launchState: "started", approvalNonce: approval.nonce, taskArn, approvalContractSha256: launch.approvalContractSha256,
    requestSha256: launch.requestSha256, launchReceiptJson: JSON.stringify(launch) };
  const task = { taskArn, taskDefinitionArn, clusterArn: STAGE_B.clusterArn, launchType: "FARGATE", enableExecuteCommand: false,
    lastStatus: "STOPPED", stopCode: "EssentialContainerExited", createdAt: "2026-10-29T12:01:00Z", startedAt: "2026-10-29T12:02:00Z", stoppedAt: "2026-10-29T12:03:00Z",
    containers: [{ name: B03_BROKER.container, exitCode: 0, image, imageDigest: image.split("@")[1] }],
    overrides: { containerOverrides: [{ name: B03_BROKER.container }], inferenceAcceleratorOverrides: [] } };
  const rows = new Map(), writes = [];
  const deps = { config: { approvalExpected: { releaseSha: sourceSha }, images: { backendImageDigest: image } },
    readApproval: async (id, version) => { assert.equal(id, STAGE_B.approvalSecretArn); assert.equal(version, crypto.createHash("sha256").update(`${approval.approvalId}\n${sourceSha}`).digest("hex")); return approvalBytes; },
    readApprovalClaim: async key => key.endsWith("#b03-incremental") ? launchRow : rows.get(key),
    recordB03LaunchReceipt: async ({ taskArn: recordedTask, launchReceiptJson }) => {
      assert.equal(recordedTask, taskArn);
      if (launchRow.launchReceiptJson) throw Object.assign(new Error("claimed"), { name: "ConditionalCheckFailedException" });
      launchRow.launchReceiptJson = launchReceiptJson;
    },
    describeTasks: async () => ({ tasks: [task] }), describeTaskDefinition: async () => ({ taskDefinition: definition, tags: [
      { key: "Component", value: "b03-incremental-release" }, { key: "Environment", value: "production" }, { key: "ManagedBy", value: "Terraform" }] }),
    verifySignature: async ({ message, signature }) => crypto.verify("sha256", message, { key: publicKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, signature),
    now: () => new Date("2026-10-29T12:20:00Z"),
    claimB03Completion: async value => { if (rows.has(value.key)) throw Object.assign(new Error("claimed"), { name: "ConditionalCheckFailedException" }); rows.set(value.key, value); },
    markB03CompletionDurable: async ({ key }) => { rows.get(key).durable = "yes"; }, writeReceipt: async value => { writes.push(value); } };
  return { request, deps, task, launchRow, rows, writes, requirements, catalogue };
}

async function independentFixture(f) {
  const { execution } = await b03Completion(f.request, f.deps);
  const identity = { account: STAGE_B.account, region: STAGE_B.region, clusterArn: STAGE_B.clusterArn, serviceArn: APP_ONLY.serviceArn,
    sourceSha, candidateSourceSha: sourceSha, candidateDigest: image.split("@")[1], verifierImageDigest: `sha256:${"c".repeat(64)}`,
    predecessorBackendDigest: `sha256:${"d".repeat(64)}`, predecessorTaskDefinition: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:37", databaseHostname: execution.databaseHostname };
  const secret = "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase4/read-only-canary-database-url-abcdef";
  const built = buildAppOnlyVerifierDefinition({ requirements: f.requirements, identity, repositoryRoot: root, databaseSecretArn: secret });
  const verifierArn = `arn:aws:ecs:eu-west-2:368992683803:task-definition/${APP_ONLY_VERIFIER.family}:5`;
  const definition = { ...built.definition, taskDefinitionArn: verifierArn, status: "ACTIVE", revision: 5 };
  const databaseBody = { schemaVersion: 1, kind: "APP_ONLY_DATABASE_COMPATIBILITY", identity, generatedAt: "2026-10-29T12:09:00Z",
    verificationContractSha256: built.verificationContractSha256, requirementsSha256: f.requirements.requirementsSha256,
    domains: Object.fromEntries(["DATABASE_SCHEMA", "RLS_FUNCTIONS", "RLS_POLICIES", "RLS_GRANTS", "RLS_FORCE_STATUS", "GENERATED_RLS_CONTRACT"].map(k => [k, "COMPATIBLE"])) };
  const body = { schemaVersion: 1, kind: "APP_ONLY_VERIFIED_COMPATIBILITY", sourceSha, generatedAt: "2026-10-29T12:11:00Z",
    inputs: { requirements: f.requirements, preparation: { identity, verificationContractSha256: built.verificationContractSha256, databaseSecretArn: secret, preparationSha256: "a".repeat(64) } },
    registration: { taskDefinitionArn: verifierArn, preparationSha256: "a".repeat(64) }, taskArn: verifierTaskArn, taskDefinitionArn: verifierArn,
    database: { ...databaseBody, evidenceSha256: canonicalSha256(databaseBody) } };
  const artifact = { ...body, resultSha256: canonicalSha256(body) };
  const reference = { sourceSha, runId: "123", runAttempt: "1", artifactId: "456", artifactDigest: `sha256:${"e".repeat(64)}`, fileSha256: "f".repeat(64) };
  const task = { taskArn: verifierTaskArn, taskDefinitionArn: verifierArn, clusterArn: STAGE_B.clusterArn, lastStatus: "STOPPED", enableExecuteCommand: false,
    launchType: "FARGATE", createdAt: "2026-10-29T12:05:00Z", stoppedAt: "2026-10-29T12:10:00Z", containers: [{ name: "production-green-read-only-rls-canary", exitCode: 0, imageDigest: identity.verifierImageDigest }],
    overrides: { containerOverrides: [{ name: "production-green-read-only-rls-canary" }], inferenceAcceleratorOverrides: [] } };
  const run = args => JSON.stringify(args[1] === "describe-task-definition" ? { taskDefinition: definition, tags: [] } : { tasks: [task] });
  const options = { reference, execution, run, repositoryRoot: root, now: Date.parse("2026-10-29T12:20:00Z"), download: () => ({ bytes: Buffer.from(JSON.stringify(artifact)) }) };
  return { options, artifact, task, reference, execution };
}

test("authenticated B03 completion binds durable launch, independent verifier and one-use consumption", async () => {
  const f = fixture(), v = await independentFixture(f);
  const independent = input => verifyB03IndependentCatalogue({ ...v.options, ...input, download: v.options.download, now: v.options.now });
  const invocation = async (_run, event, consume) => consume(await b03Completion(event, f.deps));
  const receipt = await completeProductionB03Release({ sourceSha, request: { ...f.request, operation: B03_BROKER.mode }, compatibilityReference: v.reference,
    releaseTrainRunId: "77", environment: { GITHUB_RUN_ID: "88" }, runner: v.options.run, authenticateSource: async () => {},
    authorize: async () => ({ backend: image }), independent, invoke: invocation });
  assert.equal(f.writes.length, 1); assert.equal(receipt.schemaVersion, 4);
  const proof = await b03Completion({ ...f.request, operation: "b03-completion-check", workflowRunId: "88", releaseTrainRunId: "77", completionSha256: receipt.completionSha256,
    artifactId: receipt.completion.verification.artifactReference.artifactId }, f.deps);
  assert.equal(assertAuthenticatedB03Receipt(receipt, { sourceSha, imageDigest: image.split("@")[1], workflowRunId: "88", run: v.options.run,
    independent, now: v.options.now, invoke: (_run, event, consume) => { assert.equal(event.operation, "b03-completion-check"); return consume(proof); } }), receipt.approvalId);
  f.deps.now = () => new Date("2026-10-29T12:35:00Z");
  const delayedProof = await b03Completion({ ...f.request, operation: "b03-completion-check", workflowRunId: "88", releaseTrainRunId: "77",
    completionSha256: receipt.completionSha256, artifactId: receipt.completion.verification.artifactReference.artifactId }, f.deps);
  assert.equal(assertAuthenticatedB03Receipt(receipt, { sourceSha, imageDigest: image.split("@")[1], workflowRunId: "88", run: v.options.run,
    independent, now: Date.parse("2026-10-29T12:35:00Z"), invoke: (_run, _event, consume) => consume(delayedProof) }), receipt.approvalId);
  assert.throws(() => assertAuthenticatedB03Receipt(receipt, { sourceSha, imageDigest: image.split("@")[1], workflowRunId: "88", run: v.options.run,
    independent, now: Date.parse("2026-10-29T12:42:00Z"), invoke: () => assert.fail("expired receipt reached broker") }));
  f.deps.now = () => new Date("2026-10-29T12:20:00Z");
  assert.throws(() => assertAuthenticatedB03Receipt(receipt, { sourceSha, imageDigest: image.split("@")[1], workflowRunId: "88", run: v.options.run,
    independent, now: v.options.now, invoke: () => undefined }), /did not return authenticated evidence/);
  await assert.rejects(b03Completion({ ...f.request, operation: "b03-completion-check", workflowRunId: "88", releaseTrainRunId: "77",
    completionSha256: receipt.completionSha256, artifactId: "999" }, f.deps));
  await assert.rejects(b03Completion({ ...f.request, operation: "b03-completion-record", workflowRunId: "89", releaseTrainRunId: "77", verification: receipt.completion.verification }, f.deps), /replay\/context conflict/);
  const forged = structuredClone(receipt); forged.completion.execution.packageSha256 = "0".repeat(64); forged.completionSha256 = canonicalSha256(forged.completion);
  const { receiptBundleSha256, ...forgedBody } = forged; forged.receiptBundleSha256 = canonicalSha256(forgedBody);
  assert.throws(() => assertAuthenticatedB03Receipt(forged, { sourceSha, imageDigest: image.split("@")[1], workflowRunId: "88", run: v.options.run, independent, now: v.options.now,
    invoke: (_run, _event, consume) => consume(proof) }));
});

for (const [name, mutate] of Object.entries({
  "unavailable stopped task": f => f.deps.describeTasks = async () => ({ failures: [{ arn: taskArn, reason: "MISSING" }], tasks: [] }),
  "failed task": f => f.task.containers[0].exitCode = 1,
  "unknown outcome": f => f.task.lastStatus = "RUNNING",
  "different task": f => f.task.taskArn = verifierTaskArn,
  "different image": f => f.task.containers[0].imageDigest = `sha256:${"0".repeat(64)}`,
  "runtime override": f => f.task.overrides.containerOverrides[0].command = ["sh"],
  "unauthorized execution time": f => f.task.createdAt = "2026-10-29T13:00:00Z",
})) test(`completion rejects ${name} without SQL replay`, async () => {
  const f = fixture(); mutate(f); await assert.rejects(b03Completion(f.request, f.deps)); assert.equal(f.writes.length, 0);
});

test("interrupted launch receipt is recovered from the signed claim and native task without launching SQL", async () => {
  const f = fixture(); delete f.launchRow.launchReceiptJson;
  const result = await b03Completion(f.request, f.deps);
  assert.equal(result.status, "EXECUTION_VERIFIED");
  assert.equal(f.writes.length, 1); assert.equal(JSON.parse(f.launchRow.launchReceiptJson).taskArn, taskArn);
});

for (const [name, mutate] of Object.entries({
  "stale verification": v => v.options.now += 60 * 60_000,
  "pre-commit verification": v => v.task.createdAt = "2026-10-29T12:01:00Z",
  "failed verifier": v => v.task.containers[0].exitCode = 1,
  "different verifier image": v => v.task.containers[0].imageDigest = `sha256:${"0".repeat(64)}`,
  "catalogue mismatch": v => v.options.execution.successorCatalogue.tables = "0".repeat(64),
  "wrong database": v => v.options.execution.databaseHostname = "wrong.example.internal",
  "wrong database name": v => v.options.execution.database = "other_database",
})) test(`independent database proof rejects ${name}`, async () => {
  const v = await independentFixture(fixture()); mutate(v); assert.throws(() => verifyB03IndependentCatalogue(v.options));
});

test("completion recovers a durable-write interruption, and expires without rerunning SQL", async () => {
  const f = fixture(), v = await independentFixture(f), verification = verifyB03IndependentCatalogue(v.options);
  const event = { ...f.request, operation: "b03-completion-record", workflowRunId: "88", releaseTrainRunId: "77", verification };
  const write = f.deps.writeReceipt; f.deps.writeReceipt = async () => { throw new Error("storage unavailable"); };
  await assert.rejects(b03Completion(event, f.deps)); assert.equal(f.rows.size, 1);
  f.deps.writeReceipt = write; const result = await b03Completion(event, f.deps);
  await b03Completion(event, f.deps); assert.equal(f.writes.length, 1);
  f.deps.now = () => new Date("2026-10-29T13:00:00Z");
  await assert.rejects(b03Completion({ ...f.request, operation: "b03-completion-check", workflowRunId: "88", releaseTrainRunId: "77", completionSha256: result.completionSha256,
    artifactId: verification.artifactReference.artifactId }, f.deps), /expired/);
  f.deps.now = () => new Date("2026-10-29T13:06:00Z");
  const newer = { ...verification, artifactReference: { ...verification.artifactReference, artifactId: "457" }, generatedAt: "2026-10-29T13:05:00Z" };
  const renewed = await b03Completion({ ...event, workflowRunId: "89", verification: newer }, f.deps);
  assert.equal(renewed.completion.execution.taskArn, result.completion.execution.taskArn);
  assert.equal(f.rows.size, 2); assert.equal(f.writes.length, 2);
});

test("broker refuses to seal a stale independent verification", async () => {
  const f = fixture(), v = await independentFixture(f);
  f.deps.now = () => new Date("2026-10-29T12:28:00Z");
  await assert.rejects(b03Completion({ ...f.request, operation: "b03-completion-record", workflowRunId: "88", releaseTrainRunId: "77",
    verification: verifyB03IndependentCatalogue(v.options) }, f.deps));
  assert.equal(f.rows.size, 0); assert.equal(f.writes.length, 0);
});

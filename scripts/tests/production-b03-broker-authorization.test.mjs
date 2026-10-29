import test from "node:test";
import assert from "node:assert/strict";
import { B03_BROKER, authenticateB03BrokerRequest, buildB03ExecutorDefinition, launchB03Task, b03TaskDefinitionSha256 } from "../../infra/aws/terraform/lambda/production-rls-approval-broker/b03-approval.mjs";
import { canonicalSha256, STAGE_B } from "../aws/production-green-stage-b-contract.mjs";
import { signB03Approval } from "../aws/create-production-b03-approval.mjs";
import { applyProductionB03IncrementalRelease } from "../aws/apply-production-b03-incremental-release.mjs";

const sourceSha = "4".repeat(40);
const backendImage = `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:${"a".repeat(64)}`;
const taskDefinitionArn = `arn:aws:ecs:eu-west-2:368992683803:task-definition/${B03_BROKER.family}:3`;
const catalogue = Object.fromEntries(["routines", "tables", "policies", "schemas", "roles"].map((key) => [key, "b".repeat(64)]));
const body = { schemaVersion: 1, kind: "PRODUCTION_B03_INCREMENTAL_PACKAGE", predecessorSourceSha: "d785aa7f1e154f37c0dc621082e3f6c46d5d5aec",
  sourceSha, predecessorCatalogue: catalogue, successorCatalogue: catalogue, mutations: Array.from({ length: 44 }, () => ({ owner: "auth", sql: "SELECT 1" })) };
const pkg = { ...body, packageSha256: canonicalSha256(body) };
const task = { ...buildB03ExecutorDefinition({ sourceSha, backendImage, package: pkg, databaseHostname: "db.example.internal" }),
  taskDefinitionArn, revision: 3, status: "ACTIVE" };
const approval = { schemaVersion: 1, operation: "PRODUCTION_B03_BROKER_APPROVAL", account: STAGE_B.account, region: STAGE_B.region,
  clusterArn: STAGE_B.clusterArn, approvalId: `APR-B03-${sourceSha}-1234567890abcdef`, sourceSha, backendImage,
  taskDefinitionArn, taskDefinitionSha256: b03TaskDefinitionSha256(task), packageSha256: pkg.packageSha256,
  database: B03_BROKER.database, databaseHostname: "db.example.internal", predecessorCatalogue: catalogue,
  successorCatalogue: catalogue, ticketId: "CHG-20261028-001",
  checkerIdentity: "arn:aws:sts::368992683803:assumed-role/mscqr-production-rls-independent-checker/checker",
  issuedAt: "2026-10-28T12:00:00Z", expiresAt: "2026-10-28T12:30:00Z", nonce: "1234567890abcdef", signatureBase64: "c2ln" };
const options = { now: new Date("2026-10-28T12:05:00Z"), verifySignature: async () => true,
  describeTaskDefinition: async () => ({ taskDefinition: task, tags: [
    { key: "Component", value: "b03-incremental-release" }, { key: "Environment", value: "production" }, { key: "ManagedBy", value: "Terraform" },
  ] }) };

test("B03 broker binds approval to the fixed task, package and identity", async () => {
  assert.equal((await authenticateB03BrokerRequest({ operation: B03_BROKER.mode, approval, package: pkg }, options)).approval.approvalId, approval.approvalId);
  for (const event of [
    { operation: B03_BROKER.mode, approval: { ...approval, packageSha256: "0".repeat(64) }, package: pkg },
    { operation: B03_BROKER.mode, approval, package: { ...pkg, mutations: [] } },
    { operation: B03_BROKER.mode, approval, package: pkg, overrides: { command: ["sh"] } },
  ]) await assert.rejects(authenticateB03BrokerRequest(event, options));
  await assert.rejects(authenticateB03BrokerRequest({ operation: B03_BROKER.mode, approval, package: pkg },
    { ...options, verifySignature: async () => false }));
  await assert.rejects(authenticateB03BrokerRequest({ operation: B03_BROKER.mode, approval, package: pkg },
    { ...options, now: new Date("2026-10-28T13:00:00Z") }));
});

test("B03 issuance validates source and fixed task before signing and verifies the resulting signature", async () => {
  const calls = [];
  const dependencies = { ...options, now: options.now, nonce: approval.nonce,
    authenticateSourceAndPackage: async () => calls.push("source"),
    caller: async () => ({ Arn: approval.checkerIdentity }),
    sign: async () => { calls.push("sign"); return "c2ln"; } };
  const input = { sourceSha, backendImage, pkg, databaseHostname: approval.databaseHostname, taskDefinitionArn, ticketId: approval.ticketId };
  const signed = await signB03Approval(input, dependencies);
  assert.equal(signed.operation, B03_BROKER.mode);
  assert.deepEqual(calls, ["source", "source", "sign"]);
  await assert.rejects(signB03Approval(input, { ...dependencies,
    caller: async () => ({ Arn: "arn:aws:iam::368992683803:root" }), sign: async () => assert.fail("unauthorized sign") }));
  await assert.rejects(signB03Approval(input, { ...dependencies,
    authenticateSourceAndPackage: async () => { throw new Error("source drift"); }, sign: async () => assert.fail("source drift sign") }));
});

test("B03 release refuses incomplete independent verification before any AWS operation", async () => {
  await assert.rejects(applyProductionB03IncrementalRelease({ runner: () => assert.fail("AWS must not run") }), /independent post-commit verifier/);
});

test("B03 lost launch response reconciles the original task and blocks conflicting requests", async () => {
  const taskArn = `arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/${"a".repeat(32)}`;
  const request = { taskDefinition: taskDefinitionArn, clientToken: "fixed-token" };
  let row, calls = 0, externalTasks = 0;
  const input = { authorization: { approval, approvalContractSha256: "c".repeat(64) }, request,
    claim: async identity => {
      if (row) throw Object.assign(new Error("claimed"), { name: "ConditionalCheckFailedException" });
      row = { approvalNonce: identity.nonce, approvalContractSha256: identity.approvalContractSha256,
        requestSha256: identity.requestSha256, launchState: "claimed" };
    }, readClaim: async () => row,
    runTask: async () => {
      calls++;
      if (externalTasks === 0) { externalTasks++; throw new Error("lost successful response"); }
      return { tasks: [{ taskArn }] };
    }, recordTask: async value => { row = { ...row, launchState: "started", taskArn: value.taskArn }; },
    writeReceipt: async () => {} };
  await assert.rejects(launchB03Task(input), /lost successful response/);
  assert.equal((await launchB03Task(input)).taskArn, taskArn);
  assert.equal((await launchB03Task(input)).taskArn, taskArn);
  assert.equal(externalTasks, 1); assert.equal(calls, 2);
  await assert.rejects(launchB03Task({ ...input, request: { ...request, overrides: {} } }));
  assert.equal(calls, 2);
  await assert.rejects(launchB03Task({ ...input, readClaim: async () => ({ ...row, approvalNonce: "another" }) }));
});

test("canonical Stage B issuer/publication/proof/broker path authenticates B03 and cannot reuse approval across modes", async () => {
  const crypto = await import("node:crypto");
  const { signStageBApproval } = await import("../aws/create-production-green-stage-b-approval.mjs");
  const { publishStageBApproval, approvalPublicationClientRequestToken } = await import("../aws/publish-production-green-stage-b-approval.mjs");
  const { buildApprovalPublicationValidationRequest, validateApprovalPublicationProof } = await import("../aws/check-production-green-stage-b-approval-publication.mjs");
  const { b03PublicationRequest, decodeB03Approval, encodeB03Approval } = await import("../../infra/aws/terraform/lambda/production-rls-approval-broker/b03-approval.mjs");
  const { createHandler } = await import("../../infra/aws/terraform/lambda/production-rls-approval-broker/index.mjs");
  const { STAGE_B_BROKER_TASK_DEFINITION_FAMILIES, stageBApprovalIdForReleaseSha, validateStageBApproval } = await import("../aws/production-green-stage-b-contract.mjs");
  const { stageBTemplateHashes } = await import("../aws/production-green-stage-b-task-definitions.mjs");
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const verifySignature = async ({ message, signature }) => crypto.verify("sha256", message, { key: publicKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, signature);
  const input = { operation: B03_BROKER.mode, sourceSha, backendImage, pkg, databaseHostname: approval.databaseHostname, taskDefinitionArn, ticketId: approval.ticketId };
  const signed = await signStageBApproval(input, { ...options, verifySignature, nonce: approval.nonce,
    authenticateSourceAndPackage: async () => {}, caller: async () => ({ Arn: approval.checkerIdentity }),
    sign: async ({ message }) => crypto.sign("sha256", message, { key: privateKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }).toString("base64") });
  let current, writes = 0, launches = 0, row, clock = options.now;
  const publish = bytes => publishStageBApproval({ approvalPath: "/synthetic/approval", expectedSourceSha: sourceSha,
    callerArn: approval.checkerIdentity, now: options.now, verifySignature, describeTaskDefinition: options.describeTaskDefinition,
    readFile: () => bytes, assertSource: () => {}, putSecretValue: async request => {
      writes++; assert.equal(request.SecretId, STAGE_B.approvalSecretArn); current = request.SecretString;
      return { ARN: request.SecretId, VersionId: request.ClientRequestToken, VersionStages: ["AWSCURRENT"] };
    } });
  const publication = await publish(signed.artifactBytes);
  assert.equal(publication.sourceSha, sourceSha); assert.equal(writes, 1);
  assert.equal(publication.versionId, approvalPublicationClientRequestToken({ approvalId: signed.artifact.approval.approvalId, releaseSha: sourceSha }));
  const taskDefinitionArns = Object.fromEntries(Object.entries(STAGE_B_BROKER_TASK_DEFINITION_FAMILIES).map(([mode, family]) => [mode, `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}:1`]));
  const images = { backendImageDigest: backendImage, workerImageDigest: backendImage.replace("mscqr-backend", "mscqr-worker"), executorImageDigest: backendImage, canaryImageDigest: backendImage };
  const config = { clusterArn: STAGE_B.clusterArn, approvalSecretArn: STAGE_B.approvalSecretArn,
    executorSecurityGroupId: STAGE_B.executorSecurityGroupId, privateSubnetIds: STAGE_B.privateSubnetIds,
    replayTable: STAGE_B.replayTable, receiptBucket: STAGE_B.receiptBucket, taskDefinitionArns, templateHashes: stageBTemplateHashes(), images,
    approvalExpected: { releaseSha: sourceSha, sourceContractSha256: "b".repeat(64), migrationSetDigest: "c".repeat(64), packageChecksumSha256: "d".repeat(64), deploymentId: "phase2", approvalId: stageBApprovalIdForReleaseSha(sourceSha), ticketId: input.ticketId } };
  const handler = createHandler({ config, executingBrokerVersion: "22", now: () => clock,
    readApproval: async id => { assert.equal(id, STAGE_B.approvalSecretArn); return current; }, verifySignature,
    describeTaskDefinition: options.describeTaskDefinition,
    claimApproval: async identity => {
      if (row) throw Object.assign(new Error("replay"), { name: "ConditionalCheckFailedException" });
      row = { approvalNonce: identity.nonce, approvalContractSha256: identity.approvalContractSha256, requestSha256: identity.requestSha256, launchState: "claimed" };
    }, readApprovalClaim: async () => row,
    recordB03Task: async ({ taskArn }) => { row = { ...row, taskArn, launchState: "started" }; },
    runTask: async request => {
      launches++; assert.equal(request.taskDefinition, taskDefinitionArn); assert.equal(request.overrides, undefined);
      return { tasks: [{ taskArn: `arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/${"a".repeat(32)}` }] };
    }, writeReceipt: async () => {} });
  const proofRequest = buildApprovalPublicationValidationRequest({ approvalBytes: signed.artifactBytes, expectedSourceSha: sourceSha });
  validateApprovalPublicationProof(await handler(proofRequest), proofRequest);
  assert.equal(launches, 0);
  const execute = b03PublicationRequest(signed.artifactBytes);
  await handler(execute); await handler(execute); assert.equal(launches, 1, "approval replay must not run SQL twice");
  const { startProductionB03BrokerExecution } = await import("../aws/apply-production-b03-incremental-release.mjs");
  const workflowStart = await startProductionB03BrokerExecution({ sourceSha, request: execute, runner: () => assert.fail("all calls must use the broker"),
    authorize: async () => ({ backend: backendImage }), authenticateSource: async () => {}, now: () => options.now,
    invoke: async (_runner, event, consume) => consume(await handler(event), { ExecutedVersion: "22" }) });
  assert.equal(workflowStart.status, "STARTED_UNVERIFIED"); assert.equal(launches, 1);
  clock = new Date("2026-10-28T13:00:00Z");
  await assert.rejects(handler(execute)); clock = options.now;
  await assert.rejects(handler({ ...execute, overrides: {} }));
  await assert.rejects(handler({ operation: B03_BROKER.mode, approval: signed.artifact.approval, package: pkg }));
  await assert.rejects(handler({ approvalId: execute.approvalId, mode: "full-rls-verification" }));
  await assert.rejects(validateStageBApproval(JSON.parse(current), undefined, { now: options.now, verifySignature }));
  for (const [field, value] of Object.entries({ sourceSha: "5".repeat(40), packageSha256: "0".repeat(64), backendImage: backendImage.replace("a".repeat(64), "b".repeat(64)),
    database: "another_database", databaseHostname: "another.example.internal", taskDefinitionSha256: "0".repeat(64),
    predecessorCatalogue: { ...catalogue, tables: "0".repeat(64) }, successorCatalogue: { ...catalogue, policies: "0".repeat(64) },
    taskDefinitionArn: taskDefinitionArn.replace(":3", ":4"), expiresAt: "2026-10-28T12:00:00Z", signatureBase64: "c2ln" })) {
    const forged = decodeB03Approval(signed.artifactBytes); forged.approval[field] = value;
    const bytes = encodeB03Approval(forged);
    await assert.rejects(publish(bytes), field);
    current = bytes.toString(); await assert.rejects(handler(b03PublicationRequest(bytes)), field);
  }
  current = signed.artifactBytes.toString();
  const missing = decodeB03Approval(signed.artifactBytes); delete missing.approval.signatureBase64;
  await assert.rejects(publish(encodeB03Approval(missing)));
  let sourceChecks = 0;
  await assert.rejects(publishStageBApproval({ approvalPath: "/synthetic/approval", expectedSourceSha: sourceSha,
    callerArn: approval.checkerIdentity, now: options.now, verifySignature, describeTaskDefinition: options.describeTaskDefinition,
    readFile: () => signed.artifactBytes, assertSource: () => { if (++sourceChecks === 2) throw new Error("main advanced"); },
    putSecretValue: async () => assert.fail("source drift must not publish") }), /main advanced/);
  await assert.rejects(handler({ ...execute, approvalSha256: "0".repeat(64) }));
  current = ""; await assert.rejects(handler(execute));
  assert.equal(writes, 1); assert.equal(launches, 1);
});

test("B03 transport is bounded, canonical and independent of ECS metadata representation", async () => {
  const { encodeB03Approval, decodeB03Approval } = await import("../../infra/aws/terraform/lambda/production-rls-approval-broker/b03-approval.mjs");
  const { gzipSync } = await import("node:zlib");
  const request = { operation: B03_BROKER.mode, approval, package: pkg };
  const bytes = encodeB03Approval(request);
  assert.deepEqual(decodeB03Approval(bytes), request);
  assert.throws(() => decodeB03Approval(Buffer.alloc(65537)));
  assert.throws(() => decodeB03Approval(Buffer.from(JSON.stringify(JSON.parse(bytes), null, 2))));
  const bomb = JSON.parse(bytes); bomb.packageGzipBase64 = gzipSync(Buffer.alloc(96 * 1024 + 1, "a")).toString("base64");
  assert.throws(() => decodeB03Approval(Buffer.from(JSON.stringify(bomb))));
  assert.equal(b03TaskDefinitionSha256({ ...task, registeredAt: new Date("2026-10-28T12:00:00Z") }),
    b03TaskDefinitionSha256({ ...task, registeredAt: "2026-10-28T12:00:00.000Z" }));
});

test("operation-specific approval schema covers the exact B03 transport and signed fields", async () => {
  const fs = await import("node:fs");
  const { encodeB03Approval } = await import("../../infra/aws/terraform/lambda/production-rls-approval-broker/b03-approval.mjs");
  const schema = JSON.parse(fs.readFileSync("infra/aws/terraform/production-green-stage-b/approval-contract.schema.json", "utf8"));
  const value = JSON.parse(encodeB03Approval({ operation: B03_BROKER.mode, approval, package: pkg }));
  assert.deepEqual(schema.oneOf, [{ $ref: "#/$defs/fullRls" }, { $ref: "#/$defs/b03" }]);
  assert.deepEqual([...schema.$defs.b03.required].sort(), Object.keys(value).sort());
  assert.deepEqual([...schema.$defs.b03.properties.approval.required].sort(), Object.keys(approval).sort());
  assert.equal(schema.$defs.b03.additionalProperties, false);
  assert.equal(schema.$defs.b03.properties.approval.additionalProperties, false);
  assert.equal(schema.$defs.fullRls.properties.schemaVersion.const, 2);
  assert.equal(schema.$defs.fullRls.additionalProperties, false);
});

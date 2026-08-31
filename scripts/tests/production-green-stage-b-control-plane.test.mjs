import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import test from "node:test";
import { createHandler } from "../../infra/aws/terraform/lambda/production-rls-approval-broker/index.mjs";
import { assertStageBBrokerTaskDefinitionMap, STAGE_B, STAGE_B_APPROVAL_ALGORITHM, STAGE_B_BROKER_TASK_DEFINITION_FAMILIES, canonicalStageBApproval, stageBApprovalIdForReleaseSha, validateStageBApproval } from "../aws/production-green-stage-b-contract.mjs";
import { approvedNetworkConfiguration, assertFixedTaskDefinition, renderStageBTaskDefinition, stageBTemplateHashes } from "../aws/production-green-stage-b-task-definitions.mjs";
import { validateProductionRlsApproval } from "../../backend/scripts/production-rls-approval.mjs";

const now = new Date("2026-07-29T12:00:00.000Z");
const releaseSha = "a".repeat(40); const source = "b".repeat(64); const migration = "c".repeat(64); const checksum = "d".repeat(64);
const image = (repo, seed) => `368992683803.dkr.ecr.eu-west-2.amazonaws.com/${repo}@sha256:${seed.repeat(64)}`;
const images = { backendImageDigest: image("mscqr-backend", "1"), workerImageDigest: image("mscqr-worker", "2"), executorImageDigest: image("mscqr-backend", "3"), canaryImageDigest: image("mscqr-backend", "4") };
const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const sign = (approval) => crypto.sign("sha256", Buffer.from(canonicalStageBApproval(approval)), { key: privateKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }).toString("base64");
const artifact = (overrides = {}) => {
  const value = { schemaVersion: 2, environment: "production", account: STAGE_B.account, region: STAGE_B.region, releaseSha, ...images, sourceContractSha256: source, migrationSetDigest: migration, packageChecksumSha256: checksum, deploymentId: "phase2", greenDatabaseIdentifier: STAGE_B.greenDatabaseIdentifier, greenDatabaseName: "mscqr_production_rls_green_phase2", administratorIdentity: "mscqr_prod_admin", databaseSecurityGroupId: STAGE_B.databaseSecurityGroupId, executorSecurityGroupId: STAGE_B.executorSecurityGroupId, taskDefinitionArns: taskDefinitions, taskDefinitionTemplateHashes: stageBTemplateHashes(), brokerAliasArn: STAGE_B.brokerAliasArn, brokerVersion: "1", checkerIdentity: "arn:aws:sts::368992683803:assumed-role/mscqr-production-rls-independent-checker/checker", deployerIdentity: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/deployer", executorIdentity: STAGE_B.executorRoleArn, approvalId: stageBApprovalIdForReleaseSha(releaseSha), ticketId: "CHG-STAGE-B-0001", issuedAt: "2026-07-29T11:55:00.000Z", expiresAt: "2026-07-29T13:00:00.000Z", nonce: "12345678-1234-1234-1234-123456789abc", signatureAlgorithm: STAGE_B_APPROVAL_ALGORITHM, ...overrides };
  return { ...value, signatureBase64: sign(value) };
};
const verifySignature = async ({ message, signature }) => crypto.verify("sha256", message, { key: publicKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, signature);
const taskDefinitions = Object.fromEntries(Object.entries(STAGE_B_BROKER_TASK_DEFINITION_FAMILIES).map(([mode, family]) => [mode, `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}:1`]));
const expected = { releaseSha, sourceContractSha256: source, migrationSetDigest: migration, packageChecksumSha256: checksum, deploymentId: "phase2", approvalId: stageBApprovalIdForReleaseSha(releaseSha), ticketId: "CHG-STAGE-B-0001", brokerVersion: "1", images, taskDefinitionArns: taskDefinitions };
const config = { clusterArn: STAGE_B.clusterArn, approvalSecretArn: STAGE_B.approvalSecretArn, executorSecurityGroupId: STAGE_B.executorSecurityGroupId, privateSubnetIds: [...STAGE_B.privateSubnetIds], replayTable: STAGE_B.replayTable, receiptBucket: STAGE_B.receiptBucket, taskDefinitionArns: taskDefinitions, templateHashes: stageBTemplateHashes(), approvalExpected: expected, images };

test("broker task-definition map enforces the exact mode, family, account, region, and revision contract", () => {
  assert.doesNotThrow(() => assertStageBBrokerTaskDefinitionMap(taskDefinitions));
  const cases = [
    ["arbitrary family", { ...taskDefinitions, "full-rls-verification": "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-full-rls-green-other:1" }],
    ["wrong mode family", { ...taskDefinitions, "full-rls-verification": taskDefinitions["full-rls-application-canary"] }],
    ["wrong account", { ...taskDefinitions, "full-rls-verification": taskDefinitions["full-rls-verification"].replace("368992683803", "000000000000") }],
    ["wrong region", { ...taskDefinitions, "full-rls-verification": taskDefinitions["full-rls-verification"].replace("eu-west-2", "us-east-1") }],
    ["revision zero", { ...taskDefinitions, "full-rls-verification": taskDefinitions["full-rls-verification"].replace(":1", ":0") }],
    ["missing revision", { ...taskDefinitions, "full-rls-verification": taskDefinitions["full-rls-verification"].replace(":1", "") }],
    ["missing mode", Object.fromEntries(Object.entries(taskDefinitions).filter(([mode]) => mode !== "full-rls-verification"))],
    ["unexpected mode", { ...taskDefinitions, unexpected: taskDefinitions["full-rls-verification"] }],
  ];
  for (const [label, value] of cases) assert.throws(() => assertStageBBrokerTaskDefinitionMap(value), /task-definition map/, label);
});

test("broker runtime bindings are exact before any handler work", () => {
  for (const [field, value] of [["clusterArn", "arn:aws:ecs:eu-west-2:368992683803:cluster/other"], ["approvalSecretArn", "arn:aws:secretsmanager:eu-west-2:368992683803:secret:other"], ["executorSecurityGroupId", "sg-other"], ["privateSubnetIds", ["subnet-test-invalid"]], ["replayTable", "bad table"], ["receiptBucket", "other-bucket"]]) {
    assert.throws(() => createHandler({ config: { ...config, [field]: value }, executingBrokerVersion: "1" }), /runtime bindings|reviewed contract/);
  }
});

test("Stage B approval rejects wrong signer, bindings, expiry, and mutable image input", async () => {
  await assert.rejects(() => validateStageBApproval(artifact(), expected, { now, verifySignature: async () => false }), /signature/);
  for (const [field, value, message] of [["releaseSha", "e".repeat(40), /releaseSha/], ["sourceContractSha256", "e".repeat(64), /sourceContractSha256/], ["migrationSetDigest", "e".repeat(64), /migrationSetDigest/], ["brokerVersion", "2", /brokerVersion/], ["expiresAt", "2026-07-29T11:59:00.000Z", /expired/], ["backendImageDigest", "368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend:latest", /invalid/]]) {
    await assert.rejects(() => validateStageBApproval(artifact({ [field]: value }), expected, { now, verifySignature }), message);
  }
  await assert.rejects(() => validateStageBApproval(artifact({ backendImageDigest: image("mscqr-backend", "9") }), expected, { now, verifySignature }), /immutable image contract/);
});

test("every broker request binds its signed approval to the immutable executing Lambda version", async () => {
  const handler = createHandler({ config, executingBrokerVersion: "2", readApproval: async () => JSON.stringify(artifact()), verifySignature,
    claimApproval: async () => assert.fail("moved alias version must not claim approval"), runTask: async () => assert.fail("moved alias version must not start a task"), now: () => now,
  });
  await assert.rejects(() => handler({ approvalId: stageBApprovalIdForReleaseSha(releaseSha), mode: "full-rls-verification" }), /brokerVersion/);
  assert.throws(() => createHandler({ config, executingBrokerVersion: "$LATEST" }), /immutable published Lambda version/);
});

test("executor accepts the same signed Stage B approval and binds its package checksum", async () => {
  const result = await validateProductionRlsApproval(artifact(), {
    releaseSha, sourceContractSha256: source, migrationSetDigest: migration, packageChecksumSha256: checksum,
    deploymentId: "phase2", greenDatabase: "mscqr_production_rls_green_phase2", administratorIdentity: "mscqr_prod_admin",
  }, { now, verifySignature });
  assert.equal(result.approval.independentCheckerIdentity, "arn:aws:sts::368992683803:assumed-role/mscqr-production-rls-independent-checker/checker");
  await assert.rejects(() => validateProductionRlsApproval(artifact({ packageChecksumSha256: "e".repeat(64) }), {
    releaseSha, sourceContractSha256: source, migrationSetDigest: migration, packageChecksumSha256: checksum,
    deploymentId: "phase2", greenDatabase: "mscqr_production_rls_green_phase2", administratorIdentity: "mscqr_prod_admin",
  }, { now, verifySignature }), /packageChecksumSha256/);
});

test("Stage B permits only an explicitly requested rollback inside the 24-hour grace", async () => {
  const expired = artifact({ issuedAt: "2026-07-29T10:00:00.000Z", expiresAt: "2026-07-29T11:59:00.000Z" });
  await assert.rejects(() => validateStageBApproval(expired, expected, { now, verifySignature }), /invalid or expired/);
  await assert.rejects(() => validateStageBApproval(expired, expected, { now, verifySignature, allowExpiredRollback: true, requestedMode: "full-rls-verification" }), /invalid or expired/);
  await assert.rejects(() => validateStageBApproval(expired, expected, { now: new Date("2026-07-30T12:00:00.000Z"), verifySignature, allowExpiredRollback: true, requestedMode: "full-rls-rollback" }), /invalid or expired/);
  await assert.doesNotReject(() => validateStageBApproval(expired, expected, { now, verifySignature, allowExpiredRollback: true, requestedMode: "full-rls-rollback" }));
  await assert.doesNotReject(() => validateProductionRlsApproval(expired, {
    ...expected, greenDatabase: "mscqr_production_rls_green_phase2", administratorIdentity: "mscqr_prod_admin", mode: "full-rls-rollback",
  }, { now, verifySignature, allowExpiredRollback: true }));
  await assert.rejects(() => validateStageBApproval(artifact({ releaseSha: "e".repeat(40), issuedAt: "2026-07-29T10:00:00.000Z", expiresAt: "2026-07-29T11:59:00.000Z" }), expected, { now, verifySignature, allowExpiredRollback: true, requestedMode: "full-rls-rollback" }), /releaseSha/);
});

test("Stage B templates require immutable images, private executor networking, and no administrator secret outside executor", () => {
  const common = { imageReleaseSha: releaseSha, sourceContractSha256: source, migrationSetDigest: migration, packageChecksumSha256: checksum, receiptBucket: STAGE_B.receiptBucket, executorLogGroup: "/ecs/executor", canaryLogGroup: "/ecs/canary", backendLogGroup: "/ecs/backend", workerLogGroup: "/ecs/worker" };
  const confirmations = {
    "full-rls-capability-preflight": "",
    "full-rls-admin-bootstrap": "MSCQR_PRODUCTION_GREEN_CREATE_AND_BOOTSTRAP_DATABASE",
    "full-rls-role-provision": "MSCQR_PRODUCTION_GREEN_PROVISION_RUNTIME_ROLES",
    "full-rls-role-verify": "",
    "full-rls-admin-ownership": "MSCQR_PRODUCTION_GREEN_INSTALL_OWNERSHIP_GRANTS",
    "full-rls-runtime-policy": "MSCQR_PRODUCTION_GREEN_INSTALL_RUNTIME_POLICIES",
    "full-rls-verification": "",
    "full-rls-rollback": "MSCQR_PRODUCTION_GREEN_ROLLBACK_EXACT_PACKAGE",
  };
  const executors = Object.fromEntries(Object.entries(confirmations).map(([mode, confirmation]) => {
    const definition = renderStageBTaskDefinition("executor", { ...common, executorImage: images.executorImageDigest, mode });
    assert.equal(definition.containerDefinitions.length, 1);
    assert.equal(definition.containerDefinitions[0].environment.find(({ name }) => name === "MSCQR_FULL_RLS_CONFIRMATION").value, confirmation);
    assert.doesNotMatch(JSON.stringify(definition), /\{\{[^}]+}}/);
    return [mode, definition];
  }));
  const executor = executors["full-rls-verification"];
  const canary = renderStageBTaskDefinition("canary", { ...common, canaryImage: images.canaryImageDigest });
  const backend = renderStageBTaskDefinition("backend", { ...common, backendImage: images.backendImageDigest });
  const worker = renderStageBTaskDefinition("worker", { ...common, workerImage: images.workerImageDigest });
  for (const definition of [...Object.values(executors), canary, backend, worker]) {
    assertFixedTaskDefinition(definition);
    assert.equal(definition.containerDefinitions.length, 1);
    assert.deepEqual(definition.runtimePlatform, STAGE_B.taskRuntimePlatform);
  }
  assert.match(JSON.stringify(executor), /rds!db-/);
  assert.doesNotMatch(`${JSON.stringify(canary)}${JSON.stringify(backend)}${JSON.stringify(worker)}`, /rds!db-/);
  assert.deepEqual(backend.volumes, [{ name: "backend-uploads" }]);
  assert.deepEqual(backend.containerDefinitions[0].mountPoints, [{ sourceVolume: "backend-uploads", containerPath: "/app/uploads", readOnly: false }]);
  assert.deepEqual(executor.volumes, [{ name: "executor-tmp" }]);
  assert.deepEqual(canary.volumes, [{ name: "canary-tmp" }]);
  assert.equal(worker.volumes, undefined);
  for (const definition of [executor, canary, backend, worker]) assert.equal(definition.containerDefinitions[0].readonlyRootFilesystem, true);
  for (const source of ["backend/src/middleware/incidentUpload.ts", "backend/src/services/compliancePackService.ts", "backend/src/services/legacyQrRiskReportJobService.ts"]) {
    assert.match(fs.readFileSync(source, "utf8"), /uploads/);
  }
  assert.deepEqual(approvedNetworkConfiguration(config.privateSubnetIds).awsvpcConfiguration, { subnets: [...config.privateSubnetIds].sort(), securityGroups: [STAGE_B.executorSecurityGroupId], assignPublicIp: "DISABLED" });
  assert.throws(() => approvedNetworkConfiguration([config.privateSubnetIds[0], "subnet-test-invalid"]), /approved private subnets/);
  assert.throws(() => renderStageBTaskDefinition("executor", { ...common, executorImage: "mscqr-backend:latest", mode: "full-rls-verification" }), /immutable/);
  assert.throws(() => renderStageBTaskDefinition("backend", { ...common, backendImage: image("mscqr-web", "5") }), /reviewed ECR repository/);
  assert.throws(() => assertFixedTaskDefinition({ ...backend, cpu: "256", memory: "3072" }), /fixed reviewed/);
  assert.throws(() => assertFixedTaskDefinition({ ...backend, runtimePlatform: { operatingSystemFamily: "LINUX", cpuArchitecture: "ARM64" } }), /fixed reviewed/);
  const { runtimePlatform, ...withoutRuntimePlatform } = backend;
  assert.throws(() => assertFixedTaskDefinition(withoutRuntimePlatform), /fixed reviewed/);
});

test("broker rejects replay, task substitution, image substitution, and every caller override", async () => {
  const claimed = new Set(); let request;
  const handler = createHandler({ config, executingBrokerVersion: "1", readApproval: async () => JSON.stringify(artifact()), verifySignature, now: () => now,
    claimApproval: async ({ approvalId, mode }) => { const key = `${approvalId}:${mode}`; if (claimed.has(key)) throw new Error("approval replay"); claimed.add(key); },
    runTask: async (value) => { request = value; return { failures: [], tasks: [{ taskArn: "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/fixed" }] }; },
  });
  const event = { approvalId: stageBApprovalIdForReleaseSha(releaseSha), mode: "full-rls-verification" };
  await handler(event); assert.equal("overrides" in request, false); assert.equal(request.taskDefinition, taskDefinitions[event.mode]);
  await assert.rejects(() => handler(event), /replay/);
  for (const key of ["command", "environment", "role", "networkConfiguration", "taskDefinition", "image"]) {
    await assert.rejects(() => handler({ ...event, [key]: "substitution" }), /outside the reviewed contract/);
  }
  const substituted = { ...config, taskDefinitionArns: { ...taskDefinitions, "full-rls-verification": "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-full-rls-green-other:1" } };
  assert.throws(() => createHandler({ config: substituted, executingBrokerVersion: "1", readApproval: async () => JSON.stringify(artifact()), verifySignature, claimApproval: async () => assert.fail("substituted task must not claim approval"), runTask: async () => assert.fail("substituted task must not start"), now: () => now }), /task-definition map|reviewed contract/);
});

test("broker releases only an explicit ECS rejection and blocks uncertain launches for review", async () => {
  const events = [];
  const handler = createHandler({ config, executingBrokerVersion: "1", readApproval: async () => JSON.stringify(artifact()), verifySignature, now: () => now,
    claimApproval: async () => events.push("claim"),
    releaseApproval: async () => events.push("release"),
    markLaunchUncertain: async () => events.push("uncertain"),
    runTask: async () => ({ failures: [{ reason: "capacity" }], tasks: [] }),
  });
  await assert.rejects(() => handler({ approvalId: stageBApprovalIdForReleaseSha(releaseSha), mode: "full-rls-verification" }), /claim was released/);
  assert.deepEqual(events, ["claim", "release"]);
  const uncertain = createHandler({ config, executingBrokerVersion: "1", readApproval: async () => JSON.stringify(artifact()), verifySignature, now: () => now,
    claimApproval: async () => events.push("claim-uncertain"), markLaunchUncertain: async () => events.push("uncertain"), runTask: async () => { throw new Error("timeout"); },
  });
  await assert.rejects(() => uncertain({ approvalId: stageBApprovalIdForReleaseSha(releaseSha), mode: "full-rls-verification" }), /outcome is uncertain/);
  assert.deepEqual(events, ["claim", "release", "claim-uncertain", "uncertain"]);
});

test("Stage B workflow and Docker targets keep the executor fixed and front-end excluded", () => {
  const dockerfile = fs.readFileSync("backend/Dockerfile", "utf8"); const dispatcher = fs.readFileSync(".github/workflows/production-green-stage-b-images.yml", "utf8");
  const workflow = fs.readFileSync(".github/workflows/production-green-stage-b-image-build.yml", "utf8");
  const publisher = fs.readFileSync("scripts/aws/publish-ecs-images.sh", "utf8");
  assert.match(dockerfile, /FROM node:24-bookworm-slim AS production-rls-executor/); assert.match(dockerfile, /ENTRYPOINT \["node", "scripts\/production-full-rls-green-executor\.mjs"\]/);
  assert.match(dockerfile, /scripts\/aws\/production-green-stage-b-contract\.mjs \.\/scripts\/production-green-stage-b-contract\.mjs/);
  assert.match(workflow, /rls:full-verify/); assert.match(workflow, /trivy-action/); assert.match(workflow, /cosign-idempotent-sign-and-attest\.sh"? attest/);
  assert.match(publisher, /IMAGE_TAG.*git rev-parse HEAD/); assert.match(publisher, /SOURCE_RELEASE_SHA/); assert.match(publisher, /npm run rls:full-verify/);
  assert.match(publisher, /verify_stage_b_reuse/); assert.match(publisher, /stage-b-image-bindings\.mjs/);
  assert.match(dispatcher, /stage-b-release-gate\.mjs/); assert.match(workflow, /stage-b-release-gate\.mjs/);
  assert.match(workflow, /docker save/); assert.match(workflow, /Expected exactly one immutable image record/);
  assert.doesNotMatch(`${dispatcher}${workflow}`, /mscqr-frontend:20|deploy-ecs-service|ecs update-service/i);
  const policy = fs.readFileSync("infra/aws/terraform/production-green-stage-b/broker/invocation-policy.json", "utf8");
  assert.match(policy, /mscqr-production-release-deployer/); assert.doesNotMatch(policy, /root|github-actions-mscqr-deploy|\*/i);
});

test("closure evidence upload preserves the primary failure when the producer emits no report", () => {
  const qualityGate = fs.readFileSync(".github/workflows/quality-gate.yml", "utf8");
  const record = qualityGate.indexOf("Record Stage B image-impact evidence availability");
  const upload = qualityGate.indexOf("Upload Stage B pre-merge image-impact evidence");
  assert.ok(record >= 0 && record < upload);
  assert.match(qualityGate.slice(upload, upload + 500), /env\.STAGE_B_IMAGE_IMPACT_ARTIFACT_EXISTS == 'true'/);
  assert.match(qualityGate.slice(record, upload), /primary closure failure remains authoritative/);
});

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import test from "node:test";
import { createHandler } from "../../infra/aws/terraform/lambda/production-rls-approval-broker/index.mjs";
import { STAGE_B, STAGE_B_APPROVAL_ALGORITHM, canonicalStageBApproval, validateStageBApproval } from "../aws/production-green-stage-b-contract.mjs";
import { approvedNetworkConfiguration, assertFixedTaskDefinition, renderStageBTaskDefinition, stageBTemplateHashes } from "../aws/production-green-stage-b-task-definitions.mjs";
import { validateProductionRlsApproval } from "../../backend/scripts/production-rls-approval.mjs";

const now = new Date("2026-07-29T12:00:00.000Z");
const releaseSha = "a".repeat(40); const source = "b".repeat(64); const migration = "c".repeat(64); const checksum = "d".repeat(64);
const image = (repo, seed) => `368992683803.dkr.ecr.eu-west-2.amazonaws.com/${repo}@sha256:${seed.repeat(64)}`;
const images = { backendImageDigest: image("mscqr-backend", "1"), workerImageDigest: image("mscqr-worker", "2"), executorImageDigest: image("mscqr-backend", "3"), canaryImageDigest: image("mscqr-backend", "4") };
const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const sign = (approval) => crypto.sign("sha256", Buffer.from(canonicalStageBApproval(approval)), { key: privateKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }).toString("base64");
const artifact = (overrides = {}) => {
  const value = { schemaVersion: 2, environment: "production", account: STAGE_B.account, region: STAGE_B.region, releaseSha, ...images, sourceContractSha256: source, migrationSetDigest: migration, packageChecksumSha256: checksum, deploymentId: "phase2", greenDatabaseIdentifier: STAGE_B.greenDatabaseIdentifier, greenDatabaseName: "mscqr_production_rls_green_phase2", administratorIdentity: "mscqr_prod_admin", databaseSecurityGroupId: STAGE_B.databaseSecurityGroupId, executorSecurityGroupId: STAGE_B.executorSecurityGroupId, taskDefinitionArns: taskDefinitions, taskDefinitionTemplateHashes: stageBTemplateHashes(), brokerAliasArn: STAGE_B.brokerAliasArn, brokerVersion: "1", checkerIdentity: "arn:aws:sts::368992683803:assumed-role/mscqr-production-rls-independent-checker/checker", deployerIdentity: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/deployer", executorIdentity: STAGE_B.executorRoleArn, approvalId: "APR-STAGE-B-0001", ticketId: "CHG-STAGE-B-0001", issuedAt: "2026-07-29T11:55:00.000Z", expiresAt: "2026-07-29T13:00:00.000Z", nonce: "12345678-1234-1234-1234-123456789abc", signatureAlgorithm: STAGE_B_APPROVAL_ALGORITHM, ...overrides };
  return { ...value, signatureBase64: sign(value) };
};
const verifySignature = async ({ message, signature }) => crypto.verify("sha256", message, { key: publicKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, signature);
const taskDefinitions = Object.fromEntries(["full-rls-capability-preflight", "full-rls-admin-bootstrap", "full-rls-role-provision", "full-rls-role-verify", "full-rls-admin-ownership", "full-rls-runtime-policy", "full-rls-verification", "full-rls-application-canary", "full-rls-rollback"].map((mode) => [mode, `arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-full-rls-green-${mode.replace("full-rls-", "")}:1`]));
const expected = { releaseSha, sourceContractSha256: source, migrationSetDigest: migration, packageChecksumSha256: checksum, deploymentId: "phase2", approvalId: "APR-STAGE-B-0001", ticketId: "CHG-STAGE-B-0001", images, taskDefinitionArns: taskDefinitions };
const config = { clusterArn: STAGE_B.clusterArn, approvalSecretArn: STAGE_B.approvalSecretArn, executorSecurityGroupId: STAGE_B.executorSecurityGroupId, privateSubnetIds: ["subnet-068d949017bd2ce45", "subnet-07e0a76e3a5241138"], taskDefinitionArns: taskDefinitions, templateHashes: stageBTemplateHashes(), approvalExpected: expected, images };

test("Stage B approval rejects wrong signer, bindings, expiry, and mutable image input", async () => {
  await assert.rejects(() => validateStageBApproval(artifact(), expected, { now, verifySignature: async () => false }), /signature/);
  for (const [field, value, message] of [["releaseSha", "e".repeat(40), /releaseSha/], ["sourceContractSha256", "e".repeat(64), /sourceContractSha256/], ["migrationSetDigest", "e".repeat(64), /migrationSetDigest/], ["expiresAt", "2026-07-29T11:59:00.000Z", /expired/], ["backendImageDigest", "368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend:latest", /invalid/]]) {
    await assert.rejects(() => validateStageBApproval(artifact({ [field]: value }), expected, { now, verifySignature }), message);
  }
  await assert.rejects(() => validateStageBApproval(artifact({ backendImageDigest: image("mscqr-backend", "9") }), expected, { now, verifySignature }), /immutable image contract/);
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

test("Stage B templates require immutable images, private executor networking, and no administrator secret outside executor", () => {
  const common = { releaseSha, sourceContractSha256: source, migrationSetDigest: migration, packageChecksumSha256: checksum, receiptBucket: STAGE_B.receiptBucket, executorLogGroup: "/ecs/executor", canaryLogGroup: "/ecs/canary", backendLogGroup: "/ecs/backend", workerLogGroup: "/ecs/worker" };
  const executor = renderStageBTaskDefinition("executor", { ...common, executorImage: images.executorImageDigest, mode: "full-rls-verification" });
  const canary = renderStageBTaskDefinition("canary", { ...common, canaryImage: images.canaryImageDigest });
  const backend = renderStageBTaskDefinition("backend", { ...common, backendImage: images.backendImageDigest });
  const worker = renderStageBTaskDefinition("worker", { ...common, workerImage: images.workerImageDigest });
  for (const definition of [executor, canary, backend, worker]) assertFixedTaskDefinition(definition);
  assert.match(JSON.stringify(executor), /rds!db-/);
  assert.doesNotMatch(`${JSON.stringify(canary)}${JSON.stringify(backend)}${JSON.stringify(worker)}`, /rds!db-/);
  assert.deepEqual(approvedNetworkConfiguration(config.privateSubnetIds).awsvpcConfiguration, { subnets: [...config.privateSubnetIds].sort(), securityGroups: [STAGE_B.executorSecurityGroupId], assignPublicIp: "DISABLED" });
  assert.throws(() => approvedNetworkConfiguration([config.privateSubnetIds[0], "subnet-0123456789abcdef0"]), /approved private subnets/);
  assert.throws(() => renderStageBTaskDefinition("executor", { ...common, executorImage: "mscqr-backend:latest", mode: "full-rls-verification" }), /immutable/);
  assert.throws(() => renderStageBTaskDefinition("backend", { ...common, backendImage: image("mscqr-web", "5") }), /reviewed ECR repository/);
  assert.throws(() => assertFixedTaskDefinition({ ...backend, cpu: "256", memory: "3072" }), /fixed reviewed/);
});

test("broker rejects replay, task substitution, image substitution, and every caller override", async () => {
  const claimed = new Set(); let request;
  const handler = createHandler({ config, readApproval: async () => JSON.stringify(artifact()), verifySignature, now: () => now,
    claimApproval: async ({ approvalId, mode }) => { const key = `${approvalId}:${mode}`; if (claimed.has(key)) throw new Error("approval replay"); claimed.add(key); },
    runTask: async (value) => { request = value; return { failures: [], tasks: [{ taskArn: "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/fixed" }] }; },
  });
  const event = { approvalId: "APR-STAGE-B-0001", mode: "full-rls-verification" };
  await handler(event); assert.equal("overrides" in request, false); assert.equal(request.taskDefinition, taskDefinitions[event.mode]);
  await assert.rejects(() => handler(event), /replay/);
  for (const key of ["command", "environment", "role", "networkConfiguration", "taskDefinition", "image"]) {
    await assert.rejects(() => handler({ ...event, [key]: "substitution" }), /outside the reviewed contract/);
  }
  const substituted = { ...config, taskDefinitionArns: { ...taskDefinitions, "full-rls-verification": "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-full-rls-green-other:1" } };
  const substitutedHandler = createHandler({ config: substituted, readApproval: async () => JSON.stringify(artifact()), verifySignature, claimApproval: async () => assert.fail("substituted task must not claim approval"), runTask: async () => assert.fail("substituted task must not start"), now: () => now });
  await assert.rejects(() => substitutedHandler(event), /signed approval/);
});

test("broker releases only an explicit ECS rejection and blocks uncertain launches for review", async () => {
  const events = [];
  const handler = createHandler({ config, readApproval: async () => JSON.stringify(artifact()), verifySignature, now: () => now,
    claimApproval: async () => events.push("claim"),
    releaseApproval: async () => events.push("release"),
    markLaunchUncertain: async () => events.push("uncertain"),
    runTask: async () => ({ failures: [{ reason: "capacity" }], tasks: [] }),
  });
  await assert.rejects(() => handler({ approvalId: "APR-STAGE-B-0001", mode: "full-rls-verification" }), /claim was released/);
  assert.deepEqual(events, ["claim", "release"]);
  const uncertain = createHandler({ config, readApproval: async () => JSON.stringify(artifact()), verifySignature, now: () => now,
    claimApproval: async () => events.push("claim-uncertain"), markLaunchUncertain: async () => events.push("uncertain"), runTask: async () => { throw new Error("timeout"); },
  });
  await assert.rejects(() => uncertain({ approvalId: "APR-STAGE-B-0001", mode: "full-rls-verification" }), /outcome is uncertain/);
  assert.deepEqual(events, ["claim", "release", "claim-uncertain", "uncertain"]);
});

test("Stage B workflow and Docker targets keep the executor fixed and front-end excluded", () => {
  const dockerfile = fs.readFileSync("backend/Dockerfile", "utf8"); const workflow = fs.readFileSync(".github/workflows/production-green-stage-b-images.yml", "utf8");
  const publisher = fs.readFileSync("scripts/aws/publish-ecs-images.sh", "utf8");
  assert.match(dockerfile, /FROM node:24-bookworm-slim AS production-rls-executor/); assert.match(dockerfile, /ENTRYPOINT \["node", "scripts\/production-full-rls-green-executor\.mjs"\]/);
  assert.match(dockerfile, /scripts\/aws\/production-green-stage-b-contract\.mjs \.\/scripts\/production-green-stage-b-contract\.mjs/);
  assert.match(workflow, /rls:full-verify/); assert.match(workflow, /trivy-action/); assert.match(workflow, /cosign attest/);
  assert.match(publisher, /IMAGE_TAG.*git rev-parse HEAD/); assert.match(publisher, /npm run rls:full-verify/);
  assert.match(workflow, /docker save/); assert.match(workflow, /Expected exactly one immutable image record/);
  assert.doesNotMatch(workflow, /mscqr-frontend:20|deploy-ecs-service|ecs update-service/i);
  const policy = fs.readFileSync("infra/aws/terraform/production-green-stage-b/broker/invocation-policy.json", "utf8");
  assert.match(policy, /mscqr-production-release-deployer/); assert.doesNotMatch(policy, /root|github-actions-mscqr-deploy|\*/i);
});

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import test from "node:test";
import {
  PRODUCTION_RLS_APPROVAL_ALGORITHM,
  canonicalProductionApprovalPayload,
  validateProductionRlsApproval,
} from "../../backend/scripts/production-rls-approval.mjs";
import { createHandler } from "../../infra/aws/terraform/lambda/production-rls-approval-broker/index.mjs";

const expected = {
  releaseSha: "a".repeat(40),
  sourceContractSha256: "b".repeat(64),
  migrationSetDigest: "c".repeat(64),
  deploymentId: "phase2",
  greenDatabase: "mscqr_production_rls_green_phase2",
  administratorIdentity: "mscqr_prod_admin",
  kmsKeyArn: "arn:aws:kms:eu-west-2:368992683803:key/00000000-0000-4000-8000-000000000001",
};
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const now = new Date("2026-07-28T12:00:00.000Z");
const payload = (overrides = {}) => ({
  schemaVersion: 1,
  environment: "production",
  ...expected,
  approvalId: "APR-PRODUCTION-RLS-ACTIVATION",
  ticketId: "CHG-PRODUCTION-RLS-2026-07",
  independentCheckerIdentity: "arn:aws:sts::368992683803:assumed-role/mscqr-production-rls-independent-checker/alice@example.com",
  issuedAt: "2026-07-28T11:55:00.000Z",
  expiresAt: "2026-07-28T13:55:00.000Z",
  signatureAlgorithm: PRODUCTION_RLS_APPROVAL_ALGORITHM,
  ...overrides,
});
const artifact = (overrides = {}) => {
  const approval = payload(overrides);
  const signature = crypto.sign("sha256", canonicalProductionApprovalPayload(approval), {
    key: privateKey,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength: 32,
  });
  return { ...approval, signatureBase64: signature.toString("base64") };
};
const verifySignature = ({ message, signature }) => crypto.verify("sha256", message, {
  key: publicKey,
  padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
  saltLength: 32,
}, signature);
const validate = (candidate, expectation = expected, options = {}) =>
  validateProductionRlsApproval(candidate, expectation, { now, verifySignature, ...options });
const syntheticSubnet = ["subnet", "0123456789abcdef0"].join("-");
const syntheticApprovalSecretArn = [
  "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr",
  "production",
  "rls-green",
  "phase2",
  "approval-ABC123",
].join("/");

test("production package generator fails closed without approval", () => {
  const result = spawnSync(process.execPath, [
    "scripts/rls/generate-clean-room-rls-sql.mjs",
    "--environment", "production",
    "--deployment-id", "phase2",
  ], { cwd: process.cwd(), encoding: "utf8" });
  assert.notEqual(result.status, 0);
  assert.match(`${result.stdout}${result.stderr}`, /approval artifact/);
});

test("production approval rejects missing, malformed and expired artifacts", async () => {
  await assert.rejects(() => validate(""), /not valid JSON/);
  await assert.rejects(() => validate(JSON.stringify({})), /fields do not match/);
  await assert.rejects(() => validate(artifact({ expiresAt: "2026-07-28T11:59:59.000Z" })), /invalid or expired/);
  await assert.rejects(() => validate(artifact({
    issuedAt: "2026-07-28T12:04:00.000Z",
    expiresAt: "2026-07-28T12:03:00.000Z",
  })), /invalid or expired/);
});

test("production approval rejects every required execution binding mismatch", async () => {
  for (const [field, value] of [
    ["releaseSha", "d".repeat(40)],
    ["greenDatabase", "mscqr_production_rls_green_wrong"],
    ["administratorIdentity", "mscqr_other_admin"],
    ["migrationSetDigest", "e".repeat(64)],
  ]) {
    await assert.rejects(() => validate(artifact({ [field]: value })), new RegExp(field === "administratorIdentity" ? "invalid" : field));
  }
});

test("production approval rejects a foreign checker and invalid signature", async () => {
  await assert.rejects(
    () => validate(artifact({ independentCheckerIdentity: "arn:aws:sts::368992683803:assumed-role/other/alice" })),
    /invalid/
  );
  const candidate = artifact();
  candidate.signatureBase64 = Buffer.from("invalid").toString("base64");
  await assert.rejects(() => validate(candidate), /signature verification failed/);
});

test("production approval accepts an exact, unexpired, independently signed contract", async () => {
  const result = await validate(artifact());
  assert.equal(result.approval.approvalId, "APR-PRODUCTION-RLS-ACTIVATION");
  assert.match(result.approvalContractSha256, /^[a-f0-9]{64}$/);
});

test("approval broker launches only the fixed private task without overrides", async () => {
  let request;
  const taskDefinition =
    "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-full-rls-green-verification:7";
  const handler = createHandler({
    config: {
      clusterArn: "arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main",
      taskDefinitionArns: { "full-rls-verification": taskDefinition },
      approvalSecretArn: syntheticApprovalSecretArn,
      subnets: [syntheticSubnet],
      securityGroups: ["sg-0123456789abcdef0"],
      approvalExpected: expected,
    },
    readApproval: async () => JSON.stringify(artifact()),
    verifySignature,
    now,
    runTask: async (value) => {
      request = value;
      return {
        failures: [],
        tasks: [{ taskArn: "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/0123456789abcdef" }],
      };
    },
  });
  const result = await handler({ mode: "full-rls-verification", approvalId: "APR-PRODUCTION-RLS-ACTIVATION" });
  assert.equal(result.taskDefinitionArn, taskDefinition);
  assert.equal(request.taskDefinition, taskDefinition);
  assert.equal(request.networkConfiguration.awsvpcConfiguration.assignPublicIp, "DISABLED");
  assert.equal("overrides" in request, false);
});

test("approval broker rejects requests not bound to the signed approval", async () => {
  const handler = createHandler({
    config: {
      clusterArn: "arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main",
      taskDefinitionArns: {
        "full-rls-verification":
          "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-full-rls-green-verification:7",
      },
      approvalSecretArn: syntheticApprovalSecretArn,
      subnets: [syntheticSubnet],
      securityGroups: ["sg-0123456789abcdef0"],
      approvalExpected: expected,
    },
    readApproval: async () => JSON.stringify(artifact()),
    verifySignature,
    now,
    runTask: async () => assert.fail("unapproved task must not start"),
  });
  await assert.rejects(
    () => handler({ mode: "full-rls-verification", approvalId: "APR-WRONG" }),
    /approval ID mismatch/
  );
  await assert.rejects(
    () => handler({ mode: "not-reviewed", approvalId: "APR-130-RLS-ACTIVATION" }),
    /outside the reviewed contract/
  );
});

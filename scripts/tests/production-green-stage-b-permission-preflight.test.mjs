import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { assertPermissionReport, runApply } from "../apply-production-green-stage-b.mjs";
import {
  deriveRequiredEvaluations,
  runPermissionPreflight,
  simulatePrincipalPolicy,
  validateManifest,
} from "../aws/validate-production-green-stage-b-permissions.mjs";

const manifest = JSON.parse(fs.readFileSync("documents/ops/iam/MSCQRProductionGreenStageBPermissionManifest-v1.json", "utf8"));
const roleArn = "arn:aws:iam::368992683803:role/mscqr-production-release-deployer";
const plan = {
  variables: {
    account_id: { value: "368992683803" },
    aws_region: { value: "eu-west-2" },
  },
  resource_changes: [{
    address: 'aws_ecs_task_definition.candidate["read_only_canary"]',
    type: "aws_ecs_task_definition",
    change: { actions: ["create"], after: { family: "mscqr-production-full-rls-green-read-only-canary" } },
  }],
};
const planBytes = Buffer.from(JSON.stringify(plan));
const now = "2026-08-01T12:00:00.000Z";
const clearCloudTrail = () => ({ status: "clear", eventsChecked: 0, unresolvedDenials: [] });
const allowRequiredDenyForbidden = ({ evaluation }) => ({ decision: evaluation.id.startsWith("pass-unrelated-role") || evaluation.id.startsWith("pass-to-lambda") || evaluation.id.startsWith("invoke-broker") || evaluation.id.startsWith("execute-ecs-task") || evaluation.id.startsWith("update-ecs-service") || evaluation.id.startsWith("create-iam-role") || evaluation.id.startsWith("deregister-task-definition") ? "explicitDeny" : "allowed", matchedStatements: 1 });

test("manifest is source-controlled, exact-accounted, and has no wildcard PassRole", () => {
  assert.equal(validateManifest(manifest), true);
  const passRole = manifest.required.find((entry) => entry.action === "iam:PassRole");
  assert.deepEqual(passRole.resources, [
    "arn:aws:iam::368992683803:role/mscqr-production-full-rls-green-read-only-canary-execution",
    "arn:aws:iam::368992683803:role/mscqr-production-full-rls-green-read-only-canary-task",
  ]);
});

test("exact canary create derives Register, TagResource, and both PassRole evaluations", () => {
  const derived = deriveRequiredEvaluations(plan, manifest);
  const passRoles = derived.required.filter((item) => item.action === "iam:PassRole");
  assert.deepEqual(passRoles.map((item) => item.resource), [
    "arn:aws:iam::368992683803:role/mscqr-production-full-rls-green-read-only-canary-execution",
    "arn:aws:iam::368992683803:role/mscqr-production-full-rls-green-read-only-canary-task",
  ]);
  assert.ok(derived.required.some((item) => item.action === "ecs:RegisterTaskDefinition"));
  assert.ok(derived.required.some((item) => item.action === "ecs:TagResource"));
});

test("complete mocked preflight passes and binds the exact plan SHA", () => {
  const report = runPermissionPreflight({
    roleArn, plan, planBytes, manifest, generatedAt: now, now, policyPublishedAt: "2026-08-01T11:55:00.000Z", cloudTrailSessionName: "test-session",
    simulate: allowRequiredDenyForbidden,
    cloudTrail: clearCloudTrail,
  });
  assert.equal(report.status, "valid");
  assert.equal(report.planSha256, crypto.createHash("sha256").update(planBytes).digest("hex"));
  assert.equal(report.deniedCount, 0);
  assertPermissionReport(report, { planSha256: report.planSha256, now });
});

test("missing required PassRole fails closed", () => {
  const report = runPermissionPreflight({
    roleArn, plan, planBytes, manifest, generatedAt: now, now, policyPublishedAt: "2026-08-01T11:55:00.000Z", cloudTrailSessionName: "test-session",
    simulate: ({ evaluation }) => evaluation.action === "iam:PassRole" ? { decision: "implicitDeny" } : allowRequiredDenyForbidden({ evaluation }),
    cloudTrail: clearCloudTrail,
  });
  assert.equal(report.status, "invalid");
  assert.ok(report.requiredEvaluations.some((item) => item.action === "iam:PassRole" && item.decision === "implicitDeny"));
  assert.throws(() => assertPermissionReport(report, { planSha256: report.planSha256, now }), /valid permission-preflight report/);
});

test("PassRole with the wrong service context is rejected by the manifest", () => {
  const broken = structuredClone(manifest);
  broken.required.find((entry) => entry.action === "iam:PassRole").context[0].values = ["lambda.amazonaws.com"];
  assert.throws(() => validateManifest(broken), /must require ECS tasks/);
});

test("wrong role, account, region, missing context, and unreviewed plan actions fail closed", () => {
  assert.throws(() => runPermissionPreflight({ roleArn: "arn:aws:iam::368992683803:role/unrelated", plan, planBytes, manifest, generatedAt: now, now, policyPublishedAt: now, cloudTrailSessionName: "test", simulate: allowRequiredDenyForbidden, cloudTrail: clearCloudTrail }), /role ARN/);
  assert.throws(() => runPermissionPreflight({ roleArn, plan: { ...plan, variables: { ...plan.variables, account_id: { value: "000000000000" } } }, planBytes, manifest, generatedAt: now, now, policyPublishedAt: now, cloudTrailSessionName: "test", simulate: allowRequiredDenyForbidden, cloudTrail: clearCloudTrail }), /account or region/);
  const broken = structuredClone(manifest); broken.required.find((entry) => entry.action === "iam:PassRole").context = [];
  assert.throws(() => validateManifest(broken), /must require ECS tasks/);
  assert.throws(() => deriveRequiredEvaluations({ ...plan, resource_changes: [...plan.resource_changes, { address: "aws_ecs_service.unexpected", type: "aws_ecs_service", change: { actions: ["update"], after: {} } }] }, manifest), /No permission manifest entry/);
});

test("IAM simulation uses argv arrays and passes context explicitly", () => {
  let captured;
  const result = simulatePrincipalPolicy({
    roleArn,
    evaluation: { id: "pass-test", action: "iam:PassRole", resource: "arn:aws:iam::368992683803:role/test", context: [{ key: "iam:PassedToService", type: "string", values: ["ecs-tasks.amazonaws.com"] }] },
    run: (args) => { captured = args; return JSON.stringify({ evaluationResults: [{ evalDecision: "allowed", matchedStatements: [] }] }); },
  });
  assert.equal(result.decision, "allowed");
  assert.ok(captured.includes("--context-entries"));
  assert.equal(captured.some((value) => value.includes(";") || value.includes("$(") || value.includes("`")), false);
});

test("forbidden allowed evaluation fails closed", () => {
  const report = runPermissionPreflight({
    roleArn, plan, planBytes, manifest, generatedAt: now, now, policyPublishedAt: "2026-08-01T11:55:00.000Z", cloudTrailSessionName: "test-session",
    simulate: ({ evaluation }) => evaluation.id.startsWith("pass-unrelated-role") ? { decision: "allowed" } : allowRequiredDenyForbidden({ evaluation }),
    cloudTrail: clearCloudTrail,
  });
  assert.equal(report.status, "invalid");
  assert.ok(report.forbiddenEvaluations.some((item) => item.id.startsWith("pass-unrelated-role") && item.decision === "allowed"));
});

test("wrong plan binding and stale reports are rejected", () => {
  const report = runPermissionPreflight({
    roleArn, plan, planBytes, manifest, generatedAt: now, now, policyPublishedAt: "2026-08-01T11:55:00.000Z", cloudTrailSessionName: "test-session",
    simulate: allowRequiredDenyForbidden,
    cloudTrail: clearCloudTrail,
  });
  assert.throws(() => assertPermissionReport(report, { planSha256: "0".repeat(64), now }), /different plan/);
  assert.throws(() => assertPermissionReport({ ...report, generatedAt: "2026-08-01T11:00:00.000Z" }, { planSha256: report.planSha256, now }), /expired/);
});

test("CloudTrail denial supplements simulation and blocks preflight", () => {
  const report = runPermissionPreflight({
    roleArn, plan, planBytes, manifest, generatedAt: now, now, policyPublishedAt: "2026-08-01T11:55:00.000Z", cloudTrailSessionName: "test-session",
    simulate: allowRequiredDenyForbidden,
    cloudTrail: () => ({ status: "unresolved-denial", eventsChecked: 1, unresolvedDenials: [{ eventName: "PassRole" }] }),
  });
  assert.equal(report.status, "invalid");
  assert.equal(report.deniedCount, 1);
  assert.throws(() => assertPermissionReport(report, { planSha256: report.planSha256, now }), /valid permission-preflight report/);
});

test("saved-plan apply wrapper refuses to run without a permission report", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-preflight-"));
  const planPath = path.join(directory, "plan.tfplan");
  fs.writeFileSync(planPath, "saved-plan");
  assert.throws(() => runApply({
    argv: ["--plan", planPath, "--plan-json", path.join(directory, "plan.json"), "--reference-audit", path.join(directory, "audit.json"), "--permission-report", path.join(directory, "permission.json"), "--plan-sha256", "0".repeat(64), "--audit-sha256", "0".repeat(64)],
    env: { MSCQR_STAGE_B_APPLY_ENABLED: "true", MSCQR_STAGE_B_APPLY_CONFIRM: "MSCQR_APPLY_PRODUCTION_GREEN_STAGE_B_ONCE", TF_WORKSPACE: "production" },
    deps: { getCaller: () => `${roleArn}/test-session`, apply: () => { throw new Error("apply must not be reached"); } },
  }), /Permission-preflight report is missing/);
});

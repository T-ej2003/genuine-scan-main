import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { buildStageBDeploymentCapabilityGraph } from "../aws/generate-production-green-stage-b-capability-graph.mjs";
import { STAGE_B } from "../aws/production-green-stage-b-contract.mjs";
import { RELEASE_POLICY_SOURCES, deriveRequiredEvaluations, sourcePolicyEvidence, validateManifest } from "../aws/validate-production-green-stage-b-permissions.mjs";

const read = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
const list = (value) => Array.isArray(value) ? value : [value];
const matches = (pattern, value) => pattern === "*" || pattern === value || (pattern.endsWith("*") && value.startsWith(pattern.slice(0, -1)));
const policies = RELEASE_POLICY_SOURCES.map(({ name, arn, sourcePath }) => ({ name, arn, sourcePath, document: read(sourcePath) }));
const manifest = read("documents/ops/iam/MSCQRProductionGreenStageBPermissionManifest-v1.json");
const reconciliationDocument = fs.readFileSync("documents/ops/iam/PRODUCTION_GREEN_STAGE_B_RELEASE_IAM_RECONCILIATION_2026-08-04.md", "utf8");
const contextMap = (evaluation) => new Map((evaluation.context || []).map(({ key, values }) => [key, values.map(String)]));
const conditionsMatch = (condition = {}, evaluation) => {
  const context = contextMap(evaluation);
  for (const [operator, entries] of Object.entries(condition)) {
    for (const [key, expectedValue] of Object.entries(entries)) {
      const expected = list(expectedValue).map(String);
      const actual = context.get(key);
      if (operator === "StringEquals" && (!actual || actual.length !== 1 || !expected.includes(actual[0]))) return false;
      if (operator === "ArnEquals" && (!actual || actual.length !== 1 || !expected.includes(actual[0]))) return false;
      if (operator === "ArnLike" && (!actual || actual.length !== 1 || !expected.some((pattern) => matches(pattern, actual[0])))) return false;
      if (operator === "StringEqualsIfExists" && actual && (actual.length !== expected.length || !actual.every((value) => expected.includes(value)))) return false;
      if (operator === "ForAllValues:StringEquals" && (!actual || !actual.every((value) => expected.includes(value)))) return false;
      if (operator === "Bool" && (!actual || actual.length !== 1 || actual[0].toLowerCase() !== expected[0].toLowerCase())) return false;
      if (operator === "NumericEquals" && (!actual || actual.length !== expected.length || !actual.every((value) => expected.some((candidate) => Number(candidate) === Number(value))))) return false;
      if (operator === "Null" && String(!actual) !== expected[0]) return false;
      if (!["StringEquals", "ArnEquals", "ArnLike", "StringEqualsIfExists", "ForAllValues:StringEquals", "Bool", "NumericEquals", "Null"].includes(operator)) throw new Error(`Unsupported IAM condition operator: ${operator}.`);
    }
  }
  return true;
};
const allows = (evaluation) => policies.some(({ document }) => document.Statement.some((statement) => {
  return statement.Effect === "Allow" && conditionsMatch(statement.Condition, evaluation)
    && list(statement.Action).includes(evaluation.action)
    && list(statement.Resource).some((resource) => matches(resource, evaluation.resource));
}));

test("release-role ownership is exactly eight managed policies and no inline authority", () => {
  assert.deepEqual(RELEASE_POLICY_SOURCES.map(({ name }) => name), [
    "MSCQRProductionGreenStageARelease",
    "MSCQRProductionGreenStageBBrokerCodeSigningRead",
    "MSCQRProductionGreenStageBProviderRecovery",
    "MSCQRProductionGreenStageBProviderReadOnly",
    "MSCQRProductionGreenStageBReferenceAuditReadOnly",
    "MSCQRProductionGreenStageBFinalApplyWrite",
    "MSCQRProductionGreenStageBTaskDefinitionRegistration",
    "MSCQRProductionGreenStageBWorkspaceState",
  ]);
  assert.equal(new Set(RELEASE_POLICY_SOURCES.map(({ arn }) => arn)).size, 8);
});

test("broker alias update is authorized on the exact broker function resource", () => {
  const functionArn = STAGE_B.brokerFunctionArn;
  const finalWrite = policies.find(({ name }) => name === "MSCQRProductionGreenStageBFinalApplyWrite").document;
  const statements = finalWrite.Statement.filter((statement) => list(statement.Action).includes("lambda:UpdateAlias"));
  const context = manifest.required.find(({ action }) => action === "lambda:UpdateAlias").context;
  assert.deepEqual(statements.map(({ Sid, Resource }) => ({ Sid, Resource })), [{ Sid: "UpdateExactStageBBrokerReviewedAlias", Resource: functionArn }]);
  assert.equal(allows({ action: "lambda:UpdateAlias", resource: functionArn, context }), true);
  assert.equal(allows({ action: "lambda:UpdateAlias", resource: STAGE_B.brokerAliasArn, context }), false);
  assert.equal(allows({ action: "lambda:UpdateAlias", resource: `${functionArn}:other`, context }), false);
  assert.equal(finalWrite.Statement.some((statement) => list(statement.Action).some((action) => ["lambda:CreateAlias", "lambda:DeleteAlias"].includes(action))), false);
  assert.equal(sourcePolicyEvidence().find(({ name }) => name === "MSCQRProductionGreenStageBFinalApplyWrite").sourceSha256, "ccbffee957ba429f12bc6a491634921c3e3d74fdda98b5e8bd79a4afbcad5cc1");
});

test("backend recovery ECR reads are exact and add no ECR write authority", () => {
  const providerRead = policies.find(({ name }) => name === "MSCQRProductionGreenStageBProviderReadOnly").document;
  const statement = providerRead.Statement.find(({ Sid }) => Sid === "ReadExactLegacyBackendRecoveryRepository");
  assert.deepEqual(statement, {
    Sid: "ReadExactLegacyBackendRecoveryRepository",
    Effect: "Allow",
    Action: ["ecr:DescribeImages", "ecr:DescribeRepositories"],
    Resource: "arn:aws:ecr:eu-west-2:368992683803:repository/mscqr-backend",
    Condition: { StringEquals: { "aws:RequestedRegion": "eu-west-2" } },
  });
  assert.equal(policies.some(({ document }) => document.Statement.some(({ Effect, Action }) => Effect === "Allow" && list(Action).some((action) => action.startsWith("ecr:") && !["ecr:DescribeImages", "ecr:DescribeRepositories"].includes(action)))), false);
});

test("production-shaped required and forbidden resources reconcile to the source policy set", () => {
  const plan = read("scripts/tests/fixtures/production-green-stage-b-production-shaped.plan.json");
  validateManifest(manifest);
  const evaluations = deriveRequiredEvaluations(plan, manifest);
  assert.equal(evaluations.required.length, 231);
  assert.equal(evaluations.forbidden.length, 37);
  assert.deepEqual(evaluations.required.filter((evaluation) => !allows(evaluation)).map(({ id }) => id), []);
  assert.deepEqual(evaluations.forbidden.filter(allows).map(({ id }) => id), []);
  const registrations = evaluations.required.filter(({ action }) => action === "ecs:RegisterTaskDefinition");
  assert.equal(registrations.length, 14);
  assert.equal(registrations.filter(allows).length, 14);
  const switchEvaluation = evaluations.required.find(({ manifestId }) => manifestId === "activate-exact-ecs-service");
  assert.equal(switchEvaluation.action, "ecs:UpdateService");
  assert.equal(switchEvaluation.resource, "arn:aws:ecs:eu-west-2:368992683803:service/mscqr-prod-euw2-main/mscqr-backend-servi-euw2");
  assert.equal(allows(switchEvaluation), true);
  assert.deepEqual(switchEvaluation.context.find(({ key }) => key === "ecs:task-definition").values, ["arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:7"]);
  const rollbackEvaluation = evaluations.required.find(({ manifestId }) => manifestId === "rollback-exact-ecs-service");
  assert.equal(allows(rollbackEvaluation), true);
  const recoveryRegistration = evaluations.required.find(({ manifestId }) => manifestId === "backend-health-recovery-register-legacy-task-definition");
  const recoveryUpdate = evaluations.required.find(({ manifestId }) => manifestId === "backend-health-recovery-update-service");
  const recoveryReads = evaluations.required.filter(({ manifestId }) => manifestId.startsWith("backend-health-recovery-describe-"));
  assert.deepEqual(recoveryReads.map(({ action, resource }) => ({ action, resource })), [
    { action: "ecr:DescribeImages", resource: "arn:aws:ecr:eu-west-2:368992683803:repository/mscqr-backend" },
    { action: "ecr:DescribeRepositories", resource: "arn:aws:ecr:eu-west-2:368992683803:repository/mscqr-backend" },
  ]);
  assert(recoveryReads.every(allows));
  for (const repository of ["mscqr-frontend", "mscqr-worker", "unrelated"]) {
    assert(recoveryReads.every((evaluation) => !allows({ ...evaluation, resource: `arn:aws:ecr:eu-west-2:368992683803:repository/${repository}` })));
  }
  assert(recoveryReads.every((evaluation) => !allows({ ...evaluation, resource: evaluation.resource.replace(":368992683803:", ":000000000000:") })));
  assert(recoveryReads.every((evaluation) => !allows({ ...evaluation, resource: evaluation.resource.replace(":eu-west-2:", ":us-east-1:") })));
  assert.equal(recoveryRegistration.resource, "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:*");
  assert.equal(recoveryRegistration.context.find(({ key }) => key === "ecs:task-cpu").values[0], "2048");
  assert.equal(recoveryRegistration.context.find(({ key }) => key === "ecs:task-memory").values[0], "4096");
  assert.equal(allows(recoveryRegistration), true);
  assert.equal(allows({ ...recoveryRegistration, resource: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-frontend:48" }), false);
  assert.equal(allows(replaceContext(recoveryRegistration, "ecs:task-cpu", ["1024"])), false);
  assert.equal(allows(replaceContext(recoveryRegistration, "ecs:task-memory", ["2048"])), false);
  assert.equal(recoveryUpdate.resource, "arn:aws:ecs:eu-west-2:368992683803:service/mscqr-prod-euw2-main/mscqr-backend-servi-euw2");
  assert.equal(allows(recoveryUpdate), true);
  assert.equal(allows({ ...recoveryUpdate, resource: "arn:aws:ecs:eu-west-2:368992683803:service/mscqr-prod-euw2-main/mscqr-frontend-servi-euw2" }), false);
  assert.equal(allows(replaceContext(recoveryUpdate, "ecs:cluster", ["arn:aws:ecs:eu-west-2:368992683803:cluster/unrelated"])), false);
  assert.equal(allows(replaceContext(recoveryUpdate, "ecs:task-definition", ["arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-frontend:48"])), false);
  for (const [manifestId, roleArn] of [
    ["rollback-exact-backend-execution-passrole", "arn:aws:iam::368992683803:role/mscqr-ecs-execution-role"],
    ["rollback-exact-backend-task-passrole", "arn:aws:iam::368992683803:role/mscqr-ecs-task-role"],
  ]) {
    const passRole = evaluations.required.find(({ manifestId: id }) => id === manifestId);
    assert.equal(passRole.action, "iam:PassRole");
    assert.equal(passRole.resource, roleArn);
    assert.equal(allows(passRole), true);
    assert.equal(allows({ ...passRole, context: passRole.context.map((entry) => entry.key === "iam:PassedToService" ? { ...entry, values: ["lambda.amazonaws.com"] } : entry) }), false);
  }
  function replaceContext(evaluation, key, values) { return { ...evaluation, context: evaluation.context.map((entry) => entry.key === key ? { ...entry, values } : entry) }; }
  assert.equal(allows(replaceContext(switchEvaluation, "ecs:task-definition", ["arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:2"])), false);
  for (const revision of [1, 5, 6, 8]) {
    assert.equal(allows(replaceContext(switchEvaluation, "ecs:task-definition", [`arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:${revision}`])), false);
  }
  assert.equal(allows(replaceContext(switchEvaluation, "ecs:cluster", ["arn:aws:ecs:eu-west-2:368992683803:cluster/other"])), false);
  assert.equal(allows(replaceContext(switchEvaluation, "aws:RequestedRegion", ["us-east-1"])), false);
  assert.equal(allows({ ...switchEvaluation, resource: "arn:aws:ecs:eu-west-2:368992683803:service/mscqr-prod-euw2-main/mscqr-unrelated-service" }), false);
  assert.equal(allows({ ...switchEvaluation, resource: "arn:aws:ecs:us-east-1:368992683803:service/mscqr-prod-euw2-main/mscqr-backend-servi-euw2" }), false);
  assert.equal(allows({ ...switchEvaluation, resource: "arn:aws:ecs:eu-west-2:123456789012:service/mscqr-prod-euw2-main/mscqr-backend-servi-euw2" }), false);
  for (const manifestId of ["update-ecs-service", "delete-ecs-service", "create-ecs-service", "deregister-task-definition"]) {
    const forbidden = evaluations.forbidden.find(({ manifestId: id }) => id === manifestId);
    assert.equal(forbidden.decision ?? "implicitDeny", "implicitDeny");
    assert.equal(allows(forbidden), false, manifestId);
  }
  assert.deepEqual(registrations.flatMap(({ context }) => context).filter(({ key }) => key.startsWith("ecs:")).map(({ key }) => key).filter((key, index, keys) => keys.indexOf(key) === index).sort(), ["ecs:cluster", "ecs:compute-compatibility", "ecs:privileged", "ecs:task-cpu", "ecs:task-definition", "ecs:task-memory"]);
});

test("rotation coordinator legacy-current secret access is exact and action-bounded", () => {
  const finalWrite = policies.find(({ name }) => name === "MSCQRProductionGreenStageBFinalApplyWrite").document;
  const legacy = [
    "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/jwt-wBQNqk",
    "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/qr_sign_private_key-BcQFPO",
    "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/qr_sign_public_key-v7Xeex",
  ];
  const context = [{ key: "aws:RequestedRegion", type: "string", values: ["eu-west-2"] }];
  for (const resource of legacy) for (const action of ["secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue"]) assert.equal(allows({ action, resource, context }), true, `${action} ${resource}`);
  assert.equal(allows({ action: "secretsmanager:DescribeSecret", resource: legacy[0], context }), false);
  assert.equal(allows({ action: "secretsmanager:GetSecretValue", resource: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/unrelated", context }), false);
  assert.deepEqual(finalWrite.Statement.find(({ Sid }) => Sid === "ManageExactLegacyCurrentRotationSecrets").Resource, legacy);
});

test("IAM reconciliation documentation matches generated policy evidence", () => {
  const plan = read("scripts/tests/fixtures/production-green-stage-b-production-shaped.plan.json");
  const requiredEvaluations = deriveRequiredEvaluations(plan, manifest).required.length;
  const expectedPolicySha256 = sourcePolicyEvidence().find(({ name }) => name === "MSCQRProductionGreenStageBFinalApplyWrite").sourceSha256;
  const documentedPolicySha256 = reconciliationDocument.match(/canonical FinalApplyWrite SHA-256 changes from[\s\S]*?to\s+`([a-f0-9]{64})`/)?.[1];
  const documentedEvaluations = reconciliationDocument.match(/required evaluations: (\d+)\/(\d+) allowed/);
  assert.equal(documentedPolicySha256, expectedPolicySha256);
  assert.ok(documentedEvaluations);
  assert.equal(Number(documentedEvaluations[1]), requiredEvaluations);
  assert.equal(Number(documentedEvaluations[2]), requiredEvaluations);
});

test("IAM condition evaluation fails closed for missing context and unknown operators", () => {
  assert.equal(conditionsMatch({ StringEquals: { "ecs:privileged": "false" } }, { context: [] }), false);
  assert.equal(conditionsMatch({ StringEqualsIfExists: { optional: "value" } }, { context: [] }), true);
  assert.equal(conditionsMatch({ Bool: { enabled: "false" } }, { context: [{ key: "enabled", values: ["false"] }] }), true);
  assert.equal(conditionsMatch({ Null: { required: "false" } }, { context: [] }), false);
  assert.throws(() => conditionsMatch({ ArnNotLike: { key: "*" } }, { context: [] }), /Unsupported IAM condition operator/);
});

test("generated capability graph binds UpdateAlias to the broker function policy statement", () => {
  const capability = buildStageBDeploymentCapabilityGraph().capabilities.find(({ id }) => id === "manifest-update-reviewed-broker-alias");
  assert.equal(capability.resources[0], STAGE_B.brokerFunctionArn);
  assert.equal(capability.policy.sid, "UpdateExactStageBBrokerReviewedAlias");
});

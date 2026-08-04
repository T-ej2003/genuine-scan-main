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
const allows = (evaluation) => policies.some(({ document }) => document.Statement.some((statement) => {
  const context = new Map((evaluation.context || []).map(({ key, values }) => [key, values]));
  const stringEquals = statement.Condition?.StringEquals || {};
  const compatibleContext = Object.entries(stringEquals).every(([key, expected]) => !context.has(key) || context.get(key).some((value) => list(expected).map(String).includes(String(value))));
  return statement.Effect === "Allow" && compatibleContext
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

test("broker alias update is authorized only on the exact reviewed alias", () => {
  const functionArn = STAGE_B.brokerFunctionArn;
  const exactAlias = STAGE_B.brokerAliasArn;
  const finalWrite = policies.find(({ name }) => name === "MSCQRProductionGreenStageBFinalApplyWrite").document;
  const statements = finalWrite.Statement.filter((statement) => list(statement.Action).includes("lambda:UpdateAlias"));
  assert.deepEqual(statements.map(({ Sid, Resource }) => ({ Sid, Resource })), [{ Sid: "UpdateExactStageBBrokerReviewedAlias", Resource: exactAlias }]);
  assert.equal(allows({ action: "lambda:UpdateAlias", resource: exactAlias }), true);
  assert.equal(allows({ action: "lambda:UpdateAlias", resource: functionArn }), false);
  assert.equal(allows({ action: "lambda:UpdateAlias", resource: `${functionArn}:other` }), false);
  assert.equal(finalWrite.Statement.some((statement) => list(statement.Action).some((action) => ["lambda:CreateAlias", "lambda:DeleteAlias"].includes(action))), false);
  assert.equal(sourcePolicyEvidence().find(({ name }) => name === "MSCQRProductionGreenStageBFinalApplyWrite").sourceSha256, "0038d24898d2a20f806949d3329b8c29fb329e4f7e9b2406fb96ff97c2d2fa9b");
});

test("production-shaped required and forbidden resources reconcile to the source policy set", () => {
  const manifest = read("documents/ops/iam/MSCQRProductionGreenStageBPermissionManifest-v1.json");
  const plan = read("scripts/tests/fixtures/production-green-stage-b-production-shaped.plan.json");
  validateManifest(manifest);
  const evaluations = deriveRequiredEvaluations(plan, manifest);
  assert.equal(evaluations.required.length, 89);
  assert.equal(evaluations.forbidden.length, 21);
  assert.deepEqual(evaluations.required.filter((evaluation) => !allows(evaluation)).map(({ id }) => id), []);
  assert.deepEqual(evaluations.forbidden.filter(allows).map(({ id }) => id), []);
});

test("generated capability graph binds UpdateAlias to the exact alias policy statement", () => {
  const capability = buildStageBDeploymentCapabilityGraph().capabilities.find(({ id }) => id === "manifest-update-reviewed-broker-alias");
  assert.equal(capability.resources[0], STAGE_B.brokerAliasArn);
  assert.equal(capability.policy.sid, "UpdateExactStageBBrokerReviewedAlias");
});

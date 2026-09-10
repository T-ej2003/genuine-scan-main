import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { MIXED_DUAL_SLOT_RECOVERY_EXECUTION_ROLE_ARN, MIXED_DUAL_SLOT_RECOVERY_IAM_ACTION, MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES, assertMixedDualSlotRecoveryIamPreflight } from "../aws/production-mixed-dual-slot-recovery-contract.mjs";
import { readMixedDualSlotRecoveryIamCapabilityPreflight } from "../aws/preflight-production-mixed-dual-slot-recovery-iam.mjs";

const sourceSha = "a".repeat(40);
const observedAt = new Date("2026-09-10T00:00:00.000Z");
const allowed = (resource) => ({ EvalActionName: MIXED_DUAL_SLOT_RECOVERY_IAM_ACTION, EvalResourceName: resource, EvalDecision: "allowed", MatchedStatements: [{}], MissingContextValues: [], OrganizationsDecisionDetail: { AllowedByOrganizations: true } });
const runner = ({ caller = { Account: "368992683803", Arn: "arn:aws:iam::368992683803:root" }, role = { Arn: MIXED_DUAL_SLOT_RECOVERY_EXECUTION_ROLE_ARN }, results = MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES.map(allowed) } = {}) => (args) => {
  const operation = args.slice(0, 2).join(" ");
  if (operation === "sts get-caller-identity") return JSON.stringify(caller);
  if (operation === "iam get-role") return JSON.stringify({ Role: role });
  if (operation === "iam simulate-principal-policy") {
    const resources = args.slice(args.indexOf("--resource-arns") + 1); assert.equal(resources.length, 1);
    return JSON.stringify({ EvaluationResults: results.filter(({ EvalResourceName }) => EvalResourceName === resources[0]) });
  }
  throw new Error(`unexpected ${operation}`);
};

test("canonical release policy grants only seven exact recovery label mutations", () => {
  const policy = JSON.parse(fs.readFileSync("documents/ops/iam/MSCQRProductionInitialActivationLifecycle-v1.json", "utf8"));
  const statement = policy.Statement.find(({ Sid }) => Sid === "RecoverExactMixedDualSlotTopology");
  assert.deepEqual(statement, { Sid: "RecoverExactMixedDualSlotTopology", Effect: "Allow", Action: MIXED_DUAL_SLOT_RECOVERY_IAM_ACTION, Resource: [...MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES] });
  const actions = policy.Statement.flatMap(({ Action }) => Array.isArray(Action) ? Action : [Action]);
  for (const forbidden of ["secretsmanager:PutSecretValue", "secretsmanager:CreateSecret", "secretsmanager:DeleteSecret", "secretsmanager:UpdateSecret"]) assert.equal(actions.includes(forbidden), false);
});

test("effective-capability preflight requires all seven exact allows", () => {
  const preflight = readMixedDualSlotRecoveryIamCapabilityPreflight({ sourceSha, now: observedAt, run: runner() });
  assert.equal(preflight.evaluations.length, 7);
  assert.doesNotThrow(() => assertMixedDualSlotRecoveryIamPreflight(preflight, { sourceSha, now: new Date("2026-09-10T00:05:00.000Z"), requireFresh: true }));
  for (let index = 0; index < 7; index += 1) {
    const denied = MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES.map(allowed); denied[index] = { ...denied[index], EvalDecision: "implicitDeny" };
    assert.throws(() => readMixedDualSlotRecoveryIamCapabilityPreflight({ sourceSha, now: observedAt, run: runner({ results: denied }) }), new RegExp(`resource ${index + 1}`));
  }
});

test("effective-capability preflight rejects identity, scope, deny, boundary and indeterminate drift", () => {
  assert.throws(() => readMixedDualSlotRecoveryIamCapabilityPreflight({ sourceSha, now: observedAt, run: runner({ caller: { Account: "368992683803", Arn: "arn:aws:iam::368992683803:user/operator" } }) }), /administrator identity/);
  assert.throws(() => readMixedDualSlotRecoveryIamCapabilityPreflight({ sourceSha, now: observedAt, run: runner({ role: { Arn: "arn:aws:iam::368992683803:role/wrong" } }) }), /role or permissions boundary/);
  assert.throws(() => readMixedDualSlotRecoveryIamCapabilityPreflight({ sourceSha, now: observedAt, run: runner({ role: { Arn: MIXED_DUAL_SLOT_RECOVERY_EXECUTION_ROLE_ARN, PermissionsBoundary: { PermissionsBoundaryArn: "arn:aws:iam::368992683803:policy/boundary" } } }) }), /permissions boundary/);
  for (const results of [
    MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES.slice(1).map(allowed),
    [allowed(MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES[0]), ...MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES.map(allowed)],
    MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES.map((resource, index) => index ? allowed(resource) : { ...allowed(resource), EvalActionName: "secretsmanager:PutSecretValue" }),
    MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES.map((resource, index) => index ? allowed(resource) : { ...allowed(resource), EvalDecision: "explicitDeny" }),
    MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES.map((resource, index) => index ? allowed(resource) : { ...allowed(resource), MissingContextValues: ["aws:PrincipalTag/Unexpected"] }),
    MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES.map((resource, index) => index ? allowed(resource) : { ...allowed(resource), PermissionsBoundaryDecisionDetail: { AllowedByPermissionsBoundary: false } }),
    MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES.map((resource, index) => index ? allowed(resource) : { ...allowed(resource), OrganizationsDecisionDetail: { AllowedByOrganizations: false } }),
  ]) assert.throws(() => readMixedDualSlotRecoveryIamCapabilityPreflight({ sourceSha, now: observedAt, run: runner({ results }) }), /count|action|resource|capability/);
});

test("preflight canonical identity rejects wildcard, missing, extra and stale substitutions", () => {
  const preflight = readMixedDualSlotRecoveryIamCapabilityPreflight({ sourceSha, now: observedAt, run: runner() });
  for (const changed of [
    { principalArn: "arn:aws:iam::368992683803:role/wrong" },
    { action: "secretsmanager:*" },
    { resources: ["*"] },
    { resources: preflight.resources.slice(0, 6) },
    { resources: [...preflight.resources, "arn:aws:secretsmanager:eu-west-2:368992683803:secret:arbitrary"] },
    { rolePermissionsBoundary: "arn:aws:iam::368992683803:policy/boundary" },
  ]) assert.throws(() => assertMixedDualSlotRecoveryIamPreflight({ ...preflight, ...changed }, { sourceSha }), /identity|hash/);
  assert.throws(() => assertMixedDualSlotRecoveryIamPreflight(preflight, { sourceSha, now: new Date("2026-09-10T01:00:00.000Z"), requireFresh: true }), /stale/);
});

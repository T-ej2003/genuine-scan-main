import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { PRODUCTION_ENVIRONMENT_APPROVAL, createProductionEnvironmentApprovalEvidence } from "../aws/production-github-environment-approval.mjs";
import {
  BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION,
  authenticateBootstrapOperatorLiveState,
  createBootstrapOperatorPolicyAuthorization,
  createBootstrapOperatorPolicyPreparation,
  readBootstrapOperatorDesiredPolicy,
  reconcileBootstrapOperatorPolicy,
} from "../aws/production-bootstrap-operator-policy-reconciliation.mjs";
import { assertEcsExecOperatorTrustDocument } from "../aws/production-ecs-exec-operator-contract.mjs";

const sourceSha = "a".repeat(40);
const now = new Date("2026-09-14T12:00:00.000Z");
const desired = readBootstrapOperatorDesiredPolicy();
const approval = createProductionEnvironmentApprovalEvidence({
  environmentConfig: { id: 7, name: "production", can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: { id: 3, login: "reviewer" } }] }] },
  repository: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.repository, environment: "production", sourceSha,
  workflowRef: PRODUCTION_ENVIRONMENT_APPROVAL.bootstrapOperatorPolicyReconciliationWorkflowRef, eventName: "workflow_dispatch", workflowRunId: "100", workflowRunAttempt: "1", executionActor: "operator", observedAt: now.toISOString(), actualApproval: { state: "approved", environmentId: 7, environmentName: "production", userId: 3, userLogin: "reviewer" },
});
const live = (document) => ({ user: { Arn: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userArn, UserName: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userName, Path: "/" }, attachedPolicies: [], inlinePolicyNames: [BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.inlinePolicyName], groups: [], document });
const authorized = () => {
  const preparation = createBootstrapOperatorPolicyPreparation({ sourceSha, liveState: live(desired.predecessorDocument), preparedAt: now.toISOString() });
  return createBootstrapOperatorPolicyAuthorization({ sourceSha, preparation, protectedEnvironmentApprovalEvidence: approval, authorizedAt: now.toISOString() });
};
const runner = (initial) => {
  let document = structuredClone(initial); let writes = 0;
  const run = (args) => {
    if (args[0] === "sts") return JSON.stringify({ Arn: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.administratorArn });
    if (args[1] === "get-user") return JSON.stringify({ User: live(document).user });
    if (args[1] === "list-attached-user-policies") return JSON.stringify({ AttachedPolicies: [] });
    if (args[1] === "list-user-policies") return JSON.stringify({ PolicyNames: [BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.inlinePolicyName] });
    if (args[1] === "list-groups-for-user") return JSON.stringify({ Groups: [] });
    if (args[1] === "get-user-policy") return JSON.stringify({ PolicyDocument: document });
    if (args[1] === "put-user-policy") { writes += 1; document = structuredClone(desired.document); return ""; }
    throw new Error(`unexpected command: ${args.join(" ")}`);
  };
  return { run, writes: () => writes, document: () => document };
};
const permitsAssumeRole = ({ roleArn, mfa }) => desired.document.Statement.some((statement) => statement.Effect === "Allow" && statement.Action === "sts:AssumeRole" && statement.Resource === roleArn && statement.Condition?.Bool?.["aws:MultiFactorAuthPresent"] === "true" && mfa === true);

test("bootstrap policy adds only MFA-gated verifier assumption while retaining the release path", () => {
  const statements = new Map(desired.document.Statement.map((statement) => [statement.Sid, statement]));
  assert.deepEqual(statements.get("AssumeReleaseRoleOnlyWithMfa"), { Sid: "AssumeReleaseRoleOnlyWithMfa", Effect: "Allow", Action: "sts:AssumeRole", Resource: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.releaseRoleArn, Condition: { Bool: { "aws:MultiFactorAuthPresent": "true" } } });
  assert.deepEqual(statements.get("AssumeEcsExecVerifierRoleOnlyWithMfa"), { Sid: "AssumeEcsExecVerifierRoleOnlyWithMfa", Effect: "Allow", Action: "sts:AssumeRole", Resource: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.verifierRoleArn, Condition: { Bool: { "aws:MultiFactorAuthPresent": "true" } } });
  assert.deepEqual(statements.get("AssumeStageBPublisherBootstrapRoleOnlyWithMfa"), { Sid: "AssumeStageBPublisherBootstrapRoleOnlyWithMfa", Effect: "Allow", Action: "sts:AssumeRole", Resource: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.publisherBootstrapRoleArn, Condition: { Bool: { "aws:MultiFactorAuthPresent": "true" } } });
  assert.equal(desired.document.Statement.some(({ Resource }) => Resource === "*" || (Array.isArray(Resource) && Resource.includes("*"))), false);
  assert.equal(desired.document.Statement.flatMap(({ Action }) => Array.isArray(Action) ? Action : [Action]).every((action) => ["sts:AssumeRole", "iam:GetUser", "iam:ListMFADevices"].includes(action)), true);
  assert.equal(desired.document.Statement.some(({ Action }) => JSON.stringify(Action).includes("ecs:") || JSON.stringify(Action).includes("secretsmanager:")), false);
  assert.equal(permitsAssumeRole({ roleArn: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.releaseRoleArn, mfa: true }), true);
  assert.equal(permitsAssumeRole({ roleArn: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.verifierRoleArn, mfa: true }), true);
  assert.equal(permitsAssumeRole({ roleArn: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.publisherBootstrapRoleArn, mfa: true }), true);
  assert.equal(permitsAssumeRole({ roleArn: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.releaseRoleArn, mfa: false }), false);
  assert.equal(permitsAssumeRole({ roleArn: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.verifierRoleArn, mfa: false }), false);
  assert.equal(permitsAssumeRole({ roleArn: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.publisherBootstrapRoleArn, mfa: false }), false);
  assert.equal(permitsAssumeRole({ roleArn: "arn:aws:iam::368992683803:role/unrelated", mfa: true }), false);
  const trust = JSON.parse(fs.readFileSync("documents/ops/iam/MSCQR_PRODUCTION_ECS_EXEC_OPERATOR_TRUST_POLICY.json", "utf8"));
  assert.doesNotThrow(() => assertEcsExecOperatorTrustDocument(trust));
});

test("RLS operator contract and canonical policy enumerate the same three MFA-gated targets", () => {
  const contract = JSON.parse(fs.readFileSync("documents/security/rls-program/production-full-rls-executor-contract.json", "utf8"));
  const requirement = contract.stageAOperatorPath.bootstrapOperatorRequirements.find((value) => value.startsWith("only sts:AssumeRole"));
  const targets = desired.document.Statement.filter(({ Action }) => Action === "sts:AssumeRole").map(({ Resource }) => Resource).sort();
  assert.deepEqual(targets, [BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.releaseRoleArn, BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.verifierRoleArn, BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.publisherBootstrapRoleArn].sort());
  assert.equal(targets.every((target) => requirement.includes(target)), true);
  assert.equal(requirement.includes("*"), false);
  assert.equal(desired.document.Statement.filter(({ Action }) => Action === "sts:AssumeRole").every((statement) => statement.Condition?.Bool?.["aws:MultiFactorAuthPresent"] === "true"), true);
});

test("governed reconciliation accepts only the exact predecessor and converges with one PutUserPolicy", () => {
  const authorization = authorized(); const fixture = runner(desired.predecessorDocument);
  assert.equal(authenticateBootstrapOperatorLiveState(live(desired.predecessorDocument)).status, "EXACT_PREDECESSOR");
  const result = reconcileBootstrapOperatorPolicy({ run: fixture.run, authorization, sourceSha, now });
  assert.deepEqual(result, { status: "COMPLETE", iamPutUserPolicyCount: 1, recovered: false });
  assert.equal(fixture.writes(), 1);
  assert.equal(authenticateBootstrapOperatorLiveState(live(fixture.document())).status, "EXACT_COMPLETE");
});

test("missing verifier capability, malformed policy topology, and unrelated roles fail closed", () => {
  const extraRole = structuredClone(desired.document);
  extraRole.Statement.find(({ Sid }) => Sid === "AssumeEcsExecVerifierRoleOnlyWithMfa").Resource = "arn:aws:iam::368992683803:role/unrelated";
  assert.throws(() => authenticateBootstrapOperatorLiveState(live(extraRole)), /unexpected drift/);
  assert.throws(() => authenticateBootstrapOperatorLiveState({ ...live(desired.predecessorDocument), attachedPolicies: [{ PolicyArn: "arn:aws:iam::368992683803:policy/unexpected" }] }), /topology/);
  assert.throws(() => createBootstrapOperatorPolicyPreparation({ sourceSha, liveState: live(desired.document), preparedAt: now.toISOString() }), /unexpected drift|predecessor/);
});

test("authorization workflow remains actions-read only and produces a source-bound authorization", () => {
  const workflow = fs.readFileSync(".github/workflows/authorize-production-bootstrap-operator-policy-reconciliation.yml", "utf8");
  assert.match(workflow, /^permissions:\n  actions: read\n  contents: read/m);
  assert.doesNotMatch(workflow, /id-token: write|pull-requests: write|packages: write/);
  const authorization = authorized();
  assert.equal(authorization.sourceSha, sourceSha);
  assert.equal(authorization.preparation.predecessorPolicySha256, desired.predecessorPolicySha256);
  assert.equal(authorization.preparation.successorPolicySha256, desired.sourcePolicySha256);
  assert.deepEqual(authorization.maxAwsMutations, { "iam:PutUserPolicy": 1 });
  assert.deepEqual(authorization.preparation.expectedWritePlan, [{ action: "iam:PutUserPolicy", userArn: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userArn, inlinePolicyName: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.inlinePolicyName, policySha256: desired.sourcePolicySha256 }]);
});

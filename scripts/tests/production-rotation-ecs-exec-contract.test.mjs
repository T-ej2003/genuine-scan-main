import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { assertEcsExecOperatorLiveEvidence, assertEcsExecOperatorTrustDocument, buildEcsExecOperatorEvidence, collectLiveEcsExecOperatorEvidence, ECS_EXEC_OPERATOR_FORBIDDEN, ECS_EXEC_OPERATOR_POLICY_ARN, ECS_EXEC_OPERATOR_REQUIRED, ECS_EXEC_OPERATOR_SOURCE_TRUST_SHA256, normalizeEcsExecOperatorTrustDocument, normalizeMfaRequired } from "../aws/production-ecs-exec-operator-contract.mjs";
import { RELEASE_POLICY_SOURCES } from "../aws/validate-production-green-stage-b-permissions.mjs";
import { assertTaskBelongsToExactPrimaryDeployment } from "../aws/ecs-exec-target-selection.mjs";

const helper = readFileSync("scripts/aws/verify-production-rotation-via-ecs-exec.mjs", "utf8");
const selection = readFileSync("scripts/aws/ecs-exec-target-selection.mjs", "utf8");
const deploy = readFileSync("scripts/aws/deploy-ecs-service.sh", "utf8");
const runbook = readFileSync("documents/SECURITY_KEY_ROTATION_RUNBOOK.md", "utf8");
const pty = readFileSync("scripts/aws/ecs-exec-fixture-pty.py", "utf8");
const policy = JSON.parse(readFileSync("documents/ops/iam/MSCQR_PRODUCTION_ECS_EXEC_OPERATOR_POLICY.json", "utf8"));
const role = JSON.parse(readFileSync("documents/ops/iam/MSCQR_PRODUCTION_ECS_EXEC_OPERATOR_ROLE.json", "utf8"));
const trust = JSON.parse(readFileSync("documents/ops/iam/MSCQR_PRODUCTION_ECS_EXEC_OPERATOR_TRUST_POLICY.json", "utf8"));
const terraform = readFileSync("infra/aws/terraform/production-green-stage-b/main.tf", "utf8");

test("ECS Exec verifier binds the exact service deployment, task definition, digest, and release", () => {
  for (const value of ["describe-services", "describe-clusters", "list-tasks", "describe-tasks", "describe-task-definition", "requireExecuteCommandEnabled", "selectTargetTask", "taskDefinitionArn", "RELEASE_GIT_SHA", "matchingTaskCount", "selectedTaskArn", "targetDeploymentId", "startedBy", "one exact primary service deployment"]) {
    assert.ok(`${helper}\n${selection}`.includes(value), `missing ECS Exec contract: ${value}`);
  }
  assert.match(helper, /--fixture-stdin/);
  assert.doesNotMatch(helper, /--fixture-file.*remoteCommand|remoteCommand.*--fixture-file/s);
  assert.match(helper, /fixture appeared in the ECS Exec transcript/);
  assert.match(pty, /MSCQR_FIXTURE_READY/);
  assert.match(pty, /fixture in output/);
});

test("ECS Exec runtime proof rejects a task from another deployment of the same task definition", () => {
  const taskDefinition = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:51";
  const service = { deployments: [{ id: "ecs-svc/123456789", status: "PRIMARY", taskDefinition }] };
  assert.equal(assertTaskBelongsToExactPrimaryDeployment({ service, task: { startedBy: "ecs-svc/123456789" }, expectedTaskDefinitionArn: taskDefinition }).id, "ecs-svc/123456789");
  assert.throws(() => assertTaskBelongsToExactPrimaryDeployment({ service, task: { startedBy: "ecs-svc/987654321" }, expectedTaskDefinitionArn: taskDefinition }), /exact primary/);
  assert.throws(() => assertTaskBelongsToExactPrimaryDeployment({ service: { deployments: [...service.deployments, { id: "ecs-svc/987654321", status: "PRIMARY", taskDefinition }] }, task: { startedBy: "ecs-svc/123456789" }, expectedTaskDefinitionArn: taskDefinition }), /exact primary/);
});

test("production ECS Exec policy is narrow and has no shell or mutation permissions", () => {
  const actions = policy.Statement.flatMap((statement) => Array.isArray(statement.Action) ? statement.Action : [statement.Action]);
  assert(actions.includes("ecs:ExecuteCommand"));
  assert(actions.includes("ecs:DescribeTaskDefinition"));
  assert(!actions.includes("ecs:UpdateService"));
  assert(!actions.includes("ecs:RunTask"));
  assert(!actions.includes("ssm:StartSession"));
  assert.match(JSON.stringify(policy), /mscqr-prod-euw2-main/);
  assert.match(JSON.stringify(policy), /mscqr-backend-servi-euw2/);
  const execute = policy.Statement.find((entry) => entry.Action === "ecs:ExecuteCommand");
  assert.equal(execute.Resource, "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/*");
  assert.equal(execute.Condition.StringEquals["aws:ResourceTag/MSCQRExecTarget"], "production-backend");
});

test("ListTasks uses Resource * with exact cluster and region conditions", () => {
  const required = ECS_EXEC_OPERATOR_REQUIRED.find(({ action }) => action === "ecs:ListTasks");
  const statement = policy.Statement.find((entry) => entry.Action === "ecs:ListTasks");
  assert.equal(required.resources[0], "*");
  assert.deepEqual(required.context, [
    { key: "aws:RequestedRegion", type: "string", values: ["eu-west-2"] },
    { key: "ecs:cluster", type: "string", values: ["arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main"] },
  ]);
  assert.equal(statement.Resource, "*");
  assert.equal(statement.Condition.StringEquals["ecs:cluster"], "arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main");
  assert.equal(statement.Condition.StringEquals["aws:RequestedRegion"], "eu-west-2");
  assert.notEqual(required.resources[0], "arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main");
});

test("ExecuteCommand evidence binds an immutable task identity marker", () => {
  const required = ECS_EXEC_OPERATOR_REQUIRED.find(({ action }) => action === "ecs:ExecuteCommand");
  assert.equal(required.resources[0], "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/*");
  assert.deepEqual(required.context.find(({ key }) => key === "aws:ResourceTag/MSCQRExecTarget"), { key: "aws:ResourceTag/MSCQRExecTarget", type: "string", values: ["production-backend"] });
  for (const id of ["operator-unrelated-task", "operator-worker-task", "operator-rls-executor-task", "operator-rls-canary-task", "operator-wrong-container", "operator-missing-identity-marker", "operator-run-predeployment-inventory"]) {
    assert.ok(ECS_EXEC_OPERATOR_FORBIDDEN.some((entry) => entry.id === id), `missing negative ${id}`);
  }
});

test("only backend task-definition registration may set the execution marker", () => {
  const registration = JSON.parse(readFileSync("documents/ops/iam/MSCQRProductionGreenStageBTaskDefinitionRegistration-v1.json", "utf8"));
  const backend = registration.Statement.find(({ Sid }) => Sid === "RegisterExactStageBBackendTaskDefinition1024");
  const nonBackend = registration.Statement.find(({ Sid }) => Sid === "RegisterExactStageBTaskDefinitions1024");
  assert.equal(backend.Condition.StringEquals["aws:RequestTag/MSCQRExecTarget"], "production-backend");
  assert(backend.Condition["ForAllValues:StringEquals"]["aws:TagKeys"].includes("MSCQRExecTarget"));
  assert(!nonBackend.Resource.some((resource) => resource.includes("mscqr-production-rls-green-backend-candidate")));
  assert.equal(nonBackend.Condition.StringEquals["aws:RequestTag/MSCQRExecTarget"], undefined);
  assert(!nonBackend.Condition["ForAllValues:StringEquals"]["aws:TagKeys"].includes("MSCQRExecTarget"));
});

test("only the exact backend recovery path may add the execution marker through TagResource", () => {
  const verifierActions = policy.Statement.flatMap(({ Action }) => Array.isArray(Action) ? Action : [Action]);
  assert(!verifierActions.includes("ecs:TagResource"));
  for (const { sourcePath } of RELEASE_POLICY_SOURCES) {
    const source = JSON.parse(readFileSync(sourcePath, "utf8"));
    for (const statement of source.Statement.filter(({ Action }) => (Array.isArray(Action) ? Action : [Action]).includes("ecs:TagResource"))) {
      const marker = statement.Condition?.StringEquals?.["aws:RequestTag/MSCQRExecTarget"];
      const tagKeys = statement.Condition?.["ForAllValues:StringEquals"]?.["aws:TagKeys"] || [];
      if (marker === "production-backend") {
        assert.equal(sourcePath, "documents/ops/iam/MSCQRProductionGreenStageBTaskDefinitionRegistration-v1.json");
        assert.equal(statement.Sid, "TagExactStageBBackendRecoveryTaskDefinition");
        assert.deepEqual(statement.Resource, "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:*");
        assert.deepEqual(tagKeys, ["Component", "Environment", "ManagedBy", "MSCQRExecTarget"]);
      } else {
        assert.equal(marker, undefined);
        assert(!tagKeys.includes("MSCQRExecTarget"), `${sourcePath}/${statement.Sid} can add the execution marker`);
      }
    }
  }
});

test("verifier trust and policy evidence fail closed independently", () => {
  const exactTrust = structuredClone(trust);
  assert.doesNotThrow(() => assertEcsExecOperatorTrustDocument(exactTrust));
  for (const mutate of [
    (value) => delete value.Statement[0].Condition.Bool["aws:MultiFactorAuthPresent"],
    (value) => { value.Statement[0].Condition.Bool.awsMultiFactorAuthPresent = "false"; },
    (value) => { value.Statement[0].Principal.AWS = "arn:aws:iam::368992683803:role/mscqr-production-release-deployer"; },
    (value) => { value.Statement[0].Principal.AWS = "arn:aws:iam::368992683803:root"; },
    (value) => { value.Statement[0].Principal = "*"; },
    (value) => { value.Statement[0].Principal.Extra = "arn:aws:iam::368992683803:user/other"; },
    (value) => value.Statement.push({ ...value.Statement[0] }),
  ]) assert.throws(() => assertEcsExecOperatorTrustDocument((() => { const value = structuredClone(exactTrust); mutate(value); return value; })()));

  const exact = buildEcsExecOperatorEvidence();
  assert.doesNotThrow(() => assertEcsExecOperatorLiveEvidence(exact));
  assert.throws(() => assertEcsExecOperatorLiveEvidence({ ...exact, liveTrustCanonicalSha256: "0".repeat(64) }));
  assert.throws(() => assertEcsExecOperatorLiveEvidence({ ...exact, policy: { ...exact.policy, liveCanonicalSha256: "0".repeat(64) } }));
});

test("live MFA evidence normalizes only exact boolean forms", () => {
  const exact = buildEcsExecOperatorEvidence();
  assert.equal(normalizeMfaRequired("true"), true);
  assert.equal(normalizeMfaRequired(true), true);
  assert.equal(normalizeMfaRequired("false"), false);
  assert.equal(normalizeMfaRequired(false), false);
  for (const value of ["false", false]) assert.throws(() => assertEcsExecOperatorLiveEvidence({ ...exact, mfaRequired: normalizeMfaRequired(value) }), /trust evidence/);
  for (const value of ["TRUE", "1", 1, null, undefined, "yes"]) assert.throws(() => normalizeMfaRequired(value), /exact boolean or string/);
});

test("live trust normalization precedes strict validation and source hashing", () => {
  const booleanTrust = structuredClone(trust);
  booleanTrust.Statement[0].Condition.Bool["aws:MultiFactorAuthPresent"] = true;
  const normalized = normalizeEcsExecOperatorTrustDocument(booleanTrust);
  assert.equal(normalized.Statement[0].Condition.Bool["aws:MultiFactorAuthPresent"], "true");
  assert.doesNotThrow(() => assertEcsExecOperatorTrustDocument(normalized));
  const stringTrust = normalizeEcsExecOperatorTrustDocument(trust);
  assert.deepEqual(normalized, stringTrust);
  for (const value of [false, "false", "TRUE", "1", 1, null, undefined]) {
    const invalid = structuredClone(trust);
    invalid.Statement[0].Condition.Bool["aws:MultiFactorAuthPresent"] = value;
    assert.throws(() => normalizeEcsExecOperatorTrustDocument(invalid));
  }
  const missing = structuredClone(trust);
  delete missing.Statement[0].Condition.Bool["aws:MultiFactorAuthPresent"];
  assert.throws(() => normalizeEcsExecOperatorTrustDocument(missing));
});

test("live-style trust evidence reaches validation with boolean MFA", () => {
  const sourcePolicy = JSON.parse(readFileSync("documents/ops/iam/MSCQR_PRODUCTION_ECS_EXEC_OPERATOR_POLICY.json", "utf8"));
  const sourceTrust = JSON.parse(readFileSync("documents/ops/iam/MSCQR_PRODUCTION_ECS_EXEC_OPERATOR_TRUST_POLICY.json", "utf8"));
  const evidence = collectLiveEcsExecOperatorEvidence({ run: (args) => {
    if (args[1] === "get-role") return JSON.stringify({ Role: { Arn: "arn:aws:iam::368992683803:role/mscqr-production-ecs-exec-verifier", AssumeRolePolicyDocument: { ...sourceTrust, Statement: [{ ...sourceTrust.Statement[0], Condition: { Bool: { "aws:MultiFactorAuthPresent": true } } }] } } });
    if (args[1] === "list-attached-role-policies") return JSON.stringify({ AttachedPolicies: [{ PolicyArn: ECS_EXEC_OPERATOR_POLICY_ARN }] });
    if (args[1] === "list-role-policies") return JSON.stringify({ PolicyNames: [] });
    if (args[1] === "get-policy") return JSON.stringify({ Policy: { Arn: ECS_EXEC_OPERATOR_POLICY_ARN, DefaultVersionId: "v1" } });
    if (args[1] === "get-policy-version") return JSON.stringify({ PolicyVersion: { Document: sourcePolicy } });
    throw new Error(`unexpected IAM probe: ${args.join(" ")}`);
  } });
  assert.equal(evidence.mfaRequired, true);
  assert.equal(evidence.liveTrustCanonicalSha256, ECS_EXEC_OPERATOR_SOURCE_TRUST_SHA256);
  assert.doesNotThrow(() => assertEcsExecOperatorLiveEvidence(evidence));
});

test("ECS Exec verifier has a separate MFA-backed identity and the helper rejects deployer credentials", () => {
  assert.equal(role.roleArn, "arn:aws:iam::368992683803:role/mscqr-production-ecs-exec-verifier");
  assert.deepEqual(role.deploymentPermissions, []);
  assert.equal(trust.Statement[0].Principal.AWS, "arn:aws:iam::368992683803:user/mscqr-production-bootstrap-operator");
  assert.equal(trust.Statement[0].Condition.Bool["aws:MultiFactorAuthPresent"], "true");
  assert.match(helper, /get-caller-identity/);
  assert.match(helper, /ECS_EXEC_OPERATOR_CALLER_PATTERN/);
  assert.match(helper, /deployment identities are not accepted/);
  assert.doesNotMatch(helper, /mscqr-production-release-deployer.*ExecuteCommand/);
});

test("backend task role receives only the four ECS Exec message-channel actions", () => {
  assert.match(terraform, /resource "aws_iam_role_policy" "backend_ecs_exec"/);
  assert.match(terraform, /ssmmessages:CreateControlChannel/);
  assert.match(terraform, /ssmmessages:CreateDataChannel/);
  assert.match(terraform, /ssmmessages:OpenControlChannel/);
  assert.match(terraform, /ssmmessages:OpenDataChannel/);
  assert.match(terraform, /role\s*=\s*aws_iam_role\.task\["backend"\]\.id/);
});

test("canonical deployment enables and verifies ECS Exec in one service update", () => {
  assert.match(deploy, /ENABLE_EXECUTE_COMMAND=.*false/);
  assert.match(deploy, /--enable-execute-command/);
  assert.match(deploy, /Post-switch service does not have ECS Exec enabled/);
  assert.match(runbook, /ENABLE_EXECUTE_COMMAND=true/);
});

test("governed rotation propagates the reviewed task identity tag", () => {
  assert.match(deploy, /PROPAGATE_TAGS.*TASK_DEFINITION/);
  assert.match(deploy, /--propagate-tags/);
  assert.match(deploy, /CURRENT_PROPAGATE_TAGS.*TASK_DEFINITION/);
  assert.match(deploy, /CURRENT_PROPAGATE_TAGS.*TASK_DEFINITION.*\|\|/s);
  assert.match(readFileSync(".github/workflows/release-gate.yml", "utf8"), /PROPAGATE_TAGS: "TASK_DEFINITION"/);
  assert.match(terraform, /MSCQRExecTarget/);
});

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const ACCOUNT = "368992683803";
export const REGION = "eu-west-2";
export const ECS_EXEC_OPERATOR_ROLE_NAME = "mscqr-production-ecs-exec-verifier";
export const ECS_EXEC_OPERATOR_ROLE_ARN = `arn:aws:iam::${ACCOUNT}:role/${ECS_EXEC_OPERATOR_ROLE_NAME}`;
export const ECS_EXEC_OPERATOR_CALLER_PATTERN = `^arn:aws:sts::${ACCOUNT}:assumed-role/${ECS_EXEC_OPERATOR_ROLE_NAME}/[^/]+$`;
export const ECS_EXEC_OPERATOR_POLICY_PATH = "documents/ops/iam/MSCQR_PRODUCTION_ECS_EXEC_OPERATOR_POLICY.json";
export const ECS_EXEC_OPERATOR_TRUST_POLICY_PATH = "documents/ops/iam/MSCQR_PRODUCTION_ECS_EXEC_OPERATOR_TRUST_POLICY.json";
export const ECS_EXEC_OPERATOR_ROLE_CONTRACT_PATH = "documents/ops/iam/MSCQR_PRODUCTION_ECS_EXEC_OPERATOR_ROLE.json";
export const ECS_EXEC_OPERATOR_MANIFEST_KEY = "ecsExecVerifier";

const clusterArn = `arn:aws:ecs:${REGION}:${ACCOUNT}:cluster/mscqr-prod-euw2-main`;
const taskArn = `arn:aws:ecs:${REGION}:${ACCOUNT}:task/mscqr-prod-euw2-main/*`;
const serviceArn = `arn:aws:ecs:${REGION}:${ACCOUNT}:service/mscqr-prod-euw2-main/mscqr-backend-servi-euw2`;
const context = (values) => Object.freeze(values.map(({ key, type = "string", values: entries }) => Object.freeze({ key, type, values: Object.freeze([...entries]) })));
const regionContext = context([{ key: "aws:RequestedRegion", values: [REGION] }]);
const taskContext = context([
  { key: "aws:RequestedRegion", values: [REGION] },
  { key: "ecs:cluster", values: [clusterArn] },
]);
const executeContext = context([
  { key: "aws:RequestedRegion", values: [REGION] },
  { key: "ecs:cluster", values: [clusterArn] },
  { key: "ecs:container-name", values: ["backend"] },
]);
const forbidden = (id, action, resource, evaluationContext = []) => ({ id, action, resources: [resource], context: evaluationContext, expectedDecision: "implicitDeny", expectedMissingContextValues: [] });

export const ECS_EXEC_OPERATOR_REQUIRED = Object.freeze([
  { id: "operator-execute-production-backend", action: "ecs:ExecuteCommand", resources: [taskArn], context: executeContext },
  { id: "operator-list-production-backend-tasks", action: "ecs:ListTasks", resources: [clusterArn], context: regionContext },
  { id: "operator-describe-production-cluster", action: "ecs:DescribeClusters", resources: [clusterArn], context: regionContext },
  { id: "operator-describe-production-backend-tasks", action: "ecs:DescribeTasks", resources: [taskArn], context: regionContext },
  { id: "operator-describe-production-backend-service", action: "ecs:DescribeServices", resources: [serviceArn], context: regionContext },
  { id: "operator-describe-production-task-definition", action: "ecs:DescribeTaskDefinition", resources: ["*"], context: regionContext },
]);

export const ECS_EXEC_OPERATOR_FORBIDDEN = Object.freeze([
  forbidden("operator-unrelated-task", "ecs:ExecuteCommand", `arn:aws:ecs:${REGION}:${ACCOUNT}:task/mscqr-prod-euw2-main/unrelated`, executeContext),
  forbidden("operator-unrelated-cluster", "ecs:ExecuteCommand", `arn:aws:ecs:${REGION}:${ACCOUNT}:task/unrelated-cluster/unrelated`, context([
    { key: "aws:RequestedRegion", values: [REGION] },
    { key: "ecs:cluster", values: [`arn:aws:ecs:${REGION}:${ACCOUNT}:cluster/unrelated`] },
    { key: "ecs:container-name", values: ["backend"] },
  ])),
  forbidden("operator-wrong-region", "ecs:ExecuteCommand", taskArn, context([
    { key: "aws:RequestedRegion", values: ["us-east-1"] },
    { key: "ecs:cluster", values: [clusterArn] },
    { key: "ecs:container-name", values: ["backend"] },
  ])),
  forbidden("operator-unrelated-account", "ecs:ExecuteCommand", "arn:aws:ecs:eu-west-2:000000000000:task/mscqr-prod-euw2-main/unrelated", executeContext),
  forbidden("operator-update-service", "ecs:UpdateService", serviceArn, taskContext),
  forbidden("operator-register-task-definition", "ecs:RegisterTaskDefinition", "*", regionContext),
  forbidden("operator-pass-role", "iam:PassRole", "*", context([{ key: "iam:PassedToService", values: ["ecs-tasks.amazonaws.com"] }])),
  forbidden("operator-start-session", "ssm:StartSession", "*", regionContext),
  forbidden("operator-read-secret", "secretsmanager:GetSecretValue", "*", regionContext),
]);

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const readJson = (relativePath) => JSON.parse(fs.readFileSync(path.join(root, relativePath), "utf8"));

export function assertEcsExecOperatorSourceContract(manifest) {
  const contract = manifest?.principalContracts?.[ECS_EXEC_OPERATOR_MANIFEST_KEY];
  if (!contract || contract.roleArn !== ECS_EXEC_OPERATOR_ROLE_ARN || contract.policyPath !== ECS_EXEC_OPERATOR_POLICY_PATH || contract.trustPolicyPath !== ECS_EXEC_OPERATOR_TRUST_POLICY_PATH) {
    throw new Error("ECS Exec operator principal contract is missing or does not bind the reviewed role and policy sources.");
  }
  if (contract.evaluationSource !== "scripts/aws/production-ecs-exec-operator-contract.mjs") throw new Error("ECS Exec operator evaluation source is not canonical.");
  const policy = readJson(ECS_EXEC_OPERATOR_POLICY_PATH);
  const actions = policy.Statement.flatMap((statement) => Array.isArray(statement.Action) ? statement.Action : [statement.Action]);
  const expectedActions = ["ecs:ExecuteCommand", "ecs:ListTasks", "ecs:DescribeClusters", "ecs:DescribeTasks", "ecs:DescribeServices", "ecs:DescribeTaskDefinition"];
  if (JSON.stringify([...new Set(actions)].sort()) !== JSON.stringify(expectedActions.sort())) throw new Error("ECS Exec operator policy action set is broader or narrower than reviewed.");
  const forbiddenActions = ["ecs:UpdateService", "ecs:RegisterTaskDefinition", "iam:PassRole", "ssm:StartSession", "secretsmanager:GetSecretValue"];
  if (!actions.includes("ecs:ExecuteCommand") || forbiddenActions.some((action) => actions.includes(action))) throw new Error("ECS Exec operator policy is not least privilege.");
  if (actions.includes("ecs:RunTask") || actions.includes("ecs:StopTask") || actions.includes("iam:CreateRole")) throw new Error("ECS Exec operator policy contains unrelated mutation permissions.");
  const trust = readJson(ECS_EXEC_OPERATOR_TRUST_POLICY_PATH);
  if (trust.Statement?.length !== 1 || trust.Statement[0].Action !== "sts:AssumeRole" || trust.Statement[0].Principal?.AWS !== `arn:aws:iam::${ACCOUNT}:user/mscqr-production-bootstrap-operator` || trust.Statement[0].Condition?.Bool?.["aws:MultiFactorAuthPresent"] !== "true") {
    throw new Error("ECS Exec operator trust policy is not the reviewed MFA-backed bootstrap boundary.");
  }
  return true;
}

export function assertEcsExecOperatorEvidence(report) {
  const entry = report?.principalEvaluations?.ecsExecVerifier;
  if (!entry || entry.principalArn !== ECS_EXEC_OPERATOR_ROLE_ARN || entry.status !== "valid") throw new Error("ECS Exec operator simulation evidence is missing or invalid.");
  const required = new Map((entry.requiredEvaluations || []).map((item) => [item.manifestId, item]));
  const execute = required.get("operator-execute-production-backend");
  if (!execute || execute.action !== "ecs:ExecuteCommand" || execute.decision !== "allowed") throw new Error("ECS Exec operator ExecuteCommand evidence is missing.");
  return true;
}

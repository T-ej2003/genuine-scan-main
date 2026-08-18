import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { normalizeIamPolicyDocument } from "./iam-policy-document.mjs";

export const ACCOUNT = "368992683803";
export const REGION = "eu-west-2";
export const ECS_EXEC_OPERATOR_ROLE_NAME = "mscqr-production-ecs-exec-verifier";
export const ECS_EXEC_OPERATOR_ROLE_ARN = `arn:aws:iam::${ACCOUNT}:role/${ECS_EXEC_OPERATOR_ROLE_NAME}`;
export const ECS_EXEC_OPERATOR_POLICY_ARN = `arn:aws:iam::${ACCOUNT}:policy/${ECS_EXEC_OPERATOR_ROLE_NAME}`;
export const ECS_EXEC_OPERATOR_CALLER_PATTERN = `^arn:aws:sts::${ACCOUNT}:assumed-role/${ECS_EXEC_OPERATOR_ROLE_NAME}/[^/]+$`;
export const ECS_EXEC_OPERATOR_POLICY_PATH = "documents/ops/iam/MSCQR_PRODUCTION_ECS_EXEC_OPERATOR_POLICY.json";
export const ECS_EXEC_OPERATOR_TRUST_POLICY_PATH = "documents/ops/iam/MSCQR_PRODUCTION_ECS_EXEC_OPERATOR_TRUST_POLICY.json";
export const ECS_EXEC_OPERATOR_ROLE_CONTRACT_PATH = "documents/ops/iam/MSCQR_PRODUCTION_ECS_EXEC_OPERATOR_ROLE.json";
export const ECS_EXEC_OPERATOR_MANIFEST_KEY = "ecsExecVerifier";
export const ECS_EXEC_OPERATOR_TASK_TAG_KEY = "MSCQRExecTarget";
export const ECS_EXEC_OPERATOR_TASK_TAG_VALUE = "production-backend";

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
  { key: `aws:ResourceTag/${ECS_EXEC_OPERATOR_TASK_TAG_KEY}`, values: [ECS_EXEC_OPERATOR_TASK_TAG_VALUE] },
]);
const forbidden = (id, action, resource, evaluationContext = [], expectedMissingContextValues = []) => ({ id, action, resources: [resource], context: evaluationContext, expectedDecision: "implicitDeny", expectedMissingContextValues });

export const ECS_EXEC_OPERATOR_REQUIRED = Object.freeze([
  { id: "operator-execute-production-backend", action: "ecs:ExecuteCommand", resources: [taskArn], context: executeContext },
  { id: "operator-list-production-backend-tasks", action: "ecs:ListTasks", resources: ["*"], context: taskContext },
  { id: "operator-describe-production-cluster", action: "ecs:DescribeClusters", resources: [clusterArn], context: regionContext },
  { id: "operator-describe-production-backend-tasks", action: "ecs:DescribeTasks", resources: [taskArn], context: regionContext },
  { id: "operator-describe-production-backend-service", action: "ecs:DescribeServices", resources: [serviceArn], context: regionContext },
  { id: "operator-describe-production-task-definition", action: "ecs:DescribeTaskDefinition", resources: ["*"], context: regionContext },
]);

export const ECS_EXEC_OPERATOR_FORBIDDEN = Object.freeze([
  forbidden("operator-unrelated-task", "ecs:ExecuteCommand", `arn:aws:ecs:${REGION}:${ACCOUNT}:task/mscqr-prod-euw2-main/unrelated`, context([
    { key: "aws:RequestedRegion", values: [REGION] },
    { key: "ecs:cluster", values: [clusterArn] },
    { key: "ecs:container-name", values: ["backend"] },
    { key: `aws:ResourceTag/${ECS_EXEC_OPERATOR_TASK_TAG_KEY}`, values: ["unapproved"] },
  ])),
  forbidden("operator-unrelated-cluster", "ecs:ExecuteCommand", `arn:aws:ecs:${REGION}:${ACCOUNT}:task/unrelated-cluster/unrelated`, context([
    { key: "aws:RequestedRegion", values: [REGION] },
    { key: "ecs:cluster", values: [`arn:aws:ecs:${REGION}:${ACCOUNT}:cluster/unrelated`] },
    { key: "ecs:container-name", values: ["backend"] },
    { key: `aws:ResourceTag/${ECS_EXEC_OPERATOR_TASK_TAG_KEY}`, values: [ECS_EXEC_OPERATOR_TASK_TAG_VALUE] },
  ])),
  forbidden("operator-wrong-region", "ecs:ExecuteCommand", taskArn, context([
    { key: "aws:RequestedRegion", values: ["us-east-1"] },
    { key: "ecs:cluster", values: [clusterArn] },
    { key: "ecs:container-name", values: ["backend"] },
    { key: `aws:ResourceTag/${ECS_EXEC_OPERATOR_TASK_TAG_KEY}`, values: [ECS_EXEC_OPERATOR_TASK_TAG_VALUE] },
  ])),
  forbidden("operator-unrelated-account", "ecs:ExecuteCommand", "arn:aws:ecs:eu-west-2:000000000000:task/mscqr-prod-euw2-main/unrelated", executeContext),
  forbidden("operator-worker-task", "ecs:ExecuteCommand", `arn:aws:ecs:${REGION}:${ACCOUNT}:task/mscqr-prod-euw2-main/worker`, context([
    { key: "aws:RequestedRegion", values: [REGION] }, { key: "ecs:cluster", values: [clusterArn] }, { key: "ecs:container-name", values: ["worker"] }, { key: `aws:ResourceTag/${ECS_EXEC_OPERATOR_TASK_TAG_KEY}`, values: ["worker"] },
  ])),
  forbidden("operator-rls-executor-task", "ecs:ExecuteCommand", `arn:aws:ecs:${REGION}:${ACCOUNT}:task/mscqr-prod-euw2-main/rls-executor`, context([
    { key: "aws:RequestedRegion", values: [REGION] }, { key: "ecs:cluster", values: [clusterArn] }, { key: "ecs:container-name", values: ["executor"] }, { key: `aws:ResourceTag/${ECS_EXEC_OPERATOR_TASK_TAG_KEY}`, values: ["rls-executor"] },
  ])),
  forbidden("operator-rls-canary-task", "ecs:ExecuteCommand", `arn:aws:ecs:${REGION}:${ACCOUNT}:task/mscqr-prod-euw2-main/rls-canary`, context([
    { key: "aws:RequestedRegion", values: [REGION] }, { key: "ecs:cluster", values: [clusterArn] }, { key: "ecs:container-name", values: ["canary"] }, { key: `aws:ResourceTag/${ECS_EXEC_OPERATOR_TASK_TAG_KEY}`, values: ["rls-canary"] },
  ])),
  forbidden("operator-wrong-container", "ecs:ExecuteCommand", taskArn, context([
    { key: "aws:RequestedRegion", values: [REGION] }, { key: "ecs:cluster", values: [clusterArn] }, { key: "ecs:container-name", values: ["worker"] }, { key: `aws:ResourceTag/${ECS_EXEC_OPERATOR_TASK_TAG_KEY}`, values: [ECS_EXEC_OPERATOR_TASK_TAG_VALUE] },
  ])),
  forbidden("operator-missing-identity-marker", "ecs:ExecuteCommand", taskArn, context([
    { key: "aws:RequestedRegion", values: [REGION] }, { key: "ecs:cluster", values: [clusterArn] }, { key: "ecs:container-name", values: ["backend"] },
  ]), [`aws:ResourceTag/${ECS_EXEC_OPERATOR_TASK_TAG_KEY}`]),
  forbidden("operator-list-unrelated-cluster", "ecs:ListTasks", "*", context([
    { key: "aws:RequestedRegion", values: [REGION] },
    { key: "ecs:cluster", values: [`arn:aws:ecs:${REGION}:${ACCOUNT}:cluster/unrelated`] },
  ])),
  forbidden("operator-list-wrong-region", "ecs:ListTasks", "*", context([
    { key: "aws:RequestedRegion", values: ["us-east-1"] },
    { key: "ecs:cluster", values: [clusterArn] },
  ])),
  forbidden("operator-run-predeployment-inventory", "ecs:RunTask", `arn:aws:ecs:${REGION}:${ACCOUNT}:task-definition/mscqr-production-rls-green-predeployment-inventory:*`, taskContext),
  forbidden("operator-update-service", "ecs:UpdateService", serviceArn, taskContext),
  forbidden("operator-register-task-definition", "ecs:RegisterTaskDefinition", "*", regionContext),
  forbidden("operator-pass-role", "iam:PassRole", "*", context([{ key: "iam:PassedToService", values: ["ecs-tasks.amazonaws.com"] }])),
  forbidden("operator-start-session", "ssm:StartSession", "*", regionContext),
  forbidden("operator-read-secret", "secretsmanager:GetSecretValue", "*", regionContext),
]);

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const readJson = (relativePath) => JSON.parse(fs.readFileSync(path.join(root, relativePath), "utf8"));
const canonicalize = (value) => {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
};
const sha256 = (value) => crypto.createHash("sha256").update(Buffer.from(canonicalize(value))).digest("hex");
const decodeDocument = (value) => normalizeIamPolicyDocument(value, "ECS Exec IAM policy document");
const sourcePolicy = () => readJson(ECS_EXEC_OPERATOR_POLICY_PATH);
const sourceTrust = () => readJson(ECS_EXEC_OPERATOR_TRUST_POLICY_PATH);
export const ECS_EXEC_OPERATOR_SOURCE_POLICY_SHA256 = sha256(sourcePolicy());
export const ECS_EXEC_OPERATOR_SOURCE_TRUST_SHA256 = sha256(sourceTrust());

export function normalizeMfaRequired(value) {
  if (value === true || value === "true") return true;
  if (value === false || value === "false") return false;
  throw new Error("ECS Exec verifier MFA evidence must be the exact boolean or string true/false value.");
}

export function normalizeEcsExecOperatorTrustDocument(rawTrust) {
  if (!rawTrust || typeof rawTrust !== "object" || Array.isArray(rawTrust)) throw new Error("ECS Exec verifier trust evidence must be an object.");
  const trust = structuredClone(rawTrust);
  const mfa = trust.Statement?.[0]?.Condition?.Bool?.["aws:MultiFactorAuthPresent"];
  if (normalizeMfaRequired(mfa) !== true) throw new Error("ECS Exec verifier trust policy must require MFA.");
  trust.Statement[0].Condition.Bool["aws:MultiFactorAuthPresent"] = "true";
  return trust;
}

export function assertEcsExecOperatorTrustDocument(trust) {
  if (trust?.Version !== "2012-10-17" || !Array.isArray(trust.Statement) || trust.Statement.length !== 1) throw new Error("ECS Exec verifier trust policy must contain exactly one reviewed statement.");
  const statement = trust.Statement[0];
  if (statement.Effect !== "Allow" || statement.Action !== "sts:AssumeRole" || statement.Principal?.AWS !== `arn:aws:iam::${ACCOUNT}:user/mscqr-production-bootstrap-operator` || statement.Condition?.Bool?.["aws:MultiFactorAuthPresent"] !== "true") throw new Error("ECS Exec verifier trust policy is not the exact MFA-backed bootstrap trust boundary.");
  if (Object.keys(statement.Principal || {}).length !== 1 || Object.keys(statement.Condition || {}).length !== 1 || Object.keys(statement.Condition.Bool || {}).length !== 1) throw new Error("ECS Exec verifier trust policy contains extra principals or conditions.");
  return true;
}

export function assertEcsExecOperatorLiveEvidence(evidence) {
  const policy = evidence?.policy;
  if (!evidence || evidence.roleArn !== ECS_EXEC_OPERATOR_ROLE_ARN || evidence.sourceTrustCanonicalSha256 !== ECS_EXEC_OPERATOR_SOURCE_TRUST_SHA256 || evidence.liveTrustCanonicalSha256 !== ECS_EXEC_OPERATOR_SOURCE_TRUST_SHA256 || evidence.converged !== true || evidence.trustedPrincipal !== `arn:aws:iam::${ACCOUNT}:user/mscqr-production-bootstrap-operator` || evidence.mfaRequired !== true) throw new Error("ECS Exec verifier trust evidence is missing or does not converge with the reviewed source.");
  if (!policy || policy.policyArn !== ECS_EXEC_OPERATOR_POLICY_ARN || policy.sourceCanonicalSha256 !== ECS_EXEC_OPERATOR_SOURCE_POLICY_SHA256 || policy.liveCanonicalSha256 !== ECS_EXEC_OPERATOR_SOURCE_POLICY_SHA256 || policy.converged !== true || policy.attached !== true || policy.inline !== false) throw new Error("ECS Exec verifier policy evidence is missing or does not converge with the reviewed source.");
  return true;
}

export function buildEcsExecOperatorEvidence() {
  return {
    roleArn: ECS_EXEC_OPERATOR_ROLE_ARN,
    sourceTrustCanonicalSha256: ECS_EXEC_OPERATOR_SOURCE_TRUST_SHA256,
    liveTrustCanonicalSha256: ECS_EXEC_OPERATOR_SOURCE_TRUST_SHA256,
    converged: true,
    trustedPrincipal: `arn:aws:iam::${ACCOUNT}:user/mscqr-production-bootstrap-operator`,
    mfaRequired: true,
    policy: { policyArn: ECS_EXEC_OPERATOR_POLICY_ARN, sourceCanonicalSha256: ECS_EXEC_OPERATOR_SOURCE_POLICY_SHA256, liveCanonicalSha256: ECS_EXEC_OPERATOR_SOURCE_POLICY_SHA256, converged: true, attached: true, inline: false },
    status: "valid",
  };
}

export function collectLiveEcsExecOperatorEvidence({ run = (args) => execFileSync("aws", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) } = {}) {
  const roleName = ECS_EXEC_OPERATOR_ROLE_NAME;
  const role = JSON.parse(run(["iam", "get-role", "--role-name", roleName, "--output", "json", "--no-cli-pager"])).Role;
  const attached = JSON.parse(run(["iam", "list-attached-role-policies", "--role-name", roleName, "--output", "json", "--no-cli-pager"])).AttachedPolicies || [];
  const inlineNames = JSON.parse(run(["iam", "list-role-policies", "--role-name", roleName, "--output", "json", "--no-cli-pager"])).PolicyNames || [];
  if (inlineNames.length !== 0 || attached.length !== 1 || attached[0]?.PolicyArn !== ECS_EXEC_OPERATOR_POLICY_ARN) throw new Error("ECS Exec verifier live policy attachment set is not the reviewed exact set.");
  const metadata = JSON.parse(run(["iam", "get-policy", "--policy-arn", ECS_EXEC_OPERATOR_POLICY_ARN, "--output", "json", "--no-cli-pager"])).Policy;
  const version = JSON.parse(run(["iam", "get-policy-version", "--policy-arn", ECS_EXEC_OPERATOR_POLICY_ARN, "--version-id", metadata?.DefaultVersionId, "--output", "json", "--no-cli-pager"])).PolicyVersion;
  const trust = normalizeEcsExecOperatorTrustDocument(decodeDocument(role?.AssumeRolePolicyDocument));
  assertEcsExecOperatorTrustDocument(trust);
  const liveTrustCanonicalSha256 = sha256(trust);
  const liveCanonicalSha256 = sha256(decodeDocument(version?.Document));
  const evidence = { roleArn: role?.Arn, sourceTrustCanonicalSha256: ECS_EXEC_OPERATOR_SOURCE_TRUST_SHA256, liveTrustCanonicalSha256, converged: liveTrustCanonicalSha256 === ECS_EXEC_OPERATOR_SOURCE_TRUST_SHA256, trustedPrincipal: trust.Statement[0].Principal.AWS, mfaRequired: normalizeMfaRequired(trust.Statement[0].Condition.Bool["aws:MultiFactorAuthPresent"]), policy: { policyArn: metadata?.Arn, defaultVersionId: metadata?.DefaultVersionId, sourceCanonicalSha256: ECS_EXEC_OPERATOR_SOURCE_POLICY_SHA256, liveCanonicalSha256, converged: liveCanonicalSha256 === ECS_EXEC_OPERATOR_SOURCE_POLICY_SHA256, attached: true, inline: false } };
  assertEcsExecOperatorLiveEvidence(evidence);
  return { ...evidence, status: "valid" };
}

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
  const listTasks = policy.Statement.find((statement) => (Array.isArray(statement.Action) ? statement.Action : [statement.Action]).includes("ecs:ListTasks"));
  if (listTasks?.Resource !== "*" || listTasks.Condition?.StringEquals?.["aws:RequestedRegion"] !== REGION || listTasks.Condition?.StringEquals?.["ecs:cluster"] !== clusterArn) throw new Error("ECS Exec verifier ListTasks policy must use Resource * with exact region and cluster conditions.");
  const execute = policy.Statement.find((statement) => (Array.isArray(statement.Action) ? statement.Action : [statement.Action]).includes("ecs:ExecuteCommand"));
  if (execute?.Resource !== taskArn || execute.Condition?.StringEquals?.["aws:RequestedRegion"] !== REGION || execute.Condition?.StringEquals?.["ecs:cluster"] !== clusterArn || execute.Condition?.StringEquals?.["ecs:container-name"] !== "backend" || execute.Condition?.StringEquals?.[`aws:ResourceTag/${ECS_EXEC_OPERATOR_TASK_TAG_KEY}`] !== ECS_EXEC_OPERATOR_TASK_TAG_VALUE) throw new Error("ECS Exec verifier ExecuteCommand policy must bind the exact reviewed backend task tag, cluster, region, and container.");
  const role = readJson(ECS_EXEC_OPERATOR_ROLE_CONTRACT_PATH);
  if (role.roleArn !== ECS_EXEC_OPERATOR_ROLE_ARN || role.managedPolicyArn !== ECS_EXEC_OPERATOR_POLICY_ARN || JSON.stringify(role.deploymentPermissions || []) !== "[]") throw new Error("ECS Exec verifier role contract is not bound to the exact reviewed policy and zero deployment permissions.");
  const trust = readJson(ECS_EXEC_OPERATOR_TRUST_POLICY_PATH);
  assertEcsExecOperatorTrustDocument(trust);
  return true;
}

export function assertEcsExecOperatorEvidence(report) {
  const entry = report?.principalEvaluations?.ecsExecVerifier;
  if (!entry || entry.principalArn !== ECS_EXEC_OPERATOR_ROLE_ARN || entry.status !== "valid") throw new Error("ECS Exec operator simulation evidence is missing or invalid.");
  assertEcsExecOperatorLiveEvidence(report.ecsExecVerifierTrust);
  const required = new Map((entry.requiredEvaluations || []).map((item) => [item.manifestId, item]));
  const execute = required.get("operator-execute-production-backend");
  if (!execute || execute.action !== "ecs:ExecuteCommand" || execute.resource !== taskArn || execute.decision !== "allowed" || !execute.context?.some(({ key, values }) => key === `aws:ResourceTag/${ECS_EXEC_OPERATOR_TASK_TAG_KEY}` && JSON.stringify(values) === JSON.stringify([ECS_EXEC_OPERATOR_TASK_TAG_VALUE]))) throw new Error("ECS Exec operator ExecuteCommand evidence is missing or does not bind the approved backend identity marker.");
  const listTasks = required.get("operator-list-production-backend-tasks");
  if (!listTasks || listTasks.action !== "ecs:ListTasks" || listTasks.resource !== "*" || listTasks.decision !== "allowed") throw new Error("ECS Exec operator ListTasks evidence is missing or uses the wrong IAM resource shape.");
  for (const id of ["operator-unrelated-task", "operator-unrelated-cluster", "operator-wrong-region", "operator-worker-task", "operator-rls-executor-task", "operator-rls-canary-task", "operator-wrong-container", "operator-missing-identity-marker", "operator-list-unrelated-cluster", "operator-list-wrong-region"]) {
    const denied = (entry.forbiddenEvaluations || []).find((item) => item.manifestId === id);
    const expected = ECS_EXEC_OPERATOR_FORBIDDEN.find((item) => item.id === id);
    if (!denied || denied.resource !== expected?.resources?.[0] || !["implicitDeny", "explicitDeny"].includes(denied.decision)) throw new Error(`ECS Exec operator negative evidence is missing: ${id}.`);
  }
  return true;
}

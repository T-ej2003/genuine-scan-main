#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);
const policyRelPath = "documents/ops/iam/MSCQR_STAGING_ECS_EXEC_OPERATOR_POLICY_2026-07-02.json";
const policyPath = path.join(repoRoot, policyRelPath);
const applyPolicyRelPath = "documents/ops/iam/MSCQR_STAGING_TERRAFORM_APPLY_OPERATOR_POLICY_2026-07-08.json";
const applyPolicyPath = path.join(repoRoot, applyPolicyRelPath);
const applyBoundaryRelPath = "documents/ops/iam/MSCQR_STAGING_TERRAFORM_APPLY_PERMISSIONS_BOUNDARY_2026-07-08.json";
const applyBoundaryPath = path.join(repoRoot, applyBoundaryRelPath);

const allowedWildcardResourceActions = new Set([]);
const allowedActions = new Set([
  "ecs:DescribeClusters",
  "ecs:DescribeServices",
  "ecs:DescribeTasks",
  "ecs:ExecuteCommand",
  "ecs:ListTasks",
  "kms:GenerateDataKey",
  "logs:DescribeLogStreams",
  "logs:FilterLogEvents",
  "logs:GetLogEvents",
]);
const forbiddenProductionFragments = [
  "prod",
  "production",
  "mscqr-prod",
  "mscqr-prod-db-proxy",
];
const forbiddenActions = new Set([
  "secretsmanager:GetSecretValue",
  "iam:*",
  "AdministratorAccess",
]);
const explicitlyAllowedWriteActions = new Set([
  "ecs:ExecuteCommand",
  "kms:GenerateDataKey",
]);

const failures = [];

const asArray = (value) => {
  if (Array.isArray(value)) return value;
  if (typeof value === "string") return [value];
  return [];
};

const addFailure = (message) => failures.push(message);

const hasWildcard = (value) => value === "*" || value.endsWith(":*");
const isWriteLikeAction = (action) =>
  /:(Create|Delete|Put|Update|Attach|Detach|Pass|Assume|Start|Stop|Run|Terminate|Write|Execute|Generate)/i.test(action);

const readPolicy = (relPath, absPath) => {
  if (!fs.existsSync(absPath)) {
    addFailure(`${relPath}: policy file does not exist.`);
    return null;
  }

  const source = fs.readFileSync(absPath, "utf8");
  try {
    return { source, json: JSON.parse(source) };
  } catch (error) {
    addFailure(`${relPath}: JSON parse failed: ${error.message}`);
    return { source, json: null };
  }
};

const { source, json: policy } = readPolicy(policyRelPath, policyPath) || {};

if (source) {
  const normalized = source.toLowerCase();
  for (const fragment of forbiddenProductionFragments) {
    if (normalized.includes(fragment)) {
      addFailure(`${policyRelPath}: contains forbidden production fragment "${fragment}".`);
    }
  }
}

const validateApplyOperatorPolicy = () => {
  const result = readPolicy(applyPolicyRelPath, applyPolicyPath);
  if (!result) return;

  const { source: applySource, json: applyPolicy } = result;
  if (applySource) {
    const normalized = applySource.toLowerCase();
    for (const fragment of forbiddenProductionFragments) {
      if (normalized.includes(fragment)) {
        addFailure(`${applyPolicyRelPath}: contains forbidden production fragment "${fragment}".`);
      }
    }
  }

  if (!applyPolicy) return;

  if (applyPolicy.Version !== "2012-10-17") {
    addFailure(`${applyPolicyRelPath}: Version must be 2012-10-17.`);
  }
  if (!Array.isArray(applyPolicy.Statement) || applyPolicy.Statement.length !== 1) {
    addFailure(`${applyPolicyRelPath}: Statement must contain exactly one allow statement.`);
  }

  const [statement] = applyPolicy.Statement || [];
  if (!statement) return;

  if (statement.Effect !== "Allow") {
    addFailure(`${applyPolicyRelPath}: apply operator policy must use one explicit Allow statement.`);
  }

  const actions = asArray(statement.Action);
  const resources = asArray(statement.Resource);
  const expectedRoleArn = "arn:aws:iam::368992683803:role/mscqr-staging-terraform-apply-role";

  if (actions.length !== 1 || actions[0] !== "sts:AssumeRole") {
    addFailure(`${applyPolicyRelPath}: only sts:AssumeRole is allowed.`);
  }
  if (resources.length !== 1 || resources[0] !== expectedRoleArn) {
    addFailure(`${applyPolicyRelPath}: resource must be exactly ${expectedRoleArn}.`);
  }
  if (resources.some((resource) => resource === "*" || !/(staging|stg)/i.test(resource) || !/apply/i.test(resource))) {
    addFailure(`${applyPolicyRelPath}: resource must be scoped to the staging apply role.`);
  }
  if (actions.some((action) => hasWildcard(action) || /^iam:/i.test(action) || /^secretsmanager:/i.test(action))) {
    addFailure(`${applyPolicyRelPath}: wildcard, IAM, and Secrets Manager actions are forbidden.`);
  }
};

validateApplyOperatorPolicy();

const validateApplyPermissionsBoundary = () => {
  const result = readPolicy(applyBoundaryRelPath, applyBoundaryPath);
  if (!result?.json) return;

  const boundary = result.json;
  if (boundary.Version !== "2012-10-17") {
    addFailure(`${applyBoundaryRelPath}: Version must be 2012-10-17.`);
  }
  if (!Array.isArray(boundary.Statement) || boundary.Statement.length === 0) {
    addFailure(`${applyBoundaryRelPath}: Statement must be a non-empty array.`);
    return;
  }

  let hasMaximumAllow = false;
  let hasRegionDeny = false;
  let hasProductionTagDeny = false;
  let hasProductionNameDeny = false;
  let hasBoundaryEscalationDeny = false;

  for (const [index, statement] of boundary.Statement.entries()) {
    const sid = statement.Sid || `BoundaryStatement${index}`;
    const actions = asArray(statement.Action);
    const notActions = asArray(statement.NotAction);
    const resources = asArray(statement.Resource);

    if (!["Allow", "Deny"].includes(statement.Effect)) {
      addFailure(`${applyBoundaryRelPath}:${sid}: Effect must be Allow or Deny.`);
    }
    if (actions.length > 0 && notActions.length > 0) {
      addFailure(`${applyBoundaryRelPath}:${sid}: use Action or NotAction, not both.`);
    }
    if (resources.length === 0) {
      addFailure(`${applyBoundaryRelPath}:${sid}: Resource must be present.`);
    }

    if (
      statement.Effect === "Allow" &&
      actions.length === 1 &&
      actions[0] === "*" &&
      resources.length === 1 &&
      resources[0] === "*"
    ) {
      hasMaximumAllow = true;
    }

    const statementText = JSON.stringify(statement);
    if (
      statement.Effect === "Deny" &&
      statement.Condition?.StringNotEquals?.["aws:RequestedRegion"] === "eu-west-2" &&
      resources.length === 1 &&
      resources[0] === "*"
    ) {
      hasRegionDeny = true;
    }
    if (
      statement.Effect === "Deny" &&
      statement.Condition?.StringEquals?.["aws:ResourceTag/Environment"]?.includes("prod") &&
      statement.Condition?.StringEquals?.["aws:ResourceTag/Environment"]?.includes("production")
    ) {
      hasProductionTagDeny = true;
    }
    if (
      statement.Effect === "Deny" &&
      statementText.includes("*prod*") &&
      statementText.includes("*production*")
    ) {
      hasProductionNameDeny = true;
    }
    if (
      statement.Effect === "Deny" &&
      actions.includes("iam:DeleteRolePermissionsBoundary") &&
      actions.includes("iam:PutRolePermissionsBoundary") &&
      actions.includes("iam:AttachRolePolicy") &&
      actions.includes("iam:PutRolePolicy")
    ) {
      hasBoundaryEscalationDeny = true;
    }
  }

  if (!hasMaximumAllow) {
    addFailure(`${applyBoundaryRelPath}: must include an Allow * / Resource * maximum permissions statement.`);
  }
  if (!hasRegionDeny) {
    addFailure(`${applyBoundaryRelPath}: must deny non-eu-west-2 requests.`);
  }
  if (!hasProductionTagDeny) {
    addFailure(`${applyBoundaryRelPath}: must deny prod/production tagged resources.`);
  }
  if (!hasProductionNameDeny) {
    addFailure(`${applyBoundaryRelPath}: must deny production-looking resource ARNs.`);
  }
  if (!hasBoundaryEscalationDeny) {
    addFailure(`${applyBoundaryRelPath}: must deny boundary removal and inline/attached policy escalation.`);
  }
};

validateApplyPermissionsBoundary();

if (policy) {
  if (policy.Version !== "2012-10-17") {
    addFailure(`${policyRelPath}: Version must be 2012-10-17.`);
  }
  if (!Array.isArray(policy.Statement) || policy.Statement.length === 0) {
    addFailure(`${policyRelPath}: Statement must be a non-empty array.`);
  }

  let hasExecuteCommand = false;
  let hasStagingExecLogsRead = false;
  let hasScopedKms = false;

  for (const [index, statement] of (policy.Statement || []).entries()) {
    const sid = statement.Sid || `Statement${index}`;
    if (statement.Effect !== "Allow") {
      addFailure(`${sid}: operator policy template should use explicit Allow statements only.`);
    }

    const actions = asArray(statement.Action);
    const resources = asArray(statement.Resource);

    if (actions.length === 0) addFailure(`${sid}: Action must be a string or array.`);
    if (resources.length === 0) addFailure(`${sid}: Resource must be a string or array.`);

    for (const action of actions) {
      if (hasWildcard(action)) addFailure(`${sid}: wildcard action is forbidden: ${action}.`);
      if (!allowedActions.has(action)) addFailure(`${sid}: action is not approved for staging operator policy: ${action}.`);
      if (forbiddenActions.has(action)) addFailure(`${sid}: forbidden action is present: ${action}.`);
      if (/^iam:/i.test(action)) addFailure(`${sid}: IAM actions are forbidden in the operator policy: ${action}.`);
      if (/^secretsmanager:GetSecretValue$/i.test(action)) {
        addFailure(`${sid}: secretsmanager:GetSecretValue is forbidden in the operator policy.`);
      }
      if (isWriteLikeAction(action) && !explicitlyAllowedWriteActions.has(action)) {
        addFailure(`${sid}: write-like action is not explicitly allowed: ${action}.`);
      }
    }

    for (const resource of resources) {
      if (resource === "*") {
        const unapproved = actions.filter((action) => !allowedWildcardResourceActions.has(action));
        if (unapproved.length > 0) {
          addFailure(`${sid}: Resource "*" is not allowed for action(s): ${unapproved.join(", ")}.`);
        }
      }

      if (/^arn:aws:(ecs|logs):/.test(resource) && !/(staging|stg)/i.test(resource)) {
        addFailure(`${sid}: ECS/Logs resource must include staging or stg marker: ${resource}.`);
      }
      if (/^arn:aws:kms:/.test(resource) && !/STAGING_ECS_EXEC_LOG_KEY_ID|staging|stg/i.test(resource)) {
        addFailure(`${sid}: KMS resource must be scoped to the staging ECS Exec key placeholder or ARN: ${resource}.`);
      }
    }

    if (actions.includes("ecs:ExecuteCommand")) {
      hasExecuteCommand = true;
      if (resources.length === 0 || resources.some((resource) => resource === "*" || !/(staging|stg)/i.test(resource))) {
        addFailure(`${sid}: ecs:ExecuteCommand must be scoped to staging resources.`);
      }
    }

    if (actions.some((action) => action.startsWith("logs:"))) {
      const logResources = resources.filter((resource) => /^arn:aws:logs:/.test(resource));
      if (
        logResources.length === resources.length &&
        logResources.every((resource) => resource.includes("/aws/ecs/mscqr-staging/exec"))
      ) {
        hasStagingExecLogsRead = true;
      } else {
        addFailure(`${sid}: CloudWatch Logs access must be scoped to /aws/ecs/mscqr-staging/exec.`);
      }
    }

    if (actions.some((action) => action.startsWith("kms:"))) {
      if (
        actions.every((action) => action === "kms:GenerateDataKey") &&
        resources.every((resource) => /^arn:aws:kms:/.test(resource) && /STAGING_ECS_EXEC_LOG_KEY_ID|staging|stg/i.test(resource))
      ) {
        hasScopedKms = true;
      } else {
        addFailure(`${sid}: KMS access must be limited to kms:GenerateDataKey on the staging ECS Exec key.`);
      }
    }
  }

  if (!hasExecuteCommand) {
    addFailure(`${policyRelPath}: ecs:ExecuteCommand must be present.`);
  }
  if (!hasStagingExecLogsRead) {
    addFailure(`${policyRelPath}: scoped CloudWatch Logs read access for /aws/ecs/mscqr-staging/exec must be present.`);
  }
  if (!hasScopedKms) {
    addFailure(`${policyRelPath}: scoped KMS GenerateDataKey access must be present.`);
  }
}

if (failures.length > 0) {
  console.error("Staging IAM policy lint failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log("Staging IAM policy lint passed.");
console.log(`Validated policy: ${policyRelPath}`);
console.log(`Validated policy: ${applyPolicyRelPath}`);
console.log(`Validated policy: ${applyBoundaryRelPath}`);
console.log("ECS Exec and apply operator Resource=\"*\" exceptions: none.");
console.log("Apply permissions boundary intentionally uses wildcard maximum and deny statements.");

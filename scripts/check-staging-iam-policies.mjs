#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);
const policyRelPath = "documents/ops/iam/MSCQR_STAGING_ECS_EXEC_OPERATOR_POLICY_2026-07-02.json";
const policyPath = path.join(repoRoot, policyRelPath);

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

const readPolicy = () => {
  if (!fs.existsSync(policyPath)) {
    addFailure(`${policyRelPath}: policy file does not exist.`);
    return null;
  }

  const source = fs.readFileSync(policyPath, "utf8");
  try {
    return { source, json: JSON.parse(source) };
  } catch (error) {
    addFailure(`${policyRelPath}: JSON parse failed: ${error.message}`);
    return { source, json: null };
  }
};

const { source, json: policy } = readPolicy() || {};

if (source) {
  const normalized = source.toLowerCase();
  for (const fragment of forbiddenProductionFragments) {
    if (normalized.includes(fragment)) {
      addFailure(`${policyRelPath}: contains forbidden production fragment "${fragment}".`);
    }
  }
}

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
console.log("Allowed Resource=\"*\" exceptions: none.");

#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);
const resolvePolicyPath = (defaultRelPath, overridePath) => {
  if (!overridePath) return path.join(repoRoot, defaultRelPath);
  return path.isAbsolute(overridePath) ? overridePath : path.resolve(repoRoot, overridePath);
};
const policyRelPath = "documents/ops/iam/MSCQR_STAGING_ECS_EXEC_OPERATOR_POLICY_2026-07-02.json";
const policyPath = resolvePolicyPath(policyRelPath, process.env.MSCQR_STAGING_IAM_ECS_EXEC_OPERATOR_POLICY_PATH);
const applyPolicyRelPath = "documents/ops/iam/MSCQR_STAGING_TERRAFORM_APPLY_OPERATOR_POLICY_2026-07-08.json";
const applyPolicyPath = resolvePolicyPath(applyPolicyRelPath, process.env.MSCQR_STAGING_IAM_APPLY_OPERATOR_POLICY_PATH);
const applyRolePolicyRelPath = "documents/ops/iam/MSCQR_STAGING_TERRAFORM_APPLY_ROLE_POLICY_2026-07-08.json";
const applyRolePolicyPath = resolvePolicyPath(applyRolePolicyRelPath, process.env.MSCQR_STAGING_IAM_APPLY_ROLE_POLICY_PATH);
const applyBoundaryRelPath = "documents/ops/iam/MSCQR_STAGING_TERRAFORM_APPLY_PERMISSIONS_BOUNDARY_2026-07-08.json";
const applyBoundaryPath = resolvePolicyPath(applyBoundaryRelPath, process.env.MSCQR_STAGING_IAM_APPLY_BOUNDARY_PATH);

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
]);
const explicitlyAllowedWriteActions = new Set([
  "ecs:ExecuteCommand",
  "kms:GenerateDataKey",
]);
const stagingTerraformManagedRoleArns = new Set([
  "arn:aws:iam::368992683803:role/mscqr-staging-ecs-execution-role",
  "arn:aws:iam::368992683803:role/mscqr-staging-ecs-task-role",
]);
const stagingTerraformExecutionRoleArn = "arn:aws:iam::368992683803:role/mscqr-staging-ecs-execution-role";
const reviewedEcsExecutionManagedPolicyArn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy";
const requiredStagingTerraformIamActions = new Set([
  "iam:CreateRole",
  "iam:DeleteRole",
  "iam:GetRole",
  "iam:ListAttachedRolePolicies",
  "iam:ListRolePolicies",
  "iam:PassRole",
  "iam:TagRole",
  "iam:UntagRole",
  "iam:UpdateAssumeRolePolicy",
  "iam:DeleteRolePolicy",
  "iam:GetRolePolicy",
  "iam:PutRolePolicy",
  "iam:AttachRolePolicy",
  "iam:DetachRolePolicy",
]);

const failures = [];

const asArray = (value) => {
  if (Array.isArray(value)) return value;
  if (typeof value === "string") return [value];
  return [];
};

const addFailure = (message) => failures.push(message);

const hasWildcard = (value) => value === "*" || value.endsWith(":*");
const actionMatches = (pattern, action) => {
  if (pattern === "*" || pattern.toLowerCase() === action.toLowerCase()) return true;
  if (!pattern.includes("*")) return false;
  const escaped = pattern.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/\\\*/g, ".*");
  return new RegExp(`^${escaped}$`, "i").test(action);
};
const statementDeniesAction = (statement, action) => {
  const actions = asArray(statement.Action);
  const notActions = asArray(statement.NotAction);
  if (actions.length > 0) return actions.some((pattern) => actionMatches(pattern, action));
  if (notActions.length > 0) return !notActions.some((pattern) => actionMatches(pattern, action));
  return true;
};
const invalidArnServiceWildcardReason = (resource) => {
  if (typeof resource !== "string" || !resource.startsWith("arn:")) return null;
  const [, partition, service] = resource.split(":", 4);
  if (!partition || !service) return null;
  if (/[*?]/.test(service)) {
    return "Resource ARN service segment must be fully qualified for AWS IAM";
  }
  return null;
};
const isWriteLikeAction = (action) =>
  /:(Create|Delete|Put|Update|Attach|Detach|Pass|Assume|Start|Stop|Run|Terminate|Write|Execute|Generate)/i.test(action);
const isIamWriteLikeAction = (action) => /^iam:/i.test(action) && isWriteLikeAction(action);

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

const validateApplyRolePolicy = () => {
  const result = readPolicy(applyRolePolicyRelPath, applyRolePolicyPath);
  if (!result) return;

  const { source: applyRoleSource, json: applyRolePolicy } = result;
  if (applyRoleSource) {
    const normalized = applyRoleSource.toLowerCase();
    for (const fragment of forbiddenProductionFragments) {
      if (normalized.includes(fragment)) {
        addFailure(`${applyRolePolicyRelPath}: contains forbidden production fragment "${fragment}".`);
      }
    }
    if (/AdministratorAccess/i.test(applyRoleSource)) {
      addFailure(`${applyRolePolicyRelPath}: AdministratorAccess is forbidden.`);
    }
  }

  if (!applyRolePolicy) return;

  if (applyRolePolicy.Version !== "2012-10-17") {
    addFailure(`${applyRolePolicyRelPath}: Version must be 2012-10-17.`);
  }
  if (!Array.isArray(applyRolePolicy.Statement) || applyRolePolicy.Statement.length === 0) {
    addFailure(`${applyRolePolicyRelPath}: Statement must be a non-empty array.`);
    return;
  }

  const seenActions = new Set();

  for (const [index, statement] of applyRolePolicy.Statement.entries()) {
    const sid = statement.Sid || `ApplyRolePolicyStatement${index}`;
    const actions = asArray(statement.Action);
    const resources = asArray(statement.Resource);

    if (statement.Effect !== "Allow") {
      addFailure(`${applyRolePolicyRelPath}:${sid}: apply role policy must use explicit Allow statements only.`);
    }
    if (actions.length === 0) addFailure(`${applyRolePolicyRelPath}:${sid}: Action must be a string or array.`);
    if (resources.length === 0) addFailure(`${applyRolePolicyRelPath}:${sid}: Resource must be a string or array.`);

    for (const action of actions) {
      seenActions.add(action);
      if (hasWildcard(action)) addFailure(`${applyRolePolicyRelPath}:${sid}: wildcard action is forbidden: ${action}.`);
      if (action === "iam:*") addFailure(`${applyRolePolicyRelPath}:${sid}: iam:* is forbidden.`);
      if (!requiredStagingTerraformIamActions.has(action)) {
        addFailure(`${applyRolePolicyRelPath}:${sid}: action is not approved for staging Terraform apply IAM management: ${action}.`);
      }
      if (isIamWriteLikeAction(action) && resources.includes("*")) {
        addFailure(`${applyRolePolicyRelPath}:${sid}: Resource "*" is forbidden for IAM write action ${action}.`);
      }
    }

    for (const resource of resources) {
      const invalidReason = invalidArnServiceWildcardReason(resource);
      if (invalidReason) {
        addFailure(`${applyRolePolicyRelPath}:${sid}: ${invalidReason}: ${resource}.`);
      }
      if (resource === "*") {
        addFailure(`${applyRolePolicyRelPath}:${sid}: Resource "*" is forbidden in the staging Terraform apply role policy.`);
        continue;
      }
      if (!/^arn:aws:iam::368992683803:role\//.test(resource)) {
        addFailure(`${applyRolePolicyRelPath}:${sid}: resource must be an IAM role ARN in the staging account: ${resource}.`);
      }
      if (!stagingTerraformManagedRoleArns.has(resource)) {
        addFailure(`${applyRolePolicyRelPath}:${sid}: resource must be one of the Terraform-managed staging ECS role ARNs: ${resource}.`);
      }
      if (/(^|[-_/])(prod|production)([-_/]|$)/i.test(resource)) {
        addFailure(`${applyRolePolicyRelPath}:${sid}: production-looking IAM role resource is forbidden: ${resource}.`);
      }
    }

    if (actions.some((action) => action === "iam:AttachRolePolicy" || action === "iam:DetachRolePolicy")) {
      const policyArn = statement.Condition?.StringEquals?.["iam:PolicyARN"];
      if (policyArn !== reviewedEcsExecutionManagedPolicyArn) {
        addFailure(`${applyRolePolicyRelPath}:${sid}: managed policy attach/detach must be limited to ${reviewedEcsExecutionManagedPolicyArn}.`);
      }
      if (resources.length !== 1 || resources[0] !== stagingTerraformExecutionRoleArn) {
        addFailure(`${applyRolePolicyRelPath}:${sid}: managed policy attach/detach must target only ${stagingTerraformExecutionRoleArn}.`);
      }
    }
  }

  for (const requiredAction of requiredStagingTerraformIamActions) {
    if (!seenActions.has(requiredAction)) {
      addFailure(`${applyRolePolicyRelPath}: missing required Terraform staging IAM action ${requiredAction}.`);
    }
  }
};

validateApplyRolePolicy();

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
  let hasBoundaryTamperingDeny = false;
  let hasOutsideStagingRoleDeny = false;
  let hasUnreviewedManagedPolicyAttachmentDeny = false;
  const requiredDenyConflicts = [];

  for (const [index, statement] of boundary.Statement.entries()) {
    const sid = statement.Sid || `BoundaryStatement${index}`;
    const actions = asArray(statement.Action);
    const notActions = asArray(statement.NotAction);
    const resources = asArray(statement.Resource);
    const notResources = asArray(statement.NotResource);

    if (!["Allow", "Deny"].includes(statement.Effect)) {
      addFailure(`${applyBoundaryRelPath}:${sid}: Effect must be Allow or Deny.`);
    }
    if (actions.length > 0 && notActions.length > 0) {
      addFailure(`${applyBoundaryRelPath}:${sid}: use Action or NotAction, not both.`);
    }
    if (resources.length > 0 && notResources.length > 0) {
      addFailure(`${applyBoundaryRelPath}:${sid}: use Resource or NotResource, not both.`);
    }
    if (resources.length === 0 && notResources.length === 0) {
      addFailure(`${applyBoundaryRelPath}:${sid}: Resource or NotResource must be present.`);
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

    for (const resource of [...resources, ...notResources]) {
      const invalidReason = invalidArnServiceWildcardReason(resource);
      if (invalidReason) {
        addFailure(`${applyBoundaryRelPath}:${sid}: ${invalidReason}: ${resource}.`);
      }
    }

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
      actions.includes("iam:DeleteRolePermissionsBoundary") &&
      actions.includes("iam:PutRolePermissionsBoundary") &&
      actions.includes("iam:CreatePolicyVersion") &&
      actions.includes("iam:SetDefaultPolicyVersion")
    ) {
      hasBoundaryTamperingDeny = true;
    }
    if (
      statement.Effect === "Deny" &&
      notResources.length === stagingTerraformManagedRoleArns.size &&
      [...stagingTerraformManagedRoleArns].every((resource) => notResources.includes(resource)) &&
      actions.includes("iam:CreateRole") &&
      actions.includes("iam:PutRolePolicy") &&
      actions.includes("iam:AttachRolePolicy") &&
      actions.includes("iam:PassRole")
    ) {
      hasOutsideStagingRoleDeny = true;
    }
    if (
      statement.Effect === "Deny" &&
      actions.includes("iam:AttachRolePolicy") &&
      actions.includes("iam:DetachRolePolicy") &&
      resources.length === 1 &&
      resources[0] === stagingTerraformExecutionRoleArn &&
      statement.Condition?.StringNotEquals?.["iam:PolicyARN"] === reviewedEcsExecutionManagedPolicyArn
    ) {
      hasUnreviewedManagedPolicyAttachmentDeny = true;
    }

    if (statement.Effect === "Deny") {
      for (const requiredAction of requiredStagingTerraformIamActions) {
        if (!statementDeniesAction(statement, requiredAction)) continue;

        for (const roleArn of stagingTerraformManagedRoleArns) {
          const resourceDenied =
            resources.includes("*") ||
            resources.includes(roleArn) ||
            (notResources.length > 0 && !notResources.includes(roleArn));
          if (!resourceDenied) continue;

          const reviewedManagedAttachmentException =
            (requiredAction === "iam:AttachRolePolicy" || requiredAction === "iam:DetachRolePolicy") &&
            roleArn === stagingTerraformExecutionRoleArn &&
            statement.Condition?.StringNotEquals?.["iam:PolicyARN"] === reviewedEcsExecutionManagedPolicyArn;
          const productionTagException = statement.Condition?.StringEquals?.["aws:ResourceTag/Environment"] !== undefined;

          if (!reviewedManagedAttachmentException && !productionTagException) {
            requiredDenyConflicts.push(`${sid} denies ${requiredAction} on ${roleArn}`);
          }
        }
      }
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
  if (!hasBoundaryTamperingDeny) {
    addFailure(`${applyBoundaryRelPath}: must deny boundary tampering and managed-policy version escalation.`);
  }
  if (!hasOutsideStagingRoleDeny) {
    addFailure(`${applyBoundaryRelPath}: must deny IAM role management outside Terraform-managed staging ECS roles.`);
  }
  if (!hasUnreviewedManagedPolicyAttachmentDeny) {
    addFailure(`${applyBoundaryRelPath}: must deny unreviewed managed policy attachment to the staging ECS execution role.`);
  }
  if (requiredDenyConflicts.length > 0) {
    for (const conflict of requiredDenyConflicts) {
      addFailure(`${applyBoundaryRelPath}: boundary must not deny required staging Terraform IAM action: ${conflict}.`);
    }
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
console.log(`Validated policy: ${applyRolePolicyRelPath}`);
console.log(`Validated policy: ${applyBoundaryRelPath}`);
console.log("ECS Exec and apply operator Resource=\"*\" exceptions: none.");
console.log("Apply role policy is scoped to Terraform-managed staging ECS IAM roles only.");
console.log("Apply permissions boundary intentionally uses wildcard maximum and targeted deny statements.");

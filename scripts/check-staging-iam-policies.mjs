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
const backendAccessPolicyRelPath = "documents/ops/iam/MSCQR_STAGING_TERRAFORM_BACKEND_ACCESS_POLICY_2026-07-08.json";
const backendAccessPolicyPath = resolvePolicyPath(backendAccessPolicyRelPath, process.env.MSCQR_STAGING_IAM_BACKEND_ACCESS_POLICY_PATH);
const backendBootstrapPolicyRelPath = "documents/ops/iam/MSCQR_STAGING_TERRAFORM_BACKEND_BOOTSTRAP_POLICY_2026-07-08.json";
const backendBootstrapPolicyPath = resolvePolicyPath(
  backendBootstrapPolicyRelPath,
  process.env.MSCQR_STAGING_IAM_BACKEND_BOOTSTRAP_POLICY_PATH,
);

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
  "arn:aws:iam::368992683803:role/mscqr-staging-database-role-admin-task",
  "arn:aws:iam::368992683803:role/mscqr-staging-ecs-execution-role",
  "arn:aws:iam::368992683803:role/mscqr-staging-ecs-task-role",
]);
const stagingTerraformExecutionRoleArn = "arn:aws:iam::368992683803:role/mscqr-staging-ecs-execution-role";
const stagingTerraformTaskRoleArn = "arn:aws:iam::368992683803:role/mscqr-staging-ecs-task-role";
const stagingTerraformDatabaseRoleAdminTaskRoleArn = "arn:aws:iam::368992683803:role/mscqr-staging-database-role-admin-task";
const reviewedEcsExecutionManagedPolicyArn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy";
const backendStateBucketArn = "arn:aws:s3:::mscqr-staging-terraform-state-368992683803";
const backendStateObjectArn = `${backendStateBucketArn}/staging-api/terraform.tfstate`;
const backendStateLockObjectArn = `${backendStateObjectArn}.tflock`;
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
const requiredActionAllowedRoleArns = (action) => {
  if (action === "iam:AttachRolePolicy" || action === "iam:DetachRolePolicy") {
    return [stagingTerraformExecutionRoleArn];
  }
  return [...stagingTerraformManagedRoleArns];
};

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

const validateNoProductionFragments = (relPath, source) => {
  if (!source) return;
  const normalized = source.toLowerCase();
  for (const fragment of forbiddenProductionFragments) {
    if (normalized.includes(fragment)) {
      addFailure(`${relPath}: contains forbidden production fragment "${fragment}".`);
    }
  }
};

const validateNoBroadS3Access = (relPath, policy) => {
  if (!policy) return;
  for (const [index, statement] of (policy.Statement || []).entries()) {
    const sid = statement.Sid || `Statement${index}`;
    const actions = asArray(statement.Action);
    const resources = asArray(statement.Resource);
    for (const action of actions) {
      if (action === "s3:*" || action === "*") {
        addFailure(`${relPath}:${sid}: broad S3 action is forbidden: ${action}.`);
      }
    }
    for (const resource of resources) {
      if (resource === "*") {
        addFailure(`${relPath}:${sid}: Resource "*" is forbidden for staging Terraform backend access.`);
      }
      if (/(^|[-_/])(prod|production)([-_/]|$)|mscqr-prod/i.test(resource)) {
        addFailure(`${relPath}:${sid}: production-looking S3 resource is forbidden: ${resource}.`);
      }
    }
  }
};

const { source, json: policy } = readPolicy(policyRelPath, policyPath) || {};

validateNoProductionFragments(policyRelPath, source);

const validateApplyOperatorPolicy = () => {
  const result = readPolicy(applyPolicyRelPath, applyPolicyPath);
  if (!result) return;

  const { source: applySource, json: applyPolicy } = result;
  validateNoProductionFragments(applyPolicyRelPath, applySource);

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
  validateNoProductionFragments(applyRolePolicyRelPath, applyRoleSource);
  if (applyRoleSource) {
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
  const allowedResourcesByAction = new Map();

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
      const allowedResources = allowedResourcesByAction.get(action) || new Set();
      for (const resource of resources) allowedResources.add(resource);
      allowedResourcesByAction.set(action, allowedResources);
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
    const allowedResources = allowedResourcesByAction.get(requiredAction) || new Set();
    for (const requiredRoleArn of requiredActionAllowedRoleArns(requiredAction)) {
      if (!allowedResources.has(requiredRoleArn)) {
        addFailure(`${applyRolePolicyRelPath}: ${requiredAction} must allow required Terraform-managed role ${requiredRoleArn}.`);
      }
    }
  }
};

validateApplyRolePolicy();

const validateBackendAccessPolicy = () => {
  const result = readPolicy(backendAccessPolicyRelPath, backendAccessPolicyPath);
  if (!result) return;

  const { source: backendSource, json: backendPolicy } = result;
  validateNoProductionFragments(backendAccessPolicyRelPath, backendSource);
  validateNoBroadS3Access(backendAccessPolicyRelPath, backendPolicy);
  if (/dynamodb/i.test(backendSource || "")) {
    addFailure(`${backendAccessPolicyRelPath}: DynamoDB locking is not required for the default S3 lockfile backend.`);
  }

  if (!backendPolicy) return;
  if (backendPolicy.Version !== "2012-10-17") {
    addFailure(`${backendAccessPolicyRelPath}: Version must be 2012-10-17.`);
  }
  if (!Array.isArray(backendPolicy.Statement) || backendPolicy.Statement.length !== 3) {
    addFailure(`${backendAccessPolicyRelPath}: Statement must contain exactly the list, state object, and lockfile statements.`);
    return;
  }

  const bySid = new Map(backendPolicy.Statement.map((statement) => [statement.Sid, statement]));
  const listStatement = bySid.get("ListStagingTerraformStatePrefix");
  const stateStatement = bySid.get("ReadWriteStagingTerraformStateObject");
  const lockStatement = bySid.get("ReadWriteDeleteStagingTerraformStateLockfile");

  if (!listStatement) addFailure(`${backendAccessPolicyRelPath}: missing ListStagingTerraformStatePrefix statement.`);
  if (!stateStatement) addFailure(`${backendAccessPolicyRelPath}: missing ReadWriteStagingTerraformStateObject statement.`);
  if (!lockStatement) addFailure(`${backendAccessPolicyRelPath}: missing ReadWriteDeleteStagingTerraformStateLockfile statement.`);

  if (listStatement) {
    const actions = asArray(listStatement.Action);
    const resources = asArray(listStatement.Resource);
    const prefix = listStatement.Condition?.StringLike?.["s3:prefix"];
    if (listStatement.Effect !== "Allow") addFailure(`${backendAccessPolicyRelPath}: list statement must Allow.`);
    if (actions.length !== 1 || actions[0] !== "s3:ListBucket") {
      addFailure(`${backendAccessPolicyRelPath}: list statement must allow only s3:ListBucket.`);
    }
    if (resources.length !== 1 || resources[0] !== backendStateBucketArn) {
      addFailure(`${backendAccessPolicyRelPath}: list statement resource must be ${backendStateBucketArn}.`);
    }
    if (prefix !== "staging-api/terraform.tfstate*") {
      addFailure(`${backendAccessPolicyRelPath}: list statement must be limited to s3:prefix staging-api/terraform.tfstate*.`);
    }
  }

  if (stateStatement) {
    const actions = asArray(stateStatement.Action).sort();
    const resources = asArray(stateStatement.Resource);
    if (stateStatement.Effect !== "Allow") addFailure(`${backendAccessPolicyRelPath}: state object statement must Allow.`);
    if (JSON.stringify(actions) !== JSON.stringify(["s3:GetObject", "s3:PutObject"])) {
      addFailure(`${backendAccessPolicyRelPath}: state object statement must allow only s3:GetObject and s3:PutObject.`);
    }
    if (resources.length !== 1 || resources[0] !== backendStateObjectArn) {
      addFailure(`${backendAccessPolicyRelPath}: state object resource must be ${backendStateObjectArn}.`);
    }
  }

  if (lockStatement) {
    const actions = asArray(lockStatement.Action).sort();
    const resources = asArray(lockStatement.Resource);
    if (lockStatement.Effect !== "Allow") addFailure(`${backendAccessPolicyRelPath}: lockfile statement must Allow.`);
    if (JSON.stringify(actions) !== JSON.stringify(["s3:DeleteObject", "s3:GetObject", "s3:PutObject"])) {
      addFailure(`${backendAccessPolicyRelPath}: lockfile statement must allow GetObject, PutObject, and DeleteObject.`);
    }
    if (resources.length !== 1 || resources[0] !== backendStateLockObjectArn) {
      addFailure(`${backendAccessPolicyRelPath}: lockfile resource must be ${backendStateLockObjectArn}.`);
    }
  }
};

validateBackendAccessPolicy();

const validateBackendBootstrapPolicy = () => {
  const result = readPolicy(backendBootstrapPolicyRelPath, backendBootstrapPolicyPath);
  if (!result) return;

  const { source: bootstrapSource, json: bootstrapPolicy } = result;
  validateNoProductionFragments(backendBootstrapPolicyRelPath, bootstrapSource);
  validateNoBroadS3Access(backendBootstrapPolicyRelPath, bootstrapPolicy);
  if (!bootstrapPolicy) return;

  if (bootstrapPolicy.Version !== "2012-10-17") {
    addFailure(`${backendBootstrapPolicyRelPath}: Version must be 2012-10-17.`);
  }
  if (!Array.isArray(bootstrapPolicy.Statement) || bootstrapPolicy.Statement.length !== 2) {
    addFailure(`${backendBootstrapPolicyRelPath}: Statement must contain exactly create and configure statements.`);
    return;
  }

  const allowedBootstrapActions = new Set([
    "s3:CreateBucket",
    "s3:GetBucketLocation",
    "s3:GetBucketPolicy",
    "s3:GetBucketPublicAccessBlock",
    "s3:GetBucketVersioning",
    "s3:GetEncryptionConfiguration",
    "s3:GetLifecycleConfiguration",
    "s3:GetBucketOwnershipControls",
    "s3:ListBucket",
    "s3:PutBucketPolicy",
    "s3:PutBucketPublicAccessBlock",
    "s3:PutBucketVersioning",
    "s3:PutEncryptionConfiguration",
    "s3:PutLifecycleConfiguration",
    "s3:PutBucketOwnershipControls",
  ]);

  let hasCreate = false;
  let hasConfigure = false;
  for (const [index, statement] of bootstrapPolicy.Statement.entries()) {
    const sid = statement.Sid || `BackendBootstrapStatement${index}`;
    const actions = asArray(statement.Action);
    const resources = asArray(statement.Resource);
    if (statement.Effect !== "Allow") {
      addFailure(`${backendBootstrapPolicyRelPath}:${sid}: bootstrap policy must use explicit Allow statements only.`);
    }
    if (resources.length !== 1 || resources[0] !== backendStateBucketArn) {
      addFailure(`${backendBootstrapPolicyRelPath}:${sid}: resource must be exactly ${backendStateBucketArn}.`);
    }
    for (const action of actions) {
      if (!allowedBootstrapActions.has(action)) {
        addFailure(`${backendBootstrapPolicyRelPath}:${sid}: action is not approved for backend bootstrap: ${action}.`);
      }
    }
    if (actions.includes("s3:CreateBucket")) {
      hasCreate = true;
      if (statement.Condition?.StringEquals?.["aws:RequestedRegion"] !== "eu-west-2") {
        addFailure(`${backendBootstrapPolicyRelPath}:${sid}: CreateBucket must require aws:RequestedRegion eu-west-2.`);
      }
    } else {
      hasConfigure = true;
    }
  }
  if (!hasCreate) addFailure(`${backendBootstrapPolicyRelPath}: missing s3:CreateBucket statement.`);
  if (!hasConfigure) addFailure(`${backendBootstrapPolicyRelPath}: missing bucket controls configuration statement.`);
};

validateBackendBootstrapPolicy();

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
  let hasTaskRoleManagedPolicyAttachmentDeny = false;
  let hasDatabaseRoleAdminManagedPolicyAttachmentDeny = false;
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
    if (
      statement.Effect === "Deny" &&
      actions.includes("iam:AttachRolePolicy") &&
      actions.includes("iam:DetachRolePolicy") &&
      resources.length === 1 &&
      resources[0] === stagingTerraformTaskRoleArn
    ) {
      hasTaskRoleManagedPolicyAttachmentDeny = true;
    }
    if (
      statement.Effect === "Deny" &&
      actions.includes("iam:AttachRolePolicy") &&
      actions.includes("iam:DetachRolePolicy") &&
      resources.length === 1 &&
      resources[0] === stagingTerraformDatabaseRoleAdminTaskRoleArn
    ) {
      hasDatabaseRoleAdminManagedPolicyAttachmentDeny = true;
    }

    if (statement.Effect === "Deny") {
      for (const requiredAction of requiredStagingTerraformIamActions) {
        if (!statementDeniesAction(statement, requiredAction)) continue;

        for (const roleArn of requiredActionAllowedRoleArns(requiredAction)) {
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
  if (!hasTaskRoleManagedPolicyAttachmentDeny) {
    addFailure(`${applyBoundaryRelPath}: must deny managed policy attachment to the staging ECS task role.`);
  }
  if (!hasDatabaseRoleAdminManagedPolicyAttachmentDeny) {
    addFailure(`${applyBoundaryRelPath}: must deny managed policy attachment to the staging database-role admin task role.`);
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
console.log(`Validated policy: ${backendAccessPolicyRelPath}`);
console.log(`Validated policy: ${backendBootstrapPolicyRelPath}`);
console.log("ECS Exec and apply operator Resource=\"*\" exceptions: none.");
console.log("Apply role policy is scoped to Terraform-managed staging ECS IAM roles only.");
console.log("Apply permissions boundary intentionally uses wildcard maximum and targeted deny statements.");
console.log("Terraform backend S3 access is scoped to the staging state object and S3 lockfile only.");

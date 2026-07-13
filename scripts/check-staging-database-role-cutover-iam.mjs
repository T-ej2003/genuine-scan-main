#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const root = path.resolve(new URL("..", import.meta.url).pathname);
const accountId = "368992683803";
const region = "eu-west-2";
const roleName = "mscqr-staging-database-role-cutover";
const userArn = `arn:aws:iam::${accountId}:user/mscqr-staging-database-role-cutover-user`;
const roleArn = `arn:aws:iam::${accountId}:role/${roleName}`;
const clusterArn = `arn:aws:ecs:${region}:${accountId}:cluster/mscqr-staging-euw2-main`;
const serviceArn = `arn:aws:ecs:${region}:${accountId}:service/mscqr-staging-euw2-main/mscqr-staging-backend-service-euw2`;
const taskArn = `arn:aws:ecs:${region}:${accountId}:task/mscqr-staging-euw2-main/*`;
const taskDefinitionArn = `arn:aws:ecs:${region}:${accountId}:task-definition/mscqr-staging-backend:*`;
const appSecretArn = "${STAGING_APP_DATABASE_SECRET_ARN_PATTERN}";
const files = {
  trust: "documents/ops/iam/MSCQR_STAGING_DATABASE_ROLE_CUTOVER_TRUST_POLICY_2026-07-13.json",
  assume: "documents/ops/iam/MSCQR_STAGING_DATABASE_ROLE_CUTOVER_ASSUME_ROLE_POLICY_2026-07-13.json",
  role: "documents/ops/iam/MSCQR_STAGING_DATABASE_ROLE_CUTOVER_POLICY_2026-07-13.json",
};
const overrides = {
  trust: process.env.MSCQR_STAGING_DATABASE_ROLE_CUTOVER_TRUST_POLICY_PATH,
  assume: process.env.MSCQR_STAGING_DATABASE_ROLE_CUTOVER_ASSUME_POLICY_PATH,
  role: process.env.MSCQR_STAGING_DATABASE_ROLE_CUTOVER_POLICY_PATH,
};
const failures = [];
const asArray = (value) => Array.isArray(value) ? value : typeof value === "string" ? [value] : [];
const same = (actual, expected) => JSON.stringify([...actual].sort()) === JSON.stringify([...expected].sort());
const read = (key) => {
  const file = overrides[key] ? path.resolve(overrides[key]) : path.join(root, files[key]);
  try { return JSON.parse(fs.readFileSync(file, "utf8")); }
  catch (error) { failures.push(`${files[key]}: ${error.message}`); return null; }
};
const statement = (policy, sid) => {
  const value = policy?.Statement?.find((item) => item.Sid === sid);
  if (!value) failures.push(`Missing required statement ${sid}.`);
  return value;
};
const resourceIs = (value, expected) => same(asArray(value), asArray(expected));

const trust = read("trust");
const assume = read("assume");
const role = read("role");
for (const [label, policy] of [["Trust", trust], ["Assume", assume], ["Role", role]]) {
  if (policy?.Version !== "2012-10-17" || !Array.isArray(policy?.Statement)) failures.push(`${label} policy must be a valid 2012-10-17 policy.`);
  if (/(^|[-_/])(prod|production)([-_/*]|$)/i.test(JSON.stringify(policy))) failures.push(`${label} policy contains a production-looking resource.`);
}

if (trust) {
  const value = trust.Statement[0];
  if (trust.Statement.length !== 1 || value?.Effect !== "Allow" || !same(asArray(value?.Action), ["sts:AssumeRole"]) || value?.Principal?.AWS !== userArn) failures.push(`Trust policy must allow only ${userArn}.`);
  if (value?.Condition?.Bool?.["aws:MultiFactorAuthPresent"] !== "true") failures.push("Trust policy must require MFA.");
  if (["*", `arn:aws:iam::${accountId}:root`, `arn:aws:iam::${accountId}:role/mscqr-staging-database-role-operator`, `arn:aws:iam::${accountId}:role/mscqr-staging-terraform-plan-role`, `arn:aws:iam::${accountId}:role/mscqr-staging-terraform-apply-role`].includes(value?.Principal?.AWS)) failures.push("Trust policy includes a forbidden principal.");
}
if (assume) {
  const value = assume.Statement[0];
  if (assume.Statement.length !== 1 || value?.Effect !== "Allow" || !same(asArray(value?.Action), ["sts:AssumeRole"]) || !resourceIs(value?.Resource, roleArn)) failures.push(`Assume policy must allow only ${roleArn}.`);
}

if (role) {
  const allowedActions = new Set([
    "sts:GetCallerIdentity", "ecs:DescribeServices", "ecs:DescribeTasks", "ecs:DescribeTaskDefinition", "ecs:ListServices",
    "ecs:ListTaskDefinitions", "ecs:ListTasks", "events:ListRules", "events:ListTargetsByRule", "secretsmanager:DescribeSecret",
    "ecs:RegisterTaskDefinition", "ecs:TagResource", "ecs:UpdateService", "ecs:ExecuteCommand", "kms:GenerateDataKey", "iam:PassRole",
  ]);
  const actions = new Set(role.Statement.flatMap((item) => asArray(item.Action)));
  for (const action of allowedActions) if (!actions.has(action)) failures.push(`Missing required action ${action}.`);
  for (const action of actions) if (!allowedActions.has(action) || action.includes("*")) failures.push(`Unapproved or wildcard action ${action}.`);
  for (const forbidden of ["lambda:InvokeFunction", "secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue", "secretsmanager:UpdateSecret", "rds:ModifyDBInstance", "ecs:RunTask", "ecs:UntagResource", "ssmmessages:CreateControlChannel", "ssmmessages:OpenDataChannel"]) if (actions.has(forbidden)) failures.push(`Forbidden action ${forbidden}.`);
  for (const item of role.Statement) if (item.Effect !== "Allow") failures.push(`${item.Sid || "Statement"}: only explicit Allow statements are permitted.`);

  const exactResources = new Map([
    ["DescribeExactStagingBackendService", serviceArn],
    ["DescribeOnlyReviewedStagingTasks", taskArn],
    ["ListOnlyStagingEventBridgeRuleTargets", `arn:aws:events:${region}:${accountId}:rule/mscqr-staging*`],
    ["DescribeOnlyStagingAppDatabaseSecretMetadata", appSecretArn],
    ["RegisterOnlyReviewedStagingBackendTaskDefinitionFamily", taskDefinitionArn],
    ["TagOnlyReviewedStagingBackendTaskDefinitionOnRegistration", taskDefinitionArn],
    ["UpdateOnlyExactStagingBackendService", serviceArn],
  ]);
  for (const [sid, resource] of exactResources) if (!resourceIs(statement(role, sid)?.Resource, resource)) failures.push(`${sid} must use only ${resource}.`);

  const wildcardSids = new Set(["IdentifyExactStagingAccount", "DescribeTaskDefinitionsRequiredByEcsApi", "ListExactStagingClusterServices", "ListTaskDefinitionsRequiredByEcsApi", "ListExactStagingBackendTasks", "ListStagingEventBridgeRulesRequiredForConsumerInventory"]);
  for (const item of role.Statement) {
    if (asArray(item.Resource).includes("*") && !wildcardSids.has(item.Sid)) failures.push(`${item.Sid}: Resource wildcard is not approved.`);
    if (item.Sid !== "IdentifyExactStagingAccount" && item.Action !== "iam:PassRole" && item.Condition?.StringEquals?.["aws:RequestedRegion"] !== region) failures.push(`${item.Sid}: exact staging region condition is required.`);
  }
  const listServices = statement(role, "ListExactStagingClusterServices");
  if (listServices?.Condition?.ArnEquals?.["ecs:cluster"] !== clusterArn) failures.push("ListServices must be constrained to the exact staging cluster.");
  const listTasks = statement(role, "ListExactStagingBackendTasks");
  if (listTasks?.Condition?.StringEquals?.["ecs:cluster"] !== clusterArn) failures.push("ListTasks must be constrained to the exact staging cluster.");
  const update = statement(role, "UpdateOnlyExactStagingBackendService");
  if (update?.Condition?.ArnLike?.["ecs:task-definition"] !== taskDefinitionArn) failures.push("UpdateService must accept only the reviewed backend task-definition family.");
  const tagOnCreate = statement(role, "TagOnlyReviewedStagingBackendTaskDefinitionOnRegistration");
  if (!same(asArray(tagOnCreate?.Action), ["ecs:TagResource"]) || tagOnCreate?.Condition?.StringEquals?.["ecs:CreateAction"] !== "RegisterTaskDefinition") failures.push("TagResource must be limited to RegisterTaskDefinition tag-on-create.");
  const execute = statement(role, "ExecuteIdentityProofOnlyInReviewedBackendContainer");
  if (!resourceIs(execute?.Resource, [clusterArn, taskArn]) || execute?.Condition?.StringEquals?.["ecs:container-name"] !== "backend" || execute?.Condition?.StringEquals?.["ecs:cluster"] !== clusterArn) failures.push("ExecuteCommand must be constrained to the reviewed cluster tasks and backend container.");
  const passRole = statement(role, "PassOnlyReviewedStagingBackendTaskRolesToEcs");
  if (!resourceIs(passRole?.Resource, [`arn:aws:iam::${accountId}:role/mscqr-staging-ecs-execution-role`, `arn:aws:iam::${accountId}:role/mscqr-staging-ecs-task-role`]) || passRole?.Condition?.StringEquals?.["iam:PassedToService"] !== "ecs-tasks.amazonaws.com") failures.push("PassRole must be limited to the exact task roles and ECS tasks service.");
  const kms = statement(role, "GenerateOnlyStagingExecSessionDataKey");
  if (!resourceIs(kms?.Resource, "${STAGING_ECS_EXEC_KMS_KEY_ARN}")) failures.push("KMS permission must retain the exact staging key substitution token.");
}

const terraform = fs.readFileSync(path.join(root, "infra/terraform/staging-api/main.tf"), "utf8");
const terraformPolicy = terraform.match(/resource "aws_iam_role_policy" "database_role_cutover"[\s\S]*?(?=\nresource |$)/)?.[0] || "";
for (const required of [roleName, "aws:MultiFactorAuthPresent", "ecs:RegisterTaskDefinition", "ecs:TagResource", "ecs:CreateAction", "ecs:UpdateService", "ecs:ExecuteCommand", "secretsmanager:DescribeSecret", "iam:PassedToService", "aws_kms_key.ecs_exec_logs.arn"]) if (!terraform.includes(required)) failures.push(`Terraform cutover role is missing ${required}.`);
for (const forbidden of ["lambda:InvokeFunction", "secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue", "rds:ModifyDBInstance", "ecs:RunTask", "ecs:UntagResource"]) if (terraformPolicy.includes(forbidden)) failures.push(`Terraform cutover role contains forbidden action ${forbidden}.`);

if (failures.length) {
  console.error("Staging database-role cutover IAM lint failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}
console.log("Staging database-role cutover IAM lint passed.");
console.log(`Validated dedicated MFA-gated role ${roleName} with no Lambda, secret-value, RDS, or database mutation permission.`);

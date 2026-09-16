import assert from "node:assert/strict";
import fs from "node:fs";
import { APP_ONLY } from "./production-app-only-contract.mjs";
import { canonicalJson, STAGE_B } from "./production-green-stage-b-contract.mjs";
import { parseEcsSecretsManagerReference } from "./production-ecs-runtime-dependencies.mjs";

export const APP_ONLY_VERIFIER = Object.freeze({
  family: "mscqr-production-app-only-compatibility-verifier",
  roleName: "mscqr-production-app-only-verifier-launcher",
  taskRoleArn: `arn:aws:iam::${APP_ONLY.account}:role/mscqr-production-full-rls-green-read-only-canary-task`,
  executionRoleArn: `arn:aws:iam::${APP_ONLY.account}:role/mscqr-production-full-rls-green-read-only-canary-execution`,
  logGroup: "/ecs/mscqr-production/rls-green-read-only-canary",
  database: "mscqr_production_rls_green_phase2",
  databaseRole: "mscqr_prod_rls_canary_read",
  databaseSecretName: "mscqr/production/rls-green/phase4/read-only-canary-database-url",
});
export const APP_ONLY_PROVISIONING = Object.freeze({
  roleName: "mscqr-production-app-only-permission-provisioner",
  roleArn: `arn:aws:iam::${APP_ONLY.account}:role/mscqr-production-app-only-permission-provisioner`,
  deployerBoundaryArn: `arn:aws:iam::${APP_ONLY.account}:policy/MSCQRProductionAppOnlyDeployerBoundary`,
  verifierBoundaryArn: `arn:aws:iam::${APP_ONLY.account}:policy/MSCQRProductionAppOnlyVerifierBoundary`,
  inlinePolicyName: "app-only-exact-capability",
});
const familyArn = (family) => `arn:aws:ecs:${APP_ONLY.region}:${APP_ONLY.account}:task-definition/${family}:*`;
const regional = { StringEquals: { "aws:RequestedRegion": APP_ONLY.region } };
const allow = (Sid, Action, Resource, Condition = regional) => ({ Sid, Effect: "Allow", Action, Resource, ...(Condition === null ? {} : { Condition }) });
const passRoles = (roles) => allow("PassExactTaskRoles", "iam:PassRole", roles, { StringEquals: { "iam:PassedToService": "ecs-tasks.amazonaws.com" } });

// Compatibility preparation authority, never attached to the app deployer.
// Source-derived secret metadata is readable; only the five reviewed JSON
// selectors need values. Neither application nor canary DB credentials are
// readable by the launcher (ECS delivers the canary secret to its task).
export function appOnlyCompatibilityReadPolicy() {
  const template = JSON.parse(fs.readFileSync(new URL("../../infra/aws/terraform/production-green-stage-b/task-definitions/green-backend-candidate.json", import.meta.url), "utf8"));
  const secrets = template.containerDefinitions[0].secrets;
  const metadata = [...new Set(secrets.map(({ valueFrom }) => parseEcsSecretsManagerReference(valueFrom).resource))].sort();
  const selectorNames = ["AUTH_MFA_ENCRYPTION_KEY", "JWT_SECRET", "QR_SIGN_PRIVATE_KEY", "QR_SIGN_PUBLIC_KEY", "REDIS_URL"];
  const selected = secrets.filter(({ name }) => selectorNames.includes(name));
  assert.deepEqual(selected.map(({ name }) => name).sort(), [...selectorNames].sort());
  const prefix = `arn:aws:secretsmanager:${APP_ONLY.region}:${APP_ONLY.account}:secret:`;
  const values = selected.map(({ valueFrom }) => parseEcsSecretsManagerReference(valueFrom).resource).sort();
  assert.ok(values.every((arn) => arn.startsWith(`${prefix}mscqr/prod/`) && !arn.includes("database")));
  return { Version: "2012-10-17", Statement: [
    ...appOnlyDeployerPolicy().Statement.filter(({ Sid }) => ["ReadExactService", "ReadRegionalTaskDefinitions", "ReadProductionTasks", "ListProductionTasks", "ReadCallerIdentity"].includes(Sid)),
    allow("ReadRuntimeIam", ["iam:GetRole", "iam:GetRolePolicy", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies", "iam:SimulatePrincipalPolicy"],
      [APP_ONLY.taskRoleArn, APP_ONLY.executionRoleArn, APP_ONLY_VERIFIER.taskRoleArn, APP_ONLY_VERIFIER.executionRoleArn], null),
    allow("ReadPublishedImages", ["ecr:DescribeImages", "ecr:DescribeRepositories", "ecr:GetRepositoryPolicy"],
      ["mscqr-backend", "mscqr-worker"].map((name) => `arn:aws:ecr:${APP_ONLY.region}:${APP_ONLY.account}:repository/${name}`), null),
    allow("ReadRuntimeSecretMetadata", ["secretsmanager:DescribeSecret", "secretsmanager:ListSecretVersionIds", "secretsmanager:GetResourcePolicy"], metadata, null),
    allow("ReadCanarySecretIdentity", "secretsmanager:DescribeSecret", `${prefix}${APP_ONLY_VERIFIER.databaseSecretName}-??????`, null),
    allow("CheckExactJsonSelectors", "secretsmanager:GetSecretValue", values, null),
    // These describe APIs have no resource-level authorization. Fixed adapters
    // constrain IDs/prefixes; the IAM ceiling is the production region.
    allow("ReadRegionalNetworkAndLogMetadata", ["ec2:DescribeSubnets", "ec2:DescribeRouteTables", "ec2:DescribeSecurityGroups", "logs:DescribeLogGroups"], "*"),
    allow("ReadDatabaseConfiguration", "rds:DescribeDBInstances", `arn:aws:rds:${APP_ONLY.region}:${APP_ONLY.account}:db:${STAGE_B.greenDatabaseIdentifier}`, null),
    allow("ReadDatabaseTls", "rds:DescribeDBParameters", `arn:aws:rds:${APP_ONLY.region}:${APP_ONLY.account}:pg:mscqr-production-rls-green-pg18`, null),
    allow("ReadRuntimeEncryptionPolicy", ["kms:DescribeKey", "kms:GetKeyPolicy"], STAGE_B.approvalKmsKeyArn, null),
    allow("ReadSourceOwnedStorageKey", "kms:DescribeKey", `arn:aws:kms:${APP_ONLY.region}:${APP_ONLY.account}:key/*`,
      { "ForAnyValue:StringEquals": { "kms:ResourceAliases": "alias/mscqr-production-rls-green-storage" } }),
  ] };
}

// These are separate identity policies. Never merge the launcher permission
// into the app deployer, even as a convenience during preparation.
export function appOnlyDeployerPolicy() {
  const family = familyArn(APP_ONLY.family);
  return { Version: "2012-10-17", Statement: [
    allow("ActivateCandidateFamilyOnExactService", "ecs:UpdateService", APP_ONLY.serviceArn, {
      StringEquals: { "aws:RequestedRegion": APP_ONLY.region },
      ArnEquals: { "ecs:cluster": APP_ONLY.clusterArn },
      ArnLike: { "ecs:task-definition": family },
    }),
    allow("RegisterImageOnlyCandidate", "ecs:RegisterTaskDefinition", family),
    allow("ReadExactBackendImageViability", "ecr:DescribeImages", `arn:aws:ecr:${APP_ONLY.region}:${APP_ONLY.account}:repository/mscqr-backend`),
    // Registration with preserved tags requires TagResource authorization. The
    // application does not call TagResource separately; CreateAction enforces it.
    allow("PreserveTagsAtRegistration", "ecs:TagResource", family, {
      StringEquals: { "aws:RequestedRegion": APP_ONLY.region, "ecs:CreateAction": "RegisterTaskDefinition" },
    }),
    passRoles([APP_ONLY.taskRoleArn, APP_ONLY.executionRoleArn]),
    allow("ReadExactService", "ecs:DescribeServices", APP_ONLY.serviceArn),
    // AWS gives DescribeTaskDefinition no resource-level scope or family key.
    // Fixed adapters validate the exact ARN; IAM constrains this read by region.
    allow("ReadRegionalTaskDefinitions", "ecs:DescribeTaskDefinition", "*"),
    allow("ReadProductionTasks", "ecs:DescribeTasks", `arn:aws:ecs:${APP_ONLY.region}:${APP_ONLY.account}:task/${APP_ONLY.cluster}/*`, { ...regional, ArnEquals: { "ecs:cluster": APP_ONLY.clusterArn } }),
    // Fargate has no container-instance resource; constrain listing by cluster.
    allow("ListProductionTasks", "ecs:ListTasks", "*", { ...regional, ArnEquals: { "ecs:cluster": APP_ONLY.clusterArn } }),
    allow("ReadCallerIdentity", "sts:GetCallerIdentity", "*", undefined),
  ] };
}

export function appOnlyVerifierLauncherPolicy(exactTaskDefinitionArn) {
  assert.match(exactTaskDefinitionArn || "", new RegExp(`^arn:aws:ecs:${APP_ONLY.region}:${APP_ONLY.account}:task-definition/${APP_ONLY_VERIFIER.family}:[1-9][0-9]*$`));
  return { Version: "2012-10-17", Statement: [
    ...appOnlyCompatibilityReadPolicy().Statement,
    allow("RunExactReadOnlyVerifier", "ecs:RunTask", exactTaskDefinitionArn, {
      StringEquals: { "aws:RequestedRegion": APP_ONLY.region, "ecs:enable-execute-command": "false" },
      ArnEquals: { "ecs:cluster": APP_ONLY.clusterArn },
    }),
    passRoles([APP_ONLY_VERIFIER.taskRoleArn, APP_ONLY_VERIFIER.executionRoleArn]),
    allow("ReadVerifierOutput", "logs:GetLogEvents", `arn:aws:logs:${APP_ONLY.region}:${APP_ONLY.account}:log-group:${APP_ONLY_VERIFIER.logGroup}:log-stream:app-only/*`),
  ] };
}

export function appOnlyProductionOidcTrust() {
  return { Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: "sts:AssumeRoleWithWebIdentity",
    Principal: { Federated: `arn:aws:iam::${APP_ONLY.account}:oidc-provider/token.actions.githubusercontent.com` },
    Condition: { StringEquals: { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
      "token.actions.githubusercontent.com:sub": "repo:T-ej2003/genuine-scan-main:environment:production" } } }] };
}

// Boundary installation is a separate governed bootstrap. The provisioner
// cannot create/change/remove boundaries or alter trust on existing roles.
// Its policy writes therefore cannot turn the two runtime identities into an
// administrator, even if an inline-policy payload were accidentally broadened.
export function appOnlyPermissionProvisionerPolicy() {
  const verifierRole = `arn:aws:iam::${APP_ONLY.account}:role/${APP_ONLY_VERIFIER.roleName}`;
  const verifierFamily = familyArn(APP_ONLY_VERIFIER.family);
  return { Version: "2012-10-17", Statement: [
    ...appOnlyDeployerPolicy().Statement.filter(({ Sid }) => ["ReadExactService", "ReadProductionTasks", "ListProductionTasks"].includes(Sid)),
    ...[[APP_ONLY.roleArn, APP_ONLY_PROVISIONING.deployerBoundaryArn], [verifierRole, APP_ONLY_PROVISIONING.verifierBoundaryArn]].map(([role, boundary], index) =>
      allow(`CreateBoundedRole${index}`, "iam:CreateRole", role, { StringEquals: { "iam:PermissionsBoundary": boundary } })),
    allow("ReadExactAppRoles", ["iam:GetRole", "iam:GetRolePolicy", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies"], [APP_ONLY.roleArn, verifierRole], null),
    allow("ReadImmutableAppBoundaries", ["iam:GetPolicy", "iam:GetPolicyVersion"], [APP_ONLY_PROVISIONING.deployerBoundaryArn, APP_ONLY_PROVISIONING.verifierBoundaryArn], null),
    allow("ProvisionBoundedInlinePolicies", "iam:PutRolePolicy", [APP_ONLY.roleArn, verifierRole], null),
    allow("RegisterOnlyReadOnlyVerifier", "ecs:RegisterTaskDefinition", verifierFamily),
    allow("ReadRegionalTaskDefinitions", "ecs:DescribeTaskDefinition", "*"),
    passRoles([APP_ONLY_VERIFIER.taskRoleArn, APP_ONLY_VERIFIER.executionRoleArn]),
    allow("SimulateOnlyAppRoles", "iam:SimulatePrincipalPolicy", [APP_ONLY.roleArn, verifierRole], null),
    allow("ReadCallerIdentity", "sts:GetCallerIdentity", "*", undefined),
  ] };
}

// The launcher identity policy selects ONE revision. A reusable outer boundary
// caps every future revision to this verifier family and its fixed task roles.
export function appOnlyVerifierBoundaryPolicy() {
  const policy = appOnlyVerifierLauncherPolicy(`${familyArn(APP_ONLY_VERIFIER.family).slice(0, -1)}1`);
  for (const statement of policy.Statement) {
    if (statement.Sid === "RunExactReadOnlyVerifier") statement.Resource = familyArn(APP_ONLY_VERIFIER.family);
    // Sid labels are not authorization semantics. Omit them from the managed
    // boundary to retain exact scopes within IAM's 6144-character limit.
    delete statement.Sid;
  }
  assert.ok(JSON.stringify(policy).length <= 6144, "Verifier boundary exceeds IAM managed-policy quota");
  return policy;
}

export function appOnlyVerifierNetwork() {
  return { awsvpcConfiguration: { subnets: [...STAGE_B.privateSubnetIds], securityGroups: [STAGE_B.executorSecurityGroupId], assignPublicIp: "DISABLED" } };
}

export function assertAppOnlyVerifierLaunch(request, { taskDefinitionArn, clientToken }) {
  assert.match(clientToken || "", /^[a-f0-9]{64}$/);
  appOnlyVerifierLauncherPolicy(taskDefinitionArn); // Exact family/revision validation.
  const expected = { cluster: APP_ONLY.clusterArn, taskDefinition: taskDefinitionArn,
    launchType: "FARGATE", count: 1, enableExecuteCommand: false,
    clientToken, networkConfiguration: appOnlyVerifierNetwork() };
  assert.equal(canonicalJson(request), canonicalJson(expected), "Verifier launch contains an override or unexpected network/task identity");
  return true;
}

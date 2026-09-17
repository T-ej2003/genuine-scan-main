import test from "node:test";
import assert from "node:assert/strict";
import { appOnlyDeployerPolicy, appOnlyVerifierLauncherPolicy, appOnlyVerifierNetwork, assertAppOnlyVerifierLaunch, APP_ONLY_VERIFIER,
  APP_ONLY_PROVISIONING, appOnlyCompatibilityReadPolicy, appOnlyPermissionProvisionerPolicy, appOnlyVerifierBoundaryPolicy, appOnlyProductionOidcTrust,
  appOnlyRuntimeSecretArns, appOnlySecretMetadataResources } from "../aws/production-app-only-policy.mjs";
import fs from "node:fs";
import { parseEcsSecretsManagerReference } from "../aws/production-ecs-runtime-dependencies.mjs";
import { APP_ONLY } from "../aws/production-app-only-contract.mjs";

const verifierArn = `arn:aws:ecs:${APP_ONLY.region}:${APP_ONLY.account}:task-definition/${APP_ONLY_VERIFIER.family}:1`;
test("task-definition readback uses AWS-supported regional scope without widening mutations", () => {
  for (const policy of [appOnlyDeployerPolicy(), appOnlyCompatibilityReadPolicy(), appOnlyVerifierLauncherPolicy(verifierArn), appOnlyPermissionProvisionerPolicy()]) {
    const reads = policy.Statement.filter(({ Action }) => Action === "ecs:DescribeTaskDefinition");
    assert.equal(reads.length, 1);
    assert.equal(reads[0].Resource, "*");
    assert.deepEqual(reads[0].Condition, { StringEquals: { "aws:RequestedRegion": APP_ONLY.region } });
    for (const statement of policy.Statement.filter(({ Action }) => ["ecs:RegisterTaskDefinition", "ecs:UpdateService", "ecs:RunTask"].includes(Action)))
      assert.notEqual(statement.Resource, "*");
  }
});
test("app principal has no verifier, credential, IAM-write or state-write capability", () => {
  const policy = appOnlyDeployerPolicy();
  const actions = policy.Statement.flatMap(({ Action }) => Action);
  assert.deepEqual(actions.sort(), ["ecr:DescribeImages", "ecs:UpdateService", "ecs:RegisterTaskDefinition", "ecs:TagResource", "iam:PassRole", "ecs:DescribeServices", "ecs:DescribeTaskDefinition", "ecs:DescribeTasks", "ecs:ListTasks", "sts:GetCallerIdentity"].sort());
  assert.equal(policy.Statement.find(({ Action }) => Action === "ecr:DescribeImages").Resource, `arn:aws:ecr:${APP_ONLY.region}:${APP_ONLY.account}:repository/mscqr-backend`);
  const update = policy.Statement.find(({ Action }) => Action === "ecs:UpdateService");
  assert.equal(update.Resource, APP_ONLY.serviceArn);
  assert.equal(update.Condition.ArnEquals["ecs:cluster"], APP_ONLY.clusterArn);
  assert.equal(update.Condition.ArnLike["ecs:task-definition"], `arn:aws:ecs:${APP_ONLY.region}:${APP_ONLY.account}:task-definition/${APP_ONLY.family}:*`);
  const pass = policy.Statement.find(({ Action }) => Action === "iam:PassRole");
  assert.deepEqual(pass.Resource, [APP_ONLY.taskRoleArn, APP_ONLY.executionRoleArn]);
  assert.deepEqual(pass.Condition, { StringEquals: { "iam:PassedToService": "ecs-tasks.amazonaws.com" } });
  assert.deepEqual(policy.Statement.filter(({ Resource }) => Resource === "*").map(({ Action }) => Action).sort(), ["ecs:DescribeTaskDefinition", "ecs:ListTasks", "sts:GetCallerIdentity"]);
});
test("verifier principal cannot deploy or register and launches only exact revision", () => {
  const policy = appOnlyVerifierLauncherPolicy(verifierArn);
  assert.deepEqual(policy.Statement.flatMap(({ Action }) => Action).sort(), [...appOnlyCompatibilityReadPolicy().Statement.flatMap(({ Action }) => Action),
    "ecs:RunTask", "iam:PassRole", "logs:GetLogEvents"].sort());
  for (const sid of ["ReadExactService", "ReadRegionalTaskDefinitions", "ListProductionTasks"])
    assert.deepEqual(policy.Statement.find((s) => s.Sid === sid), appOnlyDeployerPolicy().Statement.find((s) => s.Sid === sid));
  assert.equal(policy.Statement.find(({ Action }) => Action === "ecs:RunTask").Resource, verifierArn);
  for (const bad of [verifierArn.replace(":1", ":*"), verifierArn.replace(APP_ONLY_VERIFIER.family, "other"), verifierArn.replace(APP_ONLY.account, "000000000000")]) assert.throws(() => appOnlyVerifierLauncherPolicy(bad));
});
test("RunTask rejects all command, environment, network and task substitutions", () => {
  const clientToken = "a".repeat(64);
  const request = { cluster: APP_ONLY.clusterArn, taskDefinition: verifierArn, launchType: "FARGATE", count: 1,
    enableExecuteCommand: false, clientToken, networkConfiguration: appOnlyVerifierNetwork() };
  const expected = { taskDefinitionArn: verifierArn, clientToken };
  assert.equal(assertAppOnlyVerifierLaunch(request, expected), true);
  for (const [key, value] of Object.entries({ overrides: { containerOverrides: [{ command: ["sh"] }] }, cluster: "other", taskDefinition: "other", count: 2, enableExecuteCommand: true, networkConfiguration: {}, clientToken: "b".repeat(64) })) {
    assert.throws(() => assertAppOnlyVerifierLaunch({ ...request, [key]: value }, expected));
  }
});

test("provisioner can create only two boundary-constrained roles and can update only the app deployer's exact trust", () => {
  const policy = appOnlyPermissionProvisionerPolicy();
  const verifierRole = `arn:aws:iam::${APP_ONLY.account}:role/${APP_ONLY_VERIFIER.roleName}`;
  const creates = policy.Statement.filter(({ Action }) => Action === "iam:CreateRole");
  assert.deepEqual(creates.map(({ Resource, Condition }) => [Resource, Condition]), [
    [APP_ONLY.roleArn, { StringEquals: { "iam:PermissionsBoundary": APP_ONLY_PROVISIONING.deployerBoundaryArn } }],
    [verifierRole, { StringEquals: { "iam:PermissionsBoundary": APP_ONLY_PROVISIONING.verifierBoundaryArn } }],
  ]);
  const actions = policy.Statement.flatMap(({ Action }) => Action);
  assert.deepEqual([...new Set(actions)].sort(), ["iam:CreateRole", "iam:GetRole", "iam:GetRolePolicy", "iam:ListRolePolicies",
    "iam:ListAttachedRolePolicies", "iam:PutRolePolicy", "iam:PassRole", "iam:SimulatePrincipalPolicy", "iam:GetPolicy", "iam:GetPolicyVersion",
    "iam:UpdateAssumeRolePolicy", "ecs:RegisterTaskDefinition", "ecs:DescribeTaskDefinition", "ecs:DescribeServices", "ecs:DescribeTasks", "ecs:ListTasks", "sts:GetCallerIdentity"].sort());
  for (const statement of policy.Statement.filter(({ Action }) => [].concat(Action).some((action) => action.startsWith("iam:") && action !== "iam:PassRole"))) {
    const resources = statement.Sid === "ReadImmutableAppBoundaries"
      ? [APP_ONLY_PROVISIONING.deployerBoundaryArn, APP_ONLY_PROVISIONING.verifierBoundaryArn] : [APP_ONLY.roleArn, verifierRole];
    assert.ok([].concat(statement.Resource).every((arn) => resources.includes(arn)));
    assert.equal(statement.Condition?.StringEquals?.["aws:RequestedRegion"], undefined, "Global IAM APIs must not be pinned to an ECS endpoint region");
  }
  const registration = policy.Statement.find(({ Action }) => Action === "ecs:RegisterTaskDefinition");
  assert.equal(registration.Resource, verifierArn.replace(/:1$/, ":*"));
  const pass = policy.Statement.find(({ Action }) => Action === "iam:PassRole");
  assert.deepEqual(pass.Resource, [APP_ONLY_VERIFIER.taskRoleArn, APP_ONLY_VERIFIER.executionRoleArn]);
  assert.deepEqual(pass.Condition, { StringEquals: { "iam:PassedToService": "ecs-tasks.amazonaws.com" } });
  assert.deepEqual(policy.Statement.find(({ Action }) => Action === "iam:UpdateAssumeRolePolicy"), { Sid: "UpdateExactAppDeployerTrust", Effect: "Allow", Action: "iam:UpdateAssumeRolePolicy", Resource: APP_ONLY.roleArn });
});

test("verifier boundary permits family evolution but identity policy selects one revision", () => {
  const exact = appOnlyVerifierLauncherPolicy(verifierArn), boundary = appOnlyVerifierBoundaryPolicy();
  const mutation = (action) => boundary.Statement.find(({ Action }) => [].concat(Action).includes(action));
  assert.deepEqual(mutation("ecs:RunTask").Condition, {
    StringEquals: { "aws:RequestedRegion": APP_ONLY.region, "ecs:enable-execute-command": "false" },
    ArnEquals: { "ecs:cluster": APP_ONLY.clusterArn },
  });
  assert.deepEqual(mutation("iam:PassRole"), { Effect: "Allow", Action: "iam:PassRole",
    Resource: [APP_ONLY_VERIFIER.taskRoleArn, APP_ONLY_VERIFIER.executionRoleArn],
    Condition: { StringEquals: { "iam:PassedToService": "ecs-tasks.amazonaws.com" } } });
  const metadata = mutation("secretsmanager:DescribeSecret");
  assert.deepEqual(metadata.Resource, exact.Statement.find(({ Sid }) => Sid === "ReadRuntimeSecretMetadata").Resource);
  assert.deepEqual(metadata.Action.sort(), ["secretsmanager:DescribeSecret", "secretsmanager:GetResourcePolicy", "secretsmanager:ListSecretVersionIds"].sort());
  assert.ok(JSON.stringify(boundary).length <= 6144);
});

test("compatibility preparation cannot read DB credentials or mutate any production service", () => {
  const policy = appOnlyCompatibilityReadPolicy();
  const actions = policy.Statement.flatMap(({ Action }) => Action);
  assert.ok(actions.every((action) => /:(?:Get|Describe|List|Simulate)/.test(action)));
  assert.ok(!actions.some((action) => /Decrypt|PassRole|RunTask|ExecuteCommand|Put|Update|Create|Delete|Sign/.test(action)));
  const values = policy.Statement.find((s) => s.Sid === "CheckExactJsonSelectors").Resource;
  assert.equal(values.length, 5);
  assert.ok(values.every((arn) => arn.includes(":secret:mscqr/prod/") && !/[?*]/.test(arn) && !arn.includes("database")));
  const metadata = policy.Statement.find((s) => s.Sid === "ReadRuntimeSecretMetadata");
  const template = JSON.parse(fs.readFileSync("infra/aws/terraform/production-green-stage-b/task-definitions/green-backend-candidate.json", "utf8"));
  const staticSecrets = template.containerDefinitions[0].secrets.map(({ valueFrom }) => parseEcsSecretsManagerReference(valueFrom).resource);
  const runtimeSecrets = appOnlyRuntimeSecretArns();
  assert.deepEqual(metadata.Resource, appOnlySecretMetadataResources(staticSecrets, runtimeSecrets));
  assert.ok(runtimeSecrets.every((arn) => metadata.Resource.includes(arn)));
  assert.ok(metadata.Resource.some((arn) => arn.includes("artifact-signing/public-key-current-")));
  assert.equal(new Set(metadata.Resource).size, metadata.Resource.length);
  assert.deepEqual(appOnlySecretMetadataResources([staticSecrets[0]], [staticSecrets[0]], runtimeSecrets),
    appOnlySecretMetadataResources([staticSecrets[0]], runtimeSecrets));
  assert.ok(!metadata.Action.includes("secretsmanager:GetSecretValue"));
  assert.deepEqual(metadata.Action.sort(), ["secretsmanager:DescribeSecret", "secretsmanager:GetResourcePolicy", "secretsmanager:ListSecretVersionIds"].sort());
  assert.ok(metadata.Resource.every((arn) => !arn.includes("*") && !arn.includes("?")));
  assert.ok(runtimeSecrets.filter((arn) => !staticSecrets.includes(arn)).every((arn) => !values.includes(arn)));
  const failedArn = runtimeSecrets.find((arn) => arn.includes("artifact-signing/public-key-current-"));
  assert.ok(metadata.Action.includes("secretsmanager:DescribeSecret") && metadata.Resource.includes(failedArn),
    "Generated reader policy must pass the exact previously denied DescribeSecret boundary");
  assert.ok(metadata.Resource.some((arn) => arn.includes("database-url/app-")));
  assert.ok(JSON.stringify(appOnlyVerifierBoundaryPolicy()).length <= 6144);
  assert.ok(JSON.stringify(appOnlyVerifierLauncherPolicy(verifierArn)).length <= 10240);
});

test("new principals require production approval plus exact role-specific reusable workflow claims", () => {
  assert.throws(() => appOnlyProductionOidcTrust());
  assert.throws(() => appOnlyProductionOidcTrust("unrelated-role"));
  for (const role of [APP_ONLY.roleArn.split("/").at(-1), APP_ONLY_PROVISIONING.roleName, APP_ONLY_VERIFIER.roleName]) {
    const trust = appOnlyProductionOidcTrust(role), condition = trust.Statement[0].Condition.StringEquals;
    assert.equal(trust.Statement.length, 1);
    assert.equal(trust.Statement[0].Action, "sts:AssumeRoleWithWebIdentity");
    assert.equal(condition["token.actions.githubusercontent.com:aud"], "sts.amazonaws.com");
    assert.equal(condition["token.actions.githubusercontent.com:sub"], "repo:T-ej2003/genuine-scan-main:environment:production");
    assert.equal(condition["token.actions.githubusercontent.com:repository_id"], "1145608538");
    assert.equal(condition["token.actions.githubusercontent.com:repository_owner_id"], "183396573");
    assert.equal(condition["token.actions.githubusercontent.com:ref"], "refs/heads/main");
    const refs = condition["token.actions.githubusercontent.com:job_workflow_ref"];
    assert.ok(refs.length > 0 && refs.every((ref) => ref.endsWith(".yml@refs/heads/main") && !ref.includes("*")));
    const deploy = "T-ej2003/genuine-scan-main/.github/workflows/deploy-production-app-only-operation.yml@refs/heads/main";
    const normal = "T-ej2003/genuine-scan-main/.github/workflows/production-deploy.yml@refs/heads/main";
    if (role === APP_ONLY.roleArn.split("/").at(-1)) assert.deepEqual(refs, [deploy, normal]);
    else { assert.ok(!refs.includes(deploy), "Application deployment cannot assume verifier or provisioner identity"); assert.ok(!refs.includes(normal)); }
  }
});

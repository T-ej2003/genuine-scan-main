import test from "node:test";
import assert from "node:assert/strict";
import { appOnlyDeployerPolicy, appOnlyVerifierLauncherPolicy, appOnlyVerifierNetwork, assertAppOnlyVerifierLaunch, APP_ONLY_VERIFIER,
  APP_ONLY_PROVISIONING, appOnlyCompatibilityReadPolicy, appOnlyPermissionProvisionerPolicy, appOnlyVerifierBoundaryPolicy, appOnlyProductionOidcTrust } from "../aws/production-app-only-policy.mjs";
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

test("provisioner can create only two boundary-constrained roles and cannot alter their boundaries or trust", () => {
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
    "ecs:RegisterTaskDefinition", "ecs:DescribeTaskDefinition", "ecs:DescribeServices", "ecs:DescribeTasks", "ecs:ListTasks", "sts:GetCallerIdentity"].sort());
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
});

test("verifier boundary permits family evolution but identity policy selects one revision", () => {
  const exact = appOnlyVerifierLauncherPolicy(verifierArn), boundary = appOnlyVerifierBoundaryPolicy();
  for (let i = 0; i < exact.Statement.length; i++) {
    const expected = structuredClone(exact.Statement[i]);
    if (expected.Sid === "RunExactReadOnlyVerifier") expected.Resource = verifierArn.replace(/:1$/, ":*");
    delete expected.Sid;
    assert.deepEqual(boundary.Statement[i], expected);
  }
  assert.deepEqual(boundary.Statement.find(({ Action }) => Action === "ecs:RunTask").Condition, {
    StringEquals: { "aws:RequestedRegion": APP_ONLY.region, "ecs:enable-execute-command": "false" },
    ArnEquals: { "ecs:cluster": APP_ONLY.clusterArn },
  });
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
  assert.ok(!metadata.Action.includes("secretsmanager:GetSecretValue"));
  assert.ok(metadata.Resource.some((arn) => arn.includes("database-url/app-")));
  assert.ok(JSON.stringify(appOnlyVerifierBoundaryPolicy()).length <= 6144);
  assert.ok(JSON.stringify(appOnlyVerifierLauncherPolicy(verifierArn)).length <= 10240);
});

test("new principals require the exact repository protected production OIDC identity", () => {
  assert.deepEqual(appOnlyProductionOidcTrust(), { Version: "2012-10-17", Statement: [{ Effect: "Allow",
    Action: "sts:AssumeRoleWithWebIdentity", Principal: { Federated: `arn:aws:iam::${APP_ONLY.account}:oidc-provider/token.actions.githubusercontent.com` },
    Condition: { StringEquals: { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
      "token.actions.githubusercontent.com:sub": "repo:T-ej2003/genuine-scan-main:environment:production" } } }] });
});

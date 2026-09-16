import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { assertAppOnlyRuntimeRequirements, collectAppOnlyNetworkDatabaseRuntime, assertAppOnlyRuntimeSimulations } from "../aws/production-app-only-runtime.mjs";
import { APP_ONLY } from "../aws/production-app-only-contract.mjs";
import { STAGE_B } from "../aws/production-green-stage-b-contract.mjs";
import { simulateRuntimeDependencies } from "../aws/production-ecs-runtime-consumability.mjs";

const fixture = () => {
  const definition = JSON.parse(fs.readFileSync("infra/aws/terraform/production-green-stage-b/task-definitions/green-backend-candidate.json", "utf8"));
  Object.assign(definition, { taskDefinitionArn: `arn:aws:ecs:${APP_ONLY.region}:${APP_ONLY.account}:task-definition/${APP_ONLY.family}:14`,
    status: "ACTIVE", runtimePlatform: STAGE_B.taskRuntimePlatform });
  const backend = definition.containerDefinitions[0];
  backend.image = `${APP_ONLY.backendRepository}@sha256:${"1".repeat(64)}`;
  backend.environment.push({ name: "NODE_ENV", value: "production" }, { name: "PORT", value: "4000" }, { name: "RUN_DB_MIGRATIONS_ON_START", value: "false" });
  backend.logConfiguration.options["awslogs-group"] = STAGE_B.inventoryLogGroupName;
  return { repositoryRoot: process.cwd(), definition, service: { networkConfiguration: { awsvpcConfiguration: {
    subnets: [...STAGE_B.privateSubnetIds], securityGroups: ["sg-0123456789abcdef0"], assignPublicIp: "DISABLED" } } } };
};
test("runtime requirements accept source-compatible capacity without requiring a Terraform candidate revision", () => {
  const input = fixture(); input.definition.cpu = "2048"; input.definition.memory = "4096";
  input.definition.containerDefinitions[0].entryPoint = [];
  assert.ok(assertAppOnlyRuntimeRequirements(input).runtimeConfigurationSha256);
});
test("existing scalar JSON envelopes retain source resource identity and require the reviewed selector", () => {
  const input = fixture();
  const secret = input.definition.containerDefinitions[0].secrets.find((s) => s.name === "AUTH_MFA_ENCRYPTION_KEY");
  secret.valueFrom += ":AUTH_MFA_ENCRYPTION_KEY::";
  assert.ok(assertAppOnlyRuntimeRequirements(input).runtimeConfigurationSha256);
  secret.valueFrom = secret.valueFrom.replace(":AUTH_MFA_ENCRYPTION_KEY::", ":arbitrary::");
  assert.throws(() => assertAppOnlyRuntimeRequirements(input), /JSON selector/);
});
test("runtime requirements reject migrations, privilege, arbitrary command/network and source-secret changes", () => {
  for (const mutate of [
    (d) => { d.definition.cpu = "256"; },
    (d) => { d.definition.taskRoleArn += "other"; },
    (d) => { d.definition.containerDefinitions[0].privileged = true; },
    (d) => { d.definition.containerDefinitions[0].readonlyRootFilesystem = false; },
    (d) => { d.definition.containerDefinitions[0].command = ["sh", "-c", "unreviewed"]; },
    (d) => { d.definition.containerDefinitions[0].entryPoint = ["sh"]; },
    (d) => { d.definition.containerDefinitions[0].environment.find((e) => e.name === "RUN_DB_MIGRATIONS_ON_START").value = "true"; },
    (d) => { d.definition.containerDefinitions[0].environment.push({ name: "PORT", value: "4000" }); },
    (d) => { d.definition.containerDefinitions[0].environment.push({ name: "DATABASE_URL", value: "substituted" }); },
    (d) => { d.definition.containerDefinitions[0].secrets[0].valueFrom += "other"; },
    (d) => { d.definition.containerDefinitions[0].portMappings[0].containerPort = 80; },
    (d) => { d.definition.containerDefinitions[0].logConfiguration.options["awslogs-group"] = "/other"; },
    (d) => { d.service.networkConfiguration.awsvpcConfiguration.assignPublicIp = "ENABLED"; },
    (d) => { d.service.networkConfiguration.awsvpcConfiguration.subnets = ["subnet-foreign"]; },
  ]) {
    const input = fixture(); mutate(input); assert.throws(() => assertAppOnlyRuntimeRequirements(input));
  }
});
test("exact inline logging simulation does not require a legacy wildcard permission", async () => {
  const dependency = { dependencyId: "fixture", principalArn: APP_ONLY.executionRoleArn, action: "logs:PutLogEvents",
    resource: `arn:aws:logs:${APP_ONLY.region}:${APP_ONLY.account}:log-group:${STAGE_B.inventoryLogGroupName}:log-stream:*` };
  const seen = [];
  const aws = async (args) => {
    const resource = args[args.indexOf("--resource-arns") + 1]; seen.push(resource);
    const action = args[args.indexOf("--action-names") + 1];
    assert.equal(action, "logs:putlogevents", "Resource-scoped simulation must normalize IAM action casing");
    return { EvaluationResults: [{ EvalActionName: action, EvalResourceName: resource, EvalDecision: "allowed" }] };
  };
  assert.equal((await simulateRuntimeDependencies([dependency], aws, { loggingResourceMode: "exact-dependency" })).fixture.decision, "allowed");
  await simulateRuntimeDependencies([dependency], aws);
  assert.deepEqual(seen, [dependency.resource, "*"]);
  await assert.rejects(simulateRuntimeDependencies([dependency], aws, { loggingResourceMode: "unreviewed" }));
});

test("runtime simulation mismatch stays unproven and cannot authorize from another action/resource", () => {
  const dependency = { dependencyId: "fixture", principalArn: APP_ONLY.executionRoleArn, action: "logs:PutLogEvents",
    resource: "reviewed-log-stream", source: "containerDefinitions[name=backend].logConfiguration" };
  const success = { fixture: { principalArn: dependency.principalArn, action: dependency.action, resource: dependency.resource, decision: "allowed" } };
  assert.equal(assertAppOnlyRuntimeSimulations([dependency], success), true);
  for (const [key, value] of Object.entries({ decision: "denied", principalArn: "another-role", action: "logs:CreateLogStream", resource: "*" })) {
    const report = structuredClone(success); report.fixture[key] = value;
    assert.throws(() => assertAppOnlyRuntimeSimulations([dependency], report), (error) => {
      assert.equal(error.unprovenCapabilities.length, 1);
      assert.equal(error.unprovenCapabilities[0].action, dependency.action);
      assert.match(error.unprovenCapabilities[0].resourceSha256, /^[a-f0-9]{64}$/);
      assert.equal(JSON.stringify(error.unprovenCapabilities).includes(dependency.resource), false);
      return true;
    });
  }
});

function networkFixture() {
  const input = fixture(), vpcId = "vpc-aaa";
  const runtimeGroup = input.service.networkConfiguration.awsvpcConfiguration.securityGroups[0];
  const kmsArn = `arn:aws:kms:${APP_ONLY.region}:${APP_ONLY.account}:key/11111111-1111-1111-1111-111111111111`;
  const responses = {
    "describe-subnets": { Subnets: STAGE_B.privateSubnetIds.map((SubnetId, i) => ({ SubnetId, VpcId: vpcId,
      State: "available", MapPublicIpOnLaunch: false, OwnerId: APP_ONLY.account, AvailabilityZone: `${APP_ONLY.region}${i ? "b" : "a"}` })) },
    "describe-route-tables": { RouteTables: [{ VpcId: vpcId, RouteTableId: "rtb-0123456789abcdef0", Associations: [{ Main: true }],
      Routes: [{ DestinationCidrBlock: "0.0.0.0/0", NatGatewayId: "nat-0123456789abcdef0", State: "active" }] }] },
    "describe-security-groups": { SecurityGroups: [runtimeGroup, STAGE_B.databaseSecurityGroupId, STAGE_B.executorSecurityGroupId].map((GroupId) => ({ GroupId, VpcId: vpcId, OwnerId: APP_ONLY.account,
      IpPermissions: GroupId === STAGE_B.databaseSecurityGroupId ? [{ IpProtocol: "tcp", FromPort: 5432, ToPort: 5432,
        UserIdGroupPairs: [runtimeGroup, STAGE_B.executorSecurityGroupId].map((id) => ({ GroupId: id, UserId: APP_ONLY.account })) }] : [] })) },
    "describe-db-instances": { DBInstances: [{ DBInstanceIdentifier: STAGE_B.greenDatabaseIdentifier,
      DBInstanceArn: `arn:aws:rds:${APP_ONLY.region}:${APP_ONLY.account}:db:${STAGE_B.greenDatabaseIdentifier}`,
      Engine: "postgres", EngineVersion: "18.4", DBInstanceStatus: "available", PubliclyAccessible: false,
      StorageEncrypted: true, MultiAZ: true, DeletionProtection: true, PendingModifiedValues: {},
      DBSubnetGroup: { VpcId: vpcId, SubnetGroupStatus: "Complete", Subnets: STAGE_B.privateSubnetIds.map((id) => ({ SubnetIdentifier: id, SubnetStatus: "Active" })) },
      VpcSecurityGroups: [{ VpcSecurityGroupId: STAGE_B.databaseSecurityGroupId, Status: "active" }],
      Endpoint: { Address: "reviewed.eu-west-2.rds.amazonaws.com", Port: 5432 },
      DBParameterGroups: [{ DBParameterGroupName: "mscqr-production-rls-green-pg18", ParameterApplyStatus: "in-sync" }], KmsKeyId: kmsArn }] },
    "describe-db-parameters": { Parameters: [{ ParameterName: "rds.force_ssl", ParameterValue: "1", Source: "system" }] },
    "describe-key": { KeyMetadata: { Arn: kmsArn, AWSAccountId: APP_ONLY.account, KeyState: "Enabled", KeyUsage: "ENCRYPT_DECRYPT" } },
  };
  const calls = [];
  return { input, responses, calls, aws: async (args) => { calls.push(args); assert.ok(Object.hasOwn(responses, args[1])); return structuredClone(responses[args[1]]); } };
}

test("runtime network/database proof is read-only and independent of Terraform state", async () => {
  const f = networkFixture();
  const result = await collectAppOnlyNetworkDatabaseRuntime({ ...f.input, aws: f.aws });
  assert.equal(result.databaseHostname, "reviewed.eu-west-2.rds.amazonaws.com");
  assert.equal(result.routes.length, 2);
  assert.deepEqual(f.calls.map((c) => c.slice(0, 2)), [["ec2", "describe-subnets"], ["ec2", "describe-route-tables"],
    ["ec2", "describe-security-groups"], ["rds", "describe-db-instances"], ["rds", "describe-db-parameters"], ["kms", "describe-key"]]);
  assert.ok(!f.calls.find((c) => c[1] === "describe-db-parameters").includes("--source"), "Effective system defaults must not be filtered out");
});

test("network/database proof rejects missing, public, foreign, pending, unencrypted or TLS-disabled resources", async () => {
  const attacks = [
    (r) => { r["describe-subnets"].Subnets.pop(); },
    (r) => { r["describe-subnets"].Subnets[0].OwnerId = "000000000000"; },
    (r) => { r["describe-subnets"].Subnets[0].MapPublicIpOnLaunch = true; },
    (r) => { r["describe-subnets"].Subnets[0].VpcId = "vpc-bbb"; },
    (r) => { r["describe-route-tables"].RouteTables[0].Routes[0].State = "blackhole"; },
    (r) => { r["describe-route-tables"].RouteTables[0].Routes.push({ DestinationIpv6CidrBlock: "::/0", GatewayId: "igw-0123456789abcdef0" }); },
    (r) => { r["describe-security-groups"].SecurityGroups[1].IpPermissions[0].IpRanges = [{ CidrIp: "0.0.0.0/0" }]; },
    (r) => { r["describe-security-groups"].SecurityGroups[1].IpPermissions[0].UserIdGroupPairs[0].UserId = "000000000000"; },
    (r) => { r["describe-security-groups"].SecurityGroups[1].IpPermissions[0].UserIdGroupPairs.pop(); },
    (r) => { r["describe-db-instances"].DBInstances[0].PubliclyAccessible = true; },
    (r) => { r["describe-db-instances"].DBInstances[0].StorageEncrypted = false; },
    (r) => { r["describe-db-instances"].DBInstances[0].EngineVersion = "17.9"; },
    (r) => { r["describe-db-instances"].DBInstances[0].PendingModifiedValues = { EngineVersion: "18.5" }; },
    (r) => { r["describe-db-instances"].DBInstances[0].DBParameterGroups[0].ParameterApplyStatus = "pending-reboot"; },
    (r) => { r["describe-db-parameters"].Parameters[0].ParameterValue = "0"; },
    (r) => { r["describe-db-parameters"].Marker = "unread-page"; },
    (r) => { r["describe-key"].KeyMetadata.KeyState = "PendingDeletion"; },
    (r) => { r["describe-key"].KeyMetadata.Arn += "other"; },
  ];
  for (const attack of attacks) {
    const f = networkFixture(); attack(f.responses);
    await assert.rejects(collectAppOnlyNetworkDatabaseRuntime({ ...f.input, aws: f.aws }));
  }
});

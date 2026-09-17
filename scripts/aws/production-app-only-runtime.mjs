import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { APP_ONLY, assertAppOnlyDefinition, assertAppOnlySessionRiskConfiguration, assertAppOnlyCas, captureAppOnlyPredecessor, assertAppOnlyCandidate, assertAppOnlyEvidenceIdentity } from "./production-app-only-contract.mjs";
import { STAGE_B, canonicalSha256 } from "./production-green-stage-b-contract.mjs";
import { deriveEcsRuntimeDependencies, collectRuntimeResourceMetadata, addEncryptionDependencies, simulateRuntimeDependencies } from "./production-ecs-runtime-consumability.mjs";
import { parseEcsSecretsManagerReference } from "./production-ecs-runtime-dependencies.mjs";
import { resolveStageASubnetRouteTable } from "./generate-production-green-stage-a-prerequisites.mjs";

// This is the source-owned runtime subset, not a claim that Terraform state or
// every account resource is clean. Source evolution must review this mapping.
export async function collectAppOnlyNetworkDatabaseRuntime({ aws, service, repositoryRoot }) {
  const source = fs.readFileSync(path.join(repositoryRoot, "infra/aws/terraform/production-green-stage-a/main.tf"), "utf8");
  assert.equal(canonicalSha256(source), "7424a2ed4a2ffc5864756b1f4e8e56a8ce3743c59db4c352f6fe7c0cb9db4a3a", "Stage-A runtime source mapping is unreviewed");
  const network = service.networkConfiguration?.awsvpcConfiguration;
  assert.equal(network?.assignPublicIp, "DISABLED");
  assert.deepEqual([...network.subnets].sort(), [...STAGE_B.privateSubnetIds].sort());
  assert.equal(network.securityGroups?.length, 1);
  const runtimeGroup = network.securityGroups[0]; assert.match(runtimeGroup, /^sg-[a-f0-9]+$/);
  const { Subnets: subnets, NextToken: subnetToken } = await aws(["ec2", "describe-subnets", "--subnet-ids", ...STAGE_B.privateSubnetIds]);
  assert.equal(subnetToken, undefined);
  assert.deepEqual(subnets.map((s) => s.SubnetId).sort(), [...STAGE_B.privateSubnetIds].sort());
  const vpcId = subnets[0].VpcId; assert.match(vpcId, /^vpc-[a-f0-9]+$/);
  assert.ok(subnets.every((s) => s.VpcId === vpcId && s.State === "available" && s.MapPublicIpOnLaunch === false && s.OwnerId === APP_ONLY.account));
  assert.equal(new Set(subnets.map((s) => s.AvailabilityZone)).size, 2);
  const routeResponse = await aws(["ec2", "describe-route-tables", "--filters", `Name=vpc-id,Values=${vpcId}`]);
  assert.equal(routeResponse.NextToken, undefined);
  const routes = subnets.map((s) => {
    const resolved = resolveStageASubnetRouteTable({ routeTables: routeResponse.RouteTables, vpcId, subnetId: s.SubnetId });
    assert.ok(resolved.table.Routes.some((r) => r.DestinationCidrBlock === "0.0.0.0/0" && r.NatGatewayId === resolved.natGatewayId && r.State === "active"));
    assert.ok(!resolved.table.Routes.some((r) => r.GatewayId?.startsWith("igw-") && ["0.0.0.0/0", "::/0"].includes(r.DestinationCidrBlock || r.DestinationIpv6CidrBlock)), "Public internet route is not private networking");
    return { subnetId: s.SubnetId, routeTableId: resolved.table.RouteTableId, natGatewayId: resolved.natGatewayId };
  }).sort((a, b) => a.subnetId.localeCompare(b.subnetId));
  const groupIds = [...new Set([runtimeGroup, STAGE_B.databaseSecurityGroupId, STAGE_B.executorSecurityGroupId])].sort();
  const groups = await aws(["ec2", "describe-security-groups", "--group-ids", ...groupIds]);
  assert.equal(groups.NextToken, undefined);
  assert.deepEqual(groups.SecurityGroups.map((g) => g.GroupId).sort(), groupIds);
  assert.ok(groups.SecurityGroups.every((g) => g.VpcId === vpcId && g.OwnerId === APP_ONLY.account));
  const databaseGroup = groups.SecurityGroups.find((g) => g.GroupId === STAGE_B.databaseSecurityGroupId);
  const permittedSources = new Set([runtimeGroup, STAGE_B.executorSecurityGroupId]);
  const observedSources = new Set();
  assert.ok(databaseGroup.IpPermissions.length > 0);
  for (const rule of databaseGroup.IpPermissions) {
    assert.equal(rule.IpProtocol, "tcp"); assert.equal(rule.FromPort, 5432); assert.equal(rule.ToPort, 5432);
    for (const key of ["IpRanges", "Ipv6Ranges", "PrefixListIds"]) assert.equal((rule[key] || []).length, 0, "Unreviewed database ingress");
    assert.ok(rule.UserIdGroupPairs?.length > 0);
    for (const pair of rule.UserIdGroupPairs) {
      assert.ok(permittedSources.has(pair.GroupId)); assert.equal(pair.UserId, APP_ONLY.account);
      assert.ok(!pair.VpcPeeringConnectionId && (!pair.VpcId || pair.VpcId === vpcId));
      observedSources.add(pair.GroupId);
    }
  }
  assert.deepEqual([...observedSources].sort(), [...permittedSources].sort());
  const response = await aws(["rds", "describe-db-instances", "--db-instance-identifier", STAGE_B.greenDatabaseIdentifier]);
  assert.equal(response.Marker, undefined); assert.equal(response.DBInstances?.length, 1);
  const db = response.DBInstances[0];
  assert.equal(db.DBInstanceIdentifier, STAGE_B.greenDatabaseIdentifier);
  assert.equal(db.DBInstanceArn, `arn:aws:rds:${APP_ONLY.region}:${APP_ONLY.account}:db:${STAGE_B.greenDatabaseIdentifier}`);
  assert.equal(db.Engine, "postgres"); assert.match(db.EngineVersion, /^18\.[0-9]+$/);
  assert.ok(Number(db.EngineVersion.split(".")[1]) >= 4);
  for (const [key, value] of Object.entries({ DBInstanceStatus: "available", PubliclyAccessible: false, StorageEncrypted: true, MultiAZ: true, DeletionProtection: true })) assert.equal(db[key], value);
  assert.equal(Object.keys(db.PendingModifiedValues || {}).length, 0, "Pending database configuration change");
  assert.equal(db.DBSubnetGroup?.VpcId, vpcId); assert.equal(db.DBSubnetGroup.SubnetGroupStatus, "Complete");
  assert.deepEqual(db.DBSubnetGroup.Subnets.map((s) => s.SubnetIdentifier).sort(), [...STAGE_B.privateSubnetIds].sort());
  assert.ok(db.DBSubnetGroup.Subnets.every((s) => s.SubnetStatus === "Active"));
  assert.deepEqual(db.VpcSecurityGroups, [{ VpcSecurityGroupId: STAGE_B.databaseSecurityGroupId, Status: "active" }]);
  assert.equal(db.Endpoint?.Port, 5432);
  assert.match(db.Endpoint.Address, /^[a-z0-9.-]+\.eu-west-2\.rds\.amazonaws\.com$/);
  assert.equal(db.DBParameterGroups?.length, 1); assert.equal(db.DBParameterGroups[0].ParameterApplyStatus, "in-sync");
  assert.equal(db.DBParameterGroups[0].DBParameterGroupName, "mscqr-production-rls-green-pg18");
  // Effective defaults count: RDS may materialize force_ssl=1 as Source=system
  // even when Terraform declares the same value. Filtering to user settings
  // would falsely reject the enforced value (or miss an unsafe default).
  const parameters = await aws(["rds", "describe-db-parameters", "--db-parameter-group-name", db.DBParameterGroups[0].DBParameterGroupName]);
  assert.equal(parameters.Marker, undefined);
  const forceTls = parameters.Parameters?.filter((p) => p.ParameterName === "rds.force_ssl");
  assert.equal(forceTls?.length, 1); assert.equal(forceTls[0].ParameterValue, "1");
  const key = (await aws(["kms", "describe-key", "--key-id", `arn:aws:kms:${APP_ONLY.region}:${APP_ONLY.account}:alias/mscqr-production-rls-green-storage`])).KeyMetadata;
  assert.equal(key?.Arn, db.KmsKeyId); assert.equal(key.AWSAccountId, APP_ONLY.account);
  assert.equal(key.KeyState, "Enabled"); assert.equal(key.KeyUsage, "ENCRYPT_DECRYPT");
  return { sourceConfigurationSha256: canonicalSha256(source), vpcId, routes,
    securityGroupsSha256: canonicalSha256(groups.SecurityGroups.sort((a, b) => a.GroupId.localeCompare(b.GroupId))),
    databaseArn: db.DBInstanceArn, databaseHostname: db.Endpoint.Address, engineVersion: db.EngineVersion,
    databaseConfigurationSha256: canonicalSha256({ network: db.DBSubnetGroup, securityGroups: db.VpcSecurityGroups,
      parameterGroup: db.DBParameterGroups, forceTls: forceTls[0].ParameterValue, kmsKeyArn: key.Arn }) };
}

// Candidate requirements, not equality to a stale Terraform task revision.
// Every retained task field is separately bound by the image-only clone/CAS.
export function assertAppOnlyRuntimeRequirements({ definition, service, repositoryRoot }) {
  const backend = assertAppOnlyDefinition(definition);
  assertAppOnlySessionRiskConfiguration(definition);
  const template = JSON.parse(fs.readFileSync(path.join(repositoryRoot, "infra/aws/terraform/production-green-stage-b/task-definitions/green-backend-candidate.json"), "utf8"));
  const required = template.containerDefinitions[0];
  for (const field of ["cpu", "memory"]) {
    assert.match(definition[field], /^[1-9][0-9]*$/);
    assert.ok(Number(definition[field]) >= Number(template[field]), `Insufficient task ${field}`);
  }
  assert.equal(backend.privileged ?? false, false);
  assert.equal(backend.readonlyRootFilesystem, true);
  assert.deepEqual(definition.requiresCompatibilities, ["FARGATE"]);
  assert.equal(backend.repositoryCredentials, undefined);
  assert.equal((backend.environmentFiles || []).length, 0);
  assert.ok((backend.entryPoint || []).length === 0 || JSON.stringify(backend.entryPoint) === JSON.stringify(required.entryPoint), "Unreviewed runtime entrypoint");
  assert.equal((backend.command || []).length, 0, "Unreviewed runtime command");
  const environment = new Map((backend.environment || []).map(({ name, value }) => [name, value]));
  const secrets = new Map((backend.secrets || []).map(({ name, valueFrom }) => [name, valueFrom]));
  assert.equal(environment.size, (backend.environment || []).length); assert.equal(secrets.size, (backend.secrets || []).length);
  assert.ok([...environment.keys()].every((key) => !secrets.has(key)), "Environment/secret name collision");
  for (const [name, value] of Object.entries({ NODE_ENV: "production", PORT: "4000", RUN_DB_MIGRATIONS_ON_START: "false",
    COOKIE_SECURE: "true", RUN_BACKGROUND_WORKERS: "false", OBJECT_STORAGE_BUCKET: STAGE_B.receiptBucket, OBJECT_STORAGE_REGION: APP_ONLY.region })) {
    assert.equal(environment.get(name), value, `Unproven application configuration: ${name}`);
  }
  for (const { name, valueFrom } of required.secrets) {
    const expected = parseEcsSecretsManagerReference(valueFrom), observed = parseEcsSecretsManagerReference(secrets.get(name));
    assert.equal(observed.resource, expected.resource, `Required source secret resource changed: ${name}`);
    // Existing governed rotation stores some scalar values in JSON envelopes.
    // Preserve the live selector, never rewrite it. Its key and version must
    // subsequently be proven by the canonical resource-consumability reader.
    assert.ok(expected.jsonKey ? observed.jsonKey === expected.jsonKey : [null, "value", name].includes(observed.jsonKey), `Unreviewed secret JSON selector: ${name}`);
    assert.equal(observed.versionStage, expected.versionStage);
    assert.equal(observed.versionId, expected.versionId);
  }
  for (const reference of secrets.values()) parseEcsSecretsManagerReference(reference);
  assert.deepEqual(backend.portMappings, required.portMappings);
  assert.deepEqual(backend.mountPoints, required.mountPoints);
  assert.equal(backend.logConfiguration?.logDriver, "awslogs");
  assert.deepEqual(backend.logConfiguration.options, { "awslogs-region": APP_ONLY.region, "awslogs-group": STAGE_B.inventoryLogGroupName, "awslogs-stream-prefix": "stage-b" });
  const network = service.networkConfiguration?.awsvpcConfiguration;
  assert.equal(network?.assignPublicIp, "DISABLED");
  assert.deepEqual([...network.subnets].sort(), [...STAGE_B.privateSubnetIds].sort());
  assert.ok(Array.isArray(network.securityGroups) && network.securityGroups.length === 1 && /^sg-[a-f0-9]+$/.test(network.securityGroups[0]));
  return { requiredDefinitionSha256: canonicalSha256(template), runtimeConfigurationSha256: canonicalSha256({ definition, network }) };
}

// Must run under the compatibility identity, never the app deployer. The
// existing resource reader may read selected JSON secrets solely to prove key
// presence; it returns metadata only. No secret value is retained as evidence.
export function assertAppOnlyRuntimeSimulations(dependencies, simulations) {
  assert.ok(dependencies.length > 0);
  const unproven = dependencies.filter(({ dependencyId, principalArn, action, resource }) => {
    const observed = simulations[dependencyId];
    return observed?.decision !== "allowed" || observed.principalArn !== principalArn || observed.action !== action || observed.resource !== resource;
  }).map(({ action, source, resource }) => ({ action, source, resourceSha256: canonicalSha256(resource) }));
  if (unproven.length) throw Object.assign(new Error("Candidate runtime capability is unproven"), { unprovenCapabilities: unproven });
  return true;
}

export async function collectAppOnlyRuntimeCompatibility({ identity, candidate, predecessor, readLive, aws, repositoryRoot, now = Date.now }) {
  const before = await readLive();
  assertAppOnlyCas(predecessor, captureAppOnlyPredecessor(before));
  assert.equal(identity.predecessorTaskDefinition, predecessor.taskDefinitionArn);
  assert.equal(identity.predecessorBackendDigest, predecessor.backendDigest);
  assertAppOnlyCandidate(before.definition, candidate, identity.candidateDigest);
  const requirements = assertAppOnlyRuntimeRequirements({ definition: before.definition, service: before.service, repositoryRoot });
  const caller = await aws(["sts", "get-caller-identity"]); assert.equal(caller.Account, APP_ONLY.account);
  const networkDatabase = await collectAppOnlyNetworkDatabaseRuntime({ aws, service: before.service, repositoryRoot });
  const readKmsKey = async (arn) => ({ metadata: (await aws(["kms", "describe-key", "--key-id", arn])).KeyMetadata,
    policy: (await aws(["kms", "get-key-policy", "--key-id", arn, "--policy-name", "default"])).Policy });
  const resourceMetadata = await collectRuntimeResourceMetadata(candidate, aws, { readKmsKey });
  const dependencies = addEncryptionDependencies(candidate, deriveEcsRuntimeDependencies(candidate), resourceMetadata);
  // Stage-B has exact inline log resources, not the legacy AWS-managed
  // Resource:"*" grant. Source/live policy equality is checked independently.
  const simulations = await simulateRuntimeDependencies(dependencies, aws, { loggingResourceMode: "exact-dependency" });
  assertAppOnlyRuntimeSimulations(dependencies, simulations);
  assertAppOnlyCas(predecessor, captureAppOnlyPredecessor(await readLive()));
  assert.deepEqual(await collectAppOnlyNetworkDatabaseRuntime({ aws, service: before.service, repositoryRoot }), networkDatabase, "Network/database changed during compatibility collection");
  const body = { schemaVersion: 1, kind: "APP_ONLY_RUNTIME_COMPATIBILITY", identity, generatedAt: new Date(now()).toISOString(),
    requirements, networkDatabase, resourceMetadata, dependencies, simulations, status: "ALREADY_APPLIED_COMPATIBLE" };
  const evidence = { ...body, evidenceSha256: canonicalSha256(body) };
  assertAppOnlyEvidenceIdentity(evidence, identity, now());
  return evidence;
}

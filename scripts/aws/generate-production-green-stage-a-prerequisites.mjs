#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { STAGE_B } from "./production-green-stage-b-contract.mjs";
import { assertStageBPrivateFile, writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";

export const STAGE_A_PREREQUISITES_GENERATOR = "scripts/aws/generate-production-green-stage-a-prerequisites.mjs";
export const STAGE_A_PREREQUISITES_SCHEMA_VERSION = 2;
export const STAGE_A_STATE_OBJECT = "mscqr/production/rls-green/stage-a/terraform.tfstate";
export const STAGE_A_EXPECTED_STATE_LINEAGE = "02afb75a-f902-ab8a-f4c1-751d4aef7837";
export const STAGE_A_MINIMUM_STATE_SERIAL = 35;
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const json = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
const exact = (value, expected, label) => { if (value !== expected) throw new Error(`${label} does not match the reviewed Stage A contract.`); return value; };

function resourceInstances(state, type, name) {
  return (state.resources || []).filter((resource) => resource.type === type && resource.name === name).flatMap((resource) => resource.instances || []);
}

export function assertStageAStateIdentity(state, { stateObject = STAGE_A_STATE_OBJECT } = {}) {
  if (stateObject !== STAGE_A_STATE_OBJECT) throw new Error(`Stage A state object is wrong: expected ${STAGE_A_STATE_OBJECT}, got ${stateObject}.`);
  if (!state || typeof state !== "object") throw new Error("Stage A state is malformed.");
  if (state.lineage !== STAGE_A_EXPECTED_STATE_LINEAGE) throw new Error(`Stage A state lineage is wrong: expected ${STAGE_A_EXPECTED_STATE_LINEAGE}, got ${state.lineage || "missing"}.`);
  if (!Number.isSafeInteger(state.serial) || state.serial < STAGE_A_MINIMUM_STATE_SERIAL) throw new Error(`Stage A state serial is stale: minimum ${STAGE_A_MINIMUM_STATE_SERIAL}, got ${Number.isSafeInteger(state.serial) ? state.serial : "missing"}.`);
  return state;
}

function stageAValues(state, options) {
  assertStageAStateIdentity(state, options);
  const value = state.outputs?.stage_b_prerequisites?.value;
  if (!value || typeof value !== "object") throw new Error("Stage A state has no stage_b_prerequisites output.");
  const endpoints = resourceInstances(state, "aws_vpc_endpoint", "executor").map((instance) => instance.attributes || {});
  const vpcIds = [...new Set(endpoints.map((item) => item.vpc_id).filter(Boolean))];
  const subnetIds = [...new Set(endpoints.flatMap((item) => item.subnet_ids || []))].sort();
  if (vpcIds.length !== 1 || subnetIds.length !== 2 || JSON.stringify(subnetIds) !== JSON.stringify([...STAGE_B.privateSubnetIds].sort())) throw new Error("Stage A state networking output is incomplete or does not match the reviewed private subnets.");
  const database = resourceInstances(state, "aws_db_instance", "green")[0]?.attributes || {};
  if (!database.identifier) throw new Error("Stage A state does not identify the green database.");
  return { value, vpcId: vpcIds[0], subnetIds, databaseIdentifier: database.identifier };
}

function awsJson(args, run) { return JSON.parse(run(args)); }
export function resolveStageASubnetRouteTable({ routeTables, vpcId, subnetId } = {}) {
  const tables = (routeTables || []).filter((table) => table?.VpcId === vpcId);
  const explicit = tables.filter((table) => (table.Associations || []).some((association) => association.SubnetId === subnetId));
  if (explicit.length > 1) throw new Error("Live Stage A subnet has multiple explicit route-table associations.");
  const candidates = explicit.length === 1 ? explicit : tables.filter((table) => (table.Associations || []).some((association) => association.Main === true));
  if (candidates.length !== 1) throw new Error("Live Stage A subnet has no unique route-table resolution.");
  const table = candidates[0]; const natGatewayId = table.Routes?.find((route) => route.DestinationCidrBlock === "0.0.0.0/0" && route.NatGatewayId)?.NatGatewayId;
  if (!natGatewayId) throw new Error("Live Stage A subnet does not have the required NAT default route.");
  return { table, natGatewayId, resolution: explicit.length === 1 ? "explicit-subnet-association" : "vpc-main-fallback" };
}
function liveEvidence({ vpcId, subnetIds, databaseIdentifier, run }) {
  const subnets = awsJson(["ec2", "describe-subnets", "--subnet-ids", ...subnetIds, "--region", STAGE_B.region, "--output", "json", "--no-cli-pager"], run).Subnets || [];
  if (subnets.length !== subnetIds.length) throw new Error("Live Stage A subnet evidence is incomplete.");
  const checkedSubnets = subnets.map((subnet) => {
    if (!subnet || !subnet.SubnetId || subnet.VpcId !== vpcId || subnet.State !== "available" || subnet.MapPublicIpOnLaunch === true) throw new Error("Live Stage A subnet is unavailable, public, or in the wrong VPC.");
    const tables = awsJson(["ec2", "describe-route-tables", "--filters", `Name=vpc-id,Values=${vpcId}`, "--region", STAGE_B.region, "--output", "json", "--no-cli-pager"], run).RouteTables || [];
    const route = resolveStageASubnetRouteTable({ routeTables: tables, vpcId, subnetId: subnet.SubnetId });
    return { subnetId: subnet.SubnetId, availabilityZone: subnet.AvailabilityZone, cidrBlock: subnet.CidrBlock, routeTableId: route.table.RouteTableId, natGatewayId: route.natGatewayId, routeTableResolution: route.resolution };
  }).sort((left, right) => left.subnetId.localeCompare(right.subnetId));
  if (new Set(checkedSubnets.map((item) => item.availabilityZone)).size !== 2) throw new Error("Live Stage A subnets do not span two availability zones.");
  const groups = awsJson(["ec2", "describe-security-groups", "--group-ids", STAGE_B.databaseSecurityGroupId, STAGE_B.executorSecurityGroupId, "--region", STAGE_B.region, "--output", "json", "--no-cli-pager"], run).SecurityGroups || [];
  if (groups.length !== 2 || groups.some((group) => group.VpcId !== vpcId)) throw new Error("Live Stage A security-group evidence is incomplete or in the wrong VPC.");
  const cluster = awsJson(["ecs", "describe-clusters", "--clusters", STAGE_B.clusterArn, "--region", STAGE_B.region, "--output", "json", "--no-cli-pager"], run).clusters || [];
  if (cluster.length !== 1 || cluster[0].clusterArn !== STAGE_B.clusterArn || cluster[0].status !== "ACTIVE") throw new Error("Live Stage A ECS cluster evidence is wrong.");
  const database = awsJson(["rds", "describe-db-instances", "--db-instance-identifier", databaseIdentifier, "--region", STAGE_B.region, "--output", "json", "--no-cli-pager"], run).DBInstances || [];
  const rdsSubnets = (database[0]?.DBSubnetGroup?.Subnets || []).map((item) => item.SubnetIdentifier).sort();
  if (database.length !== 1 || database[0].DBInstanceStatus !== "available" || JSON.stringify(rdsSubnets) !== JSON.stringify(subnetIds)) throw new Error("Live Stage A RDS networking evidence is wrong.");
  return { vpcId, privateSubnets: checkedSubnets, securityGroups: groups.map((group) => ({ groupId: group.GroupId, vpcId: group.VpcId })).sort((a, b) => a.groupId.localeCompare(b.groupId)), ecsClusterArn: cluster[0].clusterArn, databaseIdentifier, rdsSubnetIds: rdsSubnets };
}

export function generateStageAPrerequisites({ stateBackup, stateObject, toolingSha, toolingTreeSha256, outputPath, run = (args) => execFileSync("aws", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) } = {}) {
  if (!path.isAbsolute(stateBackup || "") || !path.isAbsolute(outputPath || "") || outputPath.startsWith(`${root}${path.sep}`)) throw new Error("Stage A prerequisite inputs and output must be absolute private paths.");
  if (!/^[a-f0-9]{40}$/.test(toolingSha || "") || !/^[a-f0-9]{64}$/.test(toolingTreeSha256 || "")) throw new Error("Stage A prerequisite tooling identity is malformed.");
  if (fs.existsSync(outputPath)) throw new Error("Refusing to overwrite an existing Stage A prerequisite artifact.");
  const stateArtifact = assertStageBPrivateFile({ filePath: stateBackup, repositoryRoot: root, label: "Stage A state backup" });
  const bytes = fs.readFileSync(stateArtifact.path); const state = JSON.parse(bytes); const { value, vpcId, subnetIds, databaseIdentifier } = stageAValues(state, { stateObject });
  const network = liveEvidence({ vpcId, subnetIds, databaseIdentifier, run });
  const output = {
    schemaVersion: STAGE_A_PREREQUISITES_SCHEMA_VERSION, generator: STAGE_A_PREREQUISITES_GENERATOR, toolingSha, toolingTreeSha256,
    stageAStateObject: STAGE_A_STATE_OBJECT, stageAStateLineage: STAGE_A_EXPECTED_STATE_LINEAGE, stageAStateSerial: state.serial, stageAStateSha256: sha256(bytes), networkEvidence: network,
    accountId: STAGE_B.account, region: STAGE_B.region, vpcId, privateSubnetIds: subnetIds, ecsClusterArn: STAGE_B.clusterArn,
    stageADatabaseSecurityGroupId: exact(value.database_security_group_id, STAGE_B.databaseSecurityGroupId, "Stage A database security group"), stageAExecutorSecurityGroupId: exact(value.executor_security_group_id, STAGE_B.executorSecurityGroupId, "Stage A executor security group"),
    stageAExecutorTaskRoleArn: exact(value.executor_role_arn, STAGE_B.executorRoleArn, "Stage A executor role"), stageABrokerRoleArn: exact(value.broker_role_arn, STAGE_B.brokerRoleArn, "Stage A broker role"),
    stageAExecutorLogGroupName: value.executor_log_group_name, stageAExecutorLogGroupArn: value.executor_log_group_arn, stageABrokerLogGroupName: value.broker_log_group_name, stageABrokerLogGroupArn: value.broker_log_group_arn,
    stageARuntimeSecretArns: value.runtime_secret_arns, stageAExecutorNetworkingReady: true, approvalSecretArn: exact(value.approval_secret_arn, STAGE_B.approvalSecretArn, "Stage A approval secret"), approvalKmsKeyArn: exact(value.approval_kms_key_arn, STAGE_B.approvalKmsKeyArn, "Stage A approval key"), receiptBucketArn: `arn:aws:s3:::${STAGE_B.receiptBucket}`, stageAReadOnlyCanaryDatabaseSecretArn: value.read_only_canary_database_secret_arn,
  };
  writeStageBPrivateFileAtomic({ filePath: outputPath, bytes: Buffer.from(`${JSON.stringify(output, null, 2)}\n`), repositoryRoot: root, label: "Stage A prerequisite artifact" }); return output;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const option = (name) => { const i = process.argv.indexOf(name); const value = i === -1 ? undefined : process.argv[i + 1]; if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
  generateStageAPrerequisites({ stateBackup: option("--stage-a-state-backup"), stateObject: option("--stage-a-state-object"), toolingSha: option("--tooling-sha"), toolingTreeSha256: option("--tooling-tree-sha256"), outputPath: option("--output") });
}

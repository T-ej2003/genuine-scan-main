import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { assertStageAStateIdentity, generateStageAPrerequisites, resolveStageASubnetRouteTable, STAGE_A_EXPECTED_STATE_LINEAGE, STAGE_A_MINIMUM_STATE_SERIAL, STAGE_A_STATE_OBJECT } from "../aws/generate-production-green-stage-a-prerequisites.mjs";
import { STAGE_B } from "../aws/production-green-stage-b-contract.mjs";

const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-a-prerequisites-"));
const roles = Object.fromEntries(["app", "read", "preauth", "worker", "scheduled", "operator", "migration"].map((role) => [role, `arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase2/database-url/${role}-abc123`]));
const stage = {
  lineage: STAGE_A_EXPECTED_STATE_LINEAGE, serial: STAGE_A_MINIMUM_STATE_SERIAL,
  outputs: { stage_b_prerequisites: { value: { approval_kms_key_arn: STAGE_B.approvalKmsKeyArn, approval_secret_arn: STAGE_B.approvalSecretArn, executor_role_arn: STAGE_B.executorRoleArn, broker_role_arn: STAGE_B.brokerRoleArn, database_security_group_id: STAGE_B.databaseSecurityGroupId, executor_security_group_id: STAGE_B.executorSecurityGroupId, executor_log_group_name: "/ecs/mscqr-production/full-rls-green", executor_log_group_arn: "arn:aws:logs:eu-west-2:368992683803:log-group:/ecs/mscqr-production/full-rls-green:*", broker_log_group_name: "/aws/lambda/mscqr-production-rls-approval-broker", broker_log_group_arn: "arn:aws:logs:eu-west-2:368992683803:log-group:/aws/lambda/mscqr-production-rls-approval-broker:*", runtime_secret_arns: roles, read_only_canary_database_secret_arn: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase4/read-only-canary-database-url-abc123" } } },
  resources: [
    { type: "aws_vpc_endpoint", name: "executor", instances: [{ attributes: { vpc_id: "vpc-0123456789abcdef0", subnet_ids: STAGE_B.privateSubnetIds } }] },
    { type: "aws_db_instance", name: "green", instances: [{ attributes: { identifier: "mscqr-production-rls-green" } }] },
  ],
};
const statePath = path.join(directory, "stage-a-state.json"); fs.writeFileSync(statePath, JSON.stringify(stage), { mode: 0o600 });
const run = (args) => {
  if (args[1] === "describe-subnets") return JSON.stringify({ Subnets: STAGE_B.privateSubnetIds.map((SubnetId, index) => ({ SubnetId, VpcId: "vpc-0123456789abcdef0", State: "available", MapPublicIpOnLaunch: false, AvailabilityZone: `eu-west-2${index ? "b" : "a"}`, CidrBlock: `10.0.${index}.0/24` })) });
  if (args[1] === "describe-route-tables") return JSON.stringify({ RouteTables: [{ RouteTableId: "rtb-12345678", VpcId: "vpc-0123456789abcdef0", Associations: [{ Main: true }], Routes: [{ DestinationCidrBlock: "0.0.0.0/0", NatGatewayId: "nat-12345678" }] }] });
  if (args[1] === "describe-security-groups") return JSON.stringify({ SecurityGroups: [STAGE_B.databaseSecurityGroupId, STAGE_B.executorSecurityGroupId].map((GroupId) => ({ GroupId, VpcId: "vpc-0123456789abcdef0" })) });
  if (args[1] === "describe-clusters") return JSON.stringify({ clusters: [{ clusterArn: STAGE_B.clusterArn, status: "ACTIVE" }] });
  if (args[1] === "describe-db-instances") return JSON.stringify({ DBInstances: [{ DBInstanceStatus: "available", DBSubnetGroup: { Subnets: STAGE_B.privateSubnetIds.map((SubnetIdentifier) => ({ SubnetIdentifier })) } }] });
  throw new Error(`unexpected AWS command ${args.join(" ")}`);
};

test.after(() => fs.rmSync(directory, { recursive: true, force: true }));
test("canonical Stage A handoff derives every identifier from state and read-only live evidence", () => {
  const outputPath = path.join(directory, "handoff.json");
  const output = generateStageAPrerequisites({ stateBackup: statePath, stateObject: STAGE_A_STATE_OBJECT, toolingSha: "a".repeat(40), toolingTreeSha256: "b".repeat(64), outputPath, run });
  assert.equal(output.schemaVersion, 2); assert.equal(output.stageAStateObject, STAGE_A_STATE_OBJECT); assert.equal(output.stageAStateLineage, STAGE_A_EXPECTED_STATE_LINEAGE); assert.equal(output.stageAStateSerial, STAGE_A_MINIMUM_STATE_SERIAL); assert.deepEqual(output.privateSubnetIds, [...STAGE_B.privateSubnetIds].sort()); assert.equal(output.networkEvidence.privateSubnets.length, 2); assert.equal(fs.statSync(outputPath).mode & 0o777, 0o600);
});

test("canonical Stage A handoff rejects a subnet without NAT routing", () => {
  assert.throws(() => generateStageAPrerequisites({ stateBackup: statePath, stateObject: STAGE_A_STATE_OBJECT, toolingSha: "a".repeat(40), toolingTreeSha256: "b".repeat(64), outputPath: path.join(directory, "bad.json"), run: (args) => args[1] === "describe-route-tables" ? JSON.stringify({ RouteTables: [{ RouteTableId: "rtb-12345678", VpcId: "vpc-0123456789abcdef0", Associations: [{ Main: true }], Routes: [] }] }) : run(args) }), /NAT default route/);
});

test("Stage A state identity is independent from Stage B and accepts later Stage A serials", () => {
  assert.equal(assertStageAStateIdentity({ ...stage, serial: 36 }, { stateObject: STAGE_A_STATE_OBJECT }).serial, 36);
  assert.equal(assertStageAStateIdentity({ ...stage, serial: STAGE_A_MINIMUM_STATE_SERIAL }, { stateObject: STAGE_A_STATE_OBJECT }).serial, STAGE_A_MINIMUM_STATE_SERIAL);
  assert.throws(() => assertStageAStateIdentity({ lineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", serial: 76 }, { stateObject: STAGE_A_STATE_OBJECT }), /lineage is wrong/);
  assert.throws(() => assertStageAStateIdentity({ serial: 35 }, { stateObject: STAGE_A_STATE_OBJECT }), /lineage is wrong/);
  assert.throws(() => assertStageAStateIdentity({ ...stage, serial: STAGE_A_MINIMUM_STATE_SERIAL - 1 }, { stateObject: STAGE_A_STATE_OBJECT }), /serial is stale/);
  for (const serial of [-1, "35", 35.5, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => assertStageAStateIdentity({ ...stage, serial }), /safe non-negative integer number/);
  }
  assert.throws(() => assertStageAStateIdentity(stage, { stateObject: "env:/production/mscqr/production/rls-green/stage-b/terraform.tfstate" }), /state object is wrong/);
});

const routeTable = (id, associations, routes = [{ DestinationCidrBlock: "0.0.0.0/0", NatGatewayId: "nat-12345678" }], vpcId = "vpc-0123456789abcdef0") => ({ RouteTableId: id, VpcId: vpcId, Associations: associations, Routes: routes });
const subnetA = STAGE_B.privateSubnetIds[0]; const subnetB = STAGE_B.privateSubnetIds[1];

test("Stage A route-table resolution prefers the unique explicit subnet association", () => {
  const selected = resolveStageASubnetRouteTable({ vpcId: "vpc-0123456789abcdef0", subnetId: subnetA, routeTables: [routeTable("rtb-explicit", [{ SubnetId: subnetA }]), routeTable("rtb-main", [{ Main: true }])] });
  assert.deepEqual({ id: selected.table.RouteTableId, resolution: selected.resolution }, { id: "rtb-explicit", resolution: "explicit-subnet-association" });
});

test("Stage A route-table resolution falls back to the VPC main table only without an explicit association", () => {
  const selected = resolveStageASubnetRouteTable({ vpcId: "vpc-0123456789abcdef0", subnetId: subnetA, routeTables: [routeTable("rtb-main", [{ Main: true }])] });
  assert.deepEqual({ id: selected.table.RouteTableId, resolution: selected.resolution }, { id: "rtb-main", resolution: "vpc-main-fallback" });
});

test("Stage A route-table resolution rejects ambiguous, missing, non-NAT, and wrong-VPC tables", () => {
  const input = { vpcId: "vpc-0123456789abcdef0", subnetId: subnetA };
  assert.throws(() => resolveStageASubnetRouteTable({ ...input, routeTables: [routeTable("a", [{ SubnetId: subnetA }]), routeTable("b", [{ SubnetId: subnetA }])] }), /multiple explicit/);
  assert.throws(() => resolveStageASubnetRouteTable({ ...input, routeTables: [] }), /no unique/);
  assert.throws(() => resolveStageASubnetRouteTable({ ...input, routeTables: [routeTable("explicit", [{ SubnetId: subnetA }], [])] }), /NAT default route/);
  assert.throws(() => resolveStageASubnetRouteTable({ ...input, routeTables: [routeTable("main", [{ Main: true }], [])] }), /NAT default route/);
  assert.throws(() => resolveStageASubnetRouteTable({ ...input, routeTables: [routeTable("other", [{ Main: true }], undefined, "vpc-other")] }), /no unique/);
});

test("each production subnet resolves independently", () => {
  const tables = [routeTable("rtb-a", [{ SubnetId: subnetA }]), routeTable("rtb-b", [{ SubnetId: subnetB }]), routeTable("rtb-main", [{ Main: true }])];
  assert.equal(resolveStageASubnetRouteTable({ routeTables: tables, vpcId: "vpc-0123456789abcdef0", subnetId: subnetA }).table.RouteTableId, "rtb-a");
  assert.equal(resolveStageASubnetRouteTable({ routeTables: tables, vpcId: "vpc-0123456789abcdef0", subnetId: subnetB }).table.RouteTableId, "rtb-b");
});

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { assertStageAStateContract, assertStageAStateIdentity, assertStageAStateIdentityBinding, buildStageAStateIdentity, generateStageAPrerequisites, resolveStageASubnetRouteTable, STAGE_A_EXPECTED_STATE_LINEAGE, STAGE_A_MINIMUM_STATE_SERIAL, STAGE_A_STATE_OBJECT } from "../aws/generate-production-green-stage-a-prerequisites.mjs";
import { STAGE_A_CHECKER_ROLE_TRUST } from "../aws/production-stage-a-control-plane.mjs";
import { STAGE_B } from "../aws/production-green-stage-b-contract.mjs";
import { productionStageAState } from "./fixtures/production-stage-a-state.mjs";

const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-a-prerequisites-"));
const stage = productionStageAState({ serial: STAGE_A_MINIMUM_STATE_SERIAL });
const withoutRootDrop = (state, resources) => ({ ...state, resources: state.resources.map((resource) => resources.some(([type, name]) => resource.type === type && resource.name === name) ? { ...resource, instances: [] } : resource) });
const preApplyStage = withoutRootDrop(productionStageAState({ serial: 43 }), [["aws_kms_key", "root_drop"], ["aws_kms_alias", "root_drop"]]);
const statePath = path.join(directory, "stage-a-state.json"); fs.writeFileSync(statePath, JSON.stringify(preApplyStage), { mode: 0o600 });
const run = (args) => {
  if (args[1] === "describe-subnets") return JSON.stringify({ Subnets: STAGE_B.privateSubnetIds.map((SubnetId, index) => ({ SubnetId, VpcId: "vpc-0123456789abcdef0", State: "available", MapPublicIpOnLaunch: false, AvailabilityZone: `eu-west-2${index ? "b" : "a"}`, CidrBlock: `10.0.${index}.0/24` })) });
  if (args[1] === "describe-route-tables") return JSON.stringify({ RouteTables: [{ RouteTableId: "rtb-12345678", VpcId: "vpc-0123456789abcdef0", Associations: [{ Main: true }], Routes: [{ DestinationCidrBlock: "0.0.0.0/0", NatGatewayId: "nat-12345678" }] }] });
  if (args[1] === "describe-security-groups") return JSON.stringify({ SecurityGroups: [STAGE_B.databaseSecurityGroupId, STAGE_B.executorSecurityGroupId].map((GroupId) => ({ GroupId, VpcId: "vpc-0123456789abcdef0" })) });
  if (args[1] === "describe-clusters") return JSON.stringify({ clusters: [{ clusterArn: STAGE_B.clusterArn, status: "ACTIVE" }] });
  if (args[1] === "describe-db-instances") return JSON.stringify({ DBInstances: [{ DBInstanceStatus: "available", DBSubnetGroup: { Subnets: STAGE_B.privateSubnetIds.map((SubnetIdentifier) => ({ SubnetIdentifier })) } }] });
  throw new Error(`unexpected AWS command ${args.join(" ")}`);
};

test.after(() => fs.rmSync(directory, { recursive: true, force: true }));

const stateWithCheckerPrincipal = (principal) => productionStageAState({ serial: STAGE_A_MINIMUM_STATE_SERIAL, mutate: (state) => {
  const checker = state.resources.find((resource) => resource.type === "aws_iam_role" && resource.name === "checker");
  checker.instances[0].attributes.assume_role_policy = JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { AWS: principal }, Action: STAGE_A_CHECKER_ROLE_TRUST.action }] });
  return state;
} });

test("Stage A checker trust accepts the Terraform singleton principal array and exact scalar form only", () => {
  for (const principal of [STAGE_A_CHECKER_ROLE_TRUST.principal, [STAGE_A_CHECKER_ROLE_TRUST.principal]]) {
    assert.doesNotThrow(() => assertStageAStateContract(stateWithCheckerPrincipal(principal), { stateObject: STAGE_A_STATE_OBJECT }));
  }
  for (const principal of [
    [],
    [STAGE_A_CHECKER_ROLE_TRUST.principal, "arn:aws:iam::368992683803:role/attacker"],
    ["arn:aws:iam::368992683803:role/attacker"],
    "arn:aws:iam::368992683803:role/attacker",
    [[STAGE_A_CHECKER_ROLE_TRUST.principal]],
    null,
    {},
    undefined,
    "*",
    [42],
  ]) assert.throws(() => assertStageAStateContract(stateWithCheckerPrincipal(principal), { stateObject: STAGE_A_STATE_OBJECT }), /Stage A checker.*trust/);
});

test("canonical Stage A handoff derives every identifier from state and read-only live evidence", () => {
  const outputPath = path.join(directory, "handoff.json");
  const output = generateStageAPrerequisites({ stateBackup: statePath, stateObject: STAGE_A_STATE_OBJECT, toolingSha: "a".repeat(40), toolingTreeSha256: "b".repeat(64), outputPath, run });
  assert.equal(output.schemaVersion, 2); assert.equal(output.stageAStateObject, STAGE_A_STATE_OBJECT); assert.equal(output.stageAStateLineage, STAGE_A_EXPECTED_STATE_LINEAGE); assert.equal(output.stageAStateSerial, 43); assert.deepEqual(output.privateSubnetIds, [...STAGE_B.privateSubnetIds].sort()); assert.equal(output.networkEvidence.privateSubnets.length, 2); assert.equal(fs.statSync(outputPath).mode & 0o777, 0o600);
});

test("pre-apply ABSENT root-drop state reaches the fresh-plan boundary", () => {
  assert.doesNotThrow(() => assertStageAStateContract(preApplyStage, { stateObject: STAGE_A_STATE_OBJECT, phase: "PRE_APPLY" }));
  assert.throws(() => assertStageAStateContract(stage, { stateObject: STAGE_A_STATE_OBJECT, phase: "PRE_APPLY" }), /pre-apply root-drop state must be ABSENT/);
});

test("pre-apply partial root-drop state fails closed", () => {
  for (const resources of [
    [["aws_kms_key", "root_drop"]],
    [["aws_kms_alias", "root_drop"]],
  ]) assert.throws(() => assertStageAStateContract(withoutRootDrop(stage, resources), { stateObject: STAGE_A_STATE_OBJECT, phase: "PRE_APPLY" }), /pre-apply root-drop state must be ABSENT/);
});

test("post-apply root-drop ownership remains required and exact", () => {
  assert.doesNotThrow(() => assertStageAStateContract(stage, { stateObject: STAGE_A_STATE_OBJECT }));
  assert.throws(() => assertStageAStateContract(preApplyStage, { stateObject: STAGE_A_STATE_OBJECT }), /exactly one aws_kms_key\.root_drop/);
  const wrongAlias = productionStageAState({ serial: STAGE_A_MINIMUM_STATE_SERIAL, mutate: (state) => {
    const alias = state.resources.find((resource) => resource.type === "aws_kms_alias" && resource.name === "root_drop");
    alias.instances[0].attributes.target_key_arn = "arn:aws:kms:eu-west-2:368992683803:key/22222222-2222-2222-2222-222222222222";
    return state;
  } });
  assert.throws(() => assertStageAStateContract(wrongAlias, { stateObject: STAGE_A_STATE_OBJECT }), /root-drop key and alias identities/);
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

test("Stage A identity requires an exact lowercase SHA-256 binding", () => {
  const bytes = Buffer.from(JSON.stringify(stage));
  const identity = buildStageAStateIdentity(stage, { stateBytes: bytes });
  assert.doesNotThrow(() => assertStageAStateIdentityBinding(identity, identity));
  assert.throws(() => buildStageAStateIdentity(stage), /exact authenticated state bytes/);
  for (const stateSha256 of [undefined, null, "", "a".repeat(63), "a".repeat(65), "g".repeat(64), "A".repeat(64)]) {
    assert.throws(() => assertStageAStateIdentityBinding(identity, { ...identity, stateSha256 }), /identity binding/);
  }
  assert.throws(() => assertStageAStateIdentityBinding({ ...identity, stateSha256: undefined }, identity), /identity binding/);
  assert.throws(() => assertStageAStateIdentityBinding(identity, { ...identity, stateSha256: "f".repeat(64) }), /identity binding/);
  assert.throws(() => assertStageAStateIdentityBinding(identity, { ...identity, stateSha256: undefined }), /identity binding/);
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

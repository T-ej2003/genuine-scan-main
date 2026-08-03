import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { generateStageAPrerequisites } from "../aws/generate-production-green-stage-a-prerequisites.mjs";
import { STAGE_B } from "../aws/production-green-stage-b-contract.mjs";

const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-a-prerequisites-"));
const roles = Object.fromEntries(["app", "read", "preauth", "worker", "scheduled", "operator", "migration"].map((role) => [role, `arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase2/database-url/${role}-abc123`]));
const stage = {
  lineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", serial: 76,
  outputs: { stage_b_prerequisites: { value: { approval_kms_key_arn: STAGE_B.approvalKmsKeyArn, approval_secret_arn: STAGE_B.approvalSecretArn, executor_role_arn: STAGE_B.executorRoleArn, broker_role_arn: STAGE_B.brokerRoleArn, database_security_group_id: STAGE_B.databaseSecurityGroupId, executor_security_group_id: STAGE_B.executorSecurityGroupId, executor_log_group_name: "/ecs/mscqr-production/full-rls-green", executor_log_group_arn: "arn:aws:logs:eu-west-2:368992683803:log-group:/ecs/mscqr-production/full-rls-green:*", broker_log_group_name: "/aws/lambda/mscqr-production-rls-approval-broker", broker_log_group_arn: "arn:aws:logs:eu-west-2:368992683803:log-group:/aws/lambda/mscqr-production-rls-approval-broker:*", runtime_secret_arns: roles, read_only_canary_database_secret_arn: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase4/read-only-canary-database-url-abc123" } } },
  resources: [
    { type: "aws_vpc_endpoint", name: "executor", instances: [{ attributes: { vpc_id: "vpc-0123456789abcdef0", subnet_ids: STAGE_B.privateSubnetIds } }] },
    { type: "aws_db_instance", name: "green", instances: [{ attributes: { identifier: "mscqr-production-rls-green" } }] },
  ],
};
const statePath = path.join(directory, "stage-a-state.json"); fs.writeFileSync(statePath, JSON.stringify(stage));
const run = (args) => {
  if (args[1] === "describe-subnets") return JSON.stringify({ Subnets: STAGE_B.privateSubnetIds.map((SubnetId, index) => ({ SubnetId, VpcId: "vpc-0123456789abcdef0", State: "available", MapPublicIpOnLaunch: false, AvailabilityZone: `eu-west-2${index ? "b" : "a"}`, CidrBlock: `10.0.${index}.0/24` })) });
  if (args[1] === "describe-route-tables") return JSON.stringify({ RouteTables: [{ RouteTableId: "rtb-12345678", Associations: [{ Main: true }], Routes: [{ DestinationCidrBlock: "0.0.0.0/0", NatGatewayId: "nat-12345678" }] }] });
  if (args[1] === "describe-security-groups") return JSON.stringify({ SecurityGroups: [STAGE_B.databaseSecurityGroupId, STAGE_B.executorSecurityGroupId].map((GroupId) => ({ GroupId, VpcId: "vpc-0123456789abcdef0" })) });
  if (args[1] === "describe-clusters") return JSON.stringify({ clusters: [{ clusterArn: STAGE_B.clusterArn, status: "ACTIVE" }] });
  if (args[1] === "describe-db-instances") return JSON.stringify({ DBInstances: [{ DBInstanceStatus: "available", DBSubnetGroup: { Subnets: STAGE_B.privateSubnetIds.map((SubnetIdentifier) => ({ SubnetIdentifier })) } }] });
  throw new Error(`unexpected AWS command ${args.join(" ")}`);
};

test.after(() => fs.rmSync(directory, { recursive: true, force: true }));
test("canonical Stage A handoff derives every identifier from state and read-only live evidence", () => {
  const outputPath = path.join(directory, "handoff.json");
  const output = generateStageAPrerequisites({ stateBackup: statePath, toolingSha: "a".repeat(40), toolingTreeSha256: "b".repeat(64), outputPath, run });
  assert.equal(output.schemaVersion, 2); assert.deepEqual(output.privateSubnetIds, [...STAGE_B.privateSubnetIds].sort()); assert.equal(output.networkEvidence.privateSubnets.length, 2); assert.equal(fs.statSync(outputPath).mode & 0o777, 0o600);
});

test("canonical Stage A handoff rejects a subnet without NAT routing", () => {
  assert.throws(() => generateStageAPrerequisites({ stateBackup: statePath, toolingSha: "a".repeat(40), toolingTreeSha256: "b".repeat(64), outputPath: path.join(directory, "bad.json"), run: (args) => args[1] === "describe-route-tables" ? JSON.stringify({ RouteTables: [{ RouteTableId: "rtb-12345678", Routes: [] }] }) : run(args) }), /NAT default route/);
});

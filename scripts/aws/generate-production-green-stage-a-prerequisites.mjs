#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { STAGE_B } from "./production-green-stage-b-contract.mjs";
import { assertStageARootDropKeyPolicyDocument, normalizeStageACheckerPrincipalAws, STAGE_A_CHECKER_PUBLICATION_POLICY, STAGE_A_CHECKER_ROLE_TRUST } from "./production-stage-a-control-plane.mjs";
import { assertCanonicalTerraformSerialNumber } from "./stage-b-partial-apply-recovery-contract.mjs";
import { assertStageBPrivateFile, writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";

export const STAGE_A_PREREQUISITES_GENERATOR = "scripts/aws/generate-production-green-stage-a-prerequisites.mjs";
export const STAGE_A_PREREQUISITES_SCHEMA_VERSION = 3;
export const STAGE_A_STATE_IDENTITY_VERSION = 2;
export const STAGE_A_STATE_OBJECT = "mscqr/production/rls-green/stage-a/terraform.tfstate";
export const STAGE_A_EXPECTED_STATE_LINEAGE = "02afb75a-f902-ab8a-f4c1-751d4aef7837";
export const STAGE_A_MINIMUM_STATE_SERIAL = 35;
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const SHA256 = /^[a-f0-9]{64}$/;
const json = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
const exact = (value, expected, label) => { if (value !== expected) throw new Error(`${label} does not match the reviewed Stage A contract.`); return value; };

function resourceInstances(state, type, name) {
  return (state.resources || []).filter((resource) => resource.mode === "managed" && resource.type === type && resource.name === name).flatMap((resource) => resource.instances || []);
}

const oneResource = (state, type, name) => {
  const instances = resourceInstances(state, type, name);
  if (instances.length !== 1) throw new Error(`Stage A state must contain exactly one ${type}.${name} instance.`);
  return instances[0]?.attributes || {};
};

function assertPreApplyRootDropAbsent(state) {
  const keyCount = resourceInstances(state, "aws_kms_key", "root_drop").length;
  const aliasCount = resourceInstances(state, "aws_kms_alias", "root_drop").length;
  if (keyCount === 0 && aliasCount === 0) return;
  throw new Error(`Stage A pre-apply root-drop state must be ABSENT; observed key=${keyCount}, alias=${aliasCount}. Use authenticated recovery/state census for pre-existing or partial state.`);
}

const parsePolicy = (value, label) => {
  if (typeof value !== "string") throw new Error(`${label} policy is missing.`);
  try { return JSON.parse(value); } catch { throw new Error(`${label} policy is malformed.`); }
};

const stable = (value) => Array.isArray(value) ? value.map(stable) : value && typeof value === "object" ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])])) : value;
const assertExactPolicy = (actual, expected, label) => {
  if (JSON.stringify(stable(actual)) !== JSON.stringify(stable(expected))) throw new Error(`${label} policy semantics are not the reviewed contract.`);
};

function canonicalStateJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalStateJson).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalStateJson(value[key])}`).join(",")}}`;
  if (value === undefined) throw new Error("Stage A state identity contains an unsupported undefined value.");
  return JSON.stringify(value);
}

function canonicalJsonNumber(literal) {
  const match = /^(-?)(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/.exec(literal);
  if (!match) throw new Error("Stage A state identity contains a malformed JSON number.");
  const [, sign, integer, fraction = "", exponent = "0"] = match;
  let digits = `${integer}${fraction}`.replace(/^0+/, "") || "0";
  let scale = BigInt(fraction.length) - BigInt(exponent);
  if (digits === "0") return "0";
  while (digits.endsWith("0")) { digits = digits.slice(0, -1); scale -= 1n; }
  return `${sign}${digits}e${-scale}`;
}

function assertJsonNumberPrecision(stateBytes) {
  const source = Buffer.from(stateBytes).toString("utf8");
  const numberPattern = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/y;
  for (let index = 0; index < source.length;) {
    if (source[index] === '"') {
      index += 1;
      while (index < source.length) {
        if (source[index] === "\\") index += 2;
        else if (source[index++] === '"') break;
      }
      continue;
    }
    if (source[index] !== "-" && (source[index] < "0" || source[index] > "9")) { index += 1; continue; }
    numberPattern.lastIndex = index;
    const match = numberPattern.exec(source);
    if (!match) { index += 1; continue; }
    const literal = match[0];
    const parsed = Number(literal);
    if (!Number.isFinite(parsed) || canonicalJsonNumber(literal) !== canonicalJsonNumber(String(parsed))) throw new Error(`Stage A state identity rejects lossy JSON number ${literal}.`);
    index = numberPattern.lastIndex;
  }
}

function checkResultKey(entry) {
  if (!entry || typeof entry !== "object" || Array.isArray(entry) || typeof entry.object_kind !== "string" || !entry.object_kind || typeof entry.config_addr !== "string" || !entry.config_addr) {
    throw new Error("Stage A state identity check result has no unambiguous semantic key.");
  }
  return JSON.stringify([entry.object_kind, entry.config_addr]);
}

export function normalizeStageAStateForIdentity(state) {
  if (!state || typeof state !== "object" || Array.isArray(state)) throw new Error("Stage A state identity input is malformed.");
  const normalized = structuredClone(state);
  if (Object.hasOwn(normalized, "check_results")) {
    if (!Array.isArray(normalized.check_results)) throw new Error("Stage A state identity check results are malformed.");
    const keyed = normalized.check_results.map((entry) => ({ key: checkResultKey(entry), entry }));
    if (new Set(keyed.map(({ key }) => key)).size !== keyed.length) throw new Error("Stage A state identity has duplicate check result semantic keys.");
    normalized.check_results = keyed.sort((left, right) => left.key < right.key ? -1 : left.key > right.key ? 1 : 0).map(({ entry }) => entry);
  }
  return normalized;
}

export function stageAStateSemanticSha256(state) {
  return sha256(Buffer.from(canonicalStateJson(normalizeStageAStateForIdentity(state))));
}

export function parseAuthenticatedStateBytes(stateBytes) {
  try {
    assertJsonNumberPrecision(stateBytes);
    return JSON.parse(Buffer.from(stateBytes).toString("utf8"));
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("Stage A state identity rejects lossy JSON number")) throw error;
    throw new Error("Stage A state identity requires valid JSON state bytes.");
  }
}

export function assertStageAStateIdentity(state, { stateObject = STAGE_A_STATE_OBJECT } = {}) {
  if (stateObject !== STAGE_A_STATE_OBJECT) throw new Error(`Stage A state object is wrong: expected ${STAGE_A_STATE_OBJECT}, got ${stateObject}.`);
  if (!state || typeof state !== "object") throw new Error("Stage A state is malformed.");
  if (state.lineage !== STAGE_A_EXPECTED_STATE_LINEAGE) throw new Error(`Stage A state lineage is wrong: expected ${STAGE_A_EXPECTED_STATE_LINEAGE}, got ${state.lineage || "missing"}.`);
  assertCanonicalTerraformSerialNumber(state.serial, "Stage A state serial");
  if (state.serial < STAGE_A_MINIMUM_STATE_SERIAL) throw new Error(`Stage A state serial is stale: minimum ${STAGE_A_MINIMUM_STATE_SERIAL}, got ${state.serial}.`);
  return state;
}

export function buildStageAStateIdentity(state, { stateObject = STAGE_A_STATE_OBJECT, stateBytes } = {}) {
  assertStageAStateIdentity(state, { stateObject });
  if (!Buffer.isBuffer(stateBytes) && !(stateBytes instanceof Uint8Array)) throw new Error("Stage A state identity requires the exact authenticated state bytes.");
  const parsedState = parseAuthenticatedStateBytes(stateBytes);
  const stateSha256 = stageAStateSemanticSha256(state);
  if (stateSha256 !== stageAStateSemanticSha256(parsedState)) throw new Error("Stage A state identity bytes do not match the supplied state.");
  return Object.freeze({
    stateIdentityVersion: STAGE_A_STATE_IDENTITY_VERSION,
    stateObject,
    lineage: state.lineage,
    serial: state.serial,
    stateSha256,
    account: STAGE_B.account,
    region: STAGE_B.region,
  });
}

export function assertStageAStateIdentityBinding(actual, expected) {
  const validSha256 = (value) => typeof value === "string" && SHA256.test(value);
  if (!actual || !expected || actual.stateIdentityVersion !== STAGE_A_STATE_IDENTITY_VERSION || expected.stateIdentityVersion !== STAGE_A_STATE_IDENTITY_VERSION || !validSha256(actual.stateSha256) || !validSha256(expected.stateSha256) || actual.stateObject !== expected.stateObject || actual.lineage !== expected.lineage || actual.serial !== expected.serial || actual.account !== expected.account || actual.region !== expected.region || actual.stateSha256 !== expected.stateSha256) throw new Error("Stage A state identity binding is not exact.");
  return true;
}

function stageAValues(state, options = {}) {
  assertStageAStateIdentity(state, options);
  const phase = options.phase || "POST_APPLY";
  if (phase !== "PRE_APPLY" && phase !== "POST_APPLY") throw new Error(`Unsupported Stage A state contract phase: ${phase}.`);
  const value = state.outputs?.stage_b_prerequisites?.value;
  if (!value || typeof value !== "object") throw new Error("Stage A state has no stage_b_prerequisites output.");
  const endpoints = resourceInstances(state, "aws_vpc_endpoint", "executor").map((instance) => instance.attributes || {});
  const expectedEndpointServices = ["ecr.api", "ecr.dkr", "logs", "secretsmanager", "kms"].map((service) => `com.amazonaws.${STAGE_B.region}.${service}`);
  if (endpoints.length !== expectedEndpointServices.length || JSON.stringify(endpoints.map((item) => item.service_name).sort()) !== JSON.stringify([...expectedEndpointServices].sort())) throw new Error("Stage A state interface endpoints are incomplete or unexpected.");
  const vpcIds = [...new Set(endpoints.map((item) => item.vpc_id).filter(Boolean))];
  const subnetIds = [...new Set(endpoints.flatMap((item) => item.subnet_ids || []))].sort();
  if (vpcIds.length !== 1 || subnetIds.length !== 2 || endpoints.some((item) => JSON.stringify([...(item.subnet_ids || [])].sort()) !== JSON.stringify([...STAGE_B.privateSubnetIds].sort())) || JSON.stringify(subnetIds) !== JSON.stringify([...STAGE_B.privateSubnetIds].sort())) throw new Error("Stage A state networking output is incomplete or does not match the reviewed private subnets.");
  const database = oneResource(state, "aws_db_instance", "green");
  if (!database.identifier) throw new Error("Stage A state does not identify the green database.");
  const endpointGroup = oneResource(state, "aws_security_group", "executor_endpoints");
  const databaseGroup = oneResource(state, "aws_security_group", "database");
  const executorGroup = oneResource(state, "aws_security_group", "executor");
  if (!endpointGroup.id || databaseGroup.id !== STAGE_B.databaseSecurityGroupId || executorGroup.id !== STAGE_B.executorSecurityGroupId) throw new Error("Stage A security-group identities do not match the reviewed contract.");
  if (value.database_security_group_id !== STAGE_B.databaseSecurityGroupId || value.executor_security_group_id !== STAGE_B.executorSecurityGroupId) throw new Error("Stage A prerequisite security-group outputs are wrong.");
  if (oneResource(state, "aws_iam_role", "executor").arn !== STAGE_B.executorRoleArn || oneResource(state, "aws_iam_role", "broker").arn !== STAGE_B.brokerRoleArn) throw new Error("Stage A runtime IAM role identities are wrong.");
  const checkerRole = oneResource(state, "aws_iam_role", "checker");
  if (checkerRole.arn !== STAGE_B.checkerRoleArn) throw new Error("Stage A checker role identity is wrong.");
  const checkerTrust = parsePolicy(checkerRole.assume_role_policy, "Stage A checker trust");
  const normalizedCheckerTrust = Array.isArray(checkerTrust.Statement) && checkerTrust.Statement.length > 0
    ? {
        ...checkerTrust,
        Statement: checkerTrust.Statement.map((statement, index) => index === 0 && statement && typeof statement === "object" && !Array.isArray(statement) && statement.Principal && typeof statement.Principal === "object" && !Array.isArray(statement.Principal)
          ? { ...statement, Principal: { ...statement.Principal, AWS: normalizeStageACheckerPrincipalAws(statement.Principal.AWS) } }
          : statement),
      }
    : checkerTrust;
  assertExactPolicy(normalizedCheckerTrust, { Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { AWS: STAGE_A_CHECKER_ROLE_TRUST.principal }, Action: STAGE_A_CHECKER_ROLE_TRUST.action }] }, "Stage A checker trust");
  if (phase === "PRE_APPLY") assertPreApplyRootDropAbsent(state);
  else {
    const rootDropKey = oneResource(state, "aws_kms_key", "root_drop");
    const rootDropAlias = oneResource(state, "aws_kms_alias", "root_drop");
    if (!new RegExp(`^arn:aws:kms:${STAGE_B.region}:${STAGE_B.account}:key/[a-f0-9-]{36}$`).test(rootDropKey.arn || "") || rootDropKey.key_usage !== "SIGN_VERIFY" || rootDropKey.customer_master_key_spec !== "RSA_3072" || rootDropAlias.arn !== STAGE_B.rootDropKmsKeyArn || rootDropAlias.target_key_arn !== rootDropKey.arn) throw new Error("Stage A root-drop key and alias identities are wrong.");
    assertStageARootDropKeyPolicyDocument(parsePolicy(rootDropKey.policy, "Stage A root-drop key"));
  }
  if (oneResource(state, "aws_kms_key", "approval").arn !== STAGE_B.approvalKmsKeyArn || oneResource(state, "aws_secretsmanager_secret", "approval").arn !== STAGE_B.approvalSecretArn) throw new Error("Stage A approval resource identities are wrong.");
  assertExactPolicy(parsePolicy(oneResource(state, "aws_iam_role", "executor").assume_role_policy, "Stage A executor trust"), { Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { Service: "ecs-tasks.amazonaws.com" }, Action: "sts:AssumeRole" }] }, "Stage A executor trust");
  assertExactPolicy(parsePolicy(oneResource(state, "aws_iam_role", "broker").assume_role_policy, "Stage A broker trust"), { Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { Service: "lambda.amazonaws.com" }, Action: "sts:AssumeRole" }] }, "Stage A broker trust");
  const checkerPolicy = oneResource(state, "aws_iam_role_policy", "checker_assume_target");
  assertExactPolicy(parsePolicy(checkerPolicy.policy, "Stage A checker role-chain"), { Version: "2012-10-17", Statement: [{ Sid: "AssumeExactRlsIndependentChecker", Effect: "Allow", Action: "sts:AssumeRole", Resource: "arn:aws:iam::368992683803:role/mscqr-production-rls-independent-checker" }] }, "Stage A checker role-chain");
  const checkerPublicationPolicy = oneResource(state, "aws_iam_role_policy", "checker");
  assertExactPolicy(parsePolicy(checkerPublicationPolicy.policy, "Stage A checker publication"), { Version: "2012-10-17", Statement: [{ Sid: "SignExactStageBApproval", Effect: "Allow", Action: STAGE_A_CHECKER_PUBLICATION_POLICY.kmsAction, Resource: STAGE_A_CHECKER_PUBLICATION_POLICY.kmsResource }, { Sid: "PublishExactStageBApproval", Effect: "Allow", Action: STAGE_A_CHECKER_PUBLICATION_POLICY.publishAction, Resource: STAGE_A_CHECKER_PUBLICATION_POLICY.publishResource }] }, "Stage A checker publication");
  for (const key of ["approval_kms_key_arn", "approval_secret_arn", "executor_role_arn", "broker_role_arn", "database_security_group_id", "executor_security_group_id", "executor_log_group_name", "executor_log_group_arn", "broker_log_group_name", "broker_log_group_arn", "runtime_secret_arns", "read_only_canary_database_secret_arn"]) if (value[key] === undefined || value[key] === null) throw new Error("Stage A prerequisite output is incomplete.");
  if (!value.runtime_secret_arns || typeof value.runtime_secret_arns !== "object" || Array.isArray(value.runtime_secret_arns) || Object.keys(value.runtime_secret_arns).length === 0) throw new Error("Stage A runtime secret output is incomplete.");
  return { value, vpcId: vpcIds[0], subnetIds, databaseIdentifier: database.identifier, endpointSecurityGroupId: endpointGroup.id, databaseSecurityGroupId: databaseGroup.id, executorSecurityGroupId: executorGroup.id };
}

export function assertStageAStateContract(state, options = {}) {
  const result = stageAValues(state, options);
  return Object.freeze({ ...result, stateLineage: state.lineage, stateSerial: state.serial });
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

export function generateStageAPrerequisites({ stateBackup, stateObject, toolingSha, toolingTreeSha256, outputPath, phase, run = (args) => execFileSync("aws", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) } = {}) {
  if (!["PRE_APPLY", "POST_APPLY"].includes(phase)) throw new Error("Stage A prerequisite generation requires an explicit PRE_APPLY or POST_APPLY phase.");
  if (!path.isAbsolute(stateBackup || "") || !path.isAbsolute(outputPath || "") || outputPath.startsWith(`${root}${path.sep}`)) throw new Error("Stage A prerequisite inputs and output must be absolute private paths.");
  if (!/^[a-f0-9]{40}$/.test(toolingSha || "") || !/^[a-f0-9]{64}$/.test(toolingTreeSha256 || "")) throw new Error("Stage A prerequisite tooling identity is malformed.");
  if (fs.existsSync(outputPath)) throw new Error("Refusing to overwrite an existing Stage A prerequisite artifact.");
  const stateArtifact = assertStageBPrivateFile({ filePath: stateBackup, repositoryRoot: root, label: "Stage A state backup" });
  const bytes = fs.readFileSync(stateArtifact.path); const state = parseAuthenticatedStateBytes(bytes); const { value, vpcId, subnetIds, databaseIdentifier } = assertStageAStateContract(state, { stateObject, phase });
  const network = liveEvidence({ vpcId, subnetIds, databaseIdentifier, run });
  const output = {
    schemaVersion: STAGE_A_PREREQUISITES_SCHEMA_VERSION, generator: STAGE_A_PREREQUISITES_GENERATOR, toolingSha, toolingTreeSha256,
    stageAStateIdentityVersion: STAGE_A_STATE_IDENTITY_VERSION, stageAStateObject: STAGE_A_STATE_OBJECT, stageAStateLineage: STAGE_A_EXPECTED_STATE_LINEAGE, stageAStateSerial: state.serial, stageAStateSha256: stageAStateSemanticSha256(state), networkEvidence: network,
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
  generateStageAPrerequisites({ stateBackup: option("--stage-a-state-backup"), stateObject: option("--stage-a-state-object"), toolingSha: option("--tooling-sha"), toolingTreeSha256: option("--tooling-tree-sha256"), outputPath: option("--output"), phase: option("--phase") });
}

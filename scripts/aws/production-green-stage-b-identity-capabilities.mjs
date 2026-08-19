import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { STAGE_B } from "./production-green-stage-b-contract.mjs";
import { buildStageAStateIdentity, STAGE_A_STATE_OBJECT } from "./generate-production-green-stage-a-prerequisites.mjs";
import { STAGE_B_TERRAFORM_BACKEND } from "./stage-b-terraform-backend-contract.mjs";
import { RELEASE_CALLER_PATTERN } from "./validate-production-green-stage-b-permissions.mjs";
import { STAGE_B_BROKER_POLICY } from "./stage-b-deployment-contract.mjs";
import { ensureStageBPrivateDirectory, ensureStageBPrivateFile, writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";
import { CHECKER_SOURCE_ROLE_NAME, assertRoleATrustResponse } from "./production-checker-chain-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
export const IDENTITY_CAPABILITY_MATRIX_PATH = "documents/ops/iam/MSCQRProductionGreenStageBDeploymentCapabilities-v1.json";
export const RELEASE_PREFLIGHT_SCHEMA_VERSION = 1;

const roleName = (arn) => arn.split("/").at(-1);
const policyArn = STAGE_B_BROKER_POLICY.arn;
const canaryRoles = [
  "mscqr-production-full-rls-green-read-only-canary-execution",
  "mscqr-production-full-rls-green-read-only-canary-task",
];
const logGroups = ["backend", "canary", "worker", "read-only-canary"].map((name) => `arn:aws:logs:${STAGE_B.region}:${STAGE_B.account}:log-group:/ecs/mscqr-production/rls-green-${name}`);

export const RELEASE_READ_PROBES = Object.freeze([
  ["caller", "sts:GetCallerIdentity", ["sts", "get-caller-identity"]],
  ["stage-a-subnets", "ec2:DescribeSubnets", ["ec2", "describe-subnets", "--subnet-ids", ...STAGE_B.privateSubnetIds]],
  ["stage-a-route-tables", "ec2:DescribeRouteTables", ["ec2", "describe-route-tables"]],
  ["stage-a-security-groups", "ec2:DescribeSecurityGroups", ["ec2", "describe-security-groups", "--group-ids", STAGE_B.databaseSecurityGroupId, STAGE_B.executorSecurityGroupId]],
  ["stage-a-cluster", "ecs:DescribeClusters", ["ecs", "describe-clusters", "--clusters", STAGE_B.clusterArn]],
  ["stage-a-database", "rds:DescribeDBInstances", ["rds", "describe-db-instances", "--db-instance-identifier", STAGE_B.greenDatabaseIdentifier]],
  ["backend-bucket", "s3:GetBucketLocation", ["s3api", "get-bucket-location", "--bucket", STAGE_B_TERRAFORM_BACKEND.bucketName]],
  ["stage-a-state", "s3:GetObject", ["s3api", "get-object", "--bucket", STAGE_B_TERRAFORM_BACKEND.bucketName, "--key", STAGE_A_STATE_OBJECT, "{output}"]],
  ["stage-b-state", "s3:GetObject", ["s3api", "get-object", "--bucket", STAGE_B_TERRAFORM_BACKEND.bucketName, "--key", STAGE_B_TERRAFORM_BACKEND.stateKey, "{output}"]],
  ["audit-services", "ecs:ListServices", ["ecs", "list-services", "--cluster", STAGE_B.clusterArn]],
  ["audit-tasks", "ecs:ListTasks", ["ecs", "list-tasks", "--cluster", STAGE_B.clusterArn]],
  ["audit-task-definition", "ecs:DescribeTaskDefinition", ["ecs", "describe-task-definition", "--task-definition", STAGE_B.frontendTaskDefinition]],
  ["recovery-backend-revisions", "ecs:ListTaskDefinitions", ["ecs", "list-task-definitions", "--family-prefix", "mscqr-production-rls-green-backend-candidate", "--status", "ACTIVE", "--sort", "DESC"]],
  ["audit-broker", "lambda:GetFunctionConfiguration", ["lambda", "get-function-configuration", "--function-name", STAGE_B.brokerFunctionArn]],
  ["audit-broker-alias", "lambda:GetAlias", ["lambda", "get-alias", "--function-name", STAGE_B.brokerFunctionArn, "--name", STAGE_B.brokerAliasQualifier]],
  ["refresh-broker-policy", "iam:GetPolicy", ["iam", "get-policy", "--policy-arn", policyArn]],
  ["refresh-broker-policy-versions", "iam:ListPolicyVersions", ["iam", "list-policy-versions", "--policy-arn", policyArn]],
  ["refresh-broker-attachments", "iam:ListAttachedRolePolicies", ["iam", "list-attached-role-policies", "--role-name", roleName(STAGE_B.brokerRoleArn)]],
  ["checker-role-a-trust", "iam:GetRole", ["iam", "get-role", "--role-name", CHECKER_SOURCE_ROLE_NAME]],
  ...canaryRoles.flatMap((name) => [
    [`refresh-${name}-role`, "iam:GetRole", ["iam", "get-role", "--role-name", name]],
    [`refresh-${name}-inline-policies`, "iam:ListRolePolicies", ["iam", "list-role-policies", "--role-name", name]],
    [`refresh-${name}-attached-policies`, "iam:ListAttachedRolePolicies", ["iam", "list-attached-role-policies", "--role-name", name]],
  ]),
  ...logGroups.map((arn, index) => [`refresh-log-tags-${index + 1}`, "logs:ListTagsForResource", ["logs", "list-tags-for-resource", "--resource-arn", arn]]),
].map(([id, action, args]) => Object.freeze({ id, action, args: Object.freeze([...args]) })));

export function readIdentityCapabilityMatrix() {
  const matrix = JSON.parse(fs.readFileSync(path.join(root, IDENTITY_CAPABILITY_MATRIX_PATH), "utf8"));
  if (matrix.schemaVersion !== 1 || matrix.account !== STAGE_B.account || matrix.region !== STAGE_B.region || matrix.phases?.length !== 34) throw new Error("Stage B identity capability matrix identity is wrong.");
  const releaseActions = new Set(matrix.capabilities.filter(({ identity }) => identity === "RELEASE_DEPLOYER").map(({ action }) => action));
  for (const probe of RELEASE_READ_PROBES) if (!releaseActions.has(probe.action)) throw new Error(`Stage B identity capability matrix omits release action ${probe.action}.`);
  if (matrix.capabilities.some(({ identity, action }) => identity === "RELEASE_DEPLOYER" && ["iam:SimulatePrincipalPolicy", "cloudtrail:LookupEvents"].includes(action))) throw new Error("Stage B release identity must not own administrator audit actions.");
  return { ...matrix, calls: matrix.capabilities };
}

function safeError(error) {
  const value = `${error?.stderr || error?.message || error}`;
  return /AccessDenied|Unauthorized/i.test(value) ? "AccessDenied" : "ReadProbeFailed";
}

export function runReleaseReadPreflight({
  region = STAGE_B.region,
  outputDirectory,
  run = (args) => execFileSync("aws", [...args, "--region", region, "--output", "json", "--no-cli-pager"], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }),
} = {}) {
  if (region !== STAGE_B.region) throw new Error("Stage B release preflight region is wrong.");
  if (!path.isAbsolute(outputDirectory || "")) throw new Error("Stage B release preflight requires an absolute private output directory.");
  readIdentityCapabilityMatrix();
  ensureStageBPrivateDirectory({ directory: outputDirectory, repositoryRoot: root, create: true, normalize: true });
  const stageAStateIdentityOutputPath = path.join(outputDirectory, "stage-a-state-identity.json");
  fs.rmSync(stageAStateIdentityOutputPath, { force: true });
  const requiredReads = {}; const failed = []; const responses = new Map(); let total = 0;
  let caller; let checkerTrust = null; let stageAStateIdentity = null;
  for (const probe of RELEASE_READ_PROBES) {
    total += 1;
    const outputPath = path.join(outputDirectory, `${probe.id}.json`);
    const args = probe.args.map((value) => value === "{output}" ? outputPath : value);
    try {
      const response = run(args, probe);
      if (probe.id === "stage-a-state" || probe.id === "stage-b-state") {
        ensureStageBPrivateFile({ filePath: outputPath, repositoryRoot: root, normalize: true, label: `${probe.id} backup` });
        if (probe.id === "stage-a-state") {
          const stateBytes = fs.readFileSync(outputPath);
          stageAStateIdentity = buildStageAStateIdentity(JSON.parse(stateBytes), { stateBytes });
        }
      }
      responses.set(probe.id, response);
      if (probe.id === "caller") {
        caller = JSON.parse(response).Arn;
        if (!new RegExp(RELEASE_CALLER_PATTERN).test(caller || "")) throw new Error("WrongCaller");
      }
      if (probe.id === "checker-role-a-trust") checkerTrust = assertRoleATrustResponse(JSON.parse(response));
      if (requiredReads[probe.action] !== "denied") requiredReads[probe.action] = "allowed";
    } catch (error) {
      requiredReads[probe.action] = "denied";
      failed.push({ id: probe.id, action: probe.action, classification: safeError(error) });
    }
  }
  const dependent = [];
  try {
    const serviceArns = JSON.parse(responses.get("audit-services") || "{}").serviceArns || [];
    if (serviceArns.length) dependent.push({ id: "audit-service-details", action: "ecs:DescribeServices", args: ["ecs", "describe-services", "--cluster", STAGE_B.clusterArn, "--services", ...serviceArns] });
    const taskArns = JSON.parse(responses.get("audit-tasks") || "{}").taskArns || [];
    if (taskArns.length) dependent.push({ id: "audit-task-details", action: "ecs:DescribeTasks", args: ["ecs", "describe-tasks", "--cluster", STAGE_B.clusterArn, "--tasks", ...taskArns] });
    const defaultVersionId = JSON.parse(responses.get("refresh-broker-policy") || "{}").Policy?.DefaultVersionId;
    if (defaultVersionId) dependent.push({ id: "refresh-broker-policy-version", action: "iam:GetPolicyVersion", args: ["iam", "get-policy-version", "--policy-arn", policyArn, "--version-id", defaultVersionId] });
    for (const roleName of canaryRoles) {
      const inlinePolicyNames = JSON.parse(responses.get(`refresh-${roleName}-inline-policies`) || "{}").PolicyNames || [];
      for (const policyName of inlinePolicyNames) dependent.push({ id: `refresh-${roleName}-inline-policy-${policyName}`, action: "iam:GetRolePolicy", args: ["iam", "get-role-policy", "--role-name", roleName, "--policy-name", policyName] });
    }
  } catch (error) {
    failed.push({ id: "dependent-read-discovery", action: "dependent-read-discovery", classification: safeError(error) });
  }
  for (const probe of dependent) {
    total += 1;
    try { run(probe.args, probe); if (requiredReads[probe.action] !== "denied") requiredReads[probe.action] = "allowed"; }
    catch (error) { requiredReads[probe.action] = "denied"; failed.push({ id: probe.id, action: probe.action, classification: safeError(error) }); }
  }
  const status = failed.length === 0 && checkerTrust?.exact === true && checkerTrust?.mfaRequired === true && stageAStateIdentity ? "valid" : "blocked";
  let stageAStateIdentityPath = null;
  if (status === "valid") {
    stageAStateIdentityPath = stageAStateIdentityOutputPath;
    writeStageBPrivateFileAtomic({ filePath: stageAStateIdentityPath, bytes: Buffer.from(`${JSON.stringify(stageAStateIdentity, null, 2)}\n`), repositoryRoot: root, overwrite: true, label: "Stage-A state identity" });
  }
  return { schemaVersion: RELEASE_PREFLIGHT_SCHEMA_VERSION, caller: caller || null, account: STAGE_B.account, region, total, allowed: total - failed.length, requiredReads, checkerTrust, stageAStateIdentityPath, failed, skipped: [], status };
}

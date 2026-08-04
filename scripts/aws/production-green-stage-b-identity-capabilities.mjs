import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { STAGE_B } from "./production-green-stage-b-contract.mjs";
import { STAGE_A_STATE_OBJECT } from "./generate-production-green-stage-a-prerequisites.mjs";
import { STAGE_B_TERRAFORM_BACKEND } from "./stage-b-terraform-backend-contract.mjs";
import { RELEASE_CALLER_PATTERN } from "./validate-production-green-stage-b-permissions.mjs";
import { STAGE_B_BROKER_POLICY } from "./stage-b-deployment-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
export const IDENTITY_CAPABILITY_MATRIX_PATH = "documents/ops/iam/MSCQRProductionGreenStageBIdentityCapabilities-v1.json";
export const RELEASE_PREFLIGHT_SCHEMA_VERSION = 1;

const roleName = (arn) => arn.split("/").at(-1);
const policyArn = STAGE_B_BROKER_POLICY.arn;
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
  ["audit-broker", "lambda:GetFunctionConfiguration", ["lambda", "get-function-configuration", "--function-name", STAGE_B.brokerFunctionArn]],
  ["audit-broker-alias", "lambda:GetAlias", ["lambda", "get-alias", "--function-name", STAGE_B.brokerFunctionArn, "--name", STAGE_B.brokerAliasQualifier]],
  ["refresh-broker-policy", "iam:GetPolicy", ["iam", "get-policy", "--policy-arn", policyArn]],
  ["refresh-broker-policy-versions", "iam:ListPolicyVersions", ["iam", "list-policy-versions", "--policy-arn", policyArn]],
  ["refresh-broker-attachments", "iam:ListAttachedRolePolicies", ["iam", "list-attached-role-policies", "--role-name", roleName(STAGE_B.brokerRoleArn)]],
  ["refresh-canary-execution-role", "iam:GetRole", ["iam", "get-role", "--role-name", "mscqr-production-full-rls-green-read-only-canary-execution"]],
  ["refresh-canary-task-role", "iam:GetRole", ["iam", "get-role", "--role-name", "mscqr-production-full-rls-green-read-only-canary-task"]],
  ["refresh-canary-inline-policies", "iam:ListRolePolicies", ["iam", "list-role-policies", "--role-name", "mscqr-production-full-rls-green-read-only-canary-execution"]],
  ["refresh-canary-attached-policies", "iam:ListAttachedRolePolicies", ["iam", "list-attached-role-policies", "--role-name", "mscqr-production-full-rls-green-read-only-canary-execution"]],
  ...logGroups.map((arn, index) => [`refresh-log-tags-${index + 1}`, "logs:ListTagsForResource", ["logs", "list-tags-for-resource", "--resource-arn", arn]]),
].map(([id, action, args]) => Object.freeze({ id, action, args: Object.freeze([...args]) })));

export function readIdentityCapabilityMatrix() {
  const matrix = JSON.parse(fs.readFileSync(path.join(root, IDENTITY_CAPABILITY_MATRIX_PATH), "utf8"));
  const manifest = JSON.parse(fs.readFileSync(path.join(root, matrix.terraformAuthority), "utf8"));
  if (matrix.schemaVersion !== 1 || matrix.account !== STAGE_B.account || matrix.region !== STAGE_B.region) throw new Error("Stage B identity capability matrix identity is wrong.");
  const releaseActions = new Set(matrix.calls.filter(({ identity }) => identity === "release-deployer").map(({ action }) => action));
  for (const probe of RELEASE_READ_PROBES) if (!releaseActions.has(probe.action)) throw new Error(`Stage B identity capability matrix omits release action ${probe.action}.`);
  if (matrix.calls.some(({ identity, action }) => identity === "release-deployer" && ["iam:SimulatePrincipalPolicy", "cloudtrail:LookupEvents"].includes(action))) throw new Error("Stage B release identity must not own administrator audit actions.");
  return {
    ...matrix,
    calls: [
      ...matrix.calls,
      ...[[manifest.required, false], [manifest.forbidden, true]].flatMap(([entries, forbidden]) => entries.map((entry) => ({
        phase: entry.phase,
        executable: "terraform-provider-or-production-validator",
        action: entry.action,
        resource: entry.resources,
        context: entry.context,
        identity: forbidden ? "administrator-simulation-only" : "release-deployer",
        access: entry.phase === "apply" ? "mutation" : "read",
        permissionManifestId: entry.id,
      }))),
    ],
  };
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
  fs.mkdirSync(outputDirectory, { recursive: true, mode: 0o700 });
  const requiredReads = {}; const failed = []; const responses = new Map();
  let caller;
  for (const probe of RELEASE_READ_PROBES) {
    const outputPath = path.join(outputDirectory, `${probe.id}.json`);
    const args = probe.args.map((value) => value === "{output}" ? outputPath : value);
    try {
      const response = run(args, probe);
      responses.set(probe.id, response);
      if (probe.id === "caller") {
        caller = JSON.parse(response).Arn;
        if (!new RegExp(RELEASE_CALLER_PATTERN).test(caller || "")) throw new Error("WrongCaller");
      }
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
    const inlinePolicyNames = JSON.parse(responses.get("refresh-canary-inline-policies") || "{}").PolicyNames || [];
    for (const policyName of inlinePolicyNames) dependent.push({ id: `refresh-canary-inline-policy-${policyName}`, action: "iam:GetRolePolicy", args: ["iam", "get-role-policy", "--role-name", "mscqr-production-full-rls-green-read-only-canary-execution", "--policy-name", policyName] });
  } catch (error) {
    failed.push({ id: "dependent-read-discovery", action: "dependent-read-discovery", classification: safeError(error) });
  }
  for (const probe of dependent) {
    try { run(probe.args, probe); if (requiredReads[probe.action] !== "denied") requiredReads[probe.action] = "allowed"; }
    catch (error) { requiredReads[probe.action] = "denied"; failed.push({ id: probe.id, action: probe.action, classification: safeError(error) }); }
  }
  return { schemaVersion: RELEASE_PREFLIGHT_SCHEMA_VERSION, caller: caller || null, account: STAGE_B.account, region, requiredReads, failed, skipped: [], status: failed.length === 0 ? "valid" : "blocked" };
}

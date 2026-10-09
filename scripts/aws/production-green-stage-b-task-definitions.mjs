import fs from "node:fs";
import { execFileSync } from "node:child_process";
import path from "node:path";
import os from "node:os";
import { assertStageBRuntimePlatform, canonicalSha256, assertImmutableImage, STAGE_B, STAGE_B_MODES, STAGE_B_TASK_TEMPLATE_KEYS } from "./production-green-stage-b-contract.mjs";
import { deriveEcsRuntimeDependencies } from "./production-ecs-runtime-dependencies.mjs";

const root = "infra/aws/terraform/production-green-stage-b/task-definitions";
// Original-release expectations must execute the original renderer and its dependencies together.
function originalRenderer(sourceSha, operation, args = []) {
  if (!/^[a-f0-9]{40}$/.test(sourceSha || "")) throw new Error("Task renderer source must be exact.");
  const resolved = execFileSync("git", ["rev-parse", "--verify", `${sourceSha}^{commit}`], { encoding: "utf8" }).trim();
  if (resolved !== sourceSha) throw new Error("Task renderer source does not resolve to its exact commit.");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-original-renderer-"));
  try {
    const inputs = [root, "scripts/aws/production-green-stage-b-task-definitions.mjs", "scripts/aws/production-green-stage-b-contract.mjs", "scripts/aws/production-ecs-runtime-dependencies.mjs"];
    const tree = execFileSync("git", ["ls-tree", "-rz", sourceSha, "--", ...inputs], { encoding: "utf8" }).split("\0").filter(Boolean);
    if (tree.some(entry => !/^100(?:644|755) blob [a-f0-9]{40}\t/.test(entry))) throw new Error("Original renderer inputs must be ordinary Git files.");
    const expected = tree.map(entry => entry.split("\t")[1]).sort();
    if (inputs.slice(1).some(file => !expected.includes(file))) throw new Error("Original renderer dependency is missing.");
    const archive = execFileSync("git", ["archive", "--format=tar", sourceSha, ...inputs], { maxBuffer: 64 * 1024 * 1024 });
    execFileSync("tar", ["-xf", "-", "-C", directory], { input: archive });
    const observed = [];
    const visit = current => { for (const name of fs.readdirSync(current)) { const file = path.join(current, name), stat = fs.lstatSync(file); if (stat.isSymbolicLink()) throw new Error("Original renderer cannot contain symlinks."); if (stat.isDirectory()) visit(file); else { if (!stat.isFile()) throw new Error("Unsupported original renderer input."); observed.push(path.relative(directory, file).split(path.sep).join("/")); } } };
    visit(directory);
    if (JSON.stringify(observed.sort()) !== JSON.stringify(expected)) throw new Error("Original renderer archive differs from its authenticated Git tree.");
    const script = 'import fs from "node:fs"; const {operation,args}=JSON.parse(fs.readFileSync(0,"utf8")); const renderer=await import("./scripts/aws/production-green-stage-b-task-definitions.mjs"); const {STAGE_B}=await import("./scripts/aws/production-green-stage-b-contract.mjs"); const bindings={receiptBucket:STAGE_B.receiptBucket,executorLogGroup:STAGE_B.executorLogGroupName,canaryLogGroup:STAGE_B.canaryLogGroupName}; process.stdout.write(JSON.stringify(operation==="taskBindings" ? bindings : renderer[operation](...args)));';
    return JSON.parse(execFileSync(process.execPath, ["--input-type=module", "-e", script], { cwd: directory, input: JSON.stringify({ operation, args }), encoding: "utf8", env: {}, maxBuffer: 4 * 1024 * 1024 }));
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}
const files = Object.freeze(Object.fromEntries(STAGE_B_TASK_TEMPLATE_KEYS.map((key) => [key, {
  executor: "green-activation-executor.json", canary: "green-application-canary.json", backend: "green-backend-candidate.json", worker: "green-worker-candidate.json",
}[key]])));
const imagePatterns = Object.freeze({
  backend: /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-backend@sha256:[a-f0-9]{64}$/,
  worker: /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-worker@sha256:[a-f0-9]{64}$/,
  executor: /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-backend@sha256:[a-f0-9]{64}$/,
  canary: /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-backend@sha256:[a-f0-9]{64}$/,
});
const confirmations = Object.freeze({
  "full-rls-role-provision": "MSCQR_PRODUCTION_GREEN_PROVISION_RUNTIME_ROLES",
  "full-rls-admin-bootstrap": "MSCQR_PRODUCTION_GREEN_CREATE_AND_BOOTSTRAP_DATABASE",
  "full-rls-admin-ownership": "MSCQR_PRODUCTION_GREEN_INSTALL_OWNERSHIP_GRANTS",
  "full-rls-runtime-policy": "MSCQR_PRODUCTION_GREEN_INSTALL_RUNTIME_POLICIES",
  "full-rls-rollback": "MSCQR_PRODUCTION_GREEN_ROLLBACK_EXACT_PACKAGE",
});
export const STAGE_B_BACKEND_PORT_MAPPING = Object.freeze({ containerPort: 4000, hostPort: 4000, protocol: "tcp", name: "backend-4000-tcp", appProtocol: "http" });
const readTemplate = (kind, sourceSha) => {
  if (!files[kind]) throw new Error("Unknown Stage B task template.");
  if (sourceSha !== undefined && !/^[a-f0-9]{40}$/.test(sourceSha)) throw new Error("Task template source must be exact.");
  return JSON.parse(sourceSha ? execFileSync("git", ["show", `${sourceSha}:${path.join(root, files[kind])}`], { encoding: "utf8" }) : fs.readFileSync(path.join(root, files[kind]), "utf8"));
};
const replace = (value, values) => {
  if (Array.isArray(value)) return value.map((item) => replace(item, values));
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, replace(item, values)]));
  return typeof value === "string" ? value.replace(/{{([A-Z0-9_]+)}}/g, (_, key) => {
    if (!(key in values)) throw new Error(`Missing fixed Stage B task binding: ${key}.`);
    return values[key];
  }) : value;
};
const assertNoTokens = (value) => {
  const text = JSON.stringify(value);
  if (/{{[A-Z0-9_]+}}/.test(text)) throw new Error("Stage B task template has an unresolved binding.");
};

const reviewedTemplate = (kind, sourceSha) => ({ ...readTemplate(kind, sourceSha), runtimePlatform: { ...STAGE_B.taskRuntimePlatform } });
export const stageBTaskDefinitionBindings = sourceSha => sourceSha !== undefined ? originalRenderer(sourceSha, "taskBindings") : { receiptBucket: STAGE_B.receiptBucket, executorLogGroup: STAGE_B.executorLogGroupName, canaryLogGroup: STAGE_B.canaryLogGroupName };
export const stageBTemplateHashes = (sourceSha) => sourceSha !== undefined ? originalRenderer(sourceSha, "stageBTemplateHashes") : Object.fromEntries(Object.entries(files).map(([kind]) => [kind, canonicalSha256(reviewedTemplate(kind))]));
export const approvedNetworkConfiguration = (privateSubnetIds) => {
  if (!Array.isArray(privateSubnetIds) || privateSubnetIds.length !== STAGE_B.privateSubnetIds.length
      || [...privateSubnetIds].sort().join(",") !== [...STAGE_B.privateSubnetIds].sort().join(",")) {
    throw new Error("Stage B requires exactly two approved private subnets.");
  }
  return { awsvpcConfiguration: { subnets: [...privateSubnetIds].sort(), securityGroups: [STAGE_B.executorSecurityGroupId], assignPublicIp: "DISABLED" } };
};

export function assertFixedTaskDefinition(definition) {
  try { assertStageBRuntimePlatform(definition?.runtimePlatform, { format: "aws", label: "Stage B task definition runtimePlatform" }); }
  catch { throw new Error("Stage B task definition is outside the fixed reviewed contract."); }
  const container = definition?.containerDefinitions?.[0];
  const environmentNames = container?.environment?.map(({ name }) => name) || [];
  const secretNames = container?.secrets?.map(({ name }) => name) || [];
  const backendUploads = definition?.family === "mscqr-production-rls-green-backend-candidate";
  const uploadMount = container?.mountPoints?.find((mount) => mount.sourceVolume === "backend-uploads");
  const scratchMount = container?.mountPoints?.find((mount) => /^(executor|canary)-tmp$/.test(mount.sourceVolume));
  const fargateSizes = new Set(["256/512", "256/1024", "512/1024", "512/2048", "1024/2048", "1024/3072", "1024/4096", "2048/4096", "2048/5120", "2048/6144", "2048/7168", "2048/8192", "4096/8192", "4096/16384", "4096/30720"]);
  if (!container || definition.networkMode !== "awsvpc" || !definition.requiresCompatibilities?.includes("FARGATE")
      || container.privileged || container.interactive || container.pseudoTerminal || !Array.isArray(container.entryPoint)
      || (Object.hasOwn(container, "command") && (!Array.isArray(container.command) || container.command.length)) || !container.logConfiguration
      || !["awslogs"].includes(container.logConfiguration.logDriver) || !container.image?.includes("@sha256:")
      || !fargateSizes.has(`${definition.cpu}/${definition.memory}`) || new Set(environmentNames).size !== environmentNames.length
      || new Set(secretNames).size !== secretNames.length || environmentNames.some((name) => secretNames.includes(name))
      || (backendUploads && (!definition.volumes?.some((volume) => volume.name === "backend-uploads" && !Object.hasOwn(volume, "host"))
        || uploadMount?.containerPath !== "/app/uploads" || uploadMount.readOnly !== false))
      || (backendUploads && JSON.stringify(container.portMappings || []) !== JSON.stringify([STAGE_B_BACKEND_PORT_MAPPING]))
      || (!backendUploads && (definition.volumes?.length || container.mountPoints?.length) && (!scratchMount || scratchMount.containerPath !== "/tmp" || scratchMount.readOnly !== false
        || definition.volumes?.length !== 1 || container.mountPoints?.length !== 1))
      || JSON.stringify(definition).includes("rds!db-70d459ec-4f6f-45da-aafc-618e83d660a1-Dy9GLo")
        && (definition.taskRoleArn !== STAGE_B.executorRoleArn || definition.executionRoleArn !== STAGE_B.executorExecutionRoleArn)) {
    throw new Error("Stage B task definition is outside the fixed reviewed contract.");
  }
  if (definition.networkMode === "host" || JSON.stringify(definition).match(/hostPath|sourcePath|privileged\s*:\s*true/)) {
    throw new Error("Stage B task definition permits a prohibited host boundary.");
  }
  deriveEcsRuntimeDependencies(definition);
  return definition;
}

export function renderStageBTaskDefinition(kind, bindings, sourceSha) {
  if (sourceSha !== undefined) return originalRenderer(sourceSha, "renderStageBTaskDefinition", [kind, bindings]);
  const base = { RELEASE_SHA: bindings.imageReleaseSha, SOURCE_CONTRACT_SHA256: bindings.sourceContractSha256, MIGRATION_SET_DIGEST: bindings.migrationSetDigest, PACKAGE_CHECKSUM_SHA256: bindings.packageChecksumSha256, RECEIPT_BUCKET: bindings.receiptBucket, EXECUTOR_LOG_GROUP: bindings.executorLogGroup, CANARY_LOG_GROUP: bindings.canaryLogGroup, BACKEND_LOG_GROUP: bindings.backendLogGroup, WORKER_LOG_GROUP: bindings.workerLogGroup };
  if (!/^[a-f0-9]{40}$/.test(base.RELEASE_SHA || "") || !/^[a-f0-9]{64}$/.test(base.SOURCE_CONTRACT_SHA256 || "") || !/^[a-f0-9]{64}$/.test(base.MIGRATION_SET_DIGEST || "") || !/^[a-f0-9]{64}$/.test(base.PACKAGE_CHECKSUM_SHA256 || "")) throw new Error("Stage B task release binding is invalid.");
  const imageField = `${kind.toUpperCase()}_IMAGE`;
  const image = bindings[`${kind}Image`];
  assertImmutableImage(image, `${kind} image`);
  if (!imagePatterns[kind].test(image)) throw new Error(`${kind} image is not from its reviewed ECR repository.`);
  const values = { ...base, [imageField]: image };
  if (kind === "executor") {
    if (!STAGE_B_MODES.includes(bindings.mode) || bindings.mode === "full-rls-application-canary") throw new Error("Executor mode is outside the fixed reviewed set.");
    values.MODE = bindings.mode;
    values.CONFIRMATION = confirmations[bindings.mode] || "";
  }
  const definition = replace(reviewedTemplate(kind, sourceSha), values);
  assertNoTokens(definition);
  return assertFixedTaskDefinition(definition);
}

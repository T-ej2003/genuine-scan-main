import fs from "node:fs";
import path from "node:path";
import { canonicalSha256, assertImmutableImage, STAGE_B, STAGE_B_MODES } from "./production-green-stage-b-contract.mjs";

const root = "infra/aws/terraform/production-green-stage-b/task-definitions";
const files = Object.freeze({ executor: "green-activation-executor.json", canary: "green-application-canary.json", backend: "green-backend-candidate.json", worker: "green-worker-candidate.json" });
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
const readTemplate = (kind) => {
  if (!files[kind]) throw new Error("Unknown Stage B task template.");
  return JSON.parse(fs.readFileSync(path.join(root, files[kind]), "utf8"));
};
const replace = (value, values) => {
  if (Array.isArray(value)) return value.map((item) => replace(item, values));
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, replace(item, values)]));
  return typeof value === "string" ? value.replace(/{{([A-Z_]+)}}/g, (_, key) => {
    if (!(key in values)) throw new Error(`Missing fixed Stage B task binding: ${key}.`);
    return values[key];
  }) : value;
};
const assertNoTokens = (value) => {
  const text = JSON.stringify(value);
  if (/{{[A-Z_]+}}/.test(text)) throw new Error("Stage B task template has an unresolved binding.");
};

export const stageBTemplateHashes = () => Object.fromEntries(Object.entries(files).map(([kind]) => [kind, canonicalSha256(readTemplate(kind))]));
export const approvedNetworkConfiguration = (privateSubnetIds) => {
  if (!Array.isArray(privateSubnetIds) || privateSubnetIds.length !== STAGE_B.privateSubnetIds.length
      || [...privateSubnetIds].sort().join(",") !== [...STAGE_B.privateSubnetIds].sort().join(",")) {
    throw new Error("Stage B requires exactly two approved private subnets.");
  }
  return { awsvpcConfiguration: { subnets: [...privateSubnetIds].sort(), securityGroups: [STAGE_B.executorSecurityGroupId], assignPublicIp: "DISABLED" } };
};

export function assertFixedTaskDefinition(definition) {
  const container = definition?.containerDefinitions?.[0];
  const environmentNames = container?.environment?.map(({ name }) => name) || [];
  const secretNames = container?.secrets?.map(({ name }) => name) || [];
  const fargateSizes = new Set(["256/512", "256/1024", "512/1024", "512/2048", "1024/2048", "1024/3072", "1024/4096", "2048/4096", "2048/5120", "2048/6144", "2048/7168", "2048/8192", "4096/8192", "4096/16384", "4096/30720"]);
  if (!container || definition.networkMode !== "awsvpc" || !definition.requiresCompatibilities?.includes("FARGATE")
      || container.privileged || container.interactive || container.pseudoTerminal || !Array.isArray(container.entryPoint)
      || (Object.hasOwn(container, "command") && (!Array.isArray(container.command) || container.command.length)) || !container.logConfiguration
      || !["awslogs"].includes(container.logConfiguration.logDriver) || !container.image?.includes("@sha256:")
      || !fargateSizes.has(`${definition.cpu}/${definition.memory}`) || new Set(environmentNames).size !== environmentNames.length
      || new Set(secretNames).size !== secretNames.length || environmentNames.some((name) => secretNames.includes(name))
      || JSON.stringify(definition).includes("rds!db-70d459ec-4f6f-45da-aafc-618e83d660a1-Dy9GLo")
        && (definition.taskRoleArn !== STAGE_B.executorRoleArn || definition.executionRoleArn !== STAGE_B.executorExecutionRoleArn)) {
    throw new Error("Stage B task definition is outside the fixed reviewed contract.");
  }
  if (definition.networkMode === "host" || JSON.stringify(definition).match(/hostPath|sourcePath|privileged\s*:\s*true/)) {
    throw new Error("Stage B task definition permits a prohibited host boundary.");
  }
  return definition;
}

export function renderStageBTaskDefinition(kind, bindings) {
  const base = { RELEASE_SHA: bindings.releaseSha, SOURCE_CONTRACT_SHA256: bindings.sourceContractSha256, MIGRATION_SET_DIGEST: bindings.migrationSetDigest, PACKAGE_CHECKSUM_SHA256: bindings.packageChecksumSha256, RECEIPT_BUCKET: bindings.receiptBucket, EXECUTOR_LOG_GROUP: bindings.executorLogGroup, CANARY_LOG_GROUP: bindings.canaryLogGroup, BACKEND_LOG_GROUP: bindings.backendLogGroup, WORKER_LOG_GROUP: bindings.workerLogGroup };
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
  const definition = replace(readTemplate(kind), values);
  assertNoTokens(definition);
  return assertFixedTaskDefinition(definition);
}

#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  assertImageEvidence,
  imageEvidenceSha256,
  verifyImageEvidenceSignature,
  STAGE_B_PLAN_IMAGE_BINDINGS,
} from "./production-green-stage-b-image-evidence.mjs";
import { STAGE_B, canonicalJson } from "./production-green-stage-b-contract.mjs";
import { STAGE_B_BROKER_POLICY } from "./stage-b-deployment-contract.mjs";
import { STAGE_B_TASK_DEFINITION_FAMILIES } from "./stage-b-reference-audit-contract.mjs";
import { STAGE_A_PREREQUISITES_GENERATOR, STAGE_A_PREREQUISITES_SCHEMA_VERSION } from "./generate-production-green-stage-a-prerequisites.mjs";

export const STAGE_B_TFVARS_SCHEMA_VERSION = 1;
export const STAGE_B_TFVARS_BINDING_REPORT_SCHEMA_VERSION = 1;
export const STAGE_B_EXPECTED_WORKSPACE = "production";
export const STAGE_B_EXPECTED_STATE_LINEAGE = "4e438e59-8b8b-194d-030c-5ede0c26344a";
export const STAGE_B_MINIMUM_STATE_SERIAL = 76;
export const STAGE_B_TFVARS_GENERATOR = "scripts/aws/generate-production-green-stage-b-tfvars.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const checksumsPath = path.join(root, "documents/security/rls-program/generated/checksums.json");
const digestPattern = /^[a-f0-9]{64}$/;
const imageDigestPattern = /^sha256:[a-f0-9]{64}$/;
const imageUriPattern = /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-(backend|worker)@sha256:[a-f0-9]{64}$/;
const generationPattern = /^[a-f0-9]{7,40}$/;
const candidateKeyPattern = /^([a-f0-9]{7,40})-(backend|worker|canary|read_only_canary)$/;
const executorKeyPattern = /^([a-f0-9]{7,40})-(full-rls-(admin-bootstrap|admin-ownership|capability-preflight|role-provision|role-verify|rollback|runtime-policy|verification))$/;

const stageAKeys = Object.freeze([
  "schemaVersion", "generator", "toolingSha", "toolingTreeSha256", "sourceStateLineage", "sourceStateSerial", "sourceStateSha256", "networkEvidence", "accountId", "region", "vpcId", "privateSubnetIds", "ecsClusterArn",
  "stageADatabaseSecurityGroupId", "stageAExecutorSecurityGroupId", "stageAExecutorTaskRoleArn",
  "stageABrokerRoleArn", "stageAExecutorLogGroupName", "stageAExecutorLogGroupArn",
  "stageABrokerLogGroupName", "stageABrokerLogGroupArn", "stageARuntimeSecretArns",
  "stageAExecutorNetworkingReady", "approvalSecretArn", "approvalKmsKeyArn", "receiptBucketArn",
  "stageAReadOnlyCanaryDatabaseSecretArn",
]);

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const base64Sha256 = (value) => crypto.createHash("sha256").update(value).digest("base64");
const readJson = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
const requireDigest = (value, label) => {
  if (!digestPattern.test(String(value || ""))) throw new Error(`${label} must be exactly 64 lowercase hexadecimal characters.`);
  return value;
};
const requireImageDigest = (value, label) => {
  if (!imageDigestPattern.test(String(value || "")) || String(value).length !== 71) throw new Error(`${label} must be exactly a 71-character sha256 digest.`);
  return value;
};
const quote = (value) => JSON.stringify(value);
const sortedEntries = (value) => Object.entries(value || {}).sort(([a], [b]) => a.localeCompare(b));

function assertAbsoluteFile(file, label) {
  if (!path.isAbsolute(file) || !fs.statSync(file, { throwIfNoEntry: false } )?.isFile()) throw new Error(`${label} must be an existing absolute file.`);
}

function assertOutputPath(file, label) {
  if (!path.isAbsolute(file)) throw new Error(`${label} must be an absolute private path.`);
  if (path.resolve(file) === path.resolve(root) || path.resolve(file).startsWith(`${root}${path.sep}`)) {
    throw new Error(`${label} must be outside the repository.`);
  }
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
}

function outputState(file, label, fileSystem) {
  if (!fileSystem.existsSync(file)) return { file, label, exists: false };
  if (fileSystem.lstatSync(file).isDirectory()) throw new Error(`${label} output must not be a directory.`);
  return { file, label, exists: true };
}

export function writeAtomicPair({ tfvarsPath, bindingReportPath, tfvarsBytes, bindingReportBytes, allowOverwrite = false, fileSystem = fs } = {}) {
  if (path.resolve(tfvarsPath) === path.resolve(bindingReportPath)) throw new Error("Tfvars and binding-report outputs must be different files.");
  const outputs = [outputState(tfvarsPath, "Tfvars", fileSystem), outputState(bindingReportPath, "Binding-report", fileSystem)];
  if (!allowOverwrite && outputs.some(({ exists }) => exists)) throw new Error(`Refusing to overwrite existing ${outputs.find(({ exists }) => exists).file}.`);
  const temporaryDirectories = outputs.map(({ file }) => fileSystem.mkdtempSync(path.join(path.dirname(file), ".stage-b-tfvars-")));
  const temporaryFiles = outputs.map(({ file }, index) => path.join(temporaryDirectories[index], path.basename(file)));
  const backups = [];
  const committed = [];
  try {
    for (const [index, bytes] of [tfvarsBytes, bindingReportBytes].entries()) {
      fileSystem.writeFileSync(temporaryFiles[index], bytes, { flag: "wx", mode: 0o600 });
      fileSystem.chmodSync(temporaryFiles[index], 0o600);
    }
    for (const output of outputs) {
      const current = outputState(output.file, output.label, fileSystem);
      if (current.exists !== output.exists || (!allowOverwrite && current.exists)) throw new Error(`${output.label} output changed during generation.`);
    }
    if (allowOverwrite) {
      for (const output of outputs) {
        if (!output.exists) continue;
        const directory = fileSystem.mkdtempSync(path.join(path.dirname(output.file), ".stage-b-tfvars-backup-"));
        const backup = path.join(directory, path.basename(output.file));
        fileSystem.renameSync(output.file, backup);
        backups.push({ output: output.file, backup, directory });
      }
    }
    for (let index = 0; index < outputs.length; index += 1) {
      fileSystem.renameSync(temporaryFiles[index], outputs[index].file);
      committed.push(outputs[index].file);
    }
  } catch (error) {
    for (const file of committed) fileSystem.rmSync(file, { force: true });
    for (const { output, backup } of backups.reverse()) if (fileSystem.existsSync(backup)) fileSystem.renameSync(backup, output);
    throw error;
  } finally {
    for (const directory of temporaryDirectories) fileSystem.rmSync(directory, { recursive: true, force: true });
    for (const { directory } of backups) fileSystem.rmSync(directory, { recursive: true, force: true });
  }
}

export function validateStageBStageAInput(input, { toolingSha, toolingTreeSha256 } = {}) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("Stage-A prerequisite input is malformed.");
  if (JSON.stringify(Object.keys(input).sort()) !== JSON.stringify([...stageAKeys].sort())) throw new Error("Stage-A prerequisite input fields do not match the reviewed contract.");
  if (input.schemaVersion !== STAGE_A_PREREQUISITES_SCHEMA_VERSION || input.generator !== STAGE_A_PREREQUISITES_GENERATOR || input.accountId !== STAGE_B.account || input.region !== STAGE_B.region) throw new Error("Stage-A prerequisite account, region, schema, or generator is wrong.");
  if (!/^[a-f0-9]{40}$/.test(input.toolingSha || "") || !digestPattern.test(input.toolingTreeSha256 || "") || input.sourceStateLineage !== STAGE_B_EXPECTED_STATE_LINEAGE || !Number.isInteger(input.sourceStateSerial) || input.sourceStateSerial < STAGE_B_MINIMUM_STATE_SERIAL || !digestPattern.test(input.sourceStateSha256 || "")) throw new Error("Stage-A prerequisite provenance is malformed.");
  if ((toolingSha !== undefined && input.toolingSha !== toolingSha) || (toolingTreeSha256 !== undefined && input.toolingTreeSha256 !== toolingTreeSha256)) throw new Error("Stage-A prerequisite tooling provenance does not match this deployment.");
  if (!/^vpc-[a-f0-9]+$/.test(input.vpcId)) throw new Error("Stage-A VPC ID is malformed.");
  if (!Array.isArray(input.privateSubnetIds)) throw new Error("Stage-A private subnets are malformed.");
  if (JSON.stringify([...input.privateSubnetIds].sort()) !== JSON.stringify([...STAGE_B.privateSubnetIds].sort())) throw new Error("Stage-A private subnets do not match the reviewed contract.");
  if (input.ecsClusterArn !== STAGE_B.clusterArn || input.stageADatabaseSecurityGroupId !== STAGE_B.databaseSecurityGroupId || input.stageAExecutorSecurityGroupId !== STAGE_B.executorSecurityGroupId || input.stageABrokerRoleArn !== STAGE_B.brokerRoleArn || input.stageAExecutorTaskRoleArn !== STAGE_B.executorRoleArn) throw new Error("Stage-A identity bindings do not match the reviewed contract.");
  if (input.stageAExecutorLogGroupName !== "/ecs/mscqr-production/full-rls-green" || input.stageABrokerLogGroupName !== "/aws/lambda/mscqr-production-rls-approval-broker") throw new Error("Stage-A log-group names do not match the reviewed contract.");
  if (!/^arn:aws:logs:eu-west-2:368992683803:log-group:\/ecs\/mscqr-production\/full-rls-green(?::\*)?$/.test(input.stageAExecutorLogGroupArn)) throw new Error("Stage-A executor log-group ARN is malformed.");
  if (!/^arn:aws:logs:eu-west-2:368992683803:log-group:\/aws\/lambda\/mscqr-production-rls-approval-broker(?::\*)?$/.test(input.stageABrokerLogGroupArn)) throw new Error("Stage-A broker log-group ARN is malformed.");
  if (input.stageAExecutorNetworkingReady !== true) throw new Error("Stage-A executor networking readiness is not proven.");
  const network = input.networkEvidence;
  if (!network || network.vpcId !== input.vpcId || network.ecsClusterArn !== input.ecsClusterArn || !Array.isArray(network.privateSubnets) || JSON.stringify(network.privateSubnets.map((item) => item.subnetId).sort()) !== JSON.stringify([...input.privateSubnetIds].sort()) || network.privateSubnets.some((item) => !item.availabilityZone || !item.routeTableId || !/^nat-[a-f0-9]+$/.test(item.natGatewayId || "")) || new Set(network.privateSubnets.map((item) => item.availabilityZone)).size !== 2 || !Array.isArray(network.securityGroups) || JSON.stringify(network.securityGroups.map((item) => item.groupId).sort()) !== JSON.stringify([STAGE_B.databaseSecurityGroupId, STAGE_B.executorSecurityGroupId].sort()) || network.securityGroups.some((item) => item.vpcId !== input.vpcId) || !Array.isArray(network.rdsSubnetIds) || JSON.stringify([...network.rdsSubnetIds].sort()) !== JSON.stringify([...input.privateSubnetIds].sort())) throw new Error("Stage-A prerequisite live networking evidence is incomplete or wrong.");
  if (input.approvalSecretArn !== STAGE_B.approvalSecretArn || input.approvalKmsKeyArn !== STAGE_B.approvalKmsKeyArn || input.receiptBucketArn !== `arn:aws:s3:::${STAGE_B.receiptBucket}`) throw new Error("Stage-A approval or receipt binding is wrong.");
  if (!/^arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr\/production\/rls-green\/phase4\/read-only-canary-database-url-[A-Za-z0-9]+$/.test(input.stageAReadOnlyCanaryDatabaseSecretArn)) throw new Error("Stage-A read-only-canary secret ARN is malformed.");
  const roles = ["app", "read", "preauth", "worker", "scheduled", "operator", "migration"];
  if (JSON.stringify(Object.keys(input.stageARuntimeSecretArns || {}).sort()) !== JSON.stringify([...roles].sort())) throw new Error("Stage-A runtime secret roles are incomplete or over-broad.");
  for (const role of roles) if (!new RegExp(`^arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase2/database-url/${role}-[A-Za-z0-9]+$`).test(input.stageARuntimeSecretArns[role])) throw new Error(`Stage-A runtime secret ARN is malformed: ${role}.`);
  return input;
}

function parseContainerDefinitions(attributes, label) {
  let definitions;
  try { definitions = typeof attributes.container_definitions === "string" ? JSON.parse(attributes.container_definitions) : attributes.container_definitions; } catch { throw new Error(`${label} container definitions are malformed.`); }
  if (!Array.isArray(definitions) || definitions.length === 0) throw new Error(`${label} container definitions are missing.`);
  return definitions;
}

function retainedDefinition(attributes, label) {
  if (!attributes || typeof attributes !== "object" || !/^arn:aws:ecs:eu-west-2:368992683803:task-definition\/[A-Za-z0-9_-]+:[1-9][0-9]*$/.test(attributes.arn || "")) throw new Error(`${label} ARN is malformed.`);
  if (!/^[1-9][0-9]*$/.test(String(attributes.revision || "")) || !attributes.family) throw new Error(`${label} revision or family is missing.`);
  const volumes = attributes.volume || [];
  if (!Array.isArray(volumes) || volumes.some((volume) => !volume || typeof volume.name !== "string")) throw new Error(`${label} volumes are malformed.`);
  const definition = { family: attributes.family, networkMode: attributes.network_mode, requiresCompatibilities: attributes.requires_compatibilities, cpu: attributes.cpu, memory: attributes.memory, containerDefinitions: parseContainerDefinitions(attributes, label), volumes: volumes.map(({ name }) => ({ name })) };
  if (typeof definition.networkMode !== "string" || !Array.isArray(definition.requiresCompatibilities) || definition.cpu === undefined || definition.memory === undefined) throw new Error(`${label} task-definition contract is incomplete.`);
  return { definition, arn: attributes.arn, revision: String(attributes.revision) };
}

function resourceInstances(state, type, name) {
  return (state.resources || []).filter((resource) => resource.type === type && resource.name === name).flatMap((resource) => resource.instances || []);
}

function taskDefinitionFamily(kind, category) {
  const address = category === "executor" ? `aws_ecs_task_definition.executor["${kind}"]` : `aws_ecs_task_definition.candidate["${kind}"]`;
  return STAGE_B_TASK_DEFINITION_FAMILIES[address];
}

export function deriveRetainedDefinitions(state) {
  if (!state || typeof state !== "object" || state.lineage !== STAGE_B_EXPECTED_STATE_LINEAGE) throw new Error("Terraform state lineage is wrong or missing.");
  if (state.workspace && state.workspace !== STAGE_B_EXPECTED_WORKSPACE) throw new Error("Terraform state workspace is not production.");
  if (!Number.isInteger(state.serial) || state.serial < STAGE_B_MINIMUM_STATE_SERIAL) throw new Error("Terraform state serial is stale or malformed.");
  const resources = state.resources || [];
  if (resources.some((resource) => resource.type === "aws_ecs_task_definition" && ["candidate", "executor"].includes(resource.name))) throw new Error("Terraform state still contains current Stage B task-definition addresses.");
  const candidates = {};
  const familyRevisions = new Set();
  for (const instance of resourceInstances(state, "aws_ecs_task_definition", "candidate_retained")) {
    const match = candidateKeyPattern.exec(String(instance.index_key || ""));
    if (!match || !generationPattern.test(match[1]) || candidates[instance.index_key]) throw new Error(`Retained candidate key is missing, malformed, or duplicated: ${instance.index_key}.`);
    const { definition, revision } = retainedDefinition(instance.attributes, `Retained candidate ${instance.index_key}`);
    const expectedFamily = taskDefinitionFamily(match[2], "candidate");
    if (definition.family !== expectedFamily) throw new Error(`Retained candidate family does not match ${instance.index_key}.`);
    const familyRevision = `${definition.family}:${revision}`;
    if (familyRevisions.has(familyRevision)) throw new Error(`Retained task-definition family/revision is duplicated: ${familyRevision}.`);
    familyRevisions.add(familyRevision);
    candidates[instance.index_key] = { kind: match[2], definition: JSON.stringify(definition) };
  }
  const executors = {};
  for (const instance of resourceInstances(state, "aws_ecs_task_definition", "executor_retained")) {
    const match = executorKeyPattern.exec(String(instance.index_key || ""));
    if (!match || executors[instance.index_key]) throw new Error(`Retained executor key is missing, malformed, or duplicated: ${instance.index_key}.`);
    const mode = match[2];
    const { definition, revision } = retainedDefinition(instance.attributes, `Retained executor ${instance.index_key}`);
    if (definition.family !== taskDefinitionFamily(mode, "executor")) throw new Error(`Retained executor family does not match ${instance.index_key}.`);
    const familyRevision = `${definition.family}:${revision}`;
    if (familyRevisions.has(familyRevision)) throw new Error(`Retained task-definition family/revision is duplicated: ${familyRevision}.`);
    familyRevisions.add(familyRevision);
    executors[instance.index_key] = { mode, definition: JSON.stringify(definition) };
  }
  if (!Object.keys(candidates).length || !Object.keys(executors).length) throw new Error("Terraform state retained task-definition evidence is incomplete.");
  const candidateGenerations = new Map();
  for (const key of Object.keys(candidates)) { const match = candidateKeyPattern.exec(key); const kinds = candidateGenerations.get(match[1]) || new Set(); kinds.add(match[2]); candidateGenerations.set(match[1], kinds); }
  const executorGenerations = new Map();
  for (const key of Object.keys(executors)) { const match = executorKeyPattern.exec(key); const modes = executorGenerations.get(match[1]) || new Set(); modes.add(match[2]); executorGenerations.set(match[1], modes); }
  const requiredCandidates = new Set(["backend", "worker", "canary"]); const requiredReadOnlyCandidates = new Set([...requiredCandidates, "read_only_canary"]); const requiredExecutors = new Set(["full-rls-admin-bootstrap", "full-rls-admin-ownership", "full-rls-capability-preflight", "full-rls-role-provision", "full-rls-role-verify", "full-rls-rollback", "full-rls-runtime-policy", "full-rls-verification"]);
  const completeGeneration = (kinds) => [requiredCandidates, requiredReadOnlyCandidates].some((expected) => JSON.stringify([...kinds].sort()) === JSON.stringify([...expected].sort()));
  if ([...candidateGenerations.values()].some((kinds) => !completeGeneration(kinds)) || [...executorGenerations.values()].some((modes) => JSON.stringify([...modes].sort()) !== JSON.stringify([...requiredExecutors].sort())) || candidateGenerations.size !== executorGenerations.size || [...candidateGenerations.keys()].some((generation) => !executorGenerations.has(generation)) || [...executorGenerations.keys()].some((generation) => !candidateGenerations.has(generation))) throw new Error("Terraform state retained task-definition generations are incomplete; each generation must contain all 11 or all 12 task-definition families.");
  const policy = resourceInstances(state, "aws_iam_policy", "broker");
  if (policy.length !== 1 || policy[0].attributes?.arn !== STAGE_B_BROKER_POLICY.arn) throw new Error("Terraform state broker managed policy evidence is missing or wrong.");
  const attachment = resourceInstances(state, "aws_iam_role_policy_attachment", "broker");
  if (attachment.length !== 1 || attachment[0].attributes?.policy_arn !== STAGE_B_BROKER_POLICY.arn || attachment[0].attributes?.role !== STAGE_B_BROKER_POLICY.roleName) throw new Error("Terraform state broker policy attachment evidence is missing or wrong.");
  if (resourceInstances(state, "aws_iam_role_policy", "broker").length) throw new Error("Terraform state contains the legacy broker inline policy address.");
  return { retainedCandidateTaskDefinitions: Object.fromEntries(sortedEntries(candidates)), retainedExecutorTaskDefinitions: Object.fromEntries(sortedEntries(executors)), serial: state.serial, counts: { candidate: Object.keys(candidates).length, executor: Object.keys(executors).length } };
}

export function deriveContractDigests({ file = checksumsPath } = {}) {
  const bytes = fs.readFileSync(file); const checksums = JSON.parse(bytes);
  const sourceContractSha256 = requireDigest(checksums.sourceContractSha256, "Source-contract digest");
  const migrationSetDigest = requireDigest(checksums.migrationSetDigest, "Migration-set digest");
  return { sourceContractSha256, migrationSetDigest, packageChecksumSha256: sha256(bytes), checksumsSha256: sha256(bytes) };
}

function extractImages(report, imageReleaseSha) {
  const records = new Map();
  for (const image of report.images) {
    if (records.has(image.service)) throw new Error(`Signed image evidence contains duplicate service ${image.service}.`);
    records.set(image.service, image);
  }
  const images = {};
  for (const [variable, binding] of Object.entries(STAGE_B_PLAN_IMAGE_BINDINGS)) {
    const image = records.get(binding.service);
    if (!image || image.repository !== binding.repository || image.tag !== (binding.service === "backend" || binding.service === "worker" ? imageReleaseSha : `${imageReleaseSha}-${binding.service === "rls-executor" ? "rls-executor" : "rls-canary"}`)) throw new Error(`Signed image evidence does not match ${variable}.`);
    const digest = requireImageDigest(image.digest, `${variable} digest`);
    const reference = `${STAGE_B.account}.dkr.ecr.${STAGE_B.region}.amazonaws.com/${binding.repository}@${digest}`;
    if (!imageUriPattern.test(reference)) throw new Error(`${variable} image reference is outside the reviewed contract.`);
    images[variable] = { value: reference, digest, service: binding.service, repository: binding.repository, tag: image.tag };
  }
  return images;
}

function renderMap(value, renderValue) {
  return `{\n${sortedEntries(value).map(([key, item]) => `  ${quote(key)} = ${renderValue(item)}`).join("\n")}\n}`;
}

function renderRetained(value, field) {
  return renderMap(value, (entry) => `{ ${field} = ${quote(entry[field])}, definition = ${quote(entry.definition)} }`);
}

export function renderTfvars(values) {
  const lines = [
    `account_id = ${quote(values.account_id)}`,
    `aws_region = ${quote(values.aws_region)}`,
    `vpc_id = ${quote(values.vpc_id)}`,
    `private_subnet_ids = [${values.private_subnet_ids.map(quote).join(", ")}]`,
    `ecs_cluster_arn = ${quote(values.ecs_cluster_arn)}`,
    `stage_a_database_security_group_id = ${quote(values.stage_a_database_security_group_id)}`,
    `stage_a_executor_security_group_id = ${quote(values.stage_a_executor_security_group_id)}`,
    `stage_a_executor_task_role_arn = ${quote(values.stage_a_executor_task_role_arn)}`,
    `stage_a_broker_role_arn = ${quote(values.stage_a_broker_role_arn)}`,
    `stage_a_executor_log_group_name = ${quote(values.stage_a_executor_log_group_name)}`,
    `stage_a_executor_log_group_arn = ${quote(values.stage_a_executor_log_group_arn)}`,
    `stage_a_broker_log_group_name = ${quote(values.stage_a_broker_log_group_name)}`,
    `stage_a_broker_log_group_arn = ${quote(values.stage_a_broker_log_group_arn)}`,
    `stage_a_runtime_secret_arns = ${renderMap(values.stage_a_runtime_secret_arns, quote)}`,
    `stage_a_executor_networking_ready = ${values.stage_a_executor_networking_ready}`,
    `approval_secret_arn = ${quote(values.approval_secret_arn)}`,
    `approval_kms_key_arn = ${quote(values.approval_kms_key_arn)}`,
    `receipt_bucket_arn = ${quote(values.receipt_bucket_arn)}`,
    `broker_package_path = ${quote(values.broker_package_path)}`,
    `tooling_sha = ${quote(values.tooling_sha)}`,
    `image_release_sha = ${quote(values.image_release_sha)}`,
    `canonical_image_evidence_sha256 = ${quote(values.canonical_image_evidence_sha256)}`,
    `source_contract_sha256 = ${quote(values.source_contract_sha256)}`,
    `migration_set_digest = ${quote(values.migration_set_digest)}`,
    `package_checksum_sha256 = ${quote(values.package_checksum_sha256)}`,
    `backend_image = ${quote(values.backend_image)}`,
    `worker_image = ${quote(values.worker_image)}`,
    `executor_image = ${quote(values.executor_image)}`,
    `canary_image = ${quote(values.canary_image)}`,
    `read_only_canary_image = ${quote(values.read_only_canary_image)}`,
    `stage_a_read_only_canary_database_secret_arn = ${quote(values.stage_a_read_only_canary_database_secret_arn)}`,
    `retained_candidate_task_definitions = ${renderRetained(values.retained_candidate_task_definitions, "kind")}`,
    `retained_executor_task_definitions = ${renderRetained(values.retained_executor_task_definitions, "mode")}`,
  ];
  return `${lines.join("\n")}\n`;
}

function readGeneratedString(tfvarsBytes, variable) {
  const line = tfvarsBytes.toString("utf8").split("\n").find((candidate) => candidate.startsWith(`${variable} = `));
  const encoded = line?.slice(variable.length + 3);
  if (!encoded) throw new Error(`Stage B tfvars is missing ${variable}.`);
  try { return JSON.parse(encoded); } catch { throw new Error(`Stage B tfvars ${variable} is malformed.`); }
}

function assertBrokerPackageBinding(tfvarsBytes, report) {
  if (!path.isAbsolute(report.brokerPackagePath)) throw new Error("Stage B broker package path in the binding report must be absolute.");
  const tfvarsBrokerPath = readGeneratedString(tfvarsBytes, "broker_package_path");
  if (!path.isAbsolute(tfvarsBrokerPath) || tfvarsBrokerPath !== report.brokerPackagePath) throw new Error("Stage B broker package path does not match the canonical binding report.");
  const stat = fs.lstatSync(tfvarsBrokerPath, { throwIfNoEntry: false });
  if (!stat?.isFile() || stat.isSymbolicLink() || stat.size === 0) throw new Error("Stage B broker package must be a non-empty regular file.");
  const bytes = fs.readFileSync(tfvarsBrokerPath);
  if (sha256(bytes) !== report.brokerPackageRawSha256) throw new Error("Stage B broker package raw SHA256 does not match the canonical binding report.");
  if (base64Sha256(bytes) !== report.brokerPackageBase64Sha256) throw new Error("Stage B broker package base64 SHA256 does not match the canonical binding report.");
}

function assertStageAPrerequisiteBinding(report) {
  for (const [field, label] of [["stageAInputPath", "Stage-A prerequisite input"], ["stageAStateBackupPath", "Stage-A state backup"]]) {
    if (!path.isAbsolute(report[field] || "")) throw new Error(`${label} path in the binding report must be absolute.`);
    const stat = fs.lstatSync(report[field], { throwIfNoEntry: false });
    if (!stat?.isFile() || stat.isSymbolicLink()) throw new Error(`${label} must remain a regular file.`);
  }
  const inputBytes = fs.readFileSync(report.stageAInputPath); const stateBytes = fs.readFileSync(report.stageAStateBackupPath);
  if (sha256(inputBytes) !== report.stageAInputSha256) throw new Error("Stage-A prerequisite input was modified after canonical generation.");
  if (sha256(stateBytes) !== report.stageAStateBackupSha256) throw new Error("Stage-A state backup was modified after canonical generation.");
  const input = validateStageBStageAInput(JSON.parse(inputBytes), { toolingSha: report.toolingSha, toolingTreeSha256: report.toolingTreeSha256 });
  if (input.sourceStateSha256 !== report.stageAStateBackupSha256) throw new Error("Stage-A prerequisite input no longer matches its source state backup.");
}

export function assertStageBTfvarsBinding({ tfvarsPath, bindingReportPath, bindingReportSha256, expectedToolingSha, expectedToolingTreeSha256, expectedImageReleaseSha, expectedImageEvidenceSha256 } = {}) {
  assertAbsoluteFile(tfvarsPath, "Tfvars"); assertAbsoluteFile(bindingReportPath, "Binding report");
  const tfvarsBytes = fs.readFileSync(tfvarsPath); const reportBytes = fs.readFileSync(bindingReportPath); const report = JSON.parse(reportBytes);
  if (bindingReportSha256 && sha256(reportBytes) !== bindingReportSha256) throw new Error("Stage B tfvars binding-report SHA256 does not match the approved digest.");
  if (report?.schemaVersion !== STAGE_B_TFVARS_BINDING_REPORT_SCHEMA_VERSION || report.tfvarsSchemaVersion !== STAGE_B_TFVARS_SCHEMA_VERSION || report.generator !== STAGE_B_TFVARS_GENERATOR) throw new Error("Stage B tfvars binding report is not produced by the canonical generator.");
  if (report.tfvarsSha256 !== sha256(tfvarsBytes)) throw new Error("Stage B tfvars was modified after canonical generation.");
  assertBrokerPackageBinding(tfvarsBytes, report);
  assertStageAPrerequisiteBinding(report);
  for (const [key, expected] of [["toolingSha", expectedToolingSha], ["toolingTreeSha256", expectedToolingTreeSha256], ["imageReleaseSha", expectedImageReleaseSha], ["imageEvidenceCanonicalSha256", expectedImageEvidenceSha256]]) if (expected !== undefined && report[key] !== expected) throw new Error(`Stage B tfvars binding report ${key} does not match the current deployment identity.`);
  if (report.stateLineage !== STAGE_B_EXPECTED_STATE_LINEAGE || !Number.isInteger(report.stateSerial)) throw new Error("Stage B tfvars binding report state identity is malformed.");
  const expectedImages = ["backend", "worker", "executor", "canary", "readOnlyCanary"];
  if (JSON.stringify(Object.keys(report.images || {}).sort()) !== JSON.stringify([...expectedImages].sort())) throw new Error("Stage B tfvars binding report does not contain exactly the five image bindings.");
  for (const image of Object.values(report.images)) {
    if (image.matchesEvidence !== true || image.digestLength !== 71 || !imageReferencePattern(image.imageReference) || !tfvarsBytes.toString("utf8").includes(`${image.terraformVariable} = ${quote(image.imageReference)}`)) throw new Error("Stage B tfvars image binding is missing, modified, or not equal to signed evidence.");
  }
  return report;
}

function imageReferencePattern(value) { return imageUriPattern.test(String(value || "")); }

function validateTfvarsValues(values) {
  for (const field of ["tooling_sha", "image_release_sha"]) if (!/^[a-f0-9]{40}$/.test(values[field] || "")) throw new Error(`${field} is malformed.`);
  for (const field of ["canonical_image_evidence_sha256", "source_contract_sha256", "migration_set_digest", "package_checksum_sha256"]) requireDigest(values[field], field);
  for (const field of ["backend_image", "worker_image", "executor_image", "canary_image", "read_only_canary_image"]) if (!imageUriPattern.test(values[field] || "")) throw new Error(`${field} is not an immutable Stage B image reference.`);
}

export function generateStageBTfvars({ imageEvidence, imageEvidenceSignature, stateBackup, stageAInput, stageAStateBackup, brokerPackagePath, toolingSha, toolingTreeSha256, imageReleaseSha, workflowRunId, canonicalArtifactSha256, workspace = STAGE_B_EXPECTED_WORKSPACE, now = new Date().toISOString(), verifySignature = verifyImageEvidenceSignature, checksumsFile = checksumsPath, outputPath, bindingReportPath, allowOverwrite = false } = {}) {
  if (!/^[a-f0-9]{40}$/.test(toolingSha || "") || !digestPattern.test(toolingTreeSha256 || "") || !/^[a-f0-9]{40}$/.test(imageReleaseSha || "")) throw new Error("Tooling, tooling-tree, or image-release identity is malformed.");
  if (workspace !== STAGE_B_EXPECTED_WORKSPACE) throw new Error("Stage B tfvars require the production workspace.");
  assertAbsoluteFile(imageEvidence, "Image evidence"); assertAbsoluteFile(imageEvidenceSignature, "Image-evidence signature"); assertAbsoluteFile(stateBackup, "State backup"); assertAbsoluteFile(stageAInput, "Stage-A prerequisite input"); assertAbsoluteFile(stageAStateBackup, "Stage-A state backup"); assertAbsoluteFile(brokerPackagePath, "Broker package");
  const brokerPackageStat = fs.lstatSync(brokerPackagePath);
  if (!brokerPackageStat.isFile() || brokerPackageStat.isSymbolicLink() || brokerPackageStat.size === 0) throw new Error("Broker package must be a non-empty regular file.");
  if (outputPath) assertOutputPath(outputPath, "Tfvars output"); if (bindingReportPath) assertOutputPath(bindingReportPath, "Binding-report output");
  if (!outputPath || !bindingReportPath) throw new Error("Tfvars and binding-report output paths are required.");
  const report = readJson(imageEvidence); const signature = readJson(imageEvidenceSignature);
  assertImageEvidence(report, { signatureArtifact: signature, verifySignature, imageReleaseSha, workflowRunId, artifactSha256: canonicalArtifactSha256, now });
  const evidenceSha256 = imageEvidenceSha256(report);
  const images = extractImages(report, imageReleaseSha);
  const state = readJson(stateBackup); const retained = deriveRetainedDefinitions(state); const stageAStateBytes = fs.readFileSync(stageAStateBackup); const stageA = validateStageBStageAInput(readJson(stageAInput), { toolingSha, toolingTreeSha256 });
  if (sha256(stageAStateBytes) !== stageA.sourceStateSha256) throw new Error("Stage-A prerequisite input does not match its source state backup.");
  const contract = deriveContractDigests({ file: checksumsFile }); const brokerBytes = fs.readFileSync(brokerPackagePath);
  const values = {
    account_id: STAGE_B.account, aws_region: STAGE_B.region, vpc_id: stageA.vpcId, private_subnet_ids: [...stageA.privateSubnetIds].sort(), ecs_cluster_arn: stageA.ecsClusterArn,
    stage_a_database_security_group_id: stageA.stageADatabaseSecurityGroupId, stage_a_executor_security_group_id: stageA.stageAExecutorSecurityGroupId, stage_a_executor_task_role_arn: stageA.stageAExecutorTaskRoleArn, stage_a_broker_role_arn: stageA.stageABrokerRoleArn,
    stage_a_executor_log_group_name: stageA.stageAExecutorLogGroupName, stage_a_executor_log_group_arn: stageA.stageAExecutorLogGroupArn, stage_a_broker_log_group_name: stageA.stageABrokerLogGroupName, stage_a_broker_log_group_arn: stageA.stageABrokerLogGroupArn,
    stage_a_runtime_secret_arns: stageA.stageARuntimeSecretArns, stage_a_executor_networking_ready: stageA.stageAExecutorNetworkingReady, approval_secret_arn: stageA.approvalSecretArn, approval_kms_key_arn: stageA.approvalKmsKeyArn, receipt_bucket_arn: stageA.receiptBucketArn,
    broker_package_path: path.resolve(brokerPackagePath), tooling_sha: toolingSha, image_release_sha: imageReleaseSha, canonical_image_evidence_sha256: evidenceSha256, source_contract_sha256: contract.sourceContractSha256, migration_set_digest: contract.migrationSetDigest, package_checksum_sha256: contract.packageChecksumSha256,
    backend_image: images.backend_image.value, worker_image: images.worker_image.value, executor_image: images.executor_image.value, canary_image: images.canary_image.value, read_only_canary_image: images.read_only_canary_image.value, stage_a_read_only_canary_database_secret_arn: stageA.stageAReadOnlyCanaryDatabaseSecretArn,
    retained_candidate_task_definitions: retained.retainedCandidateTaskDefinitions, retained_executor_task_definitions: retained.retainedExecutorTaskDefinitions,
  };
  validateTfvarsValues(values);
  const tfvars = renderTfvars(values); const tfvarsBytes = Buffer.from(tfvars); const tfvarsSha256 = sha256(tfvarsBytes); const stateBytes = fs.readFileSync(stateBackup);
  const bindingReport = {
    schemaVersion: STAGE_B_TFVARS_BINDING_REPORT_SCHEMA_VERSION,
    tfvarsSchemaVersion: STAGE_B_TFVARS_SCHEMA_VERSION,
    generator: STAGE_B_TFVARS_GENERATOR,
    toolingSha, toolingTreeSha256, imageReleaseSha, imageEvidenceCanonicalSha256: evidenceSha256,
    imageEvidenceSource: path.basename(imageEvidence), imageEvidenceSignatureSha256: sha256(fs.readFileSync(imageEvidenceSignature)), stageAInputPath: path.resolve(stageAInput), stageAInputSha256: sha256(fs.readFileSync(stageAInput)), stageAStateBackupPath: path.resolve(stageAStateBackup), stageAStateBackupSha256: sha256(stageAStateBytes), stateLineage: state.lineage, stateSerial: retained.serial, stateBackupSha256: sha256(stateBytes),
    brokerPackagePath: path.resolve(brokerPackagePath), brokerPackageRawSha256: sha256(brokerBytes), brokerPackageBase64Sha256: base64Sha256(brokerBytes), sourceContractSha256: contract.sourceContractSha256, migrationSetDigest: contract.migrationSetDigest, packageChecksumSha256: contract.packageChecksumSha256,
    images: Object.fromEntries(Object.entries(images).map(([variable, image]) => [variable === "read_only_canary_image" ? "readOnlyCanary" : variable.replace(/_image$/, ""), { terraformVariable: variable, service: image.service, repository: image.repository, tag: image.tag, imageReference: image.value, digestLength: image.digest.length, digest: image.digest, matchesEvidence: report.images.find((record) => record.service === image.service)?.digest === image.digest }])),
    retainedDefinitions: { candidate: retained.counts.candidate, executor: retained.counts.executor },
    tfvarsSha256,
  };
  if (Object.values(bindingReport.images).some((image) => image.digestLength !== 71 || image.matchesEvidence !== true)) throw new Error("Stage B image binding report contains an unequal or malformed digest.");
  writeAtomicPair({ tfvarsPath: outputPath, bindingReportPath, tfvarsBytes, bindingReportBytes: Buffer.from(`${JSON.stringify(bindingReport, null, 2)}\n`), allowOverwrite });
  return { outputPath, bindingReportPath, tfvarsSha256, bindingReport, values };
}

function requiredOption(argv, option) { const index = argv.indexOf(option); const value = index === -1 ? undefined : argv[index + 1]; if (!value || value.startsWith("--")) throw new Error(`${option} is required.`); return value; }

export function parseCli(argv = process.argv.slice(2)) {
  return {
    imageEvidence: requiredOption(argv, "--image-evidence"), imageEvidenceSignature: requiredOption(argv, "--image-evidence-signature"), stateBackup: requiredOption(argv, "--state-backup"), stageAInput: requiredOption(argv, "--stage-a-input"), stageAStateBackup: requiredOption(argv, "--stage-a-state-backup"), brokerPackagePath: requiredOption(argv, "--broker-package"),
    toolingSha: requiredOption(argv, "--tooling-sha"), toolingTreeSha256: requiredOption(argv, "--tooling-tree-sha256"), imageReleaseSha: requiredOption(argv, "--image-release-sha"), workflowRunId: requiredOption(argv, "--workflow-run-id"), canonicalArtifactSha256: requiredOption(argv, "--canonical-artifact-sha256"), workspace: requiredOption(argv, "--workspace"), outputPath: requiredOption(argv, "--output"), bindingReportPath: requiredOption(argv, "--binding-report"), allowOverwrite: argv.includes("--allow-overwrite"),
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { const result = generateStageBTfvars(parseCli()); console.log(JSON.stringify({ outputPath: result.outputPath, bindingReportPath: result.bindingReportPath, tfvarsSha256: result.tfvarsSha256 }, null, 2)); } catch (error) { console.error(error.message); process.exitCode = 1; }
}

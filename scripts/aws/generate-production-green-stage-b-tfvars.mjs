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
import { STAGE_B, STAGE_B_MODES, canonicalJson } from "./production-green-stage-b-contract.mjs";
import { resolveStageBRecoveryMode, STAGE_B_BROKER_POLICY } from "./stage-b-deployment-contract.mjs";
import { assertStageBBrokerPackageManifest } from "./package-production-green-stage-b-broker.mjs";
import { STAGE_B_TASK_DEFINITION_FAMILIES } from "./stage-b-reference-audit-contract.mjs";
import { assertStageAStateIdentity, STAGE_A_EXPECTED_STATE_LINEAGE, STAGE_A_MINIMUM_STATE_SERIAL, STAGE_A_PREREQUISITES_GENERATOR, STAGE_A_PREREQUISITES_SCHEMA_VERSION, STAGE_A_STATE_OBJECT } from "./generate-production-green-stage-a-prerequisites.mjs";
import { assertStageBArtifactPath, assertStageBPrivateFile, ensureStageBPrivateDirectory, writeStageBPrivateFilesAtomic } from "./stage-b-artifact-contract.mjs";
import { assertCanonicalTerraformSerialNumber, assertVerifiedStageBRecovery } from "./stage-b-partial-apply-recovery-contract.mjs";

export const STAGE_B_TFVARS_SCHEMA_VERSION = 1;
export const STAGE_B_TFVARS_BINDING_REPORT_SCHEMA_VERSION = 2;
export const STAGE_B_TFVARS_FORMAT = "hcl";
export const STAGE_B_TFVARS_EXTENSION = ".tfvars";
export const STAGE_B_EXPECTED_ENVIRONMENT = "production";
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
  "schemaVersion", "generator", "toolingSha", "toolingTreeSha256", "stageAStateObject", "stageAStateLineage", "stageAStateSerial", "stageAStateSha256", "networkEvidence", "accountId", "region", "vpcId", "privateSubnetIds", "ecsClusterArn",
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
  if (!path.isAbsolute(file)) throw new Error(`${label} must be an existing absolute file.`);
  assertStageBPrivateFile({ filePath: file, repositoryRoot: root, label });
}

function assertOutputPath(file, label) {
  if (!path.isAbsolute(file)) throw new Error(`${label} must be an absolute private path.`);
  if (path.resolve(file) === path.resolve(root) || path.resolve(file).startsWith(`${root}${path.sep}`)) {
    throw new Error(`${label} must be outside the repository.`);
  }
  ensureStageBPrivateDirectory({ directory: path.dirname(file), repositoryRoot: root, create: true });
}

export function assertStageBCanonicalTfvarsOutputPath(file) {
  if (!path.isAbsolute(file) || path.extname(file) !== STAGE_B_TFVARS_EXTENSION || file.endsWith(".tfvars.json")) {
    throw new Error("Stage B canonical HCL tfvars output must use a .tfvars filename.");
  }
  assertOutputPath(file, "Tfvars output");
  return file;
}

export function assertStageBCanonicalTfvarsFile({ tfvarsPath, bindingReport, tfvarsBytes } = {}) {
  assertStageBCanonicalTfvarsOutputPath(tfvarsPath);
  const stat = fs.lstatSync(tfvarsPath, { throwIfNoEntry: false });
  if (!stat?.isFile() || stat.isSymbolicLink()) throw new Error("Stage B canonical tfvars file must be a regular file.");
  if ((stat.mode & 0o777) !== 0o600) throw new Error("Stage B canonical tfvars file must have mode 0600.");
  const bytes = tfvarsBytes || fs.readFileSync(tfvarsPath);
  const text = bytes.toString("utf8");
  if (!Buffer.from(text, "utf8").equals(bytes) || !text.endsWith("\n")) throw new Error("Stage B canonical tfvars file must be UTF-8 HCL with one trailing newline.");
  try {
    JSON.parse(text);
    throw new Error("Stage B canonical tfvars content must be HCL, not JSON.");
  } catch (error) {
    if (error?.message === "Stage B canonical tfvars content must be HCL, not JSON.") throw error;
  }
  if (bindingReport) {
    if (bindingReport.tfvarsFormat !== STAGE_B_TFVARS_FORMAT) throw new Error("Stage B tfvars binding report format must be hcl.");
    if (bindingReport.tfvarsFileName !== path.basename(tfvarsPath)) throw new Error("Stage B tfvars binding report filename does not match the canonical tfvars file.");
    if (bindingReport.tfvarsExtension !== STAGE_B_TFVARS_EXTENSION) throw new Error("Stage B tfvars binding report extension must be .tfvars.");
    if (bindingReport.tfvarsSha256 !== sha256(bytes)) throw new Error("Stage B tfvars binding report tfvars SHA256 does not match the canonical tfvars file.");
  }
  return true;
}

export function writeAtomicPair({ tfvarsPath, bindingReportPath, tfvarsBytes, bindingReportBytes, allowOverwrite = false, fileSystem = fs } = {}) {
  assertStageBCanonicalTfvarsOutputPath(tfvarsPath);
  const resolvedBindingReportPath = assertStageBArtifactPath({ artifactPath: bindingReportPath, repositoryRoot: root, label: "Binding-report output", allowExisting: true });
  if (path.resolve(tfvarsPath) === resolvedBindingReportPath) throw new Error("Tfvars and binding-report outputs must be different files.");
  if (path.dirname(tfvarsPath) !== path.dirname(resolvedBindingReportPath)) throw new Error("Tfvars and binding-report outputs must use one private directory.");
  return writeStageBPrivateFilesAtomic({ repositoryRoot: root, overwrite: allowOverwrite, fsOps: fileSystem, files: [
    { filePath: tfvarsPath, bytes: tfvarsBytes, label: "Tfvars" },
    { filePath: resolvedBindingReportPath, bytes: bindingReportBytes, label: "Binding-report" },
  ] });
}

export function validateStageBStageAInput(input, { toolingSha, toolingTreeSha256 } = {}) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("Stage-A prerequisite input is malformed.");
  if (JSON.stringify(Object.keys(input).sort()) !== JSON.stringify([...stageAKeys].sort())) throw new Error("Stage-A prerequisite input fields do not match the reviewed contract.");
  if (input.schemaVersion !== STAGE_A_PREREQUISITES_SCHEMA_VERSION || input.generator !== STAGE_A_PREREQUISITES_GENERATOR || input.accountId !== STAGE_B.account || input.region !== STAGE_B.region) throw new Error("Stage-A prerequisite account, region, schema, or generator is wrong.");
  if (!/^[a-f0-9]{40}$/.test(input.toolingSha || "") || !digestPattern.test(input.toolingTreeSha256 || "") || input.stageAStateObject !== STAGE_A_STATE_OBJECT || input.stageAStateLineage !== STAGE_A_EXPECTED_STATE_LINEAGE || !Number.isInteger(input.stageAStateSerial) || input.stageAStateSerial < STAGE_A_MINIMUM_STATE_SERIAL || !digestPattern.test(input.stageAStateSha256 || "")) throw new Error("Stage-A prerequisite provenance is malformed.");
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

const currentTaskDefinitionCollections = new Set(Object.keys(STAGE_B_TASK_DEFINITION_FAMILIES)
  .map((address) => /^aws_ecs_task_definition\.([^.]+)\["[^"]+"\]$/.exec(address)?.[1])
  .filter(Boolean));
const retainedTaskDefinitionCollections = new Set(["candidate_retained", "executor_retained"]);

function isRootManagedTaskDefinition(resource) {
  return resource.mode === "managed" && (!Object.hasOwn(resource, "module") || resource.module === null);
}

export function isTerraformDeposedKey(value, label = "Terraform deposed identity") {
  if (typeof value !== "string" || !/^[a-f0-9]{8}$/.test(value)) throw new Error(`${label} is malformed.`);
  return true;
}

export function isTerraformDeposedInstance(instance, label = "Terraform state task-definition instance") {
  if (!instance || typeof instance !== "object" || Array.isArray(instance)) throw new Error(`${label} is malformed.`);
  if (!Object.hasOwn(instance, "deposed")) return false;
  isTerraformDeposedKey(instance.deposed, `${label} deposed identity`);
  return true;
}

export function validateCurrentTaskDefinitionState(resources) {
  const seen = new Set();
  const seenDeposed = new Set();
  for (const resource of resources.filter(({ type }) => type === "aws_ecs_task_definition")) {
    if (!isRootManagedTaskDefinition(resource)) throw new Error(`Terraform state task-definition resource is not a root managed resource: ${resource.name}.`);
    if (!currentTaskDefinitionCollections.has(resource.name)) {
      if (retainedTaskDefinitionCollections.has(resource.name)) continue;
      throw new Error(`Terraform state contains an unexpected Stage B task-definition collection: ${resource.name}.`);
    }
    if (!Array.isArray(resource.instances) || resource.instances.length === 0) throw new Error(`Terraform state current task-definition collection is empty or malformed: ${resource.name}.`);
    for (const instance of resource.instances) {
      const deposed = isTerraformDeposedInstance(instance, `Terraform state task-definition instance ${resource.name}`);
      if (typeof instance.index_key !== "string") throw new Error(`Terraform state current task-definition index is malformed: ${resource.name}.`);
      const address = `aws_ecs_task_definition.${resource.name}["${instance.index_key}"]`;
      const expectedFamily = STAGE_B_TASK_DEFINITION_FAMILIES[address];
      if (!expectedFamily) throw new Error(`Terraform state contains an unexpected current Stage B task-definition address: ${address}.`);
      if (deposed) {
        const deposedIdentity = `${address}:${instance.deposed}`;
        if (seenDeposed.has(deposedIdentity)) throw new Error(`Terraform state contains a duplicate deposed Stage B task-definition instance: ${address}.`);
        seenDeposed.add(deposedIdentity);
      } else {
        if (seen.has(address)) throw new Error(`Terraform state contains a duplicate current Stage B task-definition address: ${address}.`);
        seen.add(address);
      }
      const { definition, arn } = retainedDefinition(instance.attributes, `${deposed ? "Deposed" : "Current"} task definition ${address}`);
      const arnFamily = /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/([^:]+):/.exec(arn)?.[1];
      if (definition.family !== expectedFamily || arnFamily !== expectedFamily) throw new Error(`Terraform state current task-definition family does not match ${address}.`);
    }
  }
}

export function deriveRetainedDefinitions(state) {
  if (!state || typeof state !== "object" || state.lineage !== STAGE_B_EXPECTED_STATE_LINEAGE) throw new Error(`Stage B state lineage is wrong: expected ${STAGE_B_EXPECTED_STATE_LINEAGE}, got ${state?.lineage || "missing"}.`);
  if (state.workspace && ![STAGE_B_EXPECTED_ENVIRONMENT, "default"].includes(state.workspace)) throw new Error("Terraform state provenance is not production.");
  assertCanonicalTerraformSerialNumber(state.serial, "Stage B state serial");
  if (state.serial < STAGE_B_MINIMUM_STATE_SERIAL) throw new Error(`Stage B state serial is stale: minimum ${STAGE_B_MINIMUM_STATE_SERIAL}, got ${state.serial}.`);
  const resources = state.resources || [];
  validateCurrentTaskDefinitionState(resources);
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
    candidates[instance.index_key] = { kind: match[2], revision, arn: instance.attributes.arn, definition: JSON.stringify(definition) };
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
    executors[instance.index_key] = { mode, revision, arn: instance.attributes.arn, definition: JSON.stringify(definition) };
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

function singleStateResource(state, type, name, label) {
  const matches = (state.resources || [])
    .filter((resource) => resource.type === type && resource.name === name && resource.mode === "managed" && (!Object.hasOwn(resource, "module") || resource.module === null))
    .flatMap((resource) => resource.instances || []);
  if (matches.length !== 1) throw new Error(`${label} must contain exactly one root-managed state instance.`);
  return matches[0].attributes || {};
}

export function deriveRecoveryOnlyBindings(state) {
  const lambda = singleStateResource(state, "aws_lambda_function", "broker", "Recovery broker function state");
  const policy = singleStateResource(state, "aws_iam_policy", "broker", "Recovery broker policy state");
  if (!path.isAbsolute(lambda.filename || "")) throw new Error("Recovery broker package path must come from the absolute current Lambda state filename.");
  if (!/^[A-Za-z0-9+/]+=*$/.test(lambda.source_code_hash || "")) throw new Error("Recovery broker source_code_hash is missing or malformed.");
  const environment = lambda.environment?.[0]?.variables;
  if (!environment || typeof environment !== "object" || Array.isArray(environment) || Object.keys(environment).some((key) => typeof environment[key] !== "string")) throw new Error("Recovery broker environment must be the exact string-valued state map.");
  const expectedEnvironmentKeys = ["BROKER_APPROVAL_EXPECTED_JSON", "BROKER_APPROVAL_SECRET_ARN", "BROKER_CLUSTER_ARN", "BROKER_EXECUTOR_SECURITY_GROUP_ID", "BROKER_IMAGES_JSON", "BROKER_PRIVATE_SUBNETS_JSON", "BROKER_RECEIPT_BUCKET", "BROKER_REPLAY_TABLE", "BROKER_TASK_DEFINITIONS_JSON", "BROKER_TASK_TEMPLATE_HASHES_JSON"];
  if (JSON.stringify(Object.keys(environment).sort()) !== JSON.stringify(expectedEnvironmentKeys.sort())) throw new Error("Recovery broker environment keys are not the exact Stage B state map.");
  let taskDefinitionArns;
  let approvalExpected;
  try {
    taskDefinitionArns = JSON.parse(environment.BROKER_TASK_DEFINITIONS_JSON);
    approvalExpected = JSON.parse(environment.BROKER_APPROVAL_EXPECTED_JSON);
  } catch {
    throw new Error("Recovery broker state environment contains malformed JSON bindings.");
  }
  if (!taskDefinitionArns || typeof taskDefinitionArns !== "object" || Array.isArray(taskDefinitionArns)
    || JSON.stringify(Object.keys(taskDefinitionArns).sort()) !== JSON.stringify([...STAGE_B_MODES].sort())
    || Object.values(taskDefinitionArns).some((arn) => !/^arn:aws:ecs:eu-west-2:368992683803:task-definition\/[A-Za-z0-9_-]+:[1-9][0-9]*$/.test(arn))) {
    throw new Error("Recovery broker state task-definition mapping is incomplete or malformed.");
  }
  if (!approvalExpected || typeof approvalExpected !== "object" || !digestPattern.test(approvalExpected.packageChecksumSha256 || "")) throw new Error("Recovery broker state package identity is missing.");
  if (policy.policy === undefined || typeof policy.policy !== "string") throw new Error("Recovery broker policy state is missing its exact document.");
  return { packagePath: path.resolve(lambda.filename), sourceCodeHashBase64: lambda.source_code_hash, environment, taskDefinitionArns, approvalExpected, policyDocument: policy.policy };
}

function assertRecoveryOnlyEvidence({ recovery, state, toolingSha } = {}) {
  if (!recovery || typeof recovery !== "object") throw new Error("Recovery-only mode requires the complete signed recovery evidence bundle.");
  const files = ["refreshReportPath", "attestationPath", "signaturePath", "classificationPath"];
  for (const name of files) assertAbsoluteFile(recovery[name], `Recovery ${name}`);
  const bytes = Object.fromEntries(files.map((name) => [name, fs.readFileSync(recovery[name])]));
  const hashes = {
    refreshReportSha256: recovery.refreshReportSha256,
    attestationSha256: recovery.attestationSha256,
    signatureSha256: recovery.signatureSha256,
    classificationSha256: recovery.classificationSha256,
  };
  for (const [name, value] of Object.entries(hashes)) if (!digestPattern.test(value || "") || sha256(bytes[name.replace("Sha256", "Path")]) !== value) throw new Error(`Recovery ${name} does not match its immutable evidence bytes.`);
  const refreshReport = JSON.parse(bytes.refreshReportPath); const attestation = JSON.parse(bytes.attestationPath); const signature = JSON.parse(bytes.signaturePath); const classification = JSON.parse(bytes.classificationPath);
  const verified = assertVerifiedStageBRecovery({ refreshReport, refreshReportBytes: bytes.refreshReportPath, refreshReportSha256: hashes.refreshReportSha256, classification, classificationBytes: bytes.classificationPath, classificationSha256: hashes.classificationSha256, attestation, attestationBytes: bytes.attestationPath, attestationSha256: hashes.attestationSha256, signature, signatureBytes: bytes.signaturePath, signatureSha256: hashes.signatureSha256, expectedSourceSha: toolingSha, expectedLineage: state.lineage, expectedSerial: state.serial, verifySignature: recovery.verifySignature });
  return { ...verified, report: attestation, classification, hashes };
}

function assertPartialApplyRecoveryEvidence({ recovery, state, toolingSha, toolingTreeSha256 } = {}) {
  if (!recovery || typeof recovery !== "object") throw new Error("Partial-apply recovery mode requires the authenticated observation and refresh artifacts.");
  for (const [field, label] of [["refreshReportPath", "Partial recovery refresh report"], ["observationBindingPath", "Partial recovery observation binding report"]]) assertAbsoluteFile(recovery[field], label);
  const refreshBytes = fs.readFileSync(recovery.refreshReportPath); const observationBytes = fs.readFileSync(recovery.observationBindingPath);
  const refreshReport = JSON.parse(refreshBytes); const observationBinding = JSON.parse(observationBytes);
  const refreshReportSha256 = sha256(refreshBytes); const observationBindingSha256 = sha256(observationBytes); const stateSha256 = sha256(fs.readFileSync(recovery.stateBackupPath || ""));
  if (recovery.refreshReportSha256 !== undefined && recovery.refreshReportSha256 !== refreshReportSha256) throw new Error("Partial recovery refresh report SHA256 is caller-selected or stale.");
  if (recovery.observationBindingSha256 !== undefined && recovery.observationBindingSha256 !== observationBindingSha256) throw new Error("Partial recovery observation binding SHA256 is caller-selected or stale.");
  if (observationBinding.recoveryOnly !== false || refreshReport.schemaVersion !== 1 || refreshReport.status !== "RESOURCE_DRIFT" || refreshReport.deployablePlan !== false || refreshReport.bindingReportSha256 !== observationBindingSha256 || refreshReport.tfvarsSha256 !== observationBinding.tfvarsSha256 || refreshReport.stageBStateLineage !== state.lineage || refreshReport.stageBStateSerial !== state.serial || refreshReport.stageBStateSha256 !== stateSha256 || refreshReport.toolingSha !== toolingSha || refreshReport.toolingTreeSha256 !== toolingTreeSha256) throw new Error("Partial recovery observation or refresh evidence is not bound to the authenticated serial/state residue.");
  return { refreshReportSha256, observationBindingSha256, stateSha256, stateLineage: state.lineage, stateSerial: state.serial };
}

function deriveRecoveryExecutionSecretArns(retained, taskDefinitionArns) {
  const result = {};
  for (const kind of ["backend", "worker", "canary", "read_only_canary"]) {
    const entries = Object.values(retained.retainedCandidateTaskDefinitions).filter((entry) => entry.kind === kind);
    const exactCanary = kind === "canary" ? entries.filter((entry) => entry.arn === taskDefinitionArns["full-rls-application-canary"]) : [];
    const selected = (exactCanary.length ? exactCanary : entries).sort((left, right) => Number(right.revision) - Number(left.revision)).slice(0, 1);
    const secrets = selected.flatMap((entry) => JSON.parse(entry.definition).containerDefinitions?.[0]?.secrets || []).map((secret) => String(secret.valueFrom).match(/^arn:aws:secretsmanager:[^:]+:[^:]+:secret:[^:]+/)?.[0]).filter(Boolean);
    if (!secrets.length) throw new Error(`Recovery retained history has no execution secrets for ${kind}.`);
    result[kind] = [...new Set(secrets)].sort();
  }
  const executorEntries = Object.values(retained.retainedExecutorTaskDefinitions).filter((entry) => entry.mode === "full-rls-verification");
  const exactExecutor = executorEntries.filter((entry) => entry.arn === taskDefinitionArns["full-rls-verification"]);
  const selectedExecutor = (exactExecutor.length ? exactExecutor : executorEntries).sort((left, right) => Number(right.revision) - Number(left.revision)).slice(0, 1);
  const executorSecrets = selectedExecutor.flatMap((entry) => JSON.parse(entry.definition).containerDefinitions?.[0]?.secrets || []).map((secret) => String(secret.valueFrom).match(/^arn:aws:secretsmanager:[^:]+:[^:]+:secret:[^:]+/)?.[0]).filter(Boolean);
  if (!executorSecrets.length) throw new Error("Recovery retained history has no executor execution secrets.");
  result.executor = [...new Set(executorSecrets)].sort();
  return result;
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
    `deployment_environment = ${quote(values.deployment_environment)}`,
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
    `stage_b_recovery_only = ${values.stage_b_recovery_only === true}`,
    `stage_b_recovery_alias_target_version = ${values.stage_b_recovery_alias_target_version === null ? "null" : quote(values.stage_b_recovery_alias_target_version)}`,
    `stage_b_recovery_broker_environment = ${renderMap(values.stage_b_recovery_broker_environment || {}, quote)}`,
    `stage_b_recovery_task_definition_arns = ${renderMap(values.stage_b_recovery_task_definition_arns || {}, quote)}`,
    `stage_b_recovery_execution_secret_arns = ${renderMap(values.stage_b_recovery_execution_secret_arns || {}, (items) => `[${items.map(quote).join(", ")}]`)}`,
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
  assertStageBPrivateFile({ filePath: tfvarsBrokerPath, repositoryRoot: root, label: "Stage B broker package" });
  if (fs.statSync(tfvarsBrokerPath).size === 0) throw new Error("Stage B broker package must be a non-empty regular file.");
  const bytes = fs.readFileSync(tfvarsBrokerPath);
  if (sha256(bytes) !== report.brokerPackageRawSha256) throw new Error("Stage B broker package raw SHA256 does not match the canonical binding report.");
  if (base64Sha256(bytes) !== report.brokerPackageBase64Sha256) throw new Error("Stage B broker package base64 SHA256 does not match the canonical binding report.");
  const manifest = assertStageBBrokerPackageManifest({ brokerPackagePath: tfvarsBrokerPath, manifestPath: report.brokerPackageManifestPath, repositoryRoot: root, ...(report.recoveryOnly ? {} : { expectedToolingSha: report.toolingSha, expectedToolingTreeSha256: report.toolingTreeSha256 }) });
  if (manifest.sha256 !== report.brokerPackageManifestSha256 || manifest.manifest.rawSha256 !== report.brokerPackageRawSha256) throw new Error("Stage B broker package manifest binding does not match the canonical report.");
}

function assertStageAInputMatchesStateBackup(stageAInput, stageAStateBytes, stageAState, report) {
  const stateSha256 = sha256(stageAStateBytes);
  assertStageAStateIdentity(stageAState, { stateObject: stageAInput.stageAStateObject });
  if (stageAInput.stageAStateLineage !== stageAState.lineage) throw new Error("Stage-A prerequisite lineage does not match its source state backup.");
  if (stageAInput.stageAStateSerial !== stageAState.serial) throw new Error("Stage-A prerequisite serial does not match its source state backup.");
  if (stageAInput.stageAStateSha256 !== stateSha256) throw new Error("Stage-A prerequisite input does not match its source state backup.");
  if (report) {
    if (report.stageAStateObject !== stageAInput.stageAStateObject) throw new Error("Stage B tfvars binding report Stage-A state object does not match its source state backup.");
    if (report.stageAStateLineage !== stageAState.lineage) throw new Error("Stage B tfvars binding report Stage-A lineage does not match its source state backup.");
    if (report.stageAStateSerial !== stageAState.serial) throw new Error("Stage B tfvars binding report Stage-A serial does not match its source state backup.");
    if (report.stageAStateBackupSha256 !== stateSha256) throw new Error("Stage B tfvars binding report Stage-A state SHA256 does not match its source state backup.");
  }
  return stateSha256;
}

function assertStageAPrerequisiteBinding(report) {
  for (const [field, label] of [["stageAInputPath", "Stage-A prerequisite input"], ["stageAStateBackupPath", "Stage-A state backup"]]) {
    if (!path.isAbsolute(report[field] || "")) throw new Error(`${label} path in the binding report must be absolute.`);
    assertStageBPrivateFile({ filePath: report[field], repositoryRoot: root, label });
  }
  const inputBytes = fs.readFileSync(report.stageAInputPath); const stateBytes = fs.readFileSync(report.stageAStateBackupPath);
  if (sha256(inputBytes) !== report.stageAInputSha256) throw new Error("Stage-A prerequisite input was modified after canonical generation.");
  if (sha256(stateBytes) !== report.stageAStateBackupSha256) throw new Error("Stage-A state backup was modified after canonical generation.");
  const input = validateStageBStageAInput(JSON.parse(inputBytes), { toolingSha: report.toolingSha, toolingTreeSha256: report.toolingTreeSha256 });
  const stageAState = JSON.parse(stateBytes);
  assertStageAInputMatchesStateBackup(input, stateBytes, stageAState, report);
}

export function assertStageBTfvarsBinding({ tfvarsPath, bindingReportPath, bindingReportSha256, expectedToolingSha, expectedToolingTreeSha256, expectedImageReleaseSha, expectedImageEvidenceSha256 } = {}) {
  assertAbsoluteFile(tfvarsPath, "Tfvars"); assertAbsoluteFile(bindingReportPath, "Binding report");
  assertStageBPrivateFile({ filePath: bindingReportPath, repositoryRoot: root, label: "Stage B tfvars binding report" });
  const tfvarsBytes = fs.readFileSync(tfvarsPath); const reportBytes = fs.readFileSync(bindingReportPath); const report = JSON.parse(reportBytes);
  assertStageBCanonicalTfvarsFile({ tfvarsPath, bindingReport: report, tfvarsBytes });
  if (bindingReportSha256 && sha256(reportBytes) !== bindingReportSha256) throw new Error("Stage B tfvars binding-report SHA256 does not match the approved digest.");
  if (report?.schemaVersion !== STAGE_B_TFVARS_BINDING_REPORT_SCHEMA_VERSION || report.tfvarsSchemaVersion !== STAGE_B_TFVARS_SCHEMA_VERSION || report.generator !== STAGE_B_TFVARS_GENERATOR) throw new Error("Stage B tfvars binding report is not produced by the canonical generator.");
  if (report.tfvarsSha256 !== sha256(tfvarsBytes)) throw new Error("Stage B tfvars was modified after canonical generation.");
  if (report.recoveryOnly !== undefined && typeof report.recoveryOnly !== "boolean") throw new Error("Stage B tfvars binding recovery-only flag is malformed.");
  if (report.recoveryOnly === undefined) report.recoveryOnly = false;
  if (report.partialApplyRecovery !== undefined && typeof report.partialApplyRecovery !== "boolean") throw new Error("Stage B tfvars binding partial-recovery flag is malformed.");
  if (report.partialApplyRecovery === undefined) report.partialApplyRecovery = false;
  if (report.freshImagePartialApplyRecovery !== undefined && typeof report.freshImagePartialApplyRecovery !== "boolean") throw new Error("Stage B tfvars binding fresh-image recovery flag is malformed.");
  if (report.freshImagePartialApplyRecovery === undefined) report.freshImagePartialApplyRecovery = false;
  if (typeof report.recoveryMode !== "string") throw new Error("Stage B tfvars binding recovery mode is missing.");
  const expectedRecoveryMode = resolveStageBRecoveryMode({ recoveryOnly: report.recoveryOnly, partialApplyRecovery: report.partialApplyRecovery, freshImagePartialApplyRecovery: report.freshImagePartialApplyRecovery });
  if (report.recoveryMode !== expectedRecoveryMode) throw new Error("Stage B tfvars binding recovery mode is inconsistent.");
  assertBrokerPackageBinding(tfvarsBytes, report);
  assertStageAPrerequisiteBinding(report);
  for (const [key, expected] of [["toolingSha", expectedToolingSha], ["toolingTreeSha256", expectedToolingTreeSha256], ["imageReleaseSha", expectedImageReleaseSha], ["imageEvidenceCanonicalSha256", expectedImageEvidenceSha256]]) if (expected !== undefined && report[key] !== expected) throw new Error(`Stage B tfvars binding report ${key} does not match the current deployment identity.`);
  assertCanonicalTerraformSerialNumber(report.stateSerial, "Stage B tfvars binding state serial");
  if (report.stateLineage !== STAGE_B_EXPECTED_STATE_LINEAGE) throw new Error("Stage B tfvars binding report state identity is malformed.");
  const expectedImages = ["backend", "worker", "executor", "canary", "readOnlyCanary"];
  if (JSON.stringify(Object.keys(report.images || {}).sort()) !== JSON.stringify([...expectedImages].sort())) throw new Error("Stage B tfvars binding report does not contain exactly the five image bindings.");
  for (const image of Object.values(report.images)) {
    if (image.matchesEvidence !== true || image.digestLength !== 71 || !imageReferencePattern(image.imageReference) || !tfvarsBytes.toString("utf8").includes(`${image.terraformVariable} = ${quote(image.imageReference)}`)) throw new Error("Stage B tfvars image binding is missing, modified, or not equal to signed evidence.");
  }
  if (report.recoveryOnly === true) {
    if (!digestPattern.test(report.recoveryAttestationSha256 || "") || !digestPattern.test(report.recoveryClassificationSha256 || "") || !digestPattern.test(report.recoveryRefreshReportSha256 || "") || report.recoveryStateLineage !== report.stateLineage || report.recoveryStateSerial !== report.stateSerial || report.recoveryDesiredVersion === null || !/^[1-9][0-9]*$/.test(String(report.recoveryDesiredVersion))) throw new Error("Recovery-only tfvars binding report is incomplete or state-unbound.");
    if (!tfvarsBytes.toString("utf8").includes("stage_b_recovery_only = true") || !tfvarsBytes.toString("utf8").includes(`stage_b_recovery_alias_target_version = ${quote(report.recoveryDesiredVersion)}`)) throw new Error("Recovery-only tfvars does not carry the exact attested target binding.");
  }
  if (["PARTIAL_APPLY_RECOVERY", "FRESH_IMAGE_PARTIAL_APPLY_RECOVERY"].includes(report.recoveryMode)) {
    if (report.recoveryOnly === true || !digestPattern.test(report.recoveryRefreshReportSha256 || "") || !digestPattern.test(report.recoveryObservationBindingSha256 || "") || report.recoveryStateLineage !== report.stateLineage || report.recoveryStateSerial !== report.stateSerial) throw new Error("Partial-apply recovery tfvars binding report is incomplete or state-unbound.");
    if (tfvarsBytes.toString("utf8").includes("stage_b_recovery_only = true")) throw new Error("Partial-apply recovery tfvars cannot use RECOVERY_ALIAS_ONLY inputs.");
  }
  if (report.freshImagePartialApplyRecovery === true) {
    if (report.recoveryMode !== "FRESH_IMAGE_PARTIAL_APPLY_RECOVERY" || report.imageReleaseSha !== report.toolingSha || report.imagePublicationSourceSha !== report.toolingSha || report.imagePublicationWorkflowDefinitionSha !== report.toolingSha || !digestPattern.test(report.imagePublicationIdentitySha256 || "") || !/^\d+$/.test(String(report.imageEvidenceWorkflowRunId || ""))) throw new Error("Fresh-image partial-apply recovery tfvars binding is not source-bound to fresh publication evidence.");
  }
  return report;
}

function imageReferencePattern(value) { return imageUriPattern.test(String(value || "")); }

function validateTfvarsValues(values) {
  for (const field of ["tooling_sha", "image_release_sha"]) if (!/^[a-f0-9]{40}$/.test(values[field] || "")) throw new Error(`${field} is malformed.`);
  for (const field of ["canonical_image_evidence_sha256", "source_contract_sha256", "migration_set_digest", "package_checksum_sha256"]) requireDigest(values[field], field);
  for (const field of ["backend_image", "worker_image", "executor_image", "canary_image", "read_only_canary_image"]) if (!imageUriPattern.test(values[field] || "")) throw new Error(`${field} is not an immutable Stage B image reference.`);
}

export function generateStageBTfvars({ imageEvidence, imageEvidenceSignature, stateBackup, stageAInput, stageAStateBackup, brokerPackagePath, toolingSha, toolingTreeSha256, imageReleaseSha, workflowRunId, canonicalArtifactSha256, environment = STAGE_B_EXPECTED_ENVIRONMENT, now = new Date().toISOString(), verifySignature = verifyImageEvidenceSignature, checksumsFile = checksumsPath, outputPath, bindingReportPath, allowOverwrite = false, recoveryOnly = false, partialApplyRecovery = false, freshImagePartialApplyRecovery = false, recovery } = {}) {
  if (!/^[a-f0-9]{40}$/.test(toolingSha || "") || !digestPattern.test(toolingTreeSha256 || "") || !/^[a-f0-9]{40}$/.test(imageReleaseSha || "")) throw new Error("Tooling, tooling-tree, or image-release identity is malformed.");
  const recoveryMode = resolveStageBRecoveryMode({ recoveryOnly, partialApplyRecovery, freshImagePartialApplyRecovery });
  const partialRecoveryMode = recoveryMode === "PARTIAL_APPLY_RECOVERY" || recoveryMode === "FRESH_IMAGE_PARTIAL_APPLY_RECOVERY";
  if (recovery && recoveryMode === "NORMAL") throw new Error("Recovery artifacts require an explicit Stage B recovery mode.");
  if (freshImagePartialApplyRecovery && imageReleaseSha !== toolingSha) throw new Error("Fresh-image partial-apply recovery requires images released from the protected source SHA.");
  if (environment !== STAGE_B_EXPECTED_ENVIRONMENT) throw new Error("Stage B tfvars require the production environment.");
  assertAbsoluteFile(imageEvidence, "Image evidence"); assertAbsoluteFile(imageEvidenceSignature, "Image-evidence signature"); assertAbsoluteFile(stateBackup, "State backup"); assertAbsoluteFile(stageAInput, "Stage-A prerequisite input"); assertAbsoluteFile(stageAStateBackup, "Stage-A state backup"); assertAbsoluteFile(brokerPackagePath, "Broker package");
  const brokerPackageStat = fs.lstatSync(brokerPackagePath);
  if (!brokerPackageStat.isFile() || brokerPackageStat.isSymbolicLink() || brokerPackageStat.size === 0) throw new Error("Broker package must be a non-empty regular file.");
  if (outputPath) assertStageBCanonicalTfvarsOutputPath(outputPath); if (bindingReportPath) assertOutputPath(bindingReportPath, "Binding-report output");
  if (!outputPath || !bindingReportPath) throw new Error("Tfvars and binding-report output paths are required.");
  const report = readJson(imageEvidence); const signature = readJson(imageEvidenceSignature);
  assertImageEvidence(report, { signatureArtifact: signature, verifySignature, toolingSha, imageReleaseSha, workflowRunId, artifactSha256: canonicalArtifactSha256, now });
  if (freshImagePartialApplyRecovery && (report.publicationIdentity?.imageReleaseSha !== toolingSha || report.publicationIdentity?.workflowDefinitionSha !== toolingSha || report.publicationIdentity?.headBranch !== "main" || report.publicationIdentity?.conclusion !== "success" || report.publicationIdentity?.artifactExpired !== false)) throw new Error("Fresh-image publication evidence is not bound to the protected source or a successful non-expired publication.");
  const evidenceSha256 = imageEvidenceSha256(report);
  const images = extractImages(report, imageReleaseSha);
  const state = readJson(stateBackup); const retained = deriveRetainedDefinitions(state);
  const recoveryEvidence = recoveryOnly ? assertRecoveryOnlyEvidence({ recovery, state, toolingSha }) : null;
  const partialRecoveryEvidence = partialRecoveryMode ? assertPartialApplyRecoveryEvidence({ recovery: { ...recovery, stateBackupPath: stateBackup }, state, toolingSha, toolingTreeSha256 }) : null;
  const recoveryBindings = recoveryOnly ? deriveRecoveryOnlyBindings(state) : null;
  if (recoveryOnly && path.resolve(brokerPackagePath) !== recoveryBindings.packagePath) throw new Error("Recovery-only broker package path must match the current Lambda state filename exactly.");
  if (recoveryOnly && base64Sha256(fs.readFileSync(brokerPackagePath)) !== recoveryBindings.sourceCodeHashBase64) throw new Error("Recovery-only broker package bytes do not match the current Lambda source_code_hash.");
  const stageAStateBytes = fs.readFileSync(stageAStateBackup);
  const stageAState = JSON.parse(stageAStateBytes);
  const stageAPrerequisiteInput = validateStageBStageAInput(readJson(stageAInput), { toolingSha, toolingTreeSha256 });
  const stageAStateSha256 = assertStageAInputMatchesStateBackup(stageAPrerequisiteInput, stageAStateBytes, stageAState);
  const contract = deriveContractDigests({ file: checksumsFile }); const brokerBytes = fs.readFileSync(brokerPackagePath);
  const brokerManifest = assertStageBBrokerPackageManifest({ brokerPackagePath, repositoryRoot: root, ...(recoveryOnly ? {} : { expectedToolingSha: toolingSha, expectedToolingTreeSha256: toolingTreeSha256 }) });
  const values = {
    account_id: STAGE_B.account, aws_region: STAGE_B.region, deployment_environment: environment, vpc_id: stageAPrerequisiteInput.vpcId, private_subnet_ids: [...stageAPrerequisiteInput.privateSubnetIds].sort(), ecs_cluster_arn: stageAPrerequisiteInput.ecsClusterArn,
    stage_a_database_security_group_id: stageAPrerequisiteInput.stageADatabaseSecurityGroupId, stage_a_executor_security_group_id: stageAPrerequisiteInput.stageAExecutorSecurityGroupId, stage_a_executor_task_role_arn: stageAPrerequisiteInput.stageAExecutorTaskRoleArn, stage_a_broker_role_arn: stageAPrerequisiteInput.stageABrokerRoleArn,
    stage_a_executor_log_group_name: stageAPrerequisiteInput.stageAExecutorLogGroupName, stage_a_executor_log_group_arn: stageAPrerequisiteInput.stageAExecutorLogGroupArn, stage_a_broker_log_group_name: stageAPrerequisiteInput.stageABrokerLogGroupName, stage_a_broker_log_group_arn: stageAPrerequisiteInput.stageABrokerLogGroupArn,
    stage_a_runtime_secret_arns: stageAPrerequisiteInput.stageARuntimeSecretArns, stage_a_executor_networking_ready: stageAPrerequisiteInput.stageAExecutorNetworkingReady, approval_secret_arn: stageAPrerequisiteInput.approvalSecretArn, approval_kms_key_arn: stageAPrerequisiteInput.approvalKmsKeyArn, receipt_bucket_arn: stageAPrerequisiteInput.receiptBucketArn,
    broker_package_path: path.resolve(brokerPackagePath), tooling_sha: toolingSha, image_release_sha: imageReleaseSha, canonical_image_evidence_sha256: evidenceSha256, source_contract_sha256: contract.sourceContractSha256, migration_set_digest: contract.migrationSetDigest, package_checksum_sha256: contract.packageChecksumSha256,
    backend_image: images.backend_image.value, worker_image: images.worker_image.value, executor_image: images.executor_image.value, canary_image: images.canary_image.value, read_only_canary_image: images.read_only_canary_image.value, stage_a_read_only_canary_database_secret_arn: stageAPrerequisiteInput.stageAReadOnlyCanaryDatabaseSecretArn,
    retained_candidate_task_definitions: retained.retainedCandidateTaskDefinitions, retained_executor_task_definitions: retained.retainedExecutorTaskDefinitions,
    stage_b_recovery_only: recoveryOnly,
    stage_b_recovery_alias_target_version: recoveryOnly ? recoveryEvidence.report.currentObservedEvidence.configuredDesiredVersion : null,
    stage_b_recovery_broker_environment: recoveryOnly ? recoveryBindings.environment : {},
    stage_b_recovery_task_definition_arns: recoveryOnly ? recoveryBindings.taskDefinitionArns : {},
    stage_b_recovery_execution_secret_arns: recoveryOnly ? deriveRecoveryExecutionSecretArns(retained, recoveryBindings.taskDefinitionArns) : {},
  };
  validateTfvarsValues(values);
  const tfvars = renderTfvars(values); const tfvarsBytes = Buffer.from(tfvars); const tfvarsSha256 = sha256(tfvarsBytes); const stateBytes = fs.readFileSync(stateBackup);
  const bindingReport = {
    schemaVersion: STAGE_B_TFVARS_BINDING_REPORT_SCHEMA_VERSION,
    tfvarsSchemaVersion: STAGE_B_TFVARS_SCHEMA_VERSION,
    tfvarsFormat: STAGE_B_TFVARS_FORMAT,
    tfvarsFileName: path.basename(outputPath),
    tfvarsExtension: STAGE_B_TFVARS_EXTENSION,
    generator: STAGE_B_TFVARS_GENERATOR,
    recoveryOnly,
    partialApplyRecovery: recoveryMode === "PARTIAL_APPLY_RECOVERY",
    freshImagePartialApplyRecovery,
    recoveryMode,
    toolingSha, toolingTreeSha256, imageReleaseSha, imageEvidenceCanonicalSha256: evidenceSha256,
    imageEvidenceSource: path.basename(imageEvidence), imageEvidenceWorkflowRunId: String(report.workflowRunId), imagePublicationIdentitySha256: report.publicationIdentitySha256, imagePublicationSourceSha: report.publicationIdentity.imageReleaseSha, imagePublicationWorkflowDefinitionSha: report.publicationIdentity.workflowDefinitionSha, imageEvidenceSignatureSha256: sha256(fs.readFileSync(imageEvidenceSignature)), stageAInputPath: path.resolve(stageAInput), stageAInputSha256: sha256(fs.readFileSync(stageAInput)), stageAStateBackupPath: path.resolve(stageAStateBackup), stageAStateBackupSha256: stageAStateSha256, stageAStateObject: stageAPrerequisiteInput.stageAStateObject, stageAStateLineage: stageAState.lineage, stageAStateSerial: stageAState.serial, stateLineage: state.lineage, stateSerial: retained.serial, stateBackupSha256: sha256(stateBytes),
    brokerPackagePath: path.resolve(brokerPackagePath), brokerPackageManifestPath: brokerManifest.path, brokerPackageManifestSha256: brokerManifest.sha256, brokerPackageManifestFormat: brokerManifest.manifest.format, brokerPackageRawSha256: sha256(brokerBytes), brokerPackageBase64Sha256: base64Sha256(brokerBytes), sourceContractSha256: contract.sourceContractSha256, migrationSetDigest: contract.migrationSetDigest, packageChecksumSha256: contract.packageChecksumSha256,
    images: Object.fromEntries(Object.entries(images).map(([variable, image]) => [variable === "read_only_canary_image" ? "readOnlyCanary" : variable.replace(/_image$/, ""), { terraformVariable: variable, service: image.service, repository: image.repository, tag: image.tag, imageReference: image.value, digestLength: image.digest.length, digest: image.digest, matchesEvidence: report.images.find((record) => record.service === image.service)?.digest === image.digest }])),
    retainedDefinitions: { candidate: retained.counts.candidate, executor: retained.counts.executor },
    recoveryOnly,
    ...(recoveryOnly ? {
      recoveryAttestationSha256: recoveryEvidence.hashes.attestationSha256,
      recoveryClassificationSha256: recoveryEvidence.hashes.classificationSha256,
      recoveryRefreshReportSha256: recoveryEvidence.hashes.refreshReportSha256,
      recoveryLiveVersion: recoveryEvidence.report.currentObservedEvidence.liveVersion,
      recoveryDesiredVersion: recoveryEvidence.report.currentObservedEvidence.configuredDesiredVersion,
      recoveryStateLineage: state.lineage,
      recoveryStateSerial: state.serial,
      recoveryBrokerPackageStatePath: recoveryBindings.packagePath,
      recoveryBrokerStateSourceCodeHashBase64: recoveryBindings.sourceCodeHashBase64,
    } : {}),
    ...(partialRecoveryMode ? {
      recoveryRefreshReportSha256: partialRecoveryEvidence.refreshReportSha256,
      recoveryObservationBindingSha256: partialRecoveryEvidence.observationBindingSha256,
      recoveryStateLineage: partialRecoveryEvidence.stateLineage,
      recoveryStateSerial: partialRecoveryEvidence.stateSerial,
    } : {}),
    tfvarsSha256,
  };
  if (Object.values(bindingReport.images).some((image) => image.digestLength !== 71 || image.matchesEvidence !== true)) throw new Error("Stage B image binding report contains an unequal or malformed digest.");
  writeAtomicPair({ tfvarsPath: outputPath, bindingReportPath, tfvarsBytes, bindingReportBytes: Buffer.from(`${JSON.stringify(bindingReport, null, 2)}\n`), allowOverwrite });
  return { outputPath, bindingReportPath, tfvarsSha256, bindingReport, values };
}

function requiredOption(argv, option) { const index = argv.indexOf(option); const value = index === -1 ? undefined : argv[index + 1]; if (!value || value.startsWith("--")) throw new Error(`${option} is required.`); return value; }

export function parseCli(argv = process.argv.slice(2)) {
  const recoveryOnly = argv.includes("--recovery-only");
  const partialApplyRecovery = argv.includes("--partial-apply-recovery");
  const freshImagePartialApplyRecovery = argv.includes("--fresh-image-partial-apply-recovery");
  resolveStageBRecoveryMode({ recoveryOnly, partialApplyRecovery, freshImagePartialApplyRecovery });
  const result = {
    imageEvidence: requiredOption(argv, "--image-evidence"), imageEvidenceSignature: requiredOption(argv, "--image-evidence-signature"), stateBackup: requiredOption(argv, "--state-backup"), stageAInput: requiredOption(argv, "--stage-a-input"), stageAStateBackup: requiredOption(argv, "--stage-a-state-backup"), brokerPackagePath: requiredOption(argv, "--broker-package"),
    toolingSha: requiredOption(argv, "--tooling-sha"), toolingTreeSha256: requiredOption(argv, "--tooling-tree-sha256"), imageReleaseSha: requiredOption(argv, "--image-release-sha"), workflowRunId: requiredOption(argv, "--workflow-run-id"), canonicalArtifactSha256: requiredOption(argv, "--canonical-artifact-sha256"), environment: requiredOption(argv, "--environment"), outputPath: requiredOption(argv, "--output"), bindingReportPath: requiredOption(argv, "--binding-report"), allowOverwrite: argv.includes("--allow-overwrite"), recoveryOnly, partialApplyRecovery, freshImagePartialApplyRecovery,
  };
  if (recoveryOnly) result.recovery = {
    refreshReportPath: requiredOption(argv, "--refresh-report"), refreshReportSha256: requiredOption(argv, "--refresh-report-sha256"),
    attestationPath: requiredOption(argv, "--recovery-attestation"), attestationSha256: requiredOption(argv, "--recovery-attestation-sha256"),
    signaturePath: requiredOption(argv, "--recovery-signature"), signatureSha256: requiredOption(argv, "--recovery-signature-sha256"),
    classificationPath: requiredOption(argv, "--recovery-classification"), classificationSha256: requiredOption(argv, "--recovery-classification-sha256"),
  };
  if (["PARTIAL_APPLY_RECOVERY", "FRESH_IMAGE_PARTIAL_APPLY_RECOVERY"].includes(resolveStageBRecoveryMode({ recoveryOnly, partialApplyRecovery, freshImagePartialApplyRecovery }))) result.recovery = {
    refreshReportPath: requiredOption(argv, "--refresh-report"),
    observationBindingPath: requiredOption(argv, "--refresh-binding-report"),
  };
  return result;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { const result = generateStageBTfvars(parseCli()); console.log(JSON.stringify({ outputPath: result.outputPath, bindingReportPath: result.bindingReportPath, tfvarsSha256: result.tfvarsSha256 }, null, 2)); } catch (error) { console.error(error.message); process.exitCode = 1; }
}

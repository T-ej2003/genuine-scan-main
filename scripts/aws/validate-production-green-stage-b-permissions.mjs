#!/usr/bin/env node
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { STAGE_B, STAGE_B_APPROVAL_ALGORITHM } from "./production-green-stage-b-contract.mjs";
import { STAGE_B_BROKER_POLICY, STAGE_B_BROKER_POLICY_STATEMENTS } from "./stage-b-deployment-contract.mjs";
import { assertStageBDeploymentIdentity } from "./stage-b-deployment-identity.mjs";
import { assertStageBTerraformBackendManifest } from "./stage-b-terraform-backend-contract.mjs";

export const PERMISSION_PREFLIGHT_SCHEMA_VERSION = 1;
export const PERMISSION_EVIDENCE_MAX_AGE_MS = 15 * 60 * 1000;
export const PERMISSION_PREFLIGHT_CLOCK_SKEW_MS = 60 * 1000;
export const PERMISSION_EVIDENCE_VALIDITY_MODEL = "live-plan-bound-15m";
export const ACCOUNT = "368992683803";
export const REGION = "eu-west-2";
export const RELEASE_ROLE_ARN = `arn:aws:iam::${ACCOUNT}:role/mscqr-production-release-deployer`;
const STAGE_A_LIVE_EVIDENCE_EVALUATIONS = Object.freeze([
  ["collect-stage-a-live-subnets", "ec2:DescribeSubnets"],
  ["collect-stage-a-live-route-tables", "ec2:DescribeRouteTables"],
  ["collect-stage-a-live-security-groups", "ec2:DescribeSecurityGroups"],
  ["collect-stage-a-live-cluster", "ecs:DescribeClusters"],
  ["collect-stage-a-live-database", "rds:DescribeDBInstances"],
]);
export const APPROVED_PREFLIGHT_GENERATOR_ARNS = Object.freeze([`arn:aws:iam::${ACCOUNT}:root`]);
export const RELEASE_CALLER_PATTERN = `^arn:aws:sts::${ACCOUNT}:assumed-role/mscqr-production-release-deployer/[^/]+$`;
export const PERMISSION_REPORT_SIGNING_KEY_ARN = STAGE_B.approvalKmsKeyArn;
export const PERMISSION_REPORT_SIGNING_ALGORITHM = STAGE_B_APPROVAL_ALGORITHM;
const BROKER_ROLE_NAME = STAGE_B_BROKER_POLICY.roleName;
const BROKER_MANAGED_POLICY_ARN = STAGE_B_BROKER_POLICY.arn;
const BROKER_MANAGED_POLICY_NAME = STAGE_B_BROKER_POLICY.name;
const BROKER_POLICY_STATEMENTS = STAGE_B_BROKER_POLICY_STATEMENTS;
const TASK_DEFINITION_TAG_CONTEXT = Object.freeze([
  { key: "aws:RequestedRegion", type: "string", values: [REGION] },
  { key: "aws:RequestTag/Environment", type: "string", values: ["production"] },
  { key: "aws:RequestTag/ManagedBy", type: "string", values: ["Terraform"] },
  { key: "aws:RequestTag/Component", type: "string", values: ["full-rls-green-stage-b"] },
  { key: "aws:TagKeys", type: "stringList", values: ["Environment", "ManagedBy", "Component"] },
]);
const TASK_DEFINITION_MAPPINGS = Object.freeze([
  ["backend", 'aws_ecs_task_definition.candidate["backend"]', "mscqr-production-rls-green-backend-candidate", "mscqr-production-rls-green-backend-execution", "mscqr-production-rls-green-backend-task"],
  ["worker", 'aws_ecs_task_definition.candidate["worker"]', "mscqr-production-rls-green-worker-candidate", "mscqr-production-rls-green-worker-execution", "mscqr-production-rls-green-worker-task"],
  ["application-canary", 'aws_ecs_task_definition.candidate["canary"]', "mscqr-production-full-rls-green-application-canary", "mscqr-production-rls-green-canary-execution", "mscqr-production-rls-green-canary-task"],
  ["read-only-canary", 'aws_ecs_task_definition.candidate["read_only_canary"]', "mscqr-production-full-rls-green-read-only-canary", "mscqr-production-full-rls-green-read-only-canary-execution", "mscqr-production-full-rls-green-read-only-canary-task"],
  ["full-rls-admin-bootstrap", 'aws_ecs_task_definition.executor["full-rls-admin-bootstrap"]', "mscqr-production-full-rls-green-full-rls-admin-bootstrap", "mscqr-production-full-rls-green-executor-execution", "mscqr-production-full-rls-green-executor-task"],
  ["full-rls-admin-ownership", 'aws_ecs_task_definition.executor["full-rls-admin-ownership"]', "mscqr-production-full-rls-green-full-rls-admin-ownership", "mscqr-production-full-rls-green-executor-execution", "mscqr-production-full-rls-green-executor-task"],
  ["full-rls-capability-preflight", 'aws_ecs_task_definition.executor["full-rls-capability-preflight"]', "mscqr-production-full-rls-green-full-rls-capability-preflight", "mscqr-production-full-rls-green-executor-execution", "mscqr-production-full-rls-green-executor-task"],
  ["full-rls-role-provision", 'aws_ecs_task_definition.executor["full-rls-role-provision"]', "mscqr-production-full-rls-green-full-rls-role-provision", "mscqr-production-full-rls-green-executor-execution", "mscqr-production-full-rls-green-executor-task"],
  ["full-rls-role-verify", 'aws_ecs_task_definition.executor["full-rls-role-verify"]', "mscqr-production-full-rls-green-full-rls-role-verify", "mscqr-production-full-rls-green-executor-execution", "mscqr-production-full-rls-green-executor-task"],
  ["full-rls-rollback", 'aws_ecs_task_definition.executor["full-rls-rollback"]', "mscqr-production-full-rls-green-full-rls-rollback", "mscqr-production-full-rls-green-executor-execution", "mscqr-production-full-rls-green-executor-task"],
  ["full-rls-runtime-policy", 'aws_ecs_task_definition.executor["full-rls-runtime-policy"]', "mscqr-production-full-rls-green-full-rls-runtime-policy", "mscqr-production-full-rls-green-executor-execution", "mscqr-production-full-rls-green-executor-task"],
  ["full-rls-verification", 'aws_ecs_task_definition.executor["full-rls-verification"]', "mscqr-production-full-rls-green-full-rls-verification", "mscqr-production-full-rls-green-executor-execution", "mscqr-production-full-rls-green-executor-task"],
].map(([id, address, family, executionRoleName, taskRoleName]) => Object.freeze({ id, address, family, resource: `arn:aws:ecs:${REGION}:${ACCOUNT}:task-definition/${family}:*`, executionRoleArn: `arn:aws:iam::${ACCOUNT}:role/${executionRoleName}`, taskRoleArn: `arn:aws:iam::${ACCOUNT}:role/${taskRoleName}` })));
const stageBRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const arnPattern = /^(?:arn:aws:[^:]+:[^:]*:368992683803:.+|arn:aws:s3:::[^/]+(?:\/.*)?)$/;

export const RELEASE_POLICY_SOURCES = Object.freeze([
  ["MSCQRProductionGreenStageARelease", "documents/ops/iam/MSCQRProductionGreenStageAReleaseS3Contract-v1.json"],
  ["MSCQRProductionGreenStageBProviderRecovery", "documents/ops/iam/MSCQRProductionGreenStageBProviderRecovery-v4.json"],
  ["MSCQRProductionGreenStageBReferenceAuditReadOnly", "documents/ops/iam/MSCQRProductionGreenStageBReferenceAuditReadOnly-v1.json"],
  ["MSCQRProductionGreenStageBFinalApplyWrite", "documents/ops/iam/MSCQRProductionGreenStageBFinalApplyWrite-v1.json"],
  ["MSCQRProductionGreenStageBWorkspaceState", "documents/ops/iam/MSCQRProductionGreenStageBWorkspaceState-v2.json"],
].map(([name, sourcePath]) => Object.freeze({ name, arn: `arn:aws:iam::${ACCOUNT}:policy/${name}`, sourcePath })));

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const exactActions = (actual, expected) => JSON.stringify(actual || []) === JSON.stringify(expected);

function readOption(argv, option) {
  const index = argv.indexOf(option);
  return index === -1 ? undefined : argv[index + 1];
}

function requireOption(argv, option) {
  const value = readOption(argv, option);
  if (!value || value.startsWith("--")) throw new Error(`${option} is required.`);
  return value;
}

export function parseCli(argv) {
  return {
    reportGeneratorCallerArn: requireOption(argv, "--report-generator-caller-arn"),
    simulatedRoleArn: requireOption(argv, "--simulated-role-arn"),
    planJsonPath: requireOption(argv, "--plan-json"),
    manifestPath: requireOption(argv, "--manifest"),
    outputPath: requireOption(argv, "--output"),
    signatureOutputPath: requireOption(argv, "--signature-output"),
    savedPlanPath: requireOption(argv, "--saved-plan"),
    expectedAccount: requireOption(argv, "--expected-account"),
    expectedRegion: requireOption(argv, "--expected-region"),
    generatedAt: readOption(argv, "--generated-at") || new Date().toISOString(),
    policyPublishedAt: requireOption(argv, "--policy-published-at"),
    cloudTrailSessionName: requireOption(argv, "--cloudtrail-session-name"),
  };
}

export function canonicalizeJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalizeJson).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalizeJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}

const decodePolicyDocument = (document) => typeof document === "string" ? JSON.parse(decodeURIComponent(document)) : document;
export function sourcePolicyEvidence() {
  return RELEASE_POLICY_SOURCES.map(({ name, arn, sourcePath }) => {
    const document = JSON.parse(fs.readFileSync(path.join(stageBRoot, sourcePath), "utf8"));
    return { name, arn, sourcePath, sourceSha256: sha256(Buffer.from(canonicalizeJson(document))) };
  });
}

export function collectLiveReleasePolicyEvidence({ run = (args) => execFileSync("aws", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) } = {}) {
  const roleName = RELEASE_ROLE_ARN.split("/").at(-1);
  const attached = JSON.parse(run(["iam", "list-attached-role-policies", "--role-name", roleName, "--output", "json", "--no-cli-pager"])).AttachedPolicies || [];
  const inlinePolicyNames = JSON.parse(run(["iam", "list-role-policies", "--role-name", roleName, "--output", "json", "--no-cli-pager"])).PolicyNames || [];
  const inlinePolicies = inlinePolicyNames.map((policyName) => {
    const response = JSON.parse(run(["iam", "get-role-policy", "--role-name", roleName, "--policy-name", policyName, "--output", "json", "--no-cli-pager"]));
    return { policyName, sha256: sha256(Buffer.from(canonicalizeJson(decodePolicyDocument(response.PolicyDocument)))) };
  }).sort((left, right) => left.policyName.localeCompare(right.policyName));
  const role = JSON.parse(run(["iam", "get-role", "--role-name", roleName, "--output", "json", "--no-cli-pager"])).Role;
  const policies = sourcePolicyEvidence().map((expected) => {
    const metadata = JSON.parse(run(["iam", "get-policy", "--policy-arn", expected.arn, "--output", "json", "--no-cli-pager"])).Policy;
    if (!metadata?.DefaultVersionId) throw new Error(`Live release policy has no default version: ${expected.name}.`);
    const version = JSON.parse(run(["iam", "get-policy-version", "--policy-arn", expected.arn, "--version-id", metadata.DefaultVersionId, "--output", "json", "--no-cli-pager"])).PolicyVersion;
    const liveSha256 = sha256(Buffer.from(canonicalizeJson(decodePolicyDocument(version?.Document))));
    return { ...expected, defaultVersionId: metadata.DefaultVersionId, liveSha256, attached: attached.some(({ PolicyArn }) => PolicyArn === expected.arn), matchesSource: liveSha256 === expected.sourceSha256 };
  });
  return {
    roleArn: RELEASE_ROLE_ARN,
    attachedPolicyArns: attached.map(({ PolicyArn }) => PolicyArn).sort(),
    inlinePolicyNames: [...inlinePolicyNames].sort(), inlinePolicies,
    permissionsBoundaryArn: role?.PermissionsBoundary?.PermissionsBoundaryArn || null,
    policies,
    status: policies.every(({ attached: isAttached, matchesSource }) => isAttached && matchesSource) ? "valid" : "invalid",
  };
}

export function assertReleasePolicyEvidence(evidence) {
  if (evidence?.roleArn !== RELEASE_ROLE_ARN || evidence.status !== "valid" || !Array.isArray(evidence.policies)) throw new Error("Release policy evidence is missing or invalid.");
  if (evidence.permissionsBoundaryArn !== null) throw new Error("Release policy evidence contains an unreviewed permissions boundary.");
  if (!Array.isArray(evidence.inlinePolicyNames) || !Array.isArray(evidence.inlinePolicies || []) || evidence.inlinePolicyNames.length !== (evidence.inlinePolicies || []).length) throw new Error("Release inline-policy evidence is incomplete.");
  const expected = sourcePolicyEvidence();
  const expectedAttachments = expected.map(({ arn }) => arn).sort();
  if (JSON.stringify(evidence.attachedPolicyArns || []) !== JSON.stringify(expectedAttachments)) throw new Error("Release role attachment set differs from the reviewed source policies.");
  if (evidence.inlinePolicyNames.length !== 0) throw new Error("Release role has an unreviewed inline policy.");
  if (evidence.policies.length !== expected.length) throw new Error("Release policy evidence is incomplete.");
  for (const policy of expected) {
    const actual = evidence.policies.find(({ arn }) => arn === policy.arn);
    if (!actual || actual.sourcePath !== policy.sourcePath || actual.sourceSha256 !== policy.sourceSha256 || actual.liveSha256 !== policy.sourceSha256 || actual.attached !== true || !/^v[1-9][0-9]*$/.test(actual.defaultVersionId || "")) throw new Error(`Release policy source/live identity differs: ${policy.name}.`);
  }
  return true;
}

function assertContext(context, label) {
  if (!Array.isArray(context)) throw new Error(`${label} context must be an array.`);
  for (const entry of context) {
    if (!entry || typeof entry.key !== "string" || !entry.key || !["string", "stringList", "boolean", "numeric"].includes(entry.type)) {
      throw new Error(`${label} has malformed context.`);
    }
    if (!Array.isArray(entry.values) || entry.values.length === 0 || entry.values.some((value) => typeof value !== "string")) {
      throw new Error(`${label} has malformed context values.`);
    }
  }
}

const lambdaWriteActions = new Set([
  "lambda:UpdateFunctionConfiguration",
  "lambda:UpdateFunctionCode",
  "lambda:PublishVersion",
  "lambda:UpdateAlias",
]);
const requiredLambdaContext = new Map([
  ["aws:RequestedRegion", ["eu-west-2"]],
  ["aws:ResourceTag/Environment", ["production"]],
  ["aws:ResourceTag/ManagedBy", ["Terraform"]],
  ["aws:ResourceTag/Component", ["full-rls-green-stage-b"]],
]);

function assertExactContextValues(context, expected, label) {
  const actual = new Map(context.map((entry) => [entry.key, entry]));
  for (const [key, values] of expected) {
    const entry = actual.get(key);
    if (!entry || entry.type !== "string" || JSON.stringify(entry.values) !== JSON.stringify(values)) {
      throw new Error(`${label} must include exact ${key} context.`);
    }
  }
}

function normalizeActualMissingContextValues(values, label) {
  if (!Array.isArray(values) || values.some((value) => typeof value !== "string" || value.length === 0)) {
    throw new Error(`${label} MissingContextValues is malformed.`);
  }
  return [...new Set(values)].sort();
}

export function normalizeExpectedMissingContextValues(entry, { forbidden, label = entry?.id || "permission evaluation" } = {}) {
  const values = entry?.expectedMissingContextValues;
  if (values === undefined) return [];
  if (!forbidden) throw new Error(`${label} may declare expectedMissingContextValues only for forbidden evaluations.`);
  if (!Array.isArray(values) || values.some((value) => typeof value !== "string" || value.length === 0)) {
    throw new Error(`${label} expectedMissingContextValues is malformed.`);
  }
  if (new Set(values).size !== values.length) throw new Error(`${label} expectedMissingContextValues contains duplicate keys.`);
  const suppliedKeys = new Set((entry.context || []).map(({ key }) => key));
  if (values.some((value) => suppliedKeys.has(value))) throw new Error(`${label} expectedMissingContextValues overlaps supplied context.`);
  return [...values].sort();
}

function sameStringSet(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

export function validateSimulationResult(item, result) {
  if (!result || !["allowed", "explicitDeny", "implicitDeny"].includes(result.decision)
    || !Number.isInteger(result.matchedStatements) || result.matchedStatements < 0) {
    throw new Error(`IAM simulation result is malformed for ${item.id}.`);
  }
  const actualMissing = normalizeActualMissingContextValues(result.missingContextValues, item.id);
  const expectedMissing = item.forbidden === true
    ? normalizeExpectedMissingContextValues(item, { forbidden: true, label: item.id })
    : (() => {
      const values = item.expectedMissingContextValues;
      if (values !== undefined && (!Array.isArray(values) || values.some((value) => typeof value !== "string" || value.length === 0))) throw new Error(`${item.id} expectedMissingContextValues is malformed.`);
      if (values?.length) throw new Error(`${item.id} may declare expectedMissingContextValues only for forbidden evaluations.`);
      return [];
    })();
  if (!item.forbidden && actualMissing.length > 0) throw new Error(`Required evaluation ${item.id} returned unexpected MissingContextValues: ${actualMissing.join(", ")}.`);
  if (item.forbidden && !sameStringSet(actualMissing, expectedMissing)) {
    throw new Error(`Forbidden evaluation ${item.id} returned unexpected MissingContextValues: expected=${expectedMissing.join(",")} actual=${actualMissing.join(",")}.`);
  }
  if (item.forbidden && actualMissing.length > 0 && result.decision === "allowed") {
    throw new Error(`Forbidden evaluation ${item.id} returned allowed with MissingContextValues.`);
  }
  return { ...result, missingContextValues: actualMissing };
}

export function normalizeEvaluationTuple(entry, resource) {
  return JSON.stringify({
    action: entry.action,
    resource,
    context: [...entry.context]
      .map(({ key, type, values }) => ({ key, type, values: [...values].sort() }))
      .sort((left, right) => `${left.key}\u0000${left.type}\u0000${left.values.join("\u0000")}`.localeCompare(`${right.key}\u0000${right.type}\u0000${right.values.join("\u0000")}`)),
  });
}

function assertNoDuplicateOrOverlap(requiredEntries, forbiddenEntries) {
  const requiredByTuple = new Map();
  for (const entry of requiredEntries) {
    for (const resource of entry.resources) {
      const tuple = normalizeEvaluationTuple(entry, resource);
      if (!entry.generated && requiredByTuple.has(tuple)) throw new Error(`Permission manifest duplicate required evaluation tuple: ${requiredByTuple.get(tuple)} and ${entry.id}.`);
      if (!requiredByTuple.has(tuple)) requiredByTuple.set(tuple, entry.id);
    }
  }
  const forbiddenByTuple = new Map();
  for (const entry of forbiddenEntries) {
    for (const resource of entry.resources) {
      const tuple = normalizeEvaluationTuple(entry, resource);
      if (forbiddenByTuple.has(tuple)) throw new Error(`Permission manifest duplicate forbidden evaluation tuple: ${forbiddenByTuple.get(tuple)} and ${entry.id}.`);
      forbiddenByTuple.set(tuple, entry.id);
      if (requiredByTuple.has(tuple)) {
        throw new Error(`Permission manifest required/forbidden overlap: required ${requiredByTuple.get(tuple)}, forbidden ${entry.id}, action ${entry.action}, resource ${resource}, context ${tuple}.`);
      }
    }
  }
}

export function validateManifest(manifest, { account = ACCOUNT, region = REGION } = {}) {
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) throw new Error("Permission manifest is required.");
  if (manifest?.schemaVersion !== PERMISSION_PREFLIGHT_SCHEMA_VERSION) throw new Error("Permission manifest schema version is unsupported.");
  if (manifest.accountId !== account || manifest.region !== region) throw new Error("Permission manifest account or region is wrong.");
  if (!Array.isArray(manifest.required) || !Array.isArray(manifest.forbidden)) throw new Error("Permission manifest sections are malformed.");
  assertStageBTerraformBackendManifest(manifest);
  for (const [id, action] of STAGE_A_LIVE_EVIDENCE_EVALUATIONS) {
    const entry = manifest.required.find((candidate) => candidate.id === id);
    if (!entry || entry.action !== action || JSON.stringify(entry.resources) !== JSON.stringify(["*"]) || JSON.stringify(entry.context) !== JSON.stringify([{ key: "aws:RequestedRegion", type: "string", values: [region] }])) {
      throw new Error(`Stage A live-evidence permission mapping is not exact: ${id}.`);
    }
  }
  const ids = new Set();
  for (const [entry, forbidden] of [...manifest.required.map((entry) => [entry, false]), ...manifest.forbidden.map((entry) => [entry, true])]) {
    if (!entry.id || ids.has(entry.id) || !/^[-a-z0-9]+$/.test(entry.id)) throw new Error(`Permission manifest entry id is invalid: ${entry.id || "missing"}.`);
    ids.add(entry.id);
    if (!/^[a-z0-9]+:[A-Za-z]+$/.test(entry.action || "")) throw new Error(`Permission manifest action is invalid: ${entry.id}.`);
    if (!Array.isArray(entry.resources) || entry.resources.length === 0 || entry.resources.some((resource) => resource !== "*" && !arnPattern.test(resource))) {
      throw new Error(`Permission manifest resources are invalid: ${entry.id}.`);
    }
    assertContext(entry.context, entry.id);
    normalizeExpectedMissingContextValues(entry, { forbidden, label: entry.id });
    if (lambdaWriteActions.has(entry.action)) {
      const expectedResource = entry.action === "lambda:UpdateAlias"
        ? STAGE_B.brokerAliasArn
        : STAGE_B.brokerFunctionArn;
      if (entry.resources.length !== 1 || entry.resources[0] !== expectedResource) {
        throw new Error(`${entry.id} must target only the reviewed broker function.`);
      }
      assertExactContextValues(entry.context, requiredLambdaContext, entry.id);
    }
    if (entry.action === "iam:PassRole") {
      if (entry.resources.some((resource) => resource === "*" || resource.includes("*"))) throw new Error("PassRole may not use wildcard resources.");
      const service = entry.context.find((context) => context.key === "iam:PassedToService");
      if (!service || service.type !== "string" || service.values.length !== 1 || (!forbidden && service.values[0] !== "ecs-tasks.amazonaws.com")) {
        throw new Error(`PassRole entry ${entry.id} must require ECS tasks.`);
      }
    }
    if (entry.plan) {
      if (!entry.plan.type || !Array.isArray(entry.plan.actions)) throw new Error(`Permission manifest plan selector is malformed: ${entry.id}.`);
      if (entry.plan.address && typeof entry.plan.address !== "string") throw new Error(`Permission manifest plan address is malformed: ${entry.id}.`);
      for (const key of ["roleName", "inlinePolicyName"]) {
        if (entry.plan[key] !== undefined && typeof entry.plan[key] !== "string") throw new Error(`Permission manifest plan ${key} is malformed: ${entry.id}.`);
      }
      if (entry.plan.coverageRequired !== undefined && typeof entry.plan.coverageRequired !== "boolean") throw new Error(`Permission manifest plan coverage flag is malformed: ${entry.id}.`);
    }
    if (["update-broker-managed-policy", "prune-broker-managed-policy-versions"].includes(entry.id)) {
      if (!entry.plan || entry.resources.length !== 1 || entry.resources[0] !== BROKER_MANAGED_POLICY_ARN
        || entry.plan.type !== "aws_iam_policy" || !exactActions(entry.plan.actions, ["update"])
        || entry.plan.address !== "aws_iam_policy.broker" || entry.plan.policyName !== BROKER_MANAGED_POLICY_NAME
        || entry.plan.coverageRequired !== true) {
        throw new Error("Broker managed-policy permission mapping is not exact.");
      }
    }
  }
  if (!Array.isArray(manifest.taskDefinitionMappings) || manifest.taskDefinitionMappings.length !== TASK_DEFINITION_MAPPINGS.length) throw new Error("Permission manifest must contain exactly twelve task-definition mappings.");
  const expectedMappings = new Map(TASK_DEFINITION_MAPPINGS.map((mapping) => [mapping.address, mapping]));
  const mappingAddresses = new Set();
  for (const mapping of manifest.taskDefinitionMappings) {
    if (!mapping || typeof mapping !== "object" || mappingAddresses.has(mapping.address)) throw new Error("Permission manifest task-definition mapping is missing or duplicated.");
    mappingAddresses.add(mapping.address);
    const expected = expectedMappings.get(mapping.address);
    if (!expected || mapping.id !== expected.id || mapping.family !== expected.family || mapping.resource !== expected.resource
      || mapping.executionRoleArn !== expected.executionRoleArn || mapping.taskRoleArn !== expected.taskRoleArn) {
      throw new Error(`Permission manifest task-definition mapping is outside the exact Stage B allowlist: ${mapping.address || "missing"}.`);
    }
    if (JSON.stringify(mapping.actions) !== JSON.stringify(["create"])) throw new Error(`Permission manifest task-definition actions are invalid: ${mapping.address}.`);
    assertContext(mapping.registerContext, mapping.address);
    assertContext(mapping.passRoleContext, mapping.address);
    for (const expectedContext of TASK_DEFINITION_TAG_CONTEXT) {
      const actualContext = mapping.registerContext.find((entry) => entry.key === expectedContext.key);
      if (!actualContext || actualContext.type !== expectedContext.type || JSON.stringify(actualContext.values) !== JSON.stringify(expectedContext.values)) throw new Error(`${mapping.address} must include exact ${expectedContext.key} context.`);
    }
    const service = mapping.passRoleContext.find((entry) => entry.key === "iam:PassedToService");
    if (!service || service.type !== "string" || JSON.stringify(service.values) !== JSON.stringify(["ecs-tasks.amazonaws.com"])) throw new Error(`Permission manifest PassRole context is invalid: ${mapping.address}.`);
  }
  if (mappingAddresses.size !== expectedMappings.size) throw new Error("Permission manifest task-definition mapping set is incomplete.");
  const generatedRequired = manifest.taskDefinitionMappings.flatMap((mapping) => [
    { id: `${mapping.id}-register`, action: "ecs:RegisterTaskDefinition", resources: [mapping.resource], context: mapping.registerContext, generated: true },
    { id: `${mapping.id}-tag`, action: "ecs:TagResource", resources: [mapping.resource], context: mapping.registerContext, generated: true },
    { id: `${mapping.id}-pass-execution`, action: "iam:PassRole", resources: [mapping.executionRoleArn], context: mapping.passRoleContext, generated: true },
    { id: `${mapping.id}-pass-task`, action: "iam:PassRole", resources: [mapping.taskRoleArn], context: mapping.passRoleContext, generated: true },
  ]);
  assertNoDuplicateOrOverlap([...manifest.required, ...generatedRequired], manifest.forbidden);
  return true;
}

function planMatches(selector, change) {
  if (!selector || change.type !== selector.type || !exactActions(change.change?.actions, selector.actions)) return false;
  if (selector.address && change.address !== selector.address) return false;
  if (selector.family && change.change?.after?.family !== selector.family) return false;
  if (selector.roleName && change.change?.after?.role !== selector.roleName) return false;
  if (selector.policyName && change.change?.after?.name !== selector.policyName) return false;
  return true;
}

function assertBrokerPolicyDocument(change) {
  if (change.type !== "aws_iam_policy" || change.change?.after?.name !== BROKER_MANAGED_POLICY_NAME) {
    throw new Error("Broker managed-policy identity is not exact.");
  }
  if (typeof change.change.after.policy === "string") {
    let document;
    try { document = JSON.parse(change.change.after.policy); } catch { throw new Error("Broker managed-policy document is not valid JSON."); }
    const statements = Array.isArray(document.Statement) ? document.Statement : [];
    const actual = statements.map((statement) => [statement.Sid, Array.isArray(statement.Action) ? statement.Action : [statement.Action]]).sort((left, right) => left[0].localeCompare(right[0]));
    const expected = BROKER_POLICY_STATEMENTS.map(([sid, actions]) => [sid, actions]).sort((left, right) => left[0].localeCompare(right[0]));
    if (document.Version !== "2012-10-17" || JSON.stringify(actual) !== JSON.stringify(expected)) throw new Error("Broker managed-policy document differs from the reviewed runtime contract.");
  } else if (change.change?.after_unknown?.policy !== true) {
    throw new Error("Broker managed-policy document is missing or unprovable.");
  }
}

function assertBrokerManagedPolicyChange(change) {
  if (change.address === "aws_iam_role_policy.broker") throw new Error("aws_iam_role_policy.broker is forbidden; use the dedicated managed policy.");
  if (change.address === "aws_iam_policy.broker") assertBrokerPolicyDocument(change);
  if (change.address === "aws_iam_role_policy_attachment.broker") {
    if (change.type !== "aws_iam_role_policy_attachment" || change.change?.after?.role !== BROKER_ROLE_NAME
      || (change.change?.after?.policy_arn !== undefined && change.change.after.policy_arn !== BROKER_MANAGED_POLICY_ARN)
      || !exactActions(change.change?.actions, ["no-op"])) {
      throw new Error("Broker managed-policy attachment must be the exact imported no-op attachment.");
    }
  }
}

function evaluation(entry, resource, { forbidden = false } = {}) {
  const result = {
    id: `${entry.id}:${resource}`,
    manifestId: entry.id,
    action: entry.action,
    resource,
    context: entry.context.map(({ key, type, values }) => ({ key, type, values: [...values] })),
    expectedMissingContextValues: normalizeExpectedMissingContextValues(entry, { forbidden }),
    phase: entry.phase || "unspecified",
  };
  Object.defineProperty(result, "forbidden", { value: forbidden, enumerable: false });
  return result;
}

export function deriveRequiredEvaluations(plan, manifest) {
  validateManifest(manifest);
  const changes = Array.isArray(plan?.resource_changes) ? plan.resource_changes : [];
  const required = manifest.required.filter((entry) => !entry.plan).flatMap((entry) => entry.resources.map((resource) => evaluation(entry, resource)));
  const coveredChanges = new Set();
  const matchedPlanEntries = new Set();
  for (const change of changes) {
    const actions = change.change?.actions || [];
    if (["aws_iam_role_policy.broker", "aws_iam_policy.broker", "aws_iam_role_policy_attachment.broker"].includes(change.address)) assertBrokerManagedPolicyChange(change);
    if (exactActions(actions, ["no-op"])) continue;
    const taskMapping = change.type === "aws_ecs_task_definition" && exactActions(actions, ["create"])
      ? manifest.taskDefinitionMappings.find((mapping) => mapping.address === change.address)
      : undefined;
    if (change.type === "aws_ecs_task_definition" && !taskMapping) throw new Error(`No permission manifest entry covers ${change.address} ${JSON.stringify(actions)}.`);
    if (taskMapping) {
      required.push(evaluation({ id: `${taskMapping.id}-register`, action: "ecs:RegisterTaskDefinition", context: taskMapping.registerContext, phase: "apply" }, taskMapping.resource));
      required.push(evaluation({ id: `${taskMapping.id}-tag`, action: "ecs:TagResource", context: taskMapping.registerContext, phase: "apply" }, taskMapping.resource));
      required.push(evaluation({ id: `${taskMapping.id}-pass-execution`, action: "iam:PassRole", context: taskMapping.passRoleContext, phase: "apply" }, taskMapping.executionRoleArn));
      required.push(evaluation({ id: `${taskMapping.id}-pass-task`, action: "iam:PassRole", context: taskMapping.passRoleContext, phase: "apply" }, taskMapping.taskRoleArn));
      coveredChanges.add(change.address);
      continue;
    }
    const matches = manifest.required.filter((entry) => entry.plan && planMatches(entry.plan, change));
    if (matches.length === 0) throw new Error(`No permission manifest entry covers ${change.address} ${JSON.stringify(actions)}.`);
    coveredChanges.add(change.address);
    for (const entry of matches) {
      matchedPlanEntries.add(entry.id);
      for (const resource of entry.resources) required.push(evaluation(entry, resource));
    }
  }
  for (const entry of manifest.required.filter((candidate) => candidate.plan?.coverageRequired)) {
    if (!matchedPlanEntries.has(entry.id)) throw new Error(`Permission manifest mapping has no matching plan change: ${entry.id}.`);
  }
  const forbidden = manifest.forbidden.flatMap((entry) => entry.resources.map((resource) => evaluation(entry, resource, { forbidden: true })));
  return {
    required: required.sort((left, right) => left.id.localeCompare(right.id)),
    forbidden: forbidden.sort((left, right) => left.id.localeCompare(right.id)),
    coveredChanges: [...coveredChanges].sort(),
  };
}

function contextArgs(context) {
  return context.flatMap(({ key, type, values }) => [
    `ContextKeyName=${key},ContextKeyValues=${values.join(",")},ContextKeyType=${type}`,
  ]);
}

export function simulatePrincipalPolicy({ roleArn, evaluation: item, run = (args) => execFileSync("aws", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) }) {
  const args = [
    "iam", "simulate-principal-policy",
    "--policy-source-arn", roleArn,
    "--action-names", item.action,
    "--resource-arns", item.resource,
    "--output", "json",
  ];
  if (item.context.length > 0) args.push("--context-entries", ...contextArgs(item.context));
  const response = JSON.parse(run(args));
  if (!Array.isArray(response.EvaluationResults) || response.EvaluationResults.length !== 1) {
    throw new Error(`IAM simulation returned malformed EvaluationResults for ${item.id}.`);
  }
  const result = response.EvaluationResults[0];
  if (!result || result.EvalActionName !== item.action || result.EvalResourceName !== item.resource) {
    throw new Error(`IAM simulation action or resource mismatch for ${item.id}.`);
  }
  if (!Array.isArray(result.MatchedStatements) || !Array.isArray(result.MissingContextValues)
    || !["allowed", "explicitDeny", "implicitDeny"].includes(result.EvalDecision)) {
    throw new Error(`IAM simulation returned malformed output for ${item.id}.`);
  }
  return validateSimulationResult(item, {
    decision: result.EvalDecision,
    matchedStatements: result.MatchedStatements.length,
    missingContextValues: result.MissingContextValues,
    organizationsAllowed: result.OrganizationsDecisionDetail?.AllowedByOrganizations ?? null,
    permissionsBoundaryAllowed: result.PermissionsBoundaryDecisionDetail?.AllowedByPermissionsBoundary ?? null,
  });
}

export function inspectCloudTrailDenials({ sessionName, startTime, endTime, requiredActions, run = (args) => execFileSync("aws", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) }) {
  const response = JSON.parse(run([
    "cloudtrail", "lookup-events",
    "--lookup-attributes", `AttributeKey=Username,AttributeValue=${sessionName}`,
    "--start-time", startTime,
    "--end-time", endTime,
    "--max-results", "50",
    "--output", "json",
  ]));
  const actionNames = new Set(requiredActions.map((action) => action.split(":")[1]));
  const unresolvedDenials = [];
  for (const event of response.Events || []) {
    let detail;
    try { detail = JSON.parse(event.CloudTrailEvent || "{}"); } catch { throw new Error("CloudTrail returned malformed event JSON."); }
    if (/AccessDenied|Unauthorized/i.test(detail.errorCode || "") && actionNames.has(detail.eventName)) {
      unresolvedDenials.push({ eventId: event.EventId || null, eventName: detail.eventName, eventTime: detail.eventTime || event.EventTime || null });
    }
  }
  return { status: unresolvedDenials.length === 0 ? "clear" : "unresolved-denial", eventsChecked: (response.Events || []).length, unresolvedDenials };
}

function withTempBytes(prefix, files, callback) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  try {
    const paths = Object.fromEntries(Object.entries(files).map(([name, bytes]) => {
      const filePath = path.join(directory, name);
      fs.writeFileSync(filePath, bytes, { mode: 0o600, flag: "wx" });
      return [name, filePath];
    }));
    return callback(paths);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

export function signPermissionReport(report, {
  now = new Date().toISOString(),
  keyArn = PERMISSION_REPORT_SIGNING_KEY_ARN,
  signingAlgorithm = PERMISSION_REPORT_SIGNING_ALGORITHM,
  sign = ({ digest }) => withTempBytes("mscqr-stage-b-permission-sign-", { digest }, ({ digest: digestPath }) => JSON.parse(execFileSync("aws", [
    "kms", "sign", "--key-id", keyArn, "--message", `fileb://${digestPath}`, "--message-type", "DIGEST", "--signing-algorithm", signingAlgorithm, "--output", "json",
  ], { encoding: "utf8" })).Signature),
} = {}) {
  if (report?.schemaVersion !== PERMISSION_PREFLIGHT_SCHEMA_VERSION || report.status !== "valid") throw new Error("Only a valid permission report may be signed.");
  if (keyArn !== PERMISSION_REPORT_SIGNING_KEY_ARN || signingAlgorithm !== PERMISSION_REPORT_SIGNING_ALGORITHM) throw new Error("Permission report signing contract is wrong.");
  const reportSha256 = sha256(Buffer.from(canonicalizeJson(report)));
  const signatureBase64 = String(sign({ keyArn, signingAlgorithm, digest: Buffer.from(reportSha256, "hex"), reportSha256 }) || "");
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(signatureBase64)) throw new Error("Permission report signing returned an invalid signature.");
  return { schemaVersion: 1, keyId: keyArn, keyArn, signingAlgorithm, reportSha256, signatureBase64, signedAt: now };
}

export function verifyPermissionReportSignature({ report, signatureArtifact, now = new Date().toISOString(), keyArn = PERMISSION_REPORT_SIGNING_KEY_ARN, signingAlgorithm = PERMISSION_REPORT_SIGNING_ALGORITHM, verify = ({ digest, signature }) => withTempBytes("mscqr-stage-b-permission-verify-", { digest, signature }, ({ digest: digestPath, signature: signaturePath }) => JSON.parse(execFileSync("aws", [
  "kms", "verify", "--key-id", keyArn, "--message", `fileb://${digestPath}`, "--message-type", "DIGEST", "--signature", `fileb://${signaturePath}`, "--signing-algorithm", signingAlgorithm, "--output", "json",
], { encoding: "utf8" })).SignatureValid === true) }) {
  if (!signatureArtifact || signatureArtifact.schemaVersion !== 1 || signatureArtifact.keyId !== keyArn || signatureArtifact.keyArn !== keyArn || signatureArtifact.signingAlgorithm !== signingAlgorithm) throw new Error("Permission report signature identity or algorithm is wrong.");
  const reportSha256 = sha256(Buffer.from(canonicalizeJson(report)));
  if (signatureArtifact.reportSha256 !== reportSha256) throw new Error("Permission report signature is bound to a different report.");
  const signedAtMs = Date.parse(signatureArtifact.signedAt); const nowMs = Date.parse(now);
  if (!Number.isFinite(signedAtMs) || signedAtMs > nowMs + PERMISSION_PREFLIGHT_CLOCK_SKEW_MS || nowMs - signedAtMs > PERMISSION_EVIDENCE_MAX_AGE_MS) throw new Error("Permission report signature is stale or malformed.");
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(signatureArtifact.signatureBase64 || "")) throw new Error("Permission report signature is malformed.");
  if (!verify({ keyArn, signingAlgorithm, digest: Buffer.from(reportSha256, "hex"), signature: Buffer.from(signatureArtifact.signatureBase64, "base64"), reportSha256 })) throw new Error("Permission report signature verification failed.");
  return true;
}

function validateFreshness(timestamp, now) {
  const timestampMs = Date.parse(timestamp); const nowMs = Date.parse(now);
  if (!Number.isFinite(timestampMs)) throw new Error("Permission report generatedAt is malformed.");
  if (timestampMs > nowMs + PERMISSION_PREFLIGHT_CLOCK_SKEW_MS) throw new Error("Permission report generatedAt is in the future.");
  if (nowMs - timestampMs > PERMISSION_EVIDENCE_MAX_AGE_MS) throw new Error("Permission report is expired.");
}

export function runPermissionPreflight({
  reportGeneratorCallerArn,
  simulatedRoleArn = RELEASE_ROLE_ARN,
  manifest,
  plan,
  planBytes,
  savedPlanBytes,
  expectedAccount = ACCOUNT,
  expectedRegion = REGION,
  generatedAt = new Date().toISOString(),
  policyPublishedAt,
  cloudTrailSessionName,
  purpose = "saved-plan-authorization",
  policyEvidence,
  now = new Date().toISOString(),
  simulate = ({ roleArn: sourceArn, evaluation: item }) => simulatePrincipalPolicy({ roleArn: sourceArn, evaluation: item }),
  cloudTrail = ({ sessionName, startTime, endTime, requiredActions }) => inspectCloudTrailDenials({ sessionName, startTime, endTime, requiredActions }),
} = {}) {
  if (expectedAccount !== ACCOUNT || expectedRegion !== REGION) throw new Error("Expected account or region is wrong.");
  if (!Buffer.isBuffer(savedPlanBytes) || savedPlanBytes.length === 0) throw new Error("Saved binary plan bytes are required for permission preflight.");
  if (!reportGeneratorCallerArn || !APPROVED_PREFLIGHT_GENERATOR_ARNS.includes(reportGeneratorCallerArn)) throw new Error("Permission preflight generator is not an approved audit/admin principal.");
  if (simulatedRoleArn !== RELEASE_ROLE_ARN) throw new Error("Permission preflight simulated role ARN is not the production release role.");
  validateManifest(manifest, { account: expectedAccount, region: expectedRegion });
  if (!plan?.variables || plan.variables.account_id?.value !== expectedAccount || plan.variables.aws_region?.value !== expectedRegion) throw new Error("Plan account or region is wrong.");
  const deploymentIdentity = assertStageBDeploymentIdentity({ plan });
  validateFreshness(generatedAt, now);
  if (!policyPublishedAt || !Number.isFinite(Date.parse(policyPublishedAt))) throw new Error("Policy publication timestamp is required and must be valid.");
  if (!cloudTrailSessionName) throw new Error("CloudTrail session name is required.");
  let policyEvidenceError = null;
  try { assertReleasePolicyEvidence(policyEvidence); } catch (error) { policyEvidenceError = error.message; }
  const derived = deriveRequiredEvaluations(plan, manifest);
  const runSimulation = (item) => {
    const result = validateSimulationResult(item, simulate({ roleArn: simulatedRoleArn, evaluation: item }));
    return { ...item, ...result, validation: item.forbidden ? (result.decision === "allowed" ? "rejected" : "accepted") : (result.decision === "allowed" ? "accepted" : "rejected") };
  };
  const requiredResults = derived.required.map(runSimulation);
  const forbiddenResults = derived.forbidden.map(runSimulation);
  const cloudTrailResult = cloudTrail({ sessionName: cloudTrailSessionName, startTime: policyPublishedAt, endTime: generatedAt, requiredActions: derived.required.map((item) => item.action) });
  const deniedRequired = requiredResults.filter((item) => item.decision !== "allowed");
  const allowedForbidden = forbiddenResults.filter((item) => item.decision === "allowed");
  const unresolved = cloudTrailResult.unresolvedDenials || [];
  const report = {
    schemaVersion: PERMISSION_PREFLIGHT_SCHEMA_VERSION,
    purpose,
    toolingSha: deploymentIdentity.toolingSha,
    imageReleaseSha: deploymentIdentity.imageReleaseSha,
    canonicalImageEvidenceSha256: deploymentIdentity.canonicalImageEvidenceSha256,
    reportGeneratorCallerArn,
    simulatedRoleArn,
    applyRoleArn: RELEASE_ROLE_ARN,
    applyCallerArn: null,
    applyCallerArnPattern: RELEASE_CALLER_PATTERN,
    manifestSha256: sha256(Buffer.from(canonicalizeJson(manifest))),
    planSha256: sha256(planBytes),
    savedPlanSha256: sha256(savedPlanBytes),
    canonicalPlanJsonSha256: sha256(Buffer.from(canonicalizeJson(plan))),
    generatedAt,
    policyPublishedAt,
    cloudTrailWindow: { startTime: policyPublishedAt, endTime: generatedAt, sessionName: cloudTrailSessionName },
    requiredEvaluations: requiredResults,
    forbiddenEvaluations: forbiddenResults,
    cloudTrail: cloudTrailResult,
    policyEvidence,
    policySourceLiveMismatchCount: policyEvidenceError ? 1 : 0,
    policySourceLiveMismatch: policyEvidenceError,
    requiredAllowedCount: requiredResults.filter((item) => item.decision === "allowed").length,
    requiredDeniedCount: deniedRequired.length,
    forbiddenAllowedCount: allowedForbidden.length,
    forbiddenDeniedCount: forbiddenResults.filter((item) => item.decision !== "allowed").length,
    allowedCount: requiredResults.filter((item) => item.decision === "allowed").length,
    deniedCount: deniedRequired.length + allowedForbidden.length + unresolved.length,
    status: deniedRequired.length === 0 && allowedForbidden.length === 0 && unresolved.length === 0 && !policyEvidenceError ? "valid" : "invalid",
  };
  return report;
}

export function runCli(argv = process.argv.slice(2), { getCaller = () => JSON.parse(execFileSync("aws", ["sts", "get-caller-identity", "--output", "json"], { encoding: "utf8" })).Arn, collectPolicyEvidence = collectLiveReleasePolicyEvidence, runPreflight = runPermissionPreflight, signReport = signPermissionReport } = {}) {
  const options = parseCli(argv);
  const observedCallerArn = getCaller();
  if (observedCallerArn !== options.reportGeneratorCallerArn) throw new Error("Report generator caller does not match the current AWS identity.");
  const planBytes = fs.readFileSync(path.resolve(options.planJsonPath));
  const savedPlanBytes = fs.readFileSync(path.resolve(options.savedPlanPath));
  const plan = JSON.parse(planBytes);
  const manifest = JSON.parse(fs.readFileSync(path.resolve(options.manifestPath), "utf8"));
  const report = runPreflight({ ...options, reportGeneratorCallerArn: observedCallerArn, simulatedRoleArn: options.simulatedRoleArn, manifest, plan, planBytes, savedPlanBytes, policyEvidence: collectPolicyEvidence() });
  const signatureArtifact = signReport(report, { now: options.generatedAt });
  fs.writeFileSync(path.resolve(options.outputPath), `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
  fs.writeFileSync(path.resolve(options.signatureOutputPath), `${JSON.stringify(signatureArtifact, null, 2)}\n`, { mode: 0o600 });
  process.stdout.write(`${JSON.stringify({ status: report.status, outputPath: options.outputPath, planSha256: report.planSha256, allowedCount: report.allowedCount, deniedCount: report.deniedCount })}\n`);
  if (report.status !== "valid") process.exitCode = 1;
  return report;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) runCli();

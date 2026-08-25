#!/usr/bin/env node
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { STAGE_B, STAGE_B_APPROVAL_ALGORITHM } from "./production-green-stage-b-contract.mjs";
import { assertStageBImportedBackendMetadataNormalization, assertStageBFreshImageDeposedCleanupSet, assertStageBFreshImagePartialApplyRecoveryPlan, isStageBPartialApplyDeposedTaskDefinitionCleanup, stageBMutationInstanceIdentity, STAGE_B_BROKER_POLICY, STAGE_B_BROKER_POLICY_STATEMENTS, STAGE_B_IMPORTED_BACKEND_CANDIDATE_ADDRESS, STAGE_B_IMPORTED_BACKEND_METADATA_NORMALIZATION } from "./stage-b-deployment-contract.mjs";
import { assertStageBDeploymentIdentity } from "./stage-b-deployment-identity.mjs";
import { assertStageBTerraformBackendManifest } from "./stage-b-terraform-backend-contract.mjs";
import { assertStageBArtifactPath, assertStageBPrivateFile, ensureStageBPrivateDirectory, writeStageBPrivateFilesAtomic } from "./stage-b-artifact-contract.mjs";
import { assertStageBDeploymentEvidenceFreshness, assertStageBDeploymentEvidenceTimestamp, STAGE_B_DEPLOYMENT_EVIDENCE_CLOCK_SKEW_MS, STAGE_B_DEPLOYMENT_EVIDENCE_TTL_MS, STAGE_B_DEPLOYMENT_EVIDENCE_VALIDITY_MODEL } from "./stage-b-evidence-freshness.mjs";
import { assertStageBPlanApprovedBinding, STAGE_B_PLAN_PROFILES } from "./stage-b-plan-approval-contract.mjs";
import { assertStageBImportedBackendRolloverActions, assertStageBTaskDefinitionRotation, isStageBTaskDefinitionRotationActionsValue, STAGE_B_TASK_DEFINITION_ROTATION_ACTIONS, STAGE_B_TASK_DEFINITION_ROTATION_REPLACE_PATHS } from "./stage-b-reference-audit-contract.mjs";
import { assertEcsExecOperatorEvidence, assertEcsExecOperatorLiveEvidence, assertEcsExecOperatorSourceContract, ECS_EXEC_OPERATOR_FORBIDDEN, ECS_EXEC_OPERATOR_REQUIRED, ECS_EXEC_OPERATOR_POLICY_PATH, ECS_EXEC_OPERATOR_ROLE_ARN } from "./production-ecs-exec-operator-contract.mjs";
import { buildTemporaryCapabilityEvidence } from "./production-stage-a-temporary-kms-capability.mjs";
import { normalizeIamPolicyDocument } from "./iam-policy-document.mjs";
import { assertSimulationContextCardinality, iamSimulationContextArgs } from "./iam-simulation-context.mjs";

export { assertSimulationContextCardinality } from "./iam-simulation-context.mjs";

export const PERMISSION_PREFLIGHT_SCHEMA_VERSION = 1;
export const PERMISSION_REPORT_SIGNATURE_SCHEMA_VERSION = 3;
export const PERMISSION_REPORT_BINDING_SCHEMA_VERSION = 2;
export const PERMISSION_REPORT_BINDING_DOMAIN = "MSCQR_STAGE_B_PERMISSION_EVIDENCE_V2";
export const PERMISSION_REPORT_HASH_DOMAIN = "signedBindingSha256";
export const INITIAL_ADMINISTRATOR_CAPABILITY_EVIDENCE_KIND = "INITIAL_ADMIN_CAPABILITY";
export const PLAN_BOUND_PERMISSION_EVIDENCE_KIND = "PLAN_BOUND_PERMISSION";
export const PERMISSION_EVIDENCE_MAX_AGE_MS = STAGE_B_DEPLOYMENT_EVIDENCE_TTL_MS;
export const PERMISSION_PREFLIGHT_CLOCK_SKEW_MS = STAGE_B_DEPLOYMENT_EVIDENCE_CLOCK_SKEW_MS;
export const PERMISSION_EVIDENCE_VALIDITY_MODEL = STAGE_B_DEPLOYMENT_EVIDENCE_VALIDITY_MODEL;
export const ACCOUNT = "368992683803";
export const REGION = "eu-west-2";
export const RELEASE_ROLE_ARN = `arn:aws:iam::${ACCOUNT}:role/mscqr-production-release-deployer`;
export const CUTOVER_CRITICAL_CAPABILITIES = Object.freeze([
  Object.freeze({ principal: RELEASE_ROLE_ARN, evaluationId: "apply-stage-a-endpoint-security-group-ingress", action: "ec2:AuthorizeSecurityGroupIngress" }),
  Object.freeze({ principal: RELEASE_ROLE_ARN, evaluationId: "apply-stage-a-checker-role-chain-policy", action: "iam:PutRolePolicy" }),
  Object.freeze({ principal: RELEASE_ROLE_ARN, evaluationId: "apply-stage-a-checker-publication-policy", action: "iam:PutRolePolicy" }),
  Object.freeze({ principal: RELEASE_ROLE_ARN, evaluationId: "activate-exact-ecs-service", action: "ecs:UpdateService" }),
  Object.freeze({ principal: RELEASE_ROLE_ARN, evaluationId: "rollback-exact-ecs-service", action: "ecs:UpdateService" }),
  Object.freeze({ principal: RELEASE_ROLE_ARN, evaluationId: "rollback-exact-backend-task-passrole", action: "iam:PassRole" }),
  Object.freeze({ principal: RELEASE_ROLE_ARN, evaluationId: "release-deployer-ecs-exec", action: "ecs:ExecuteCommand", expectedDenied: true }),
  Object.freeze({ principal: ECS_EXEC_OPERATOR_ROLE_ARN, evaluationId: "operator-execute-production-backend", action: "ecs:ExecuteCommand" }),
]);
const STAGE_A_LIVE_EVIDENCE_EVALUATIONS = Object.freeze([
  ["collect-stage-a-live-subnets", "ec2:DescribeSubnets"],
  ["collect-stage-a-live-route-tables", "ec2:DescribeRouteTables"],
  ["collect-stage-a-live-security-groups", "ec2:DescribeSecurityGroups"],
  ["collect-stage-a-live-cluster", "ecs:DescribeClusters"],
  ["collect-stage-a-live-database", "rds:DescribeDBInstances"],
]);
export const APPROVED_PREFLIGHT_GENERATOR_ARNS = Object.freeze([`arn:aws:iam::${ACCOUNT}:root`]);
export const RELEASE_CALLER_PATTERN = `^arn:aws:sts::${ACCOUNT}:assumed-role/mscqr-production-release-deployer/[^/]+$`;
export const STAGE_B_PERMISSION_PROFILES = Object.freeze(["NORMAL_STAGE_B_RELEASE", "RECOVERY_ALIAS_ONLY", "PARTIAL_APPLY_RECOVERY", "FRESH_IMAGE_PARTIAL_APPLY_RECOVERY"]);
export const STAGE_B_PERMISSION_PROFILE_CAPABILITIES = Object.freeze({
  NORMAL_STAGE_B_RELEASE: Object.freeze({ requiresTaskDefinitionRegistrationContexts: true }),
  RECOVERY_ALIAS_ONLY: Object.freeze({ requiresTaskDefinitionRegistrationContexts: false }),
  PARTIAL_APPLY_RECOVERY: Object.freeze({ requiresTaskDefinitionRegistrationContexts: false }),
  FRESH_IMAGE_PARTIAL_APPLY_RECOVERY: Object.freeze({ requiresTaskDefinitionRegistrationContexts: true }),
});

export function assertStageBPermissionEvidenceKind(report, expectedKind, expectedPhase) {
  if (report?.evidenceKind !== expectedKind || report?.phase !== expectedPhase) {
    throw new Error(`Stage B evidence kind must be ${expectedKind} with phase ${expectedPhase}.`);
  }
  return true;
}
export const PERMISSION_REPORT_SIGNING_KEY_ARN = STAGE_B.approvalKmsKeyArn;
export const PERMISSION_REPORT_SIGNING_ALGORITHM = STAGE_B_APPROVAL_ALGORITHM;
const BROKER_ROLE_NAME = STAGE_B_BROKER_POLICY.roleName;
const BROKER_MANAGED_POLICY_ARN = STAGE_B_BROKER_POLICY.arn;
const BROKER_MANAGED_POLICY_NAME = STAGE_B_BROKER_POLICY.name;
const BROKER_POLICY_STATEMENTS = STAGE_B_BROKER_POLICY_STATEMENTS;
const TASK_DEFINITION_TAGS = Object.freeze({ Component: "full-rls-green-stage-b", Environment: "production", ManagedBy: "Terraform" });
const BACKEND_TASK_DEFINITION_TAGS = Object.freeze({ ...TASK_DEFINITION_TAGS, MSCQRExecTarget: "production-backend" });
const TASK_DEFINITION_MAPPINGS = Object.freeze([
  ["backend", 'aws_ecs_task_definition.candidate["backend"]', "mscqr-production-rls-green-backend-candidate", "mscqr-production-rls-green-backend-execution", "mscqr-production-rls-green-backend-task", "1024", "2048"],
  ["worker", 'aws_ecs_task_definition.candidate["worker"]', "mscqr-production-rls-green-worker-candidate", "mscqr-production-rls-green-worker-execution", "mscqr-production-rls-green-worker-task", "512", "1024"],
  ["application-canary", 'aws_ecs_task_definition.candidate["canary"]', "mscqr-production-full-rls-green-application-canary", "mscqr-production-rls-green-canary-execution", "mscqr-production-rls-green-canary-task", "1024", "2048"],
  ["read-only-canary", 'aws_ecs_task_definition.candidate["read_only_canary"]', "mscqr-production-full-rls-green-read-only-canary", "mscqr-production-full-rls-green-read-only-canary-execution", "mscqr-production-full-rls-green-read-only-canary-task", "256", "512"],
  ["full-rls-admin-bootstrap", 'aws_ecs_task_definition.executor["full-rls-admin-bootstrap"]', "mscqr-production-full-rls-green-full-rls-admin-bootstrap", "mscqr-production-full-rls-green-executor-execution", "mscqr-production-full-rls-green-executor-task", "1024", "2048"],
  ["full-rls-admin-ownership", 'aws_ecs_task_definition.executor["full-rls-admin-ownership"]', "mscqr-production-full-rls-green-full-rls-admin-ownership", "mscqr-production-full-rls-green-executor-execution", "mscqr-production-full-rls-green-executor-task", "1024", "2048"],
  ["full-rls-capability-preflight", 'aws_ecs_task_definition.executor["full-rls-capability-preflight"]', "mscqr-production-full-rls-green-full-rls-capability-preflight", "mscqr-production-full-rls-green-executor-execution", "mscqr-production-full-rls-green-executor-task", "1024", "2048"],
  ["full-rls-role-provision", 'aws_ecs_task_definition.executor["full-rls-role-provision"]', "mscqr-production-full-rls-green-full-rls-role-provision", "mscqr-production-full-rls-green-executor-execution", "mscqr-production-full-rls-green-executor-task", "1024", "2048"],
  ["full-rls-role-verify", 'aws_ecs_task_definition.executor["full-rls-role-verify"]', "mscqr-production-full-rls-green-full-rls-role-verify", "mscqr-production-full-rls-green-executor-execution", "mscqr-production-full-rls-green-executor-task", "1024", "2048"],
  ["full-rls-rollback", 'aws_ecs_task_definition.executor["full-rls-rollback"]', "mscqr-production-full-rls-green-full-rls-rollback", "mscqr-production-full-rls-green-executor-execution", "mscqr-production-full-rls-green-executor-task", "1024", "2048"],
  ["full-rls-runtime-policy", 'aws_ecs_task_definition.executor["full-rls-runtime-policy"]', "mscqr-production-full-rls-green-full-rls-runtime-policy", "mscqr-production-full-rls-green-executor-execution", "mscqr-production-full-rls-green-executor-task", "1024", "2048"],
  ["full-rls-verification", 'aws_ecs_task_definition.executor["full-rls-verification"]', "mscqr-production-full-rls-green-full-rls-verification", "mscqr-production-full-rls-green-executor-execution", "mscqr-production-full-rls-green-executor-task", "1024", "2048"],
].map(([id, address, family, executionRoleName, taskRoleName, cpu, memory]) => Object.freeze({ id, address, family, cpu, memory, resource: `arn:aws:ecs:${REGION}:${ACCOUNT}:task-definition/${family}:*`, executionRoleArn: `arn:aws:iam::${ACCOUNT}:role/${executionRoleName}`, taskRoleArn: `arn:aws:iam::${ACCOUNT}:role/${taskRoleName}` })));

const taskDefinitionRegisterContext = ({ id, cpu, memory }) => [
  { key: "aws:RequestTag/Component", type: "string", values: [TASK_DEFINITION_TAGS.Component] },
  { key: "aws:RequestTag/Environment", type: "string", values: [TASK_DEFINITION_TAGS.Environment] },
  { key: "aws:RequestTag/ManagedBy", type: "string", values: [TASK_DEFINITION_TAGS.ManagedBy] },
  ...(id === "backend" ? [{ key: "aws:RequestTag/MSCQRExecTarget", type: "string", values: [BACKEND_TASK_DEFINITION_TAGS.MSCQRExecTarget] }] : []),
  { key: "aws:RequestedRegion", type: "string", values: [REGION] },
  { key: "aws:TagKeys", type: "stringList", values: Object.keys(id === "backend" ? BACKEND_TASK_DEFINITION_TAGS : TASK_DEFINITION_TAGS) },
  { key: "ecs:compute-compatibility", type: "stringList", values: ["FARGATE"] },
  { key: "ecs:privileged", type: "string", values: ["false"] },
  { key: "ecs:task-cpu", type: "numeric", values: [cpu] },
  { key: "ecs:task-memory", type: "numeric", values: [memory] },
];
const taskDefinitionTagContext = (context) => context
  .filter(({ key }) => !["ecs:task-cpu", "ecs:task-memory", "aws:RequestTag/MSCQRExecTarget"].includes(key))
  .map((entry) => entry.key === "aws:TagKeys" ? { ...entry, values: Object.keys(TASK_DEFINITION_TAGS) } : entry);
const stageBRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const STAGE_A_PROVIDER_REFRESH_CONTRACT_PATH = "documents/ops/iam/MSCQRProductionGreenStageAProviderRefreshContract-v1.json";
const arnPattern = /^(?:arn:aws:[^:]+:[^:]*:368992683803:.+|arn:aws:s3:::[^/]+(?:\/.*)?|arn:aws:iam::aws:policy\/service-role\/AmazonECSTaskExecutionRolePolicy)$/;

export const RELEASE_POLICY_SOURCES = Object.freeze([
  ["MSCQRProductionGreenStageARelease", "documents/ops/iam/MSCQRProductionGreenStageAReleaseS3Contract-v1.json"],
  ["MSCQRProductionGreenStageBBrokerCodeSigningRead", "documents/ops/iam/MSCQRProductionGreenStageBBrokerCodeSigningRead-v1.json"],
  ["MSCQRProductionGreenStageBProviderRecovery", "documents/ops/iam/MSCQRProductionGreenStageBProviderRecovery-v4.json"],
  ["MSCQRProductionGreenStageBProviderReadOnly", "documents/ops/iam/MSCQRProductionGreenStageBProviderReadOnly-v1.json"],
  ["MSCQRProductionGreenStageBReferenceAuditReadOnly", "documents/ops/iam/MSCQRProductionGreenStageBReferenceAuditReadOnly-v1.json"],
  ["MSCQRProductionGreenStageBFinalApplyWrite", "documents/ops/iam/MSCQRProductionGreenStageBFinalApplyWrite-v1.json"],
  ["MSCQRProductionGreenStageBTaskDefinitionRegistration", "documents/ops/iam/MSCQRProductionGreenStageBTaskDefinitionRegistration-v1.json"],
  ["MSCQRProductionGreenStageBWorkspaceState", "documents/ops/iam/MSCQRProductionGreenStageBWorkspaceState-v2.json"],
].map(([name, sourcePath]) => Object.freeze({ name, arn: `arn:aws:iam::${ACCOUNT}:policy/${name}`, sourcePath })));

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
export const serializePermissionReport = (report) => Buffer.from(`${JSON.stringify(report, null, 2)}\n`);
const exactActions = (actual, expected) => JSON.stringify(actual || []) === JSON.stringify(expected);
const appliesToPermissionProfile = (entry, profile) => Array.isArray(entry.profiles) && entry.profiles.includes(profile);

export function assertStageBPermissionProfile(profile) {
  if (!STAGE_B_PERMISSION_PROFILES.includes(profile)) throw new Error(`Stage B permission profile is unsupported: ${profile}`);
  return profile;
}

export function stageBPermissionProfileCapabilities(profile) {
  assertStageBPermissionProfile(profile);
  return STAGE_B_PERMISSION_PROFILE_CAPABILITIES[profile];
}

export function resolveStageBPermissionProfile({ plan, approvedPlanProfile, phase = "plan-bound", terraformConfiguration } = {}) {
  const planProfile = approvedPlanProfile || "BASELINE";
  if (!STAGE_B_PLAN_PROFILES.includes(planProfile)) throw new Error(`Stage B approved plan profile is unsupported: ${planProfile}`);
  if (phase === "plan-bound" && !approvedPlanProfile) throw new Error("PLAN_BOUND_PERMISSION requires the approved plan profile.");
  const recoveryOnly = planProfile === "RECOVERY_ALIAS_ONLY";
  const partialRecovery = planProfile === "PARTIAL_APPLY_RECOVERY";
  const freshImagePartialRecovery = planProfile === "FRESH_IMAGE_PARTIAL_APPLY_RECOVERY";
  const recoveryVariable = plan?.variables?.stage_b_recovery_only?.value;
  if (recoveryOnly !== (recoveryVariable === true) || ((partialRecovery || freshImagePartialRecovery) && recoveryVariable === true)) throw new Error("Stage B approved plan profile does not match the recovery Terraform input.");
  if (freshImagePartialRecovery) assertStageBFreshImagePartialApplyRecoveryPlan(plan, { terraformConfiguration });
  return {
    planProfile,
    permissionProfile: assertStageBPermissionProfile(recoveryOnly ? "RECOVERY_ALIAS_ONLY" : freshImagePartialRecovery ? "FRESH_IMAGE_PARTIAL_APPLY_RECOVERY" : partialRecovery ? "PARTIAL_APPLY_RECOVERY" : "NORMAL_STAGE_B_RELEASE"),
  };
}

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
    canonicalPlanJsonPath: requireOption(argv, "--canonical-plan-json"),
    manifestPath: requireOption(argv, "--manifest"),
    outputPath: requireOption(argv, "--output"),
    signatureOutputPath: requireOption(argv, "--signature-output"),
    savedPlanPath: requireOption(argv, "--saved-plan"),
    planApprovalReportPath: requireOption(argv, "--plan-approval-report"),
    planApprovalReportSha256: requireOption(argv, "--plan-approval-report-sha256"),
    referenceAuditPath: readOption(argv, "--reference-audit"),
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

export function assertPermissionReportPlanBinding(report, { planJsonBytes, savedPlanBytes, manifest, planApprovalReportSha256 } = {}) {
  if (!Buffer.isBuffer(planJsonBytes) || !Buffer.isBuffer(savedPlanBytes) || !manifest) throw new Error("Permission report plan-binding inputs are incomplete.");
  let plan;
  try { plan = JSON.parse(planJsonBytes); } catch { throw new Error("Permission report plan JSON is malformed."); }
  const expected = {
    planSha256: sha256(planJsonBytes),
    savedPlanSha256: sha256(savedPlanBytes),
    canonicalPlanJsonSha256: sha256(Buffer.from(canonicalizeJson(plan))),
    manifestSha256: sha256(Buffer.from(canonicalizeJson(manifest))),
  };
  for (const [field, value] of Object.entries(expected)) if (report?.[field] !== value) throw new Error(`Permission report ${field} does not match the selected deployment artifact.`);
  if (planApprovalReportSha256 !== undefined && report?.planApprovalReportSha256 !== planApprovalReportSha256) throw new Error("Permission report is not bound to the approved Stage B plan.");
  return expected;
}

const decodePolicyDocument = (document) => normalizeIamPolicyDocument(document, "Release IAM policy document");
export function sourcePolicyEvidence() {
  return RELEASE_POLICY_SOURCES.map(({ name, arn, sourcePath }) => {
    const document = JSON.parse(fs.readFileSync(path.join(stageBRoot, sourcePath), "utf8"));
    return { name, arn, sourcePath, sourceSha256: sha256(Buffer.from(canonicalizeJson(document))) };
  });
}

function policyConditionKeyOrigins(document, { policy = "source", sourcePath = "" } = {}) {
  const origins = new Map();
  for (const statement of document?.Statement || []) {
    for (const [operator, condition] of Object.entries(statement.Condition || {})) {
      for (const key of Object.keys(condition)) {
        if (!origins.has(key)) origins.set(key, []);
        const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
        origins.get(key).push({ policy, sid: statement.Sid, operator, sourcePath, actions: actions.filter(Boolean) });
      }
    }
  }
  return origins;
}

export function sourcePolicyConditionKeyOrigins() {
  const origins = new Map();
  for (const { name, sourcePath } of RELEASE_POLICY_SOURCES) {
    const policyOrigins = policyConditionKeyOrigins(JSON.parse(fs.readFileSync(path.join(stageBRoot, sourcePath), "utf8")), { policy: name, sourcePath });
    for (const [key, entries] of policyOrigins) origins.set(key, [...(origins.get(key) || []), ...entries]);
  }
  return origins;
}

export function operatorPolicyConditionKeyOrigins() {
  return policyConditionKeyOrigins(JSON.parse(fs.readFileSync(path.join(stageBRoot, ECS_EXEC_OPERATOR_POLICY_PATH), "utf8")), { policy: "ECS_EXEC_OPERATOR", sourcePath: ECS_EXEC_OPERATOR_POLICY_PATH });
}

function actionPatternMatches(pattern, action) {
  const escaped = String(pattern).replace(/[.*+?^${}()|[\\]\\]/g, "\\$&").replaceAll("\\*", ".*");
  return new RegExp(`^${escaped}$`).test(action);
}

function applicableConditionKeys(conditionKeyOrigins, action) {
  return new Set([...conditionKeyOrigins.entries()]
    .filter(([, entries]) => entries.some(({ actions }) => actions.some((pattern) => actionPatternMatches(pattern, action))))
    .map(([key]) => key));
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
  const keys = new Set();
  for (const entry of context) {
    if (!entry || typeof entry.key !== "string" || !entry.key || !["string", "stringList", "boolean", "numeric", "date", "ip", "binary", "numericList"].includes(entry.type)) {
      throw new Error(`${label} has malformed context.`);
    }
    if (keys.has(entry.key)) throw new Error(`${label} has duplicate context key ${entry.key}.`);
    keys.add(entry.key);
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
  if (new Set(values).size !== values.length) throw new Error(`${label} MissingContextValues contains duplicate keys.`);
  return [...values].sort();
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

export const REVIEWED_SIMULATION_CONTEXT_REGISTRY = Object.freeze([
  { key: "aws:RequestTag/Component", type: "string", values: Object.freeze(["full-rls-green-stage-a", "full-rls-green-stage-b"]) },
  { key: "aws:RequestTag/Environment", type: "string", values: Object.freeze(["production"]) },
  { key: "aws:RequestTag/ManagedBy", type: "string", values: Object.freeze(["Terraform"]) },
  { key: "aws:RequestTag/MSCQRExecTarget", type: "string", values: Object.freeze(["production-backend"]) },
  { key: "aws:RequestTag/MSCQRPreDeploymentInventory", type: "string", values: Object.freeze(["rotation-inventory"]) },
  { key: "aws:RequestedRegion", type: "string", values: Object.freeze([REGION]) },
  { key: "aws:ResourceTag/Component", type: "string", values: Object.freeze(["full-rls-green-stage-b"]) },
  { key: "aws:ResourceTag/Environment", type: "string", values: Object.freeze(["production"]) },
  { key: "aws:ResourceTag/ManagedBy", type: "string", values: Object.freeze(["Terraform"]) },
  { key: "aws:TagKeys", type: "stringList", values: Object.freeze(["Component", "Environment", "ManagedBy"]) },
  { key: "ecs:cluster", type: "string", values: Object.freeze(["arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main"]) },
  { key: "ecs:compute-compatibility", type: "stringList", values: Object.freeze(["FARGATE"]) },
  { key: "ecs:privileged", type: "string", values: Object.freeze(["false"]) },
  { key: "ecs:task-cpu", type: "numeric", values: Object.freeze(["512", "1024", "2048"]) },
  { key: "ecs:task-definition", type: "stringList", values: Object.freeze(["arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:7", "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:47"]) },
  { key: "ecs:task-memory", type: "numeric", values: Object.freeze(["512", "1024", "2048", "4096"]) },
  { key: "iam:PassedToService", type: "string", values: Object.freeze(["ecs-tasks.amazonaws.com"]) },
  { key: "s3:if-none-match", type: "string", values: Object.freeze(["present"]) },
  { key: "secretsmanager:Name", type: "string", values: Object.freeze(["mscqr/production/rls-green/artifact-signing/private-key-current", "mscqr/production/rls-green/artifact-signing/public-key-current", "mscqr/production/rls-green/artifact-signing/active-key-version", "mscqr/production/rls-green/artifact-signing/public-keys-json", "mscqr/prod/rotation/jwt-previous", "mscqr/prod/rotation/jwt-pending", "mscqr/prod/rotation/qr-private-pending", "mscqr/prod/rotation/qr-public-previous", "mscqr/prod/rotation/qr-public-pending", "mscqr/prod/rotation/qr-current-version", "mscqr/prod/rotation/qr-previous-version"]) },
]);

export function assertReviewedSimulationContextRegistry({ conditionKeyOrigins = sourcePolicyConditionKeyOrigins(), registry = REVIEWED_SIMULATION_CONTEXT_REGISTRY } = {}) {
  assertContext(registry, "Reviewed simulator context registry");
  const discoveredKeys = [...conditionKeyOrigins.keys()].sort();
  const registryKeys = registry.map(({ key }) => key).sort();
  if (!sameStringSet(discoveredKeys, registryKeys)) {
    const missing = discoveredKeys.filter((key) => !registryKeys.includes(key));
    const extra = registryKeys.filter((key) => !discoveredKeys.includes(key));
    throw new Error(`Reviewed simulator context registry differs from policy condition keys: missing=${missing.join(",") || "none"}; extra=${extra.join(",") || "none"}.`);
  }
  if (registry.some(({ values }) => values.some((value) => value === "*"))) throw new Error("Reviewed simulator context registry may not contain wildcard values.");
  return Object.freeze(registry.map(({ key, type, values }) => ({ key, type, values: [...values] })).sort((left, right) => left.key.localeCompare(right.key)));
}

export function assertDiscoveredSimulationContextKeys(contextKeyNames, { conditionKeyOrigins = sourcePolicyConditionKeyOrigins(), registry = REVIEWED_SIMULATION_CONTEXT_REGISTRY } = {}) {
  const reviewed = assertReviewedSimulationContextRegistry({ conditionKeyOrigins, registry });
  if (!Array.isArray(contextKeyNames) || contextKeyNames.some((key) => typeof key !== "string" || !key)) throw new Error("IAM context-key discovery response is malformed.");
  if (new Set(contextKeyNames).size !== contextKeyNames.length) throw new Error("IAM context-key discovery response contains duplicate keys.");
  const discovered = [...contextKeyNames].sort((left, right) => left.localeCompare(right));
  const reviewedKeys = reviewed.map(({ key }) => key);
  if (!sameStringSet(discovered, reviewedKeys)) {
    const missing = reviewedKeys.filter((key) => !discovered.includes(key));
    const extra = discovered.filter((key) => !reviewedKeys.includes(key));
    throw new Error(`IAM context-key discovery differs from the reviewed registry: missing=${missing.join(",") || "none"}; extra=${extra.join(",") || "none"}.`);
  }
  return true;
}

function mergeReviewedSimulationContext(operationContext, registry = REVIEWED_SIMULATION_CONTEXT_REGISTRY) {
  const reviewed = assertReviewedSimulationContextRegistry({ registry });
  assertContext(operationContext, "Operation-specific simulator context");
  const registryKeys = new Set(reviewed.map(({ key }) => key));
  for (const { key } of operationContext) {
    if (!registryKeys.has(key)) throw new Error(`Operation-specific simulator context key is not in the reviewed registry: ${key}.`);
  }
  const operation = new Map(operationContext.map((entry) => [entry.key, { key: entry.key, type: entry.type, values: [...entry.values] }]));
  const merged = new Map();
  for (const entry of reviewed) {
    const bound = operation.get(entry.key);
    if (bound) {
      merged.set(entry.key, bound);
      continue;
    }
    const scalar = entry.type !== "stringList" && entry.type !== "numericList";
    if (scalar && entry.values.length !== 1) continue;
    merged.set(entry.key, { key: entry.key, type: entry.type, values: [...entry.values] });
  }
  for (const entry of operationContext) {
    merged.set(entry.key, { key: entry.key, type: entry.type, values: [...entry.values] });
  }
  const complete = [...merged.values()].sort((left, right) => left.key.localeCompare(right.key));
  assertSimulationContextCardinality(complete);
  return complete;
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
  if (item.forbidden && !["explicitDeny", "implicitDeny"].includes(item.expectedDecision)) throw new Error(`Forbidden evaluation ${item.id} has no reviewed expected decision.`);
  if (item.forbidden && result.decision !== item.expectedDecision) {
    throw new Error(`Forbidden evaluation ${item.id} ${item.action} ${item.resource} returned decision ${result.decision}; expected ${item.expectedDecision}.`);
  }
  if (item.forbidden && !sameStringSet(actualMissing, expectedMissing)) {
    throw new Error(`Forbidden evaluation ${item.id} ${item.action} ${item.resource} returned unexpected MissingContextValues: expected=${expectedMissing.join(",")} actual=${actualMissing.join(",")}.`);
  }
  return { ...result, missingContextValues: actualMissing };
}

export function assertPermissionEvaluationBindings(report, manifest, { plan, permissionProfile = "NORMAL_STAGE_B_RELEASE", contextRegistry = REVIEWED_SIMULATION_CONTEXT_REGISTRY, terraformConfiguration } = {}) {
  const capabilities = stageBPermissionProfileCapabilities(permissionProfile);
  const conditionKeyOrigins = sourcePolicyConditionKeyOrigins();
  validateManifest(manifest, { contextRegistry, conditionKeyOrigins });
  const entries = new Map([...manifest.required, ...manifest.forbidden].map((entry) => [entry.id, { entry, forbidden: manifest.forbidden.includes(entry) }]));
  for (const mapping of manifest.taskDefinitionMappings) {
    entries.set(`${mapping.id}-register`, { entry: { context: mapping.registerContext }, forbidden: false });
    entries.set(`${mapping.id}-tag`, { entry: { context: taskDefinitionTagContext(mapping.registerContext) }, forbidden: false });
    for (const suffix of ["pass-execution", "pass-task"]) entries.set(`${mapping.id}-${suffix}`, { entry: { context: mapping.passRoleContext }, forbidden: false });
  }
  const taskDefinitionEvaluationIds = new Set(manifest.taskDefinitionMappings.flatMap((mapping) => [mapping.id, `${mapping.id}-register`, `${mapping.id}-tag`, `${mapping.id}-pass-execution`, `${mapping.id}-pass-task`]));
  for (const [items, forbidden] of [[report.requiredEvaluations, false], [report.forbiddenEvaluations, true]]) {
    if (!Array.isArray(items)) throw new Error("Permission-preflight evaluation results are missing.");
    if (!capabilities.requiresTaskDefinitionRegistrationContexts && items.some((item) => taskDefinitionEvaluationIds.has(item.manifestId))) throw new Error(`${permissionProfile} permission evidence cannot contain ECS task-definition evaluations.`);
    for (const item of items) {
      const binding = entries.get(item.manifestId);
      if (!binding || binding.forbidden !== forbidden) throw new Error(`Permission-preflight evaluation ${item.id} is not bound to the current manifest section.`);
      if (binding.entry.plan && !appliesToPermissionProfile(binding.entry, permissionProfile)) throw new Error(`Permission-preflight evaluation ${item.id} is outside the authenticated permission profile.`);
      const expectedContext = binding.forbidden
        ? binding.entry.context.map(({ key, type, values }) => ({ key, type, values: [...values] }))
        : mergeReviewedSimulationContext(binding.entry.context, contextRegistry);
      if (JSON.stringify(item.context) !== JSON.stringify(expectedContext)) throw new Error(`Permission-preflight evaluation ${item.id} has different context from the current reviewed registry.`);
      const expected = normalizeExpectedMissingContextValues(binding.entry, { forbidden, label: item.manifestId });
      if (JSON.stringify(item.expectedMissingContextValues || []) !== JSON.stringify(expected)) throw new Error(`Permission-preflight evaluation ${item.id} has different expected missing context.`);
      const expectedDecision = forbidden ? binding.entry.expectedDecision : undefined;
      if (forbidden && item.expectedDecision !== expectedDecision) throw new Error(`Permission-preflight evaluation ${item.id} has a different expected decision.`);
      const validated = validateSimulationResult({ ...item, forbidden, expectedDecision, expectedMissingContextValues: expected }, item);
      const expectedValidation = forbidden ? (item.decision === "allowed" ? "rejected" : "accepted") : (item.decision === "allowed" ? "accepted" : "rejected");
      if (item.missingContextExactMatch !== true || item.validation !== expectedValidation || JSON.stringify(validated.missingContextValues) !== JSON.stringify(item.missingContextValues)) throw new Error(`Permission-preflight evaluation ${item.id} has inconsistent validation evidence.`);
    }
  }
  const project = (items) => items.map(({ id, action, resource, context, decision }) => ({ id, action, resource, context, decision }));
  if (report.planCapabilities?.schemaVersion !== 1
    || JSON.stringify(report.planCapabilities.required) !== JSON.stringify(project(report.requiredEvaluations))
    || JSON.stringify(report.planCapabilities.forbidden) !== JSON.stringify(project(report.forbiddenEvaluations))) throw new Error("Permission-preflight plan capability manifest is incomplete or stale.");
  const expectedZeroMutationChanges = (plan?.resource_changes || []).flatMap((change) => {
    if (["PARTIAL_APPLY_RECOVERY", "FRESH_IMAGE_PARTIAL_APPLY_RECOVERY"].includes(permissionProfile) && isStageBPartialApplyDeposedTaskDefinitionCleanup(change)) {
      const classification = "PARTIAL_APPLY_RECOVERY_DEPOSED_TASK_DEFINITION_CLEANUP";
      return [{ address: change.address, mutationInstanceIdentity: stageBMutationInstanceIdentity(change, classification), classification, requiredAwsActions: [] }];
    }
    if (change.address === STAGE_B_IMPORTED_BACKEND_CANDIDATE_ADDRESS && JSON.stringify(change.change?.actions || []) === JSON.stringify(["update"])) {
      assertStageBImportedBackendMetadataNormalization(change, { terraformConfiguration });
      return [{ address: change.address, classification: STAGE_B_IMPORTED_BACKEND_METADATA_NORMALIZATION, requiredAwsActions: [] }];
    }
    return [];
  });
  if (expectedZeroMutationChanges.length > 0
    ? JSON.stringify(report.planCapabilities.zeroAwsMutationChanges) !== JSON.stringify(expectedZeroMutationChanges)
    : report.planCapabilities.zeroAwsMutationChanges !== undefined && JSON.stringify(report.planCapabilities.zeroAwsMutationChanges) !== "[]") throw new Error("Permission-preflight zero-AWS-mutation classification is incomplete or stale.");
  if (plan && capabilities.requiresTaskDefinitionRegistrationContexts) assertTaskDefinitionRegistrationContexts(plan, manifest, { permissionProfile, terraformConfiguration });
  if (plan) {
    const expectedMutationInstances = deriveRequiredEvaluations(plan, manifest, { permissionProfile, contextRegistry, conditionKeyOrigins, terraformConfiguration }).coveredChanges;
    if (JSON.stringify(report.planCapabilities.mutationInstances) !== JSON.stringify(expectedMutationInstances)) throw new Error("Permission-preflight mutation-instance coverage is incomplete or stale.");
  }
  if (report.phase === "initial") assertCutoverCriticalEvidence(report);
  return true;
}

export function assertCutoverCriticalEvidence(report) {
  const releaseResults = [...(report?.requiredEvaluations || []), ...(report?.forbiddenEvaluations || [])];
  for (const critical of CUTOVER_CRITICAL_CAPABILITIES.filter(({ principal }) => principal === RELEASE_ROLE_ARN)) {
    const result = releaseResults.find((item) => item.manifestId === critical.evaluationId);
    const allowed = critical.expectedDenied ? ["implicitDeny", "explicitDeny"].includes(result?.decision) : result?.decision === "allowed";
    if (!result || result.action !== critical.action || !allowed) throw new Error(`Cutover-critical release capability lacks valid evidence: ${critical.evaluationId}.`);
  }
  assertEcsExecOperatorEvidence(report);
  return true;
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
      const previous = requiredByTuple.get(tuple);
      if (previous && !entry.generated && !previous.generated) {
        const distinctApprovedPhase = previous.phases.size === 1
          && !previous.phases.has(entry.phase)
          && [previous.phases.values().next().value, entry.phase].sort().join("/") === "apply/reference-audit";
        if (!distinctApprovedPhase) throw new Error(`Permission manifest duplicate required evaluation tuple: ${previous.ids.at(-1)} and ${entry.id}.`);
      }
      if (previous) {
        previous.ids.push(entry.id);
        previous.phases.add(entry.phase);
      } else {
        requiredByTuple.set(tuple, { ids: [entry.id], phases: new Set([entry.phase]), generated: entry.generated });
      }
    }
  }
  const forbiddenByTuple = new Map();
  for (const entry of forbiddenEntries) {
    for (const resource of entry.resources) {
      const tuple = normalizeEvaluationTuple(entry, resource);
      if (forbiddenByTuple.has(tuple)) throw new Error(`Permission manifest duplicate forbidden evaluation tuple: ${forbiddenByTuple.get(tuple)} and ${entry.id}.`);
      forbiddenByTuple.set(tuple, entry.id);
      if (requiredByTuple.has(tuple)) {
        throw new Error(`Permission manifest required/forbidden overlap: required ${requiredByTuple.get(tuple).ids[0]}, forbidden ${entry.id}, action ${entry.action}, resource ${resource}, context ${tuple}.`);
      }
    }
  }
}

function assertStageAProviderRefreshManifestCoverage(manifest, region) {
  const contract = JSON.parse(fs.readFileSync(path.join(stageBRoot, STAGE_A_PROVIDER_REFRESH_CONTRACT_PATH), "utf8"));
  const requiredEntries = manifest.required;
  for (const resourceType of contract.resourceTypes || []) {
    for (const readAction of resourceType.readActions || []) {
      for (const resource of readAction.resources || []) {
        const matches = requiredEntries.filter((entry) => entry.action === readAction.action && entry.resources.includes(resource));
        if (matches.length === 0) throw new Error(`Stage A provider refresh contract is not covered by the permission manifest: ${resourceType.type} ${readAction.action} ${resource}.`);
        if (readAction.region && !matches.some((entry) => entry.context.some(({ key, type, values }) => key === "aws:RequestedRegion" && type === "string" && values.length === 1 && values[0] === region))) {
          throw new Error(`Stage A provider refresh region binding is not covered by the permission manifest: ${resourceType.type} ${readAction.action} ${resource}.`);
        }
        for (const [key, value] of Object.entries(readAction.conditions || {})) {
          if (!matches.some((entry) => entry.context.some((context) => context.key === key && context.values.includes(value)))) {
            throw new Error(`Stage A provider refresh condition binding is not covered by the permission manifest: ${resourceType.type} ${readAction.action} ${key}.`);
          }
        }
      }
    }
  }
  return true;
}

export function validateManifest(manifest, { account = ACCOUNT, region = REGION, conditionKeyOrigins = sourcePolicyConditionKeyOrigins(), contextRegistry = REVIEWED_SIMULATION_CONTEXT_REGISTRY } = {}) {
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) throw new Error("Permission manifest is required.");
  if (manifest?.schemaVersion !== PERMISSION_PREFLIGHT_SCHEMA_VERSION) throw new Error("Permission manifest schema version is unsupported.");
  if (manifest.accountId !== account || manifest.region !== region) throw new Error("Permission manifest account or region is wrong.");
  if (!Array.isArray(manifest.required) || !Array.isArray(manifest.forbidden) || !Array.isArray(manifest.checkerRequired)) throw new Error("Permission manifest sections are malformed.");
  const reviewedContextRegistry = assertReviewedSimulationContextRegistry({ conditionKeyOrigins, registry: contextRegistry });
  assertStageBTerraformBackendManifest(manifest);
  for (const [id, action] of STAGE_A_LIVE_EVIDENCE_EVALUATIONS) {
    const entry = manifest.required.find((candidate) => candidate.id === id);
    if (!entry || entry.action !== action || JSON.stringify(entry.resources) !== JSON.stringify(["*"]) || JSON.stringify(entry.context) !== JSON.stringify([{ key: "aws:RequestedRegion", type: "string", values: [region] }])) {
      throw new Error(`Stage A live-evidence permission mapping is not exact: ${id}.`);
    }
  }
  assertStageAProviderRefreshManifestCoverage(manifest, region);
  const ids = new Set();
  for (const [entry, forbidden] of [...manifest.required.map((entry) => [entry, false]), ...manifest.forbidden.map((entry) => [entry, true])]) {
    if (!entry.id || ids.has(entry.id) || !/^[-a-z0-9]+$/.test(entry.id)) throw new Error(`Permission manifest entry id is invalid: ${entry.id || "missing"}.`);
    ids.add(entry.id);
    if (!/^[a-z0-9]+:[A-Za-z]+$/.test(entry.action || "")) throw new Error(`Permission manifest action is invalid: ${entry.id}.`);
    if (!Array.isArray(entry.resources) || entry.resources.length === 0 || entry.resources.some((resource) => resource !== "*" && !arnPattern.test(resource))) {
      throw new Error(`Permission manifest resources are invalid: ${entry.id}.`);
    }
    assertContext(entry.context, entry.id);
    const expectedMissing = normalizeExpectedMissingContextValues(entry, { forbidden, label: entry.id });
    if (forbidden) {
      if (!["explicitDeny", "implicitDeny"].includes(entry.expectedDecision)) throw new Error(`${entry.id} must declare its exact forbidden expectedDecision.`);
      const unexplained = expectedMissing.filter((key) => !conditionKeyOrigins.has(key));
      if (unexplained.length) throw new Error(`${entry.id} expectedMissingContextValues has no reviewed source-policy origin: ${unexplained.join(", ")}.`);
      const inapplicable = expectedMissing.filter((key) => !applicableConditionKeys(conditionKeyOrigins, entry.action).has(key));
      if (inapplicable.length) throw new Error(`${entry.id} expectedMissingContextValues is not applicable to ${entry.action}: ${inapplicable.join(", ")}.`);
    } else if (entry.expectedDecision !== undefined) {
      throw new Error(`${entry.id} may declare expectedDecision only for forbidden evaluations.`);
    }
    if (lambdaWriteActions.has(entry.action)) {
      const expectedResource = STAGE_B.brokerFunctionArn;
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
      if (!Array.isArray(entry.profiles) || entry.profiles.length === 0 || new Set(entry.profiles).size !== entry.profiles.length || entry.profiles.some((profile) => !STAGE_B_PERMISSION_PROFILES.includes(profile))) {
        throw new Error(`${entry.id} plan permission profiles are malformed.`);
      }
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
  const checkerApprovalArn = STAGE_B.approvalSecretArn;
  if (manifest.checkerRequired.length !== 1) throw new Error("Permission manifest checker publication section is not exact.");
  for (const entry of manifest.checkerRequired) {
    if (!entry.id || ids.has(entry.id)) throw new Error(`Permission manifest checker entry id is duplicated: ${entry.id || "missing"}.`);
    ids.add(entry.id);
    if (entry.id !== "publish-stage-b-approval" || entry.phase !== "approval-publication"
        || entry.action !== "secretsmanager:PutSecretValue" || entry.principal !== STAGE_B.checkerRoleArn
        || JSON.stringify(entry.resources) !== JSON.stringify([checkerApprovalArn])
        || JSON.stringify(entry.context) !== JSON.stringify([{ key: "aws:RequestedRegion", type: "string", values: [region] }])
        || entry.resources.some((resource) => resource === "*" || resource.includes("*"))) {
      throw new Error("Checker approval publication capability is not exact.");
    }
  }
  if (!Array.isArray(manifest.taskDefinitionMappings) || manifest.taskDefinitionMappings.length !== TASK_DEFINITION_MAPPINGS.length) throw new Error("Permission manifest must contain exactly twelve task-definition mappings.");
  if (JSON.stringify(manifest.taskDefinitionRotationContract?.actions) !== JSON.stringify(STAGE_B_TASK_DEFINITION_ROTATION_ACTIONS)
    || JSON.stringify(manifest.taskDefinitionRotationContract?.replacePaths) !== JSON.stringify(STAGE_B_TASK_DEFINITION_ROTATION_REPLACE_PATHS)
    || manifest.taskDefinitionRotationContract?.authorization !== "ecs:RegisterTaskDefinition only; ecs:DeregisterTaskDefinition remains forbidden"
    || manifest.taskDefinitionRotationContract?.scope !== "exact twelve root-managed Stage B task-definition addresses") {
    throw new Error("Permission manifest task-definition rotation contract is not exact.");
  }
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
    const expectedContext = taskDefinitionRegisterContext(expected);
    if (JSON.stringify(mapping.registerContext) !== JSON.stringify(expectedContext)) throw new Error(`${mapping.address} must include the exact family-specific ECS registration context.`);
    const service = mapping.passRoleContext.find((entry) => entry.key === "iam:PassedToService");
    if (!service || service.type !== "string" || JSON.stringify(service.values) !== JSON.stringify(["ecs-tasks.amazonaws.com"])) throw new Error(`Permission manifest PassRole context is invalid: ${mapping.address}.`);
  }
  if (mappingAddresses.size !== expectedMappings.size) throw new Error("Permission manifest task-definition mapping set is incomplete.");
  const generatedRequired = manifest.taskDefinitionMappings.flatMap((mapping) => [
    { id: `${mapping.id}-register`, action: "ecs:RegisterTaskDefinition", resources: [mapping.resource], context: mapping.registerContext, generated: true },
    { id: `${mapping.id}-tag`, action: "ecs:TagResource", resources: [mapping.resource], context: taskDefinitionTagContext(mapping.registerContext), generated: true },
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

const plannedIdentity = (value) => value?.arn ?? value?.id ?? value?.name ?? value?.function_name ?? value?.role ?? value?.family ?? null;

export function createStageBMutationManifest(plan, manifest, { planProfile, planSha256, savedPlanSha256, canonicalPlanJsonSha256, planApprovalReportSha256, toolingSha, terraformConfiguration } = {}) {
  validateManifest(manifest);
  if (planProfile === "IMPORTED_BACKEND_METADATA_NORMALIZATION") assertStageBImportedBackendRolloverActions(plan?.resource_changes);
  const resources = (plan?.resource_changes || []).filter(({ change }) => !exactActions(change?.actions, ["no-op"])).map((change) => {
    const actions = change.change?.actions || [];
    let classification;
    let requiredPermissions;
    let taskDefinitionPostcondition;
    if (["PARTIAL_APPLY_RECOVERY", "FRESH_IMAGE_PARTIAL_APPLY_RECOVERY"].includes(planProfile) && isStageBPartialApplyDeposedTaskDefinitionCleanup(change)) {
      classification = "PARTIAL_APPLY_RECOVERY_DEPOSED_TASK_DEFINITION_CLEANUP";
      requiredPermissions = [];
    } else if (change.address === STAGE_B_IMPORTED_BACKEND_CANDIDATE_ADDRESS && exactActions(actions, ["update"])) {
      assertStageBImportedBackendMetadataNormalization(change, { terraformConfiguration });
      classification = STAGE_B_IMPORTED_BACKEND_METADATA_NORMALIZATION;
      requiredPermissions = [];
    } else if (change.type === "aws_ecs_task_definition") {
      const mapping = manifest.taskDefinitionMappings.find((candidate) => candidate.address === change.address);
      if (!mapping || !(exactActions(actions, ["create"]) || isStageBTaskDefinitionRotationActionsValue(actions))) throw new Error(`Mutation manifest rejects unreviewed task-definition change ${change.address}.`);
      contextFromTaskDefinitionPlan(change, mapping);
      classification = "stage-b-task-definition-registration";
      requiredPermissions = ["ecs:RegisterTaskDefinition", "ecs:TagResource", "iam:PassRole"];
      const containers = typeof change.change.after.container_definitions === "string" ? JSON.parse(change.change.after.container_definitions) : change.change.after.container_definitions;
      taskDefinitionPostcondition = {
        family: change.change.after.family,
        images: containers.map(({ name, image }) => ({ name, image })).sort((left, right) => left.name.localeCompare(right.name)),
        execution_role_arn: change.change.after.execution_role_arn,
        task_role_arn: change.change.after.task_role_arn,
        cpu: String(change.change.after.cpu),
        memory: String(change.change.after.memory),
        network_mode: change.change.after.network_mode,
        runtime_platform: change.change.after.runtime_platform,
        environment_secrets_sha256: sha256(Buffer.from(canonicalizeJson(containers.map(({ name, environment = [], secrets = [] }) => ({ name, environment, secrets }))))),
        logging_sha256: sha256(Buffer.from(canonicalizeJson(containers.map(({ name, logConfiguration = null }) => ({ name, logConfiguration }))))),
      };
    } else {
      const matches = manifest.required.filter((entry) => entry.plan && appliesToPermissionProfile(entry, "NORMAL_STAGE_B_RELEASE") && planMatches(entry.plan, change));
      if (matches.length === 0) throw new Error(`Mutation manifest has no reviewed permission mapping for ${change.address}.`);
      classification = matches.map(({ id }) => id).sort().join("+");
      requiredPermissions = [...new Set(matches.map(({ action }) => action))].sort();
    }
    const before = change.change?.before || null;
    const after = change.change?.after || null;
    return {
      address: change.address,
      mutation_instance_identity: stageBMutationInstanceIdentity(change, classification),
      type: change.type,
      actions: [...actions],
      classification,
      before_identity: plannedIdentity(before),
      after_identity: plannedIdentity(after),
      replacement_order: isStageBTaskDefinitionRotationActionsValue(actions) ? [...actions] : null,
      expected_aws_api_family: [...new Set(requiredPermissions.map((action) => action.split(":", 1)[0]))].sort(),
      expected_aws_mutation: requiredPermissions.length > 0,
      required_permissions: requiredPermissions,
      expected_remote_postcondition: { identity: plannedIdentity(after), after_sha256: sha256(Buffer.from(canonicalizeJson(after))), ...(taskDefinitionPostcondition ? { task_definition: taskDefinitionPostcondition } : {}) },
    };
  }).sort((left, right) => left.mutation_instance_identity.localeCompare(right.mutation_instance_identity));
  const outputs = Object.entries(plan?.output_changes || {}).filter(([, change]) => !exactActions(change?.actions, ["no-op"])).map(([output, change]) => ({
    output,
    actions: [...(change.actions || [])],
    before: change.before ?? null,
    after: change.after ?? null,
    after_unknown: change.after_unknown ?? false,
    classification: "derived-output-change",
  })).sort((left, right) => left.output.localeCompare(right.output));
  const body = JSON.parse(JSON.stringify({
    schemaVersion: 1,
    kind: "MSCQRProductionGreenStageBMutationManifest",
    planProfile,
    toolingSha,
    planSha256,
    savedPlanSha256,
    canonicalPlanJsonSha256,
    planApprovalReportSha256,
    resources,
    outputs,
  }));
  return Object.freeze({ ...body, mutationManifestSha256: sha256(Buffer.from(canonicalizeJson(body))) });
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

function contextFromTaskDefinitionPlan(change, manifestMapping) {
  const mapping = TASK_DEFINITION_MAPPINGS.find(({ address }) => address === manifestMapping.address);
  const after = change.change?.after;
  if (isStageBTaskDefinitionRotationActionsValue(change.change?.actions)) assertStageBTaskDefinitionRotation(change, { variables: {} }, { strict: false });
  if (!after || after.family !== mapping.family || String(after.cpu) !== mapping.cpu || String(after.memory) !== mapping.memory
    || JSON.stringify(after.requires_compatibilities) !== JSON.stringify(["FARGATE"])
    || after.execution_role_arn !== mapping.executionRoleArn || after.task_role_arn !== mapping.taskRoleArn
    || canonicalizeJson(after.tags) !== canonicalizeJson(mapping.id === "backend" ? BACKEND_TASK_DEFINITION_TAGS : TASK_DEFINITION_TAGS)) {
    throw new Error(`${change.address} task-definition registration context does not match the reviewed family contract.`);
  }
  let containers;
  try { containers = typeof after.container_definitions === "string" ? JSON.parse(after.container_definitions) : after.container_definitions; } catch { throw new Error(`${change.address} container definitions are malformed.`); }
  if (!Array.isArray(containers) || containers.length === 0 || containers.some((container) => !container || (Object.hasOwn(container, "privileged") && container.privileged !== false))) {
    throw new Error(`${change.address} cannot prove ecs:privileged=false for every container.`);
  }
  const context = taskDefinitionRegisterContext(mapping);
  if (JSON.stringify(context) !== JSON.stringify(manifestMapping.registerContext)) throw new Error(`${change.address} plan-derived ECS context differs from the permission manifest.`);
  return context;
}

export function assertTaskDefinitionRegistrationContexts(plan, manifest, { permissionProfile = "NORMAL_STAGE_B_RELEASE", terraformConfiguration } = {}) {
  validateManifest(manifest);
  const allowsReviewedDeposedCleanup = permissionProfile === "FRESH_IMAGE_PARTIAL_APPLY_RECOVERY";
  const changes = Array.isArray(plan?.resource_changes) ? plan.resource_changes : [];
  const importedBackendUpdates = changes.filter((change) => change.address === STAGE_B_IMPORTED_BACKEND_CANDIDATE_ADDRESS && exactActions(change.change?.actions, ["update"]));
  if (importedBackendUpdates.length > 1) throw new Error("Selected plan contains duplicate imported backend normalization changes.");
  const importedBackendNormalization = importedBackendUpdates.length === 1;
  if (importedBackendNormalization) assertStageBImportedBackendMetadataNormalization(importedBackendUpdates[0], { terraformConfiguration });
  const taskDefinitionChanges = changes.filter((change) => change.type === "aws_ecs_task_definition");
  const registrations = taskDefinitionChanges.filter((change) => exactActions(change.change?.actions, ["create"]) || isStageBTaskDefinitionRotationActionsValue(change.change?.actions));
  const reviewedDeposedCleanups = taskDefinitionChanges.filter((change) => allowsReviewedDeposedCleanup && isStageBPartialApplyDeposedTaskDefinitionCleanup(change));
  if (allowsReviewedDeposedCleanup) {
    assertStageBFreshImageDeposedCleanupSet(taskDefinitionChanges);
  }
  const allowedMetadataChange = (change) => importedBackendNormalization && change.address === STAGE_B_IMPORTED_BACKEND_CANDIDATE_ADDRESS && exactActions(change.change?.actions, ["update"]);
  const allowedNoOp = (change) => {
    if (!exactActions(change.change?.actions, ["no-op"])) return false;
    if (TASK_DEFINITION_MAPPINGS.some((mapping) => mapping.address === change.address)) return true;
    const retained = change.address?.match(/^(aws_ecs_task_definition\.(candidate|executor))_retained\["[a-f0-9]+-([^"]+)"\]$/);
    return Boolean(retained && TASK_DEFINITION_MAPPINGS.some((mapping) => mapping.address === `${retained[1]}["${retained[3]}"]`));
  };
  if (taskDefinitionChanges.some((change) => !registrations.includes(change) && !reviewedDeposedCleanups.includes(change) && !allowedMetadataChange(change) && !allowedNoOp(change))) throw new Error("Selected plan contains an unreviewed task-definition change.");
  const requiredMappings = importedBackendNormalization
    ? manifest.taskDefinitionMappings.filter((mapping) => mapping.address !== STAGE_B_IMPORTED_BACKEND_CANDIDATE_ADDRESS)
    : manifest.taskDefinitionMappings;
  for (const mapping of requiredMappings) {
    const matches = registrations.filter((change) => change.address === mapping.address);
    if (matches.length !== 1) throw new Error(`Selected plan must contain exactly one reviewed task-definition registration for ${mapping.address}.`);
    contextFromTaskDefinitionPlan(matches[0], mapping);
  }
  if (registrations.length !== requiredMappings.length) throw new Error("Selected plan contains an unreviewed task-definition registration or an unclassified backend normalization.");
  return true;
}

function evaluation(entry, resource, { forbidden = false, contextRegistry = REVIEWED_SIMULATION_CONTEXT_REGISTRY } = {}) {
  const result = {
    id: `${entry.id}:${resource}`,
    manifestId: entry.id,
    action: entry.action,
    resource,
    context: forbidden
      ? entry.context.map(({ key, type, values }) => ({ key, type, values: [...values] }))
      : mergeReviewedSimulationContext(entry.context, contextRegistry),
    expectedMissingContextValues: normalizeExpectedMissingContextValues(entry, { forbidden }),
    phase: entry.phase || "unspecified",
  };
  if (forbidden) result.expectedDecision = entry.expectedDecision;
  Object.defineProperty(result, "forbidden", { value: forbidden, enumerable: false });
  return result;
}

function principalEvaluation(entry, { forbidden = false } = {}) {
  const result = {
    id: `${entry.id}:${entry.resources[0]}`,
    manifestId: entry.id,
    action: entry.action,
    resource: entry.resources[0],
    context: entry.context.map(({ key, type, values }) => ({ key, type, values: [...values] })),
    expectedMissingContextValues: [...(entry.expectedMissingContextValues || [])],
    phase: "cutover-critical",
  };
  if (forbidden) {
    result.expectedDecision = entry.expectedDecision;
    Object.defineProperty(result, "forbidden", { value: true, enumerable: false });
  }
  return result;
}

export function deriveRequiredEvaluations(plan, manifest, { permissionProfile = "NORMAL_STAGE_B_RELEASE", contextRegistry = REVIEWED_SIMULATION_CONTEXT_REGISTRY, conditionKeyOrigins = sourcePolicyConditionKeyOrigins(), terraformConfiguration } = {}) {
  assertStageBPermissionProfile(permissionProfile);
  validateManifest(manifest, { contextRegistry, conditionKeyOrigins });
  const changes = Array.isArray(plan?.resource_changes) ? plan.resource_changes : [];
  const required = manifest.required.filter((entry) => !entry.plan).flatMap((entry) => entry.resources.map((resource) => evaluation(entry, resource, { contextRegistry })));
  const coveredChanges = [];
  const zeroAwsMutationChanges = [];
  const matchedPlanEntries = new Set();
  for (const change of changes) {
    const actions = change.change?.actions || [];
    if (["aws_iam_role_policy.broker", "aws_iam_policy.broker", "aws_iam_role_policy_attachment.broker"].includes(change.address)) assertBrokerManagedPolicyChange(change);
    if (exactActions(actions, ["no-op"])) continue;
    if (["PARTIAL_APPLY_RECOVERY", "FRESH_IMAGE_PARTIAL_APPLY_RECOVERY"].includes(permissionProfile) && isStageBPartialApplyDeposedTaskDefinitionCleanup(change)) {
      const classification = "PARTIAL_APPLY_RECOVERY_DEPOSED_TASK_DEFINITION_CLEANUP";
      zeroAwsMutationChanges.push({ address: change.address, mutationInstanceIdentity: stageBMutationInstanceIdentity(change, classification), classification, requiredAwsActions: [] });
      coveredChanges.push(stageBMutationInstanceIdentity(change));
      continue;
    }
    if (change.address === STAGE_B_IMPORTED_BACKEND_CANDIDATE_ADDRESS && exactActions(actions, ["update"])) {
      assertStageBImportedBackendMetadataNormalization(change, { terraformConfiguration });
      zeroAwsMutationChanges.push({ address: change.address, classification: STAGE_B_IMPORTED_BACKEND_METADATA_NORMALIZATION, requiredAwsActions: [] });
      coveredChanges.push(stageBMutationInstanceIdentity(change));
      continue;
    }
    const taskMapping = change.type === "aws_ecs_task_definition" && (exactActions(actions, ["create"]) || isStageBTaskDefinitionRotationActionsValue(actions))
      ? manifest.taskDefinitionMappings.find((mapping) => mapping.address === change.address)
      : undefined;
    if (change.type === "aws_ecs_task_definition" && !taskMapping) throw new Error(`No permission manifest entry covers ${change.address} ${JSON.stringify(actions)}.`);
    if (taskMapping) {
      if (permissionProfile === "RECOVERY_ALIAS_ONLY") throw new Error(`RECOVERY_ALIAS_ONLY rejects ECS task-definition mutation: ${change.address}.`);
      const registerContext = contextFromTaskDefinitionPlan(change, taskMapping);
      required.push(evaluation({ id: `${taskMapping.id}-register`, action: "ecs:RegisterTaskDefinition", context: registerContext, phase: "apply" }, taskMapping.resource, { contextRegistry }));
      required.push(evaluation({ id: `${taskMapping.id}-tag`, action: "ecs:TagResource", context: taskDefinitionTagContext(registerContext), phase: "apply" }, taskMapping.resource, { contextRegistry }));
      required.push(evaluation({ id: `${taskMapping.id}-pass-execution`, action: "iam:PassRole", context: taskMapping.passRoleContext, phase: "apply" }, taskMapping.executionRoleArn, { contextRegistry }));
      required.push(evaluation({ id: `${taskMapping.id}-pass-task`, action: "iam:PassRole", context: taskMapping.passRoleContext, phase: "apply" }, taskMapping.taskRoleArn, { contextRegistry }));
      coveredChanges.push(stageBMutationInstanceIdentity(change));
      continue;
    }
    const matches = manifest.required.filter((entry) => entry.plan && appliesToPermissionProfile(entry, permissionProfile) && planMatches(entry.plan, change));
    if (matches.length === 0) throw new Error(`No permission manifest entry covers ${change.address} ${JSON.stringify(actions)}.`);
    coveredChanges.push(stageBMutationInstanceIdentity(change));
    for (const entry of matches) {
      matchedPlanEntries.add(entry.id);
      for (const resource of entry.resources) required.push(evaluation(entry, resource, { contextRegistry }));
    }
  }
  for (const entry of manifest.required.filter((candidate) => candidate.plan?.coverageRequired && appliesToPermissionProfile(candidate, permissionProfile))) {
    if (!matchedPlanEntries.has(entry.id)) throw new Error(`Permission manifest mapping has no matching plan change: ${entry.id}.`);
  }
  const forbidden = manifest.forbidden.flatMap((entry) => entry.resources.map((resource) => evaluation(entry, resource, { forbidden: true, contextRegistry })));
  return {
    required: required.sort((left, right) => left.id.localeCompare(right.id)),
    forbidden: forbidden.sort((left, right) => left.id.localeCompare(right.id)),
    coveredChanges: coveredChanges.sort(),
    zeroAwsMutationChanges,
  };
}

export function simulatePrincipalPolicy({ roleArn, evaluation: item, conditionKeyOrigins, run = (args) => execFileSync("aws", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) }) {
  const args = [
    "iam", "simulate-principal-policy",
    "--policy-source-arn", roleArn,
    "--action-names", item.action,
    "--resource-arns", item.resource,
    "--output", "json",
  ];
  if (item.context.length > 0) args.push("--context-entries", ...iamSimulationContextArgs(item.context));
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
  const rawMissingContextValues = normalizeActualMissingContextValues(result.MissingContextValues, item.id);
  const scopedMissingContextValues = conditionKeyOrigins
    ? rawMissingContextValues.filter((key) => applicableConditionKeys(conditionKeyOrigins, item.action).has(key))
    : rawMissingContextValues;
  return validateSimulationResult(item, {
    decision: result.EvalDecision,
    matchedStatements: result.MatchedStatements.length,
    missingContextValues: scopedMissingContextValues,
    organizationsAllowed: result.OrganizationsDecisionDetail?.AllowedByOrganizations ?? null,
    permissionsBoundaryAllowed: result.PermissionsBoundaryDecisionDetail?.AllowedByPermissionsBoundary ?? null,
  });
}

// This is intentionally shared by the live preflight and rehearsal.  A census
// records every safely executable simulation before the final status fails
// closed, preventing a first mismatch from masking later authorization gaps.
export function runSimulationCensus({ roleArn, evaluations, simulate }) {
  if (!Array.isArray(evaluations) || typeof simulate !== "function") throw new Error("IAM simulation census inputs are invalid.");
  return evaluations.map((item) => {
    try {
      const result = validateSimulationResult(item, simulate({ roleArn, evaluation: item }));
      return { ...item, ...result, missingContextExactMatch: true, validation: item.forbidden ? (result.decision === "allowed" ? "rejected" : "accepted") : (result.decision === "allowed" ? "accepted" : "rejected") };
    } catch (error) {
      return { ...item, decision: null, matchedStatements: null, missingContextValues: [], missingContextExactMatch: false, validation: "rejected", error: error instanceof Error ? error.message : String(error) };
    }
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
  reportBytes = serializePermissionReport(report),
  sign = ({ digest }) => withTempBytes("mscqr-stage-b-permission-sign-", { digest }, ({ digest: digestPath }) => JSON.parse(execFileSync("aws", [
    "kms", "sign", "--key-id", keyArn, "--message", `fileb://${digestPath}`, "--message-type", "DIGEST", "--signing-algorithm", signingAlgorithm, "--output", "json",
  ], { encoding: "utf8" })).Signature),
} = {}) {
  if (report?.schemaVersion !== PERMISSION_PREFLIGHT_SCHEMA_VERSION || report.status !== "valid") throw new Error("Only a valid permission report may be signed.");
  if (keyArn !== PERMISSION_REPORT_SIGNING_KEY_ARN || signingAlgorithm !== PERMISSION_REPORT_SIGNING_ALGORITHM) throw new Error("Permission report signing contract is wrong.");
  const canonicalPayloadSha256 = sha256(Buffer.from(canonicalizeJson(report)));
  const reportFileSha256 = sha256(reportBytes);
  const bindingPayload = buildPermissionReportBinding({ report, canonicalPayloadSha256, reportFileSha256, keyArn, signingAlgorithm });
  const signedBindingSha256 = sha256(Buffer.from(canonicalizeJson(bindingPayload)));
  const signatureBase64 = String(sign({ keyArn, signingAlgorithm, digest: Buffer.from(signedBindingSha256, "hex"), canonicalPayloadSha256, reportFileSha256, signedBindingSha256, bindingPayload }) || "");
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(signatureBase64)) throw new Error("Permission report signing returned an invalid signature.");
  return { schemaVersion: PERMISSION_REPORT_SIGNATURE_SCHEMA_VERSION, hashDomain: PERMISSION_REPORT_HASH_DOMAIN, bindingDomain: PERMISSION_REPORT_BINDING_DOMAIN, bindingSchemaVersion: PERMISSION_REPORT_BINDING_SCHEMA_VERSION, evidenceKind: report.evidenceKind, phase: report.phase, purpose: report.purpose, accountId: ACCOUNT, region: REGION, keyId: keyArn, keyArn, signingAlgorithm, canonicalPayloadSha256, reportFileSha256, signedBindingSha256, signatureBase64, signedAt: now };
}

export function buildPermissionReportBinding({ report, canonicalPayloadSha256, reportFileSha256, keyArn = PERMISSION_REPORT_SIGNING_KEY_ARN, signingAlgorithm = PERMISSION_REPORT_SIGNING_ALGORITHM, accountId = ACCOUNT, region = REGION } = {}) {
  return { domain: PERMISSION_REPORT_BINDING_DOMAIN, schemaVersion: PERMISSION_REPORT_BINDING_SCHEMA_VERSION, evidenceKind: report?.evidenceKind, phase: report?.phase, purpose: report?.purpose, canonicalPayloadSha256, reportFileSha256, accountId, region, keyArn, signingAlgorithm };
}

export const signedPermissionReportBindingSha256 = (bindingPayload) => sha256(Buffer.from(canonicalizeJson(bindingPayload)));

export function assertPermissionReportHashDomains({ report, signatureArtifact, reportBytes, signatureBytes, expectedReportFileSha256, expectedSignatureFileSha256, expectedCanonicalPayloadSha256 } = {}) {
  if (!Buffer.isBuffer(reportBytes) || !Buffer.isBuffer(signatureBytes)) throw new Error("Permission report and signature bytes are required for hash-domain validation.");
  let parsedReport;
  let parsedSignature;
  try { parsedReport = JSON.parse(reportBytes); parsedSignature = JSON.parse(signatureBytes); } catch { throw new Error("Permission report or signature bytes are malformed."); }
  if (canonicalizeJson(parsedReport) !== canonicalizeJson(report) || canonicalizeJson(parsedSignature) !== canonicalizeJson(signatureArtifact)) throw new Error("Permission report/signature bytes do not match their parsed artifacts.");
  const canonicalPayloadSha256 = sha256(Buffer.from(canonicalizeJson(parsedReport)));
  const reportFileSha256 = sha256(reportBytes);
  const signatureFileSha256 = sha256(signatureBytes);
  if (signatureArtifact?.schemaVersion !== PERMISSION_REPORT_SIGNATURE_SCHEMA_VERSION || signatureArtifact.hashDomain !== PERMISSION_REPORT_HASH_DOMAIN || signatureArtifact.bindingDomain !== PERMISSION_REPORT_BINDING_DOMAIN || signatureArtifact.bindingSchemaVersion !== PERMISSION_REPORT_BINDING_SCHEMA_VERSION) throw new Error("Permission report signature hash-domain schema is unsupported.");
  if (signatureArtifact.canonicalPayloadSha256 !== canonicalPayloadSha256) throw new Error("Permission report signature is bound to a different canonical payload.");
  if (signatureArtifact.reportFileSha256 !== reportFileSha256) throw new Error("Permission report signature is bound to different report bytes.");
  const bindingPayload = buildPermissionReportBinding({ report: parsedReport, canonicalPayloadSha256, reportFileSha256, keyArn: signatureArtifact.keyArn, signingAlgorithm: signatureArtifact.signingAlgorithm });
  for (const field of ["evidenceKind", "phase", "purpose", "accountId", "region", "keyArn", "signingAlgorithm"]) {
    if (signatureArtifact[field] !== bindingPayload[field]) throw new Error(`Permission report signature binding field ${field} does not match the report contract.`);
  }
  const signedBindingSha256 = signedPermissionReportBindingSha256(bindingPayload);
  if (signatureArtifact.signedBindingSha256 !== signedBindingSha256) throw new Error("Permission report signature is bound to a different signed binding.");
  if (expectedCanonicalPayloadSha256 !== undefined && expectedCanonicalPayloadSha256 !== canonicalPayloadSha256) throw new Error("Permission report canonical payload SHA256 differs from the selected report.");
  if (expectedReportFileSha256 !== undefined && expectedReportFileSha256 !== reportFileSha256) throw new Error("Permission report file SHA256 differs from the selected report.");
  if (expectedSignatureFileSha256 !== undefined && expectedSignatureFileSha256 !== signatureFileSha256) throw new Error("Permission report signature file SHA256 differs from the selected signature.");
  return { canonicalPayloadSha256, reportFileSha256, signedBindingSha256, signatureFileSha256, bindingPayload };
}

export function verifyPermissionReportSignature({ report, signatureArtifact, reportBytes = serializePermissionReport(report), signatureBytes, expectedReportFileSha256, expectedSignatureFileSha256, now = new Date().toISOString(), keyArn = PERMISSION_REPORT_SIGNING_KEY_ARN, signingAlgorithm = PERMISSION_REPORT_SIGNING_ALGORITHM, verify = ({ digest, signature }) => withTempBytes("mscqr-stage-b-permission-verify-", { digest, signature }, ({ digest: digestPath, signature: signaturePath }) => JSON.parse(execFileSync("aws", [
  "kms", "verify", "--key-id", keyArn, "--message", `fileb://${digestPath}`, "--message-type", "DIGEST", "--signature", `fileb://${signaturePath}`, "--signing-algorithm", signingAlgorithm, "--output", "json",
], { encoding: "utf8" })).SignatureValid === true) }) {
  if (!signatureArtifact || signatureArtifact.keyId !== keyArn || signatureArtifact.keyArn !== keyArn || signatureArtifact.signingAlgorithm !== signingAlgorithm) throw new Error("Permission report signature identity or algorithm is wrong.");
  const effectiveSignatureBytes = signatureBytes || serializePermissionReport(signatureArtifact);
  const domains = assertPermissionReportHashDomains({ report, signatureArtifact, reportBytes, signatureBytes: effectiveSignatureBytes, expectedReportFileSha256, expectedSignatureFileSha256 });
  assertStageBDeploymentEvidenceFreshness(signatureArtifact.signedAt, { now, evidenceType: "Permission report signature" });
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(signatureArtifact.signatureBase64 || "")) throw new Error("Permission report signature is malformed.");
  if (!verify({ keyArn, signingAlgorithm, digest: Buffer.from(domains.signedBindingSha256, "hex"), signature: Buffer.from(signatureArtifact.signatureBase64, "base64"), canonicalPayloadSha256: domains.canonicalPayloadSha256, reportFileSha256: domains.reportFileSha256, signedBindingSha256: domains.signedBindingSha256, bindingPayload: domains.bindingPayload })) throw new Error("Permission report signature verification failed.");
  return true;
}

function validateFreshness(timestamp, now) {
  return assertStageBDeploymentEvidenceFreshness(timestamp, { now, evidenceType: "Permission report" });
}

export function runPermissionPreflight({
  reportGeneratorCallerArn,
  simulatedRoleArn = RELEASE_ROLE_ARN,
  manifest,
  plan,
  planBytes,
  canonicalPlanJsonBytes,
  savedPlanBytes,
  planApprovalReport,
  planApprovalReportBytes,
  planApprovalReportSha256,
  referenceAudit,
  referenceAuditBytes,
  terraformConfiguration,
  expectedAccount = ACCOUNT,
  expectedRegion = REGION,
  generatedAt = new Date().toISOString(),
  policyPublishedAt,
  cloudTrailSessionName,
  purpose = "saved-plan-authorization",
  phase = "plan-bound",
  policyEvidence,
  now = new Date().toISOString(),
  simulate = ({ roleArn: sourceArn, evaluation: item }) => simulatePrincipalPolicy({ roleArn: sourceArn, evaluation: item, conditionKeyOrigins: sourceArn === ECS_EXEC_OPERATOR_ROLE_ARN ? operatorPolicyConditionKeyOrigins() : sourcePolicyConditionKeyOrigins() }),
  discoverContextKeys = null,
  cloudTrail = ({ sessionName, startTime, endTime, requiredActions }) => inspectCloudTrailDenials({ sessionName, startTime, endTime, requiredActions }),
  ecsExecVerifierEvidence,
  contextRegistry = REVIEWED_SIMULATION_CONTEXT_REGISTRY,
} = {}) {
  if (!["initial", "plan-bound"].includes(phase)) throw new Error("Permission preflight phase is unsupported.");
  const planBound = phase === "plan-bound";
  if (expectedAccount !== ACCOUNT || expectedRegion !== REGION) throw new Error("Expected account or region is wrong.");
  if (planBound && (!Buffer.isBuffer(savedPlanBytes) || savedPlanBytes.length === 0)) throw new Error("Saved binary plan bytes are required for permission preflight.");
  if (planBound && (!planApprovalReport || !Buffer.isBuffer(planApprovalReportBytes) || !/^[a-f0-9]{64}$/.test(planApprovalReportSha256 || ""))) throw new Error("PLAN_APPROVED evidence is required before permission preflight.");
  if (planBound && !Buffer.isBuffer(canonicalPlanJsonBytes)) throw new Error("Canonical plan JSON bytes are required for permission preflight.");
  if (planBound) assertStageBPlanApprovedBinding(planApprovalReport, { approvalReportBytes: planApprovalReportBytes, approvalReportSha256: planApprovalReportSha256, savedPlanBytes, planJsonBytes: planBytes, canonicalPlanJsonBytes, referenceAudit, referenceAuditBytes, terraformConfiguration, now: new Date(now) });
  const permissionProfileBinding = resolveStageBPermissionProfile({ plan, approvedPlanProfile: planApprovalReport?.planProfile, phase, terraformConfiguration });
  if (!reportGeneratorCallerArn || !APPROVED_PREFLIGHT_GENERATOR_ARNS.includes(reportGeneratorCallerArn)) throw new Error("Permission preflight generator is not an approved audit/admin principal.");
  if (simulatedRoleArn !== RELEASE_ROLE_ARN) throw new Error("Permission preflight simulated role ARN is not the production release role.");
  const conditionKeyOrigins = sourcePolicyConditionKeyOrigins();
  const reviewedContextRegistry = assertReviewedSimulationContextRegistry({ conditionKeyOrigins, registry: contextRegistry });
  validateManifest(manifest, { account: expectedAccount, region: expectedRegion, conditionKeyOrigins, contextRegistry: reviewedContextRegistry });
  if (!plan?.variables || plan.variables.account_id?.value !== expectedAccount || plan.variables.aws_region?.value !== expectedRegion) throw new Error("Plan account or region is wrong.");
  const deploymentIdentity = assertStageBDeploymentIdentity({ plan });
  validateFreshness(generatedAt, now);
  if (!policyPublishedAt) throw new Error("Policy publication timestamp is required and must be valid.");
  assertStageBDeploymentEvidenceTimestamp(policyPublishedAt, { now, evidenceType: "Policy publication" });
  if (!cloudTrailSessionName) throw new Error("CloudTrail session name is required.");
  let policyEvidenceError = null;
  try { assertReleasePolicyEvidence(policyEvidence); } catch (error) { policyEvidenceError = error.message; }
  if (discoverContextKeys) assertDiscoveredSimulationContextKeys(discoverContextKeys({ roleArn: simulatedRoleArn }), { conditionKeyOrigins, registry: reviewedContextRegistry });
  const derived = deriveRequiredEvaluations(plan, manifest, { permissionProfile: permissionProfileBinding.permissionProfile, contextRegistry: reviewedContextRegistry, conditionKeyOrigins, terraformConfiguration });
  const requiredResults = runSimulationCensus({ roleArn: simulatedRoleArn, evaluations: derived.required, simulate });
  const forbiddenResults = runSimulationCensus({ roleArn: simulatedRoleArn, evaluations: derived.forbidden, simulate });
  const operatorRequired = ECS_EXEC_OPERATOR_REQUIRED.map((entry) => principalEvaluation(entry));
  const operatorForbidden = ECS_EXEC_OPERATOR_FORBIDDEN.map((entry) => principalEvaluation(entry, { forbidden: true }));
  const operatorRequiredResults = runSimulationCensus({ roleArn: ECS_EXEC_OPERATOR_ROLE_ARN, evaluations: operatorRequired, simulate });
  const operatorForbiddenResults = runSimulationCensus({ roleArn: ECS_EXEC_OPERATOR_ROLE_ARN, evaluations: operatorForbidden, simulate });
  const operatorDeniedRequired = operatorRequiredResults.filter((item) => item.decision !== "allowed");
  const operatorAllowedForbidden = operatorForbiddenResults.filter((item) => item.decision === "allowed" || item.validation !== "accepted");
  let operatorEvidenceError = null;
  if (phase === "initial") {
    try { assertEcsExecOperatorLiveEvidence(ecsExecVerifierEvidence); } catch (error) { operatorEvidenceError = error.message; }
  }
  const operatorStatus = operatorDeniedRequired.length === 0 && operatorAllowedForbidden.length === 0 && !operatorEvidenceError ? "valid" : "invalid";
  const cloudTrailResult = cloudTrail({ sessionName: cloudTrailSessionName, startTime: policyPublishedAt, endTime: generatedAt, requiredActions: derived.required.map((item) => item.action) });
  const deniedRequired = requiredResults.filter((item) => item.decision !== "allowed");
  const allowedForbidden = forbiddenResults.filter((item) => item.decision === "allowed" || item.validation !== "accepted");
  const unresolved = cloudTrailResult.unresolvedDenials || [];
  const mutationManifest = planBound ? createStageBMutationManifest(plan, manifest, {
    planProfile: permissionProfileBinding.planProfile,
    planSha256: planBound ? sha256(planBytes) : undefined,
    savedPlanSha256: planBound ? sha256(savedPlanBytes) : undefined,
    canonicalPlanJsonSha256: planBound ? sha256(Buffer.from(canonicalizeJson(plan))) : undefined,
    planApprovalReportSha256: planBound ? planApprovalReportSha256 : undefined,
    toolingSha: deploymentIdentity.toolingSha,
    terraformConfiguration,
  }) : undefined;
  const report = {
    schemaVersion: PERMISSION_PREFLIGHT_SCHEMA_VERSION,
    evidenceKind: planBound ? PLAN_BOUND_PERMISSION_EVIDENCE_KIND : INITIAL_ADMINISTRATOR_CAPABILITY_EVIDENCE_KIND,
    phase,
    purpose,
    planProfile: permissionProfileBinding.planProfile,
    permissionProfile: permissionProfileBinding.permissionProfile,
    toolingSha: deploymentIdentity.toolingSha,
    imageReleaseSha: deploymentIdentity.imageReleaseSha,
    canonicalImageEvidenceSha256: deploymentIdentity.canonicalImageEvidenceSha256,
    reportGeneratorCallerArn,
    simulatedRoleArn,
    applyRoleArn: RELEASE_ROLE_ARN,
    applyCallerArn: null,
    applyCallerArnPattern: RELEASE_CALLER_PATTERN,
    manifestSha256: sha256(Buffer.from(canonicalizeJson(manifest))),
    ...(planBound ? {
      planSha256: sha256(planBytes),
      savedPlanSha256: sha256(savedPlanBytes),
      canonicalPlanJsonSha256: sha256(Buffer.from(canonicalizeJson(plan))),
      planApprovalReportSha256,
    } : {}),
    generatedAt,
    policyPublishedAt,
    cloudTrailWindow: { startTime: policyPublishedAt, endTime: generatedAt, sessionName: cloudTrailSessionName },
    requiredEvaluations: requiredResults,
    forbiddenEvaluations: forbiddenResults,
    principalEvaluations: {
      releaseDeployer: { principalArn: RELEASE_ROLE_ARN, requiredEvaluations: requiredResults, forbiddenEvaluations: forbiddenResults, status: deniedRequired.length === 0 && allowedForbidden.length === 0 ? "valid" : "invalid" },
      ecsExecVerifier: { principalArn: ECS_EXEC_OPERATOR_ROLE_ARN, requiredEvaluations: operatorRequiredResults, forbiddenEvaluations: operatorForbiddenResults, status: operatorStatus },
    },
    ecsExecVerifierTrust: ecsExecVerifierEvidence || null,
    temporaryKmsCapability: buildTemporaryCapabilityEvidence({
      state: "ABSENCE_VERIFIED",
      sourceSha: deploymentIdentity.toolingSha,
      transitionId: `preflight-${deploymentIdentity.toolingSha.slice(0, 12)}`,
      defaultVersionId: policyEvidence.policies.find(({ name }) => name === "MSCQRProductionGreenStageARelease")?.defaultVersionId,
      observedAt: generatedAt,
    }),
    cutoverCritical: {
      stageAIngress: requiredResults.find(({ manifestId }) => manifestId === "apply-stage-a-endpoint-security-group-ingress")?.decision || null,
      stageACheckerRoleChain: requiredResults.find(({ manifestId }) => manifestId === "apply-stage-a-checker-role-chain-policy")?.decision || null,
      stageACheckerPublication: requiredResults.find(({ manifestId }) => manifestId === "apply-stage-a-checker-publication-policy")?.decision || null,
      releaseForward: requiredResults.find(({ manifestId }) => manifestId === "activate-exact-ecs-service")?.decision || null,
      releaseRollback: requiredResults.find(({ manifestId }) => manifestId === "rollback-exact-ecs-service")?.decision || null,
      releasePassRole: requiredResults.find(({ manifestId }) => manifestId === "rollback-exact-backend-task-passrole")?.decision || null,
      releaseEcsExec: forbiddenResults.find(({ manifestId }) => manifestId === "release-deployer-ecs-exec")?.decision || null,
      verifierEcsExec: operatorRequiredResults.find(({ manifestId }) => manifestId === "operator-execute-production-backend")?.decision || null,
    },
    planCapabilities: {
      schemaVersion: 1,
      required: requiredResults.map(({ id, action, resource, context, decision }) => ({ id, action, resource, context, decision })),
      forbidden: forbiddenResults.map(({ id, action, resource, context, decision }) => ({ id, action, resource, context, decision })),
      mutationInstances: derived.coveredChanges,
      zeroAwsMutationChanges: derived.zeroAwsMutationChanges,
      ...(planBound ? { mutationManifest } : {}),
    },
    cloudTrail: cloudTrailResult,
    policyEvidence,
    policySourceLiveMismatchCount: policyEvidenceError ? 1 : 0,
    policySourceLiveMismatch: policyEvidenceError,
    requiredAllowedCount: requiredResults.filter((item) => item.decision === "allowed").length,
    requiredDeniedCount: deniedRequired.length,
    forbiddenAllowedCount: allowedForbidden.length,
    forbiddenDeniedCount: forbiddenResults.filter((item) => item.decision !== "allowed").length,
    allowedCount: requiredResults.filter((item) => item.decision === "allowed").length,
    operatorRequiredAllowedCount: operatorRequiredResults.filter((item) => item.decision === "allowed").length,
    operatorRequiredDeniedCount: operatorDeniedRequired.length,
    operatorForbiddenAllowedCount: operatorAllowedForbidden.length,
    operatorForbiddenDeniedCount: operatorForbiddenResults.filter((item) => item.decision !== "allowed").length,
    operatorEvidenceError,
    iamEvaluationCensus: {
      total: requiredResults.length + forbiddenResults.length + operatorRequiredResults.length + operatorForbiddenResults.length,
      executed: requiredResults.length + forbiddenResults.length + operatorRequiredResults.length + operatorForbiddenResults.length,
      expectedAllowPass: [...requiredResults, ...operatorRequiredResults].filter((item) => item.decision === "allowed" && item.validation === "accepted").length,
      expectedDenyPass: [...forbiddenResults, ...operatorForbiddenResults].filter((item) => item.decision !== "allowed" && item.validation === "accepted").length,
      invalid: [...requiredResults, ...forbiddenResults, ...operatorRequiredResults, ...operatorForbiddenResults].filter((item) => item.validation !== "accepted").length,
      failures: [...requiredResults, ...forbiddenResults, ...operatorRequiredResults, ...operatorForbiddenResults].filter((item) => item.validation !== "accepted").map(({ id, action, resource, error, decision, missingContextValues }) => ({ id, action, resource, error: error || null, decision, missingContextValues })),
    },
    deniedCount: deniedRequired.length + allowedForbidden.length + operatorDeniedRequired.length + operatorAllowedForbidden.length + unresolved.length,
    status: deniedRequired.length === 0 && allowedForbidden.length === 0 && operatorStatus === "valid" && unresolved.length === 0 && !policyEvidenceError ? "valid" : "invalid",
  };
  if (phase === "initial" && report.status === "valid") assertCutoverCriticalEvidence(report);
  return report;
}

export function runCli(argv = process.argv.slice(2), { getCaller = () => JSON.parse(execFileSync("aws", ["sts", "get-caller-identity", "--output", "json"], { encoding: "utf8" })).Arn, collectPolicyEvidence = collectLiveReleasePolicyEvidence, runPreflight = runPermissionPreflight, signReport = signPermissionReport } = {}) {
  const options = parseCli(argv);
  assertStageBPrivateFile({ filePath: options.planJsonPath, repositoryRoot: stageBRoot, label: "Stage B plan JSON" });
  assertStageBPrivateFile({ filePath: options.canonicalPlanJsonPath, repositoryRoot: stageBRoot, label: "Stage B canonical plan JSON" });
  assertStageBPrivateFile({ filePath: options.savedPlanPath, repositoryRoot: stageBRoot, label: "Stage B saved plan" });
  assertStageBPrivateFile({ filePath: options.planApprovalReportPath, repositoryRoot: stageBRoot, label: "Stage B plan approval report" });
  if (options.referenceAuditPath) assertStageBPrivateFile({ filePath: options.referenceAuditPath, repositoryRoot: stageBRoot, label: "Stage B reference audit" });
  const outputPath = assertStageBArtifactPath({ artifactPath: options.outputPath, repositoryRoot: stageBRoot, label: "Stage B permission report", allowExisting: false });
  const signatureOutputPath = assertStageBArtifactPath({ artifactPath: options.signatureOutputPath, repositoryRoot: stageBRoot, label: "Stage B permission-report signature", allowExisting: false });
  if (path.dirname(outputPath) !== path.dirname(signatureOutputPath)) throw new Error("Stage B permission report and signature must use one private directory.");
  ensureStageBPrivateDirectory({ directory: path.dirname(outputPath), repositoryRoot: stageBRoot, create: true });
  const observedCallerArn = getCaller();
  if (observedCallerArn !== options.reportGeneratorCallerArn) throw new Error("Report generator caller does not match the current AWS identity.");
  const planBytes = fs.readFileSync(path.resolve(options.planJsonPath));
  const canonicalPlanJsonBytes = fs.readFileSync(path.resolve(options.canonicalPlanJsonPath));
  const savedPlanBytes = fs.readFileSync(path.resolve(options.savedPlanPath));
  const planApprovalReportBytes = fs.readFileSync(path.resolve(options.planApprovalReportPath));
  const planApprovalReport = JSON.parse(planApprovalReportBytes);
  if (["BASELINE", "IMPORTED_BACKEND_METADATA_NORMALIZATION"].includes(planApprovalReport.planProfile) && !options.referenceAuditPath) {
    throw new Error("--reference-audit is required for BASELINE plan-bound permission preflight.");
  }
  const plan = JSON.parse(planBytes);
  const referenceAuditBytes = options.referenceAuditPath ? fs.readFileSync(path.resolve(options.referenceAuditPath)) : undefined;
  const referenceAudit = referenceAuditBytes ? JSON.parse(referenceAuditBytes) : undefined;
  const manifest = JSON.parse(fs.readFileSync(path.resolve(options.manifestPath), "utf8"));
  const terraformConfiguration = fs.readFileSync(path.join(stageBRoot, "infra/aws/terraform/production-green-stage-b/main.tf"), "utf8");
  const report = runPreflight({ ...options, reportGeneratorCallerArn: observedCallerArn, simulatedRoleArn: options.simulatedRoleArn, manifest, plan, planBytes, canonicalPlanJsonBytes, savedPlanBytes, planApprovalReport, planApprovalReportBytes, referenceAudit, referenceAuditBytes, terraformConfiguration, policyEvidence: collectPolicyEvidence() });
  assertStageBPermissionEvidenceKind(report, PLAN_BOUND_PERMISSION_EVIDENCE_KIND, "plan-bound");
  process.stdout.write(`${JSON.stringify({ status: report.status, outputPath, planSha256: report.planSha256, allowedCount: report.allowedCount, deniedCount: report.deniedCount })}\n`);
  if (report.status !== "valid") {
    process.exitCode = 1; return report;
  }
  const reportBytes = serializePermissionReport(report);
  const signatureArtifact = signReport(report, { now: options.generatedAt, reportBytes });
  const signatureBytes = Buffer.from(`${JSON.stringify(signatureArtifact, null, 2)}\n`);
  assertPermissionReportHashDomains({ report, signatureArtifact, reportBytes, signatureBytes });
  writeStageBPrivateFilesAtomic({ repositoryRoot: stageBRoot, files: [
    { filePath: outputPath, bytes: reportBytes, label: "Stage B permission report" },
    { filePath: signatureOutputPath, bytes: signatureBytes, label: "Stage B permission-report signature" },
  ] });
  assertPermissionReportHashDomains({ report, signatureArtifact, reportBytes: fs.readFileSync(outputPath), signatureBytes: fs.readFileSync(signatureOutputPath) });
  return report;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) runCli();

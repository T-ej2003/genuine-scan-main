#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { RELEASE_READ_PROBES } from "./production-green-stage-b-identity-capabilities.mjs";
import { STAGE_B } from "./production-green-stage-b-contract.mjs";
import { RELEASE_POLICY_SOURCES, canonicalizeJson } from "./validate-production-green-stage-b-permissions.mjs";
import { STAGE_B_DEPLOYMENT_EVIDENCE_TTL_SECONDS } from "./stage-b-evidence-freshness.mjs";
import { ECS_EXEC_OPERATOR_FORBIDDEN, ECS_EXEC_OPERATOR_POLICY_ARN, ECS_EXEC_OPERATOR_POLICY_PATH, ECS_EXEC_OPERATOR_REQUIRED, ECS_EXEC_OPERATOR_ROLE_ARN } from "./production-ecs-exec-operator-contract.mjs";
import { STAGE_B_TERRAFORM_BACKEND } from "./stage-b-terraform-backend-contract.mjs";
import { IMAGE_EVIDENCE_SIGNING_KEY_ARN } from "./production-green-stage-b-image-evidence.mjs";
import { ROOT_DROP_SIGNING_KEY_ARN } from "./production-root-drop-evidence.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
export const CAPABILITY_GRAPH_PATH = "documents/ops/iam/MSCQRProductionGreenStageBDeploymentCapabilities-v1.json";
export const CAPABILITY_GRAPH_SCHEMA_PATH = "documents/ops/iam/MSCQRProductionGreenStageBDeploymentCapabilities-v1.schema.json";
export const CAPABILITY_GRAPH_MARKDOWN_PATH = "documents/ops/iam/MSCQRProductionGreenStageBDeploymentCapabilities-v1.md";
const manifestPath = "documents/ops/iam/MSCQRProductionGreenStageBPermissionManifest-v1.json";
const publisherPolicyPath = "infra/aws/terraform/production-green-stage-b-image-publisher/permissions-policy.json";
const terraformPath = "infra/aws/terraform/production-green-stage-b/main.tf";
const checkerPolicyPath = "infra/aws/terraform/production-green-stage-a/main.tf";
const awsCliSourceFiles = [
  "scripts/plan-production-green-stage-b.mjs", "scripts/apply-production-green-stage-b.mjs",
  "scripts/aws/create-production-green-stage-b-approval.mjs", "scripts/aws/generate-production-green-stage-a-prerequisites.mjs",
  "scripts/aws/production-green-stage-b-ecs-observations.mjs", "scripts/aws/production-green-stage-b-image-evidence.mjs",
  "scripts/aws/production-green-stage-b-identity-capabilities.mjs", "scripts/aws/run-production-green-stage-b-preflight.mjs",
  "scripts/aws/validate-production-green-stage-b-permissions.mjs", "scripts/aws/production-checker-chain-contract.mjs",
  "scripts/aws/publish-production-green-stage-b-approval.mjs", "scripts/aws/check-production-green-stage-b-approval-publication.mjs",
  "scripts/aws/recover-stage-b-backend-task-definition.mjs", "scripts/aws/forward-recover-stage-b-existing-revision.mjs",
  "scripts/aws/recover-production-backend-health.mjs",
  "scripts/aws/production-root-drop-evidence.mjs", "scripts/aws/produce-production-root-drop-evidence.mjs",
];
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const readJson = (file) => JSON.parse(fs.readFileSync(path.join(root, file), "utf8"));
const asArray = (value) => Array.isArray(value) ? value : [value];
const operatorPolicy = readJson(ECS_EXEC_OPERATOR_POLICY_PATH);

const PHASES = Object.freeze([
  ["protected-main-checkout", "scripts/aws/stage-b-release-gate.mjs"],
  ["dependency-installation", "package.json"],
  ["rls-package-verification", "scripts/rls/verify-full-rls-package.mjs"],
  ["image-impact-classification", "scripts/aws/validate-stage-b-image-reuse.mjs"],
  ["image-workflow-dispatch", "scripts/aws/dispatch-production-green-stage-b-images.mjs"],
  ["image-artifact-verification", ".github/workflows/production-green-stage-b-image-build.yml"],
  ["schema-v3-image-evidence", "scripts/aws/production-green-stage-b-image-evidence.mjs"],
  ["administrator-iam-simulation", "scripts/aws/validate-production-green-stage-b-permissions.mjs"],
  ["administrator-kms-signing", "scripts/aws/validate-production-green-stage-b-permissions.mjs"],
  ["bootstrap-mfa-session", "documents/security/rls-program/PRODUCTION_GREEN_STAGE_B_INFRASTRUCTURE_RUNBOOK.md"],
  ["release-role-assumption", "documents/security/rls-program/PRODUCTION_GREEN_STAGE_B_INFRASTRUCTURE_RUNBOOK.md"],
  ["release-direct-read-preflight", "scripts/aws/run-production-green-stage-b-preflight.mjs"],
  ["backend-config-generation", "scripts/aws/generate-production-green-stage-b-backend-config.mjs"],
  ["terraform-initialization", "scripts/aws/run-production-green-stage-b-preflight.mjs"],
  ["backend-metadata-validation", "scripts/aws/stage-b-terraform-backend-contract.mjs"],
  ["workspace-validation", "scripts/aws/stage-b-terraform-workspace.mjs"],
  ["canonical-backend-recovery", "scripts/aws/recover-stage-b-backend-task-definition.mjs"],
  ["backend-health-recovery", "scripts/aws/recover-production-backend-health.mjs"],
  ["existing-revision-forward-recovery", "scripts/aws/forward-recover-stage-b-existing-revision.mjs"],
  ["stage-b-state-pull", "scripts/aws/run-production-green-stage-b-preflight.mjs"],
  ["stage-a-state-read", "scripts/aws/run-production-green-stage-b-preflight.mjs"],
  ["stage-a-handoff-generation", "scripts/aws/generate-production-green-stage-a-prerequisites.mjs"],
  ["root-drop-evidence-signing", "scripts/aws/produce-production-root-drop-evidence.mjs"],
  ["tfvars-generation", "scripts/aws/generate-production-green-stage-b-tfvars.mjs"],
  ["refresh-only", "scripts/refresh-production-green-stage-b.mjs"],
  ["saved-plan-generation", "scripts/plan-production-green-stage-b.mjs"],
  ["plan-json-canonicalization", "scripts/plan-production-green-stage-b.mjs"],
  ["reference-audit", "scripts/aws/generate-production-green-stage-b-reference-audit.mjs"],
  ["plan-bound-permission-report", "scripts/aws/validate-production-green-stage-b-permissions.mjs"],
  ["production-closure", "scripts/aws/validate-stage-b-deployment-closure.mjs"],
  ["validator", "scripts/plan-production-green-stage-b.mjs"],
  ["wrapper-verify-only", "scripts/apply-production-green-stage-b.mjs"],
  ["wrapper-apply", "scripts/apply-production-green-stage-b.mjs"],
  ["post-apply-verification", "scripts/aws/verify-production-green-stage-b-ecs-observations.mjs"],
  ["runtime-activation-boundary", "scripts/aws/create-production-green-stage-b-approval.mjs"],
]);

const FIXED = Object.freeze([
  ["admin-image-repositories", "schema-v3-image-evidence", "ADMINISTRATOR", "ecr:DescribeRepositories", "ADMIN_DIRECT_READ", "scripts/aws/production-green-stage-b-image-evidence.mjs"],
  ["admin-image-records", "schema-v3-image-evidence", "ADMINISTRATOR", "ecr:DescribeImages", "ADMIN_DIRECT_READ", "scripts/aws/production-green-stage-b-image-evidence.mjs"],
  ["admin-role", "administrator-iam-simulation", "ADMINISTRATOR", "iam:GetRole", "ADMIN_DIRECT_READ", "scripts/aws/validate-production-green-stage-b-permissions.mjs"],
  ["admin-role-inline-list", "administrator-iam-simulation", "ADMINISTRATOR", "iam:ListRolePolicies", "ADMIN_DIRECT_READ", "scripts/aws/validate-production-green-stage-b-permissions.mjs"],
  ["admin-role-inline-read", "administrator-iam-simulation", "ADMINISTRATOR", "iam:GetRolePolicy", "ADMIN_DIRECT_READ", "scripts/aws/validate-production-green-stage-b-permissions.mjs"],
  ["admin-role-attachments", "administrator-iam-simulation", "ADMINISTRATOR", "iam:ListAttachedRolePolicies", "ADMIN_DIRECT_READ", "scripts/aws/validate-production-green-stage-b-permissions.mjs"],
  ["admin-managed-policy", "administrator-iam-simulation", "ADMINISTRATOR", "iam:GetPolicy", "ADMIN_DIRECT_READ", "scripts/aws/validate-production-green-stage-b-permissions.mjs"],
  ["admin-managed-policy-version", "administrator-iam-simulation", "ADMINISTRATOR", "iam:GetPolicyVersion", "ADMIN_DIRECT_READ", "scripts/aws/validate-production-green-stage-b-permissions.mjs"],
  ["admin-simulate-release", "administrator-iam-simulation", "ADMINISTRATOR", "iam:SimulatePrincipalPolicy", "ADMIN_SIMULATION", "scripts/aws/validate-production-green-stage-b-permissions.mjs"],
  ["admin-cloudtrail-denials", "administrator-iam-simulation", "ADMINISTRATOR", "cloudtrail:LookupEvents", "ADMIN_DIRECT_READ", "scripts/aws/validate-production-green-stage-b-permissions.mjs"],
  ["admin-sign-evidence", "administrator-kms-signing", "ADMINISTRATOR", "kms:Sign", "ADMIN_SIGN", "scripts/aws/validate-production-green-stage-b-permissions.mjs"],
  ["bootstrap-identify", "bootstrap-mfa-session", "BOOTSTRAP_OPERATOR", "sts:GetCallerIdentity", "BOOTSTRAP_SESSION", "documents/security/rls-program/PRODUCTION_GREEN_STAGE_B_INFRASTRUCTURE_RUNBOOK.md"],
  ["bootstrap-mfa", "bootstrap-mfa-session", "BOOTSTRAP_OPERATOR", "sts:GetSessionToken", "BOOTSTRAP_SESSION", "documents/security/rls-program/PRODUCTION_GREEN_STAGE_B_INFRASTRUCTURE_RUNBOOK.md"],
  ["bootstrap-assume-release", "release-role-assumption", "BOOTSTRAP_OPERATOR", "sts:AssumeRole", "BOOTSTRAP_SESSION", "documents/security/rls-program/PRODUCTION_GREEN_STAGE_B_INFRASTRUCTURE_RUNBOOK.md"],
  ["publisher-oidc", "image-workflow-dispatch", "GITHUB_IMAGE_PUBLISHER", "sts:AssumeRoleWithWebIdentity", "GITHUB_IMAGE_MUTATION", ".github/workflows/production-green-stage-b-image-build.yml"],
  ["release-verify-signature", "release-direct-read-preflight", "RELEASE_DEPLOYER", "kms:Verify", "RELEASE_DIRECT_READ", "scripts/aws/run-production-green-stage-b-preflight.mjs"],
  ["release-identify", "release-direct-read-preflight", "RELEASE_DEPLOYER", "sts:GetCallerIdentity", "RELEASE_DIRECT_READ", "scripts/aws/run-production-green-stage-b-preflight.mjs"],
]);

const ROOT_DROP_SIGNING = Object.freeze({
  id: "root-drop-sign-evidence", phase: "root-drop-evidence-signing", identity: "ROOT_OPERATOR", executor: "aws-cli",
  sourceFile: "scripts/aws/produce-production-root-drop-evidence.mjs", sourceFunction: "produce-production-root-drop-evidence",
  action: "kms:Sign", resources: [ROOT_DROP_SIGNING_KEY_ARN], context: { account: STAGE_B.account, region: STAGE_B.region },
  classification: "ROOT_DROP_SIGN", probe: "structural", policy: { sourceFile: "scripts/aws/produce-production-root-drop-evidence.mjs", sid: "root-drop-signing-boundary", livePolicyArn: null, expectedVersion: "source-bound", expectedPolicySha256: null }, required: true, mutation: true,
});

const RECOVERY_CAPABILITIES = Object.freeze([
  ["recovery-list-backend-revisions", "ecs:ListTaskDefinitions", ["*"]],
  ["recovery-describe-backend-revision", "ecs:DescribeTaskDefinition", ["*"]],
  ["recovery-register-backend-revision", "ecs:RegisterTaskDefinition", ["arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:*"]],
  ["recovery-tag-backend-revision", "ecs:TagResource", ["arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:*"]],
  ["recovery-pass-backend-task-role", "iam:PassRole", ["arn:aws:iam::368992683803:role/mscqr-production-rls-green-backend-task"]],
  ["recovery-pass-backend-execution-role", "iam:PassRole", ["arn:aws:iam::368992683803:role/mscqr-production-rls-green-backend-execution"]],
  ["recovery-read-state", "s3:GetObject", ["arn:aws:s3:::mscqr-production-terraform-state-368992683803-eu-west-2/env:/production/mscqr/production/rls-green/stage-b/terraform.tfstate"]],
  ["recovery-write-state", "s3:PutObject", ["arn:aws:s3:::mscqr-production-terraform-state-368992683803-eu-west-2/env:/production/mscqr/production/rls-green/stage-b/terraform.tfstate"]],
  ["recovery-lock-state", "s3:PutObject", ["arn:aws:s3:::mscqr-production-terraform-state-368992683803-eu-west-2/env:/production/mscqr/production/rls-green/stage-b/terraform.tfstate.tflock"]],
  ["recovery-unlock-state", "s3:DeleteObject", ["arn:aws:s3:::mscqr-production-terraform-state-368992683803-eu-west-2/env:/production/mscqr/production/rls-green/stage-b/terraform.tfstate.tflock"]],
]);

const FORWARD_RECOVERY_CAPABILITIES = Object.freeze([
  ["forward-recovery-list-backend-revisions", "ecs:ListTaskDefinitions", ["*"]],
  ["forward-recovery-describe-backend-revision", "ecs:DescribeTaskDefinition", ["arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:*"]],
  ["forward-recovery-verify-image-evidence", "kms:Verify", [IMAGE_EVIDENCE_SIGNING_KEY_ARN]],
  ["forward-recovery-read-backend-bucket-location", "s3:GetBucketLocation", [STAGE_B_TERRAFORM_BACKEND.bucketArn]],
  ["forward-recovery-read-state", "s3:GetObject", [STAGE_B_TERRAFORM_BACKEND.stateArn]],
  ["forward-recovery-write-state", "s3:PutObject", [STAGE_B_TERRAFORM_BACKEND.stateArn]],
  ["forward-recovery-lock-state", "s3:GetObject", [STAGE_B_TERRAFORM_BACKEND.lockArn]],
  ["forward-recovery-acquire-state-lock", "s3:PutObject", [STAGE_B_TERRAFORM_BACKEND.lockArn]],
  ["forward-recovery-release-state-lock", "s3:DeleteObject", [STAGE_B_TERRAFORM_BACKEND.lockArn]],
]);

const PHASE_CAPABILITY_REQUIREMENTS = Object.freeze({
  "canonical-backend-recovery": RECOVERY_CAPABILITIES.map(([id]) => id),
  "backend-health-recovery": [
    "manifest-backend-health-recovery-describe-images",
    "manifest-backend-health-recovery-describe-repositories",
    "manifest-backend-health-recovery-register-legacy-task-definition",
    "manifest-backend-health-recovery-update-service",
  ],
  "existing-revision-forward-recovery": FORWARD_RECOVERY_CAPABILITIES.map(([id]) => id),
});

const classification = (entry, forbidden) => forbidden ? "FORBIDDEN"
  : entry.phase === "apply" ? "TERRAFORM_APPLY_MUTATION"
    : entry.phase === "recovery" ? "RELEASE_DIRECT_MUTATION"
    : entry.phase === "refresh" ? "TERRAFORM_REFRESH_READ"
      : entry.phase === "reference-audit" ? "POST_APPLY_READ" : "RELEASE_DIRECT_READ";

function sourcePolicies() {
  return RELEASE_POLICY_SOURCES.map((policy) => ({ ...policy, document: readJson(policy.sourcePath), sourceSha256: sha256(Buffer.from(canonicalizeJson(readJson(policy.sourcePath)))) }));
}

function authority(entry, forbidden, policies) {
  for (const policy of policies) for (const statement of policy.document.Statement || []) {
    const actions = asArray(statement.Action);
    const resources = asArray(statement.Resource);
    if (statement.Effect === (forbidden ? "Deny" : "Allow") && actions.includes(entry.action)
      && asArray(entry.resources).every((resource) => resources.some((allowed) => allowed === "*" || allowed === resource || (allowed.endsWith("*") && resource.startsWith(allowed.slice(0, -1)))))) {
      return { sourceFile: policy.sourcePath, sid: statement.Sid, livePolicyArn: policy.arn, expectedVersion: "signed-administrator-evidence", expectedPolicySha256: policy.sourceSha256 };
    }
  }
  if (forbidden) return { sourceFile: null, sid: "implicit-deny", livePolicyArn: null, expectedVersion: null, expectedPolicySha256: null };
  throw new Error(`No reviewed source policy authorizes ${entry.id}.`);
}

function operatorAuthority(entry, forbidden) {
  if (forbidden) return { sourceFile: null, sid: "implicit-deny", livePolicyArn: null, expectedVersion: null, expectedPolicySha256: null };
  const statement = operatorPolicy.Statement.find((candidate) => {
    const actions = asArray(candidate.Action); const resources = asArray(candidate.Resource);
    const conditions = candidate.Condition?.StringEquals || {};
    return candidate.Effect === "Allow" && actions.includes(entry.action)
      && entry.resources.every((resource) => resources.some((allowed) => allowed === "*" || allowed === resource || (allowed.endsWith("*") && resource.startsWith(allowed.slice(0, -1)))))
      && (entry.context || []).filter(({ type, values }) => type === "string" && values.length === 1).every(({ key, values }) => conditions[key] === values[0]);
  });
  if (!statement) throw new Error(`No reviewed ECS Exec operator policy authorizes ${entry.id}.`);
  return { sourceFile: ECS_EXEC_OPERATOR_POLICY_PATH, sid: statement.Sid, livePolicyArn: ECS_EXEC_OPERATOR_POLICY_ARN, expectedVersion: "administrator-provisioned", expectedPolicySha256: sha256(Buffer.from(canonicalizeJson(operatorPolicy))) };
}

function checkerAuthority(entry) {
  const source = fs.readFileSync(path.join(root, checkerPolicyPath), "utf8");
  if (!source.includes('Sid = "PublishExactStageBApproval"')
      || !source.includes('Action = "secretsmanager:PutSecretValue"')
      || !source.includes("aws_secretsmanager_secret.approval.arn")) {
    throw new Error(`No reviewed checker policy authorizes ${entry.id}.`);
  }
  return { sourceFile: checkerPolicyPath, sid: "PublishExactStageBApproval", livePolicyArn: null, expectedVersion: "protected-main-source", expectedPolicySha256: sha256(Buffer.from(source)) };
}

function terraformRuntimeActions() {
  const text = fs.readFileSync(path.join(root, terraformPath), "utf8");
  return [...text.matchAll(/Action\s*=\s*(?:\[([^\]]+)\]|"([^"]+)")/g)]
    .flatMap((match) => match[2] ? [match[2]] : [...match[1].matchAll(/"([^"]+)"/g)].map((item) => item[1]))
    .filter((action) => /^[a-z0-9-]+:[A-Z]/.test(action))
    .filter((action, index, actions) => actions.indexOf(action) === index)
    .sort();
}

function discoverAwsCliActions() {
  const serviceNames = "sts|iam|kms|ecr|ec2|ecs|rds|lambda|logs|cloudtrail|secretsmanager|dynamodb|s3api";
  const pattern = new RegExp(`\\[\\s*["'](${serviceNames})["']\\s*,\\s*["']([a-z0-9-]+)["']`, "g");
  const calls = [];
  for (const sourceFile of awsCliSourceFiles) {
    const source = fs.readFileSync(path.join(root, sourceFile), "utf8");
    for (const match of source.matchAll(pattern)) {
      const service = match[1] === "s3api" ? "s3" : match[1];
      const operation = match[2].split("-").map((part) => part[0].toUpperCase() + part.slice(1)).join("").replaceAll("Db", "DB").replaceAll("Vpc", "VPC").replaceAll("Url", "URL");
      const action = service === "ecs" && operation === "Wait" ? "ecs:DescribeServices"
        : `${service}:${service === "lambda" && operation === "Invoke" ? "InvokeFunction" : operation}`;
      calls.push(sourceFile === "scripts/aws/produce-production-root-drop-evidence.mjs" && action === "kms:Sign"
        ? { sourceFile, sourceFunction: "produce-production-root-drop-evidence", phase: "root-drop-evidence-signing", identity: "ROOT_OPERATOR", action, resources: [ROOT_DROP_SIGNING_KEY_ARN], capabilityId: "root-drop-sign-evidence" }
        : { sourceFile, action });
    }
  }
  return calls.filter((call, index) => calls.findIndex((candidate) => candidate.sourceFile === call.sourceFile && candidate.action === call.action) === index)
    .sort((left, right) => `${left.sourceFile}:${left.action}`.localeCompare(`${right.sourceFile}:${right.action}`));
}

export function buildStageBDeploymentCapabilityGraph() {
  const manifest = readJson(manifestPath); const policies = sourcePolicies(); const probesByAction = new Map();
  for (const probe of RELEASE_READ_PROBES) probesByAction.set(probe.action, [...(probesByAction.get(probe.action) || []), probe.id]);
  const manifestCapabilities = [[manifest.required, false], [manifest.forbidden, true]].flatMap(([entries, forbidden]) => entries.map((entry) => ({
    id: `manifest-${entry.id}`, phase: entry.phase === "apply" ? "wrapper-apply" : ["recovery", "recovery-read"].includes(entry.phase) ? "backend-health-recovery" : entry.phase === "reference-audit" ? "reference-audit" : entry.phase === "preflight" ? "release-direct-read-preflight" : "refresh-only",
    identity: forbidden ? "ADMINISTRATOR" : "RELEASE_DEPLOYER", executor: forbidden ? "iam-simulator" : ["recovery", "recovery-read"].includes(entry.phase) ? "aws-cli" : "terraform-or-aws-cli", sourceFile: manifestPath,
    sourceFunction: entry.id, action: entry.action, resources: entry.resources, context: entry.context || [], classification: classification(entry, forbidden),
    probe: forbidden ? "administrator-simulation" : probesByAction.has(entry.action) ? "direct" : entry.phase === "apply" ? "plan-derived-simulation" : "administrator-simulation",
    probeIds: probesByAction.get(entry.action) || [], policy: authority(entry, forbidden, policies), required: true, mutation: ["apply", "recovery"].includes(entry.phase) || forbidden,
  })));
  const checkerCapabilities = manifest.checkerRequired.map((entry) => ({
    id: `checker-${entry.id}`, phase: "approval-publication", identity: "INDEPENDENT_CHECKER", executor: "aws-cli", sourceFile: manifestPath,
    sourceFunction: entry.id, action: entry.action, resources: entry.resources, context: entry.context || [], classification: "CHECKER_APPROVAL_PUBLICATION",
    probe: "structural", probeIds: [], policy: checkerAuthority(entry), required: true, mutation: true,
  }));
  const operatorCapabilities = [[ECS_EXEC_OPERATOR_REQUIRED, false], [ECS_EXEC_OPERATOR_FORBIDDEN, true]].flatMap(([entries, forbidden]) => entries.map((entry) => ({
    id: `operator-${entry.id}`, phase: "runtime-verification", identity: "ECS_EXEC_VERIFIER_OPERATOR", executor: "ecs-exec-verifier",
    sourceFile: ECS_EXEC_OPERATOR_POLICY_PATH, sourceFunction: entry.id, action: entry.action, resources: entry.resources, context: entry.context || [], classification: forbidden ? "FORBIDDEN" : entry.action === "ecs:ExecuteCommand" ? "RUNTIME_VERIFICATION_MUTATION" : "RUNTIME_VERIFICATION_READ",
    probe: "administrator-simulation", probeIds: [], policy: operatorAuthority(entry, forbidden), required: true, mutation: forbidden || entry.action === "ecs:ExecuteCommand",
  })));
  const publisher = readJson(publisherPolicyPath).Statement.flatMap((statement) => asArray(statement.Action).map((action) => ({
    id: `publisher-${statement.Sid}-${action.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`, phase: "image-workflow-dispatch", identity: "GITHUB_IMAGE_PUBLISHER", executor: "github-actions",
    sourceFile: publisherPolicyPath, sourceFunction: statement.Sid, action, resources: asArray(statement.Resource), context: statement.Condition || {}, classification: statement.Effect === "Deny" ? "FORBIDDEN" : "GITHUB_IMAGE_MUTATION",
    probe: "structural", policy: { sourceFile: publisherPolicyPath, sid: statement.Sid, livePolicyArn: "github-oidc-role-policy", expectedVersion: "protected-main-source", expectedPolicySha256: sha256(Buffer.from(canonicalizeJson(readJson(publisherPolicyPath)))) }, required: true, mutation: statement.Effect !== "Deny",
  })));
  const fixed = FIXED.map(([id, phase, identity, action, actionClass, sourceFile]) => ({ id, phase, identity, executor: sourceFile.endsWith(".yml") ? "github-actions" : "aws-cli", sourceFile, sourceFunction: id, action, resources: ["reviewed-exact-resource"], context: { account: "368992683803", region: "eu-west-2" }, classification: actionClass, probe: actionClass === "RELEASE_DIRECT_READ" ? "direct" : actionClass === "ADMIN_SIMULATION" ? "administrator-simulation" : "structural", policy: { sourceFile: identity === "RELEASE_DEPLOYER" ? manifestPath : sourceFile, sid: "identity-boundary", livePolicyArn: identity === "RELEASE_DEPLOYER" ? "signed-administrator-evidence" : null, expectedVersion: "source-bound", expectedPolicySha256: null }, required: true, mutation: ["ADMIN_SIGN", "GITHUB_IMAGE_MUTATION"].includes(actionClass) }));
  const recovery = RECOVERY_CAPABILITIES.map(([id, action, resources]) => {
    const entry = { id, action, resources };
    return { id, phase: "canonical-backend-recovery", identity: "RELEASE_DEPLOYER", executor: "aws-cli-or-terraform", sourceFile: "scripts/aws/recover-stage-b-backend-task-definition.mjs", sourceFunction: id, action, resources, context: { account: "368992683803", region: "eu-west-2" }, classification: /^(?:ecs:RegisterTaskDefinition|ecs:TagResource|s3:PutObject|s3:DeleteObject)$/.test(action) ? "CANONICAL_RECOVERY_MUTATION" : "CANONICAL_RECOVERY_READ", probe: "administrator-simulation", probeIds: [], policy: authority(entry, false, policies), required: true, mutation: /^(?:ecs:RegisterTaskDefinition|ecs:TagResource|s3:PutObject|s3:DeleteObject)$/.test(action) };
  });
  const forwardRecovery = FORWARD_RECOVERY_CAPABILITIES.map(([id, action, resources]) => {
    const entry = { id, action, resources };
    return { id, phase: "existing-revision-forward-recovery", identity: "RELEASE_DEPLOYER", executor: "terraform", sourceFile: "scripts/aws/forward-recover-stage-b-existing-revision.mjs", sourceFunction: id, action, resources, context: { account: "368992683803", region: "eu-west-2" }, classification: /^(?:s3:PutObject|s3:DeleteObject)$/.test(action) ? "FORWARD_RECOVERY_IMPORT_MUTATION" : "FORWARD_RECOVERY_READ", probe: "administrator-simulation", probeIds: [], policy: authority(entry, false, policies), required: true, mutation: /^(?:s3:PutObject|s3:DeleteObject)$/.test(action) };
  });
  const runtime = terraformRuntimeActions().map((action) => ({ id: `runtime-${action.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`, phase: "runtime-activation-boundary", identity: "SERVICE_RUNTIME", executor: "lambda-or-ecs-role", sourceFile: terraformPath, sourceFunction: "generated runtime IAM policy", action, resources: ["terraform-derived-runtime-resource"], context: {}, classification: "SERVICE_RUNTIME_ACTION", probe: "structural", policy: { sourceFile: terraformPath, sid: "terraform-generated", livePolicyArn: "created-or-updated-by-stage-b", expectedVersion: "saved-plan", expectedPolicySha256: null }, required: false, mutation: !/^(?:ecr:|kms:Verify|secretsmanager:Get|s3:Get)/.test(action) }));
  const capabilities = [...fixed, ROOT_DROP_SIGNING, ...recovery, ...forwardRecovery, ...publisher, ...manifestCapabilities, ...checkerCapabilities, ...operatorCapabilities, ...runtime].sort((a, b) => a.id.localeCompare(b.id));
  return {
    schemaVersion: 1, deployment: "production-green-stage-b", account: "368992683803", region: "eu-west-2",
    phases: PHASES.map(([id, sourceFile], index) => ({ order: index + 1, id, sourceFile })),
    identities: ["GITHUB_IMAGE_PUBLISHER", "ADMINISTRATOR", "ROOT_OPERATOR", "BOOTSTRAP_OPERATOR", "RELEASE_DEPLOYER", "INDEPENDENT_CHECKER", "ECS_EXEC_VERIFIER_OPERATOR", "SERVICE_RUNTIME"], capabilities,
    directProbes: RELEASE_READ_PROBES.map(({ id, action }) => ({ id, action })), sourceScan: discoverAwsCliActions(),
    artifactContracts: ["protected-checkout", "image-impact", "schema-v3-image-evidence", "stage-a-handoff", "tfvars-binding-report", "refresh-only", "saved-plan", "canonical-plan-json", "reference-audit", "plan-capability-manifest", "signed-permission-report"],
    stateContracts: ["stage-a-exact-object-lineage-minimum-serial-sha", "stage-b-direct-key-lineage-minimum-serial-sha", "stage-b-serial-stable-plan-to-apply"],
    freshnessContracts: [{ artifact: "image-evidence", maxAgeSeconds: 86400 }, { artifact: "reference-audit", maxAgeSeconds: STAGE_B_DEPLOYMENT_EVIDENCE_TTL_SECONDS }, { artifact: "permission-report", maxAgeSeconds: STAGE_B_DEPLOYMENT_EVIDENCE_TTL_SECONDS }],
    configurationContracts: ["head-equals-origin-main", "clean-non-shallow-checkout", "direct-production-s3-key", "strict-backend-metadata", "tf-workspace-default", "no-workspace-select-or-migration", "checker-user-mfa-live-trust-to-independent-role-chain", "structural-normal-resource-universe-append-only-retained-history", "no-service-database-alb-dns-traffic-or-secret-value-change"],
  };
}

export function assertStageBDeploymentCapabilityGraph(graph = readJson(CAPABILITY_GRAPH_PATH)) {
  const expected = buildStageBDeploymentCapabilityGraph();
  if (canonicalizeJson(graph) !== canonicalizeJson(expected)) throw new Error("Stage B deployment capability graph is stale or incomplete.");
  if (graph.phases.length !== 35 || new Set(graph.phases.map(({ id }) => id)).size !== 35) throw new Error("Stage B capability graph phase coverage is incomplete.");
  if (new Set(graph.capabilities.map(({ id }) => id)).size !== graph.capabilities.length) throw new Error("Stage B capability IDs are not unique.");
  if (graph.capabilities.some(({ identity, action }) => !identity || !action)) throw new Error("Stage B capability identity is ambiguous.");
  for (const [phase, ids] of Object.entries(PHASE_CAPABILITY_REQUIREMENTS)) {
    const phaseCapabilities = graph.capabilities.filter((capability) => capability.phase === phase);
    if (ids.some((id) => !phaseCapabilities.some((capability) => capability.id === id))) throw new Error(`Stage B phase capability coverage is incomplete: ${phase}.`);
  }
  const forwardCapabilities = graph.capabilities.filter(({ phase }) => phase === "existing-revision-forward-recovery");
  if (forwardCapabilities.some(({ action, identity, sourceFile }) => identity !== "RELEASE_DEPLOYER" || sourceFile !== "scripts/aws/forward-recover-stage-b-existing-revision.mjs" || ["ecs:RegisterTaskDefinition", "ecs:DeregisterTaskDefinition", "ecs:UpdateService", "iam:PutRolePolicy", "iam:AttachRolePolicy"].includes(action))) throw new Error("Forward recovery capability boundary is broader than zero-registration Terraform import.");
  if (graph.capabilities.some(({ identity, action }) => identity === "RELEASE_DEPLOYER" && action === "iam:SimulatePrincipalPolicy")) throw new Error("Release-deployer cannot own IAM simulation.");
  const checkerPublication = graph.capabilities.filter(({ identity, action, resources }) => identity === "INDEPENDENT_CHECKER" && action === "secretsmanager:PutSecretValue" && resources.includes(STAGE_B.approvalSecretArn));
  if (checkerPublication.length !== 1) throw new Error("Exact checker approval publication capability is absent or duplicated.");
  if (graph.capabilities.some(({ identity, action, resources }) => identity === "RELEASE_DEPLOYER" && ["secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue"].includes(action) && resources.includes(STAGE_B.approvalSecretArn))) throw new Error("Release-deployer approval secret authority is present.");
  if (graph.capabilities.some(({ identity, action, resources }) => identity === "INDEPENDENT_CHECKER" && action === "secretsmanager:GetSecretValue" && resources.includes(STAGE_B.approvalSecretArn))) throw new Error("Checker approval secret read authority is present.");
  if (graph.capabilities.some(({ identity, action }) => identity === "RELEASE_DEPLOYER" && action === "ecs:ExecuteCommand" && !graph.capabilities.some(({ id }) => id === "manifest-release-deployer-ecs-exec"))) throw new Error("Release-deployer ECS Exec boundary is not represented.");
  if (!graph.capabilities.some(({ identity, action, resources }) => identity === "ECS_EXEC_VERIFIER_OPERATOR" && action === "ecs:ExecuteCommand" && resources.includes(`arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/*`))) throw new Error("Dedicated ECS Exec operator capability is absent.");
  const rootDropSigning = graph.capabilities.find(({ id }) => id === "root-drop-sign-evidence");
  if (!rootDropSigning || rootDropSigning.phase !== "root-drop-evidence-signing" || rootDropSigning.identity !== "ROOT_OPERATOR" || rootDropSigning.sourceFile !== "scripts/aws/produce-production-root-drop-evidence.mjs" || rootDropSigning.action !== "kms:Sign" || JSON.stringify(rootDropSigning.resources) !== JSON.stringify([ROOT_DROP_SIGNING_KEY_ARN])) throw new Error("Root-drop signing capability is not exact.");
  const graphActions = new Set(graph.capabilities.map(({ action }) => action));
  for (const probe of RELEASE_READ_PROBES) if (!graphActions.has(probe.action)) throw new Error(`Release probe is absent from capability graph: ${probe.id}.`);
  assertStageBAwsCallCoverage(graph, graph.sourceScan);
  return { phases: graph.phases.length, capabilities: graph.capabilities.length, uniqueActions: graphActions.size, unmappedCalls: 0, unclassifiedCapabilities: 0, identityBoundaryViolations: 0, sourcePolicyMismatches: 0, manifestMismatches: 0, configurationContradictions: 0 };
}

export function assertStageBAwsCallCoverage(graph, calls) {
  const graphActions = new Set(graph.capabilities.map(({ action }) => action));
  for (const call of calls) {
    if (call.capabilityId) {
      const capability = graph.capabilities.find(({ id }) => id === call.capabilityId);
      if (!capability || capability.sourceFile !== call.sourceFile || capability.sourceFunction !== call.sourceFunction || capability.phase !== call.phase || capability.identity !== call.identity || capability.action !== call.action || JSON.stringify(capability.resources) !== JSON.stringify(call.resources)) throw new Error(`Production AWS call has no exact capability coverage: ${call.sourceFile} ${call.action}.`);
    } else if (call.sourceFile === "scripts/aws/produce-production-root-drop-evidence.mjs" && call.action === "kms:Sign") throw new Error(`Production AWS root-drop signing call lacks exact capability coverage: ${call.sourceFile} ${call.action}.`);
    else if (!graphActions.has(call.action)) throw new Error(`Production AWS CLI call is absent from capability graph: ${call.sourceFile} ${call.action}.`);
  }
  return true;
}

const markdown = (graph) => `# Stage B production deployment capability graph\n\nGenerated from the permission manifest, reviewed source policies, release probes, canonical recovery, zero-registration forward recovery, publisher policy, Terraform runtime policy actions, and the production path. Do not edit generated capability rows manually.\n\n- Phases: ${graph.phases.length}\n- Capability nodes: ${graph.capabilities.length}\n- Unique AWS actions: ${new Set(graph.capabilities.map(({ action }) => action)).size}\n- Identities: ${graph.identities.join(", ")}\n\n| Order | Phase | Source |\n|---:|---|---|\n${graph.phases.map(({ order, id, sourceFile }) => `| ${order} | ${id} | \`${sourceFile}\` |`).join("\n")}\n`;

export function writeStageBDeploymentCapabilityGraph() {
  const graph = buildStageBDeploymentCapabilityGraph();
  fs.writeFileSync(path.join(root, CAPABILITY_GRAPH_PATH), `${JSON.stringify(graph, null, 2)}\n`);
  fs.writeFileSync(path.join(root, CAPABILITY_GRAPH_MARKDOWN_PATH), markdown(graph));
  return assertStageBDeploymentCapabilityGraph(graph);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const write = process.argv.includes("--write");
  const result = write ? writeStageBDeploymentCapabilityGraph() : assertStageBDeploymentCapabilityGraph();
  process.stdout.write(`${JSON.stringify({ status: "valid", ...result })}\n`);
}

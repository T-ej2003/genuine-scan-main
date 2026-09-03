#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { RELEASE_READ_PROBES } from "./production-green-stage-b-identity-capabilities.mjs";
import { PRODUCTION_ACTIVATION_LIFECYCLE, STAGE_B } from "./production-green-stage-b-contract.mjs";
import { RELEASE_POLICY_SOURCES, canonicalizeJson } from "./validate-production-green-stage-b-permissions.mjs";
import { STAGE_B_DEPLOYMENT_EVIDENCE_TTL_SECONDS } from "./stage-b-evidence-freshness.mjs";
import { ECS_EXEC_OPERATOR_FORBIDDEN, ECS_EXEC_OPERATOR_POLICY_ARN, ECS_EXEC_OPERATOR_POLICY_PATH, ECS_EXEC_OPERATOR_REQUIRED, ECS_EXEC_OPERATOR_ROLE_ARN } from "./production-ecs-exec-operator-contract.mjs";
import { STAGE_B_TERRAFORM_BACKEND } from "./stage-b-terraform-backend-contract.mjs";
import { STAGE_A_TERRAFORM_BACKEND, STAGE_A_TERRAFORM_LOCK_ARN } from "./production-stage-a-root-drop-orphan-recovery.mjs";
import { IMAGE_EVIDENCE_SIGNING_KEY_ARN } from "./production-green-stage-b-image-evidence.mjs";
import { ROOT_DROP_SIGNING_KEY_ARN } from "./production-root-drop-evidence.mjs";
import { ROOT_ATTESTATION_KEY_ALIAS_ARN } from "./production-root-attestation-key.mjs";
import { PRODUCTION_RELEASE_ROLE_ARN, assertProductionReleaseOidcSourceContract } from "./production-release-oidc-contract.mjs";
import { NORMAL_ACTIVATION } from "./production-normal-backend-activation-policy.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
export const CAPABILITY_GRAPH_PATH = "documents/ops/iam/MSCQRProductionGreenStageBDeploymentCapabilities-v1.json";
export const CAPABILITY_GRAPH_SCHEMA_PATH = "documents/ops/iam/MSCQRProductionGreenStageBDeploymentCapabilities-v1.schema.json";
export const CAPABILITY_GRAPH_MARKDOWN_PATH = "documents/ops/iam/MSCQRProductionGreenStageBDeploymentCapabilities-v1.md";
const manifestPath = "documents/ops/iam/MSCQRProductionGreenStageBPermissionManifest-v1.json";
const publisherPolicyPath = "infra/aws/terraform/production-green-stage-b-image-publisher/permissions-policy.json";
const terraformPath = "infra/aws/terraform/production-green-stage-b/main.tf";
const checkerPolicyPath = "infra/aws/terraform/production-green-stage-a/main.tf";
const stageAReleaseS3ContractPath = "documents/ops/iam/MSCQRProductionGreenStageAReleaseS3Contract-v1.json";
const stageATerraformStateArn = `${STAGE_B_TERRAFORM_BACKEND.bucketArn}/${STAGE_A_TERRAFORM_BACKEND.key}`;
const rootAttestationPolicyPath = "infra/aws/terraform/production-green-stage-b-publisher-bootstrap/main.tf";
const awsCliSourceFiles = [
  "scripts/plan-production-green-stage-b.mjs", "scripts/apply-production-green-stage-b.mjs",
  "scripts/aws/create-production-green-stage-b-approval.mjs", "scripts/aws/generate-production-green-stage-a-prerequisites.mjs",
  "scripts/aws/production-green-stage-b-ecs-observations.mjs", "scripts/aws/production-green-stage-b-image-evidence.mjs",
  "scripts/aws/production-green-stage-b-identity-capabilities.mjs", "scripts/aws/run-production-green-stage-b-preflight.mjs",
  "scripts/aws/validate-production-green-stage-b-permissions.mjs", "scripts/aws/production-checker-chain-contract.mjs",
  "scripts/aws/production-release-preflight-checker-attestation.mjs",
  "scripts/aws/production-root-attestation-key.mjs", "scripts/aws/production-root-attestation-signer.mjs",
  "scripts/aws/publish-production-green-stage-b-approval.mjs", "scripts/aws/check-production-green-stage-b-approval-publication.mjs",
  "scripts/aws/recover-stage-b-backend-task-definition.mjs", "scripts/aws/forward-recover-stage-b-existing-revision.mjs",
  "scripts/aws/recover-production-backend-health.mjs",
  "scripts/aws/prepare-production-ecs-runtime-consumability.mjs",
  "scripts/aws/production-ecs-runtime-consumability.mjs",
  "scripts/aws/converge-production-ecs-runtime-policy.mjs",
  "scripts/aws/production-ecs-rollback-viability.mjs",
  "scripts/aws/production-ecs-task-census.mjs",
  "scripts/aws/production-normal-backend-activation.mjs",
  "scripts/aws/deploy-ecs-service.sh",
  "scripts/aws/production-release-oidc-contract.mjs",
  "scripts/aws/production-root-drop-evidence.mjs", "scripts/aws/produce-production-root-drop-evidence.mjs",
  "scripts/aws/production-stage-a-production-artifacts-journal.mjs",
  "scripts/aws/run-production-stage-a-production-artifacts-recovery.mjs",
  "scripts/aws/run-production-stage-a-production-artifacts-reconciliation.mjs",
  "scripts/aws/authorize-production-stage-a-production-artifacts-reconciliation.mjs",
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
  ["schema-v4-image-evidence", "scripts/aws/production-green-stage-b-image-evidence.mjs"],
  ["administrator-release-oidc-trust-convergence", "scripts/aws/converge-production-release-oidc-trust.mjs"],
  ["administrator-normal-backend-activation-convergence", "scripts/aws/production-normal-backend-activation.mjs"],
  ["administrator-iam-simulation", "scripts/aws/validate-production-green-stage-b-permissions.mjs"],
  ["administrator-kms-signing", "scripts/aws/validate-production-green-stage-b-permissions.mjs"],
  ["bootstrap-mfa-session", "documents/security/rls-program/PRODUCTION_GREEN_STAGE_B_INFRASTRUCTURE_RUNBOOK.md"],
  ["release-role-assumption", "documents/security/rls-program/PRODUCTION_GREEN_STAGE_B_INFRASTRUCTURE_RUNBOOK.md"],
  ["release-direct-read-preflight", "scripts/aws/run-production-green-stage-b-preflight.mjs"],
  ["release-preflight-checker-trust-attestation", "scripts/aws/production-release-preflight-checker-attestation.mjs"],
  ["backend-config-generation", "scripts/aws/generate-production-green-stage-b-backend-config.mjs"],
  ["terraform-initialization", "scripts/aws/run-production-green-stage-b-preflight.mjs"],
  ["backend-metadata-validation", "scripts/aws/stage-b-terraform-backend-contract.mjs"],
  ["workspace-validation", "scripts/aws/stage-b-terraform-workspace.mjs"],
  ["canonical-backend-recovery", "scripts/aws/recover-stage-b-backend-task-definition.mjs"],
  ["backend-health-recovery", "scripts/aws/recover-production-backend-health.mjs"],
  ["runtime-consumability-evidence", "scripts/aws/prepare-production-ecs-runtime-consumability.mjs"],
  ["runtime-consumability-convergence", "scripts/aws/converge-production-ecs-runtime-policy.mjs"],
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
  ["normal-backend-activation", "scripts/aws/production-normal-backend-activation.mjs"],
  ["initial-activation-lifecycle", "scripts/aws/manage-production-initial-activation-lifecycle.mjs"],
  ["dual-slot-rebaseline-durable-evidence", "scripts/aws/persist-production-dual-slot-rebaseline-durable-evidence.mjs"],
  ["stage-a-production-artifacts-policy-recovery", "scripts/aws/run-production-stage-a-production-artifacts-recovery.mjs"],
  ["stage-a-production-artifacts-state-reconciliation", "scripts/aws/run-production-stage-a-production-artifacts-reconciliation.mjs"],
]);

const NORMAL_ACTIVATION_CAPABILITIES = Object.freeze([
  ["initial-activation-read-claim", "initial-activation-lifecycle", "RELEASE_DEPLOYER", "s3:GetObject", [PRODUCTION_ACTIVATION_LIFECYCLE.claimArn], false],
  ["initial-activation-read-completion", "initial-activation-lifecycle", "RELEASE_DEPLOYER", "s3:GetObject", [PRODUCTION_ACTIVATION_LIFECYCLE.completionArn], false],
  ["initial-activation-create-claim", "initial-activation-lifecycle", "RELEASE_DEPLOYER", "s3:PutObject", [PRODUCTION_ACTIVATION_LIFECYCLE.claimArn], true],
  ["initial-activation-create-completion", "initial-activation-lifecycle", "RELEASE_DEPLOYER", "s3:PutObject", [PRODUCTION_ACTIVATION_LIFECYCLE.completionArn], true],
  ["rebaseline-evidence-read", "dual-slot-rebaseline-durable-evidence", "RELEASE_DEPLOYER", "s3:GetObject", [PRODUCTION_ACTIVATION_LIFECYCLE.rebaselineEvidenceArn], false],
  ["rebaseline-evidence-create", "dual-slot-rebaseline-durable-evidence", "RELEASE_DEPLOYER", "s3:PutObject", [PRODUCTION_ACTIVATION_LIFECYCLE.rebaselineEvidenceArn], true],
  ["normal-activation-admin-identify", "administrator-normal-backend-activation-convergence", "ADMINISTRATOR", "sts:GetCallerIdentity", ["*"], false],
  ["normal-activation-admin-read-state", "administrator-normal-backend-activation-convergence", "ADMINISTRATOR", "s3:GetObject", [STAGE_B_TERRAFORM_BACKEND.stateArn], false],
  ["normal-activation-admin-read-policy", "administrator-normal-backend-activation-convergence", "ADMINISTRATOR", "iam:GetPolicy", [NORMAL_ACTIVATION.policyArn], false],
  ["normal-activation-admin-read-policy-version", "administrator-normal-backend-activation-convergence", "ADMINISTRATOR", "iam:GetPolicyVersion", [NORMAL_ACTIVATION.policyArn], false],
  ["normal-activation-admin-list-policy-versions", "administrator-normal-backend-activation-convergence", "ADMINISTRATOR", "iam:ListPolicyVersions", [NORMAL_ACTIVATION.policyArn], false],
  ["normal-activation-admin-prune-policy-version", "administrator-normal-backend-activation-convergence", "ADMINISTRATOR", "iam:DeletePolicyVersion", [NORMAL_ACTIVATION.policyArn], true],
  ["normal-activation-admin-publish-policy-version", "administrator-normal-backend-activation-convergence", "ADMINISTRATOR", "iam:CreatePolicyVersion", [NORMAL_ACTIVATION.policyArn], true],
  ["normal-activation-admin-simulate-exact-target", "administrator-normal-backend-activation-convergence", "ADMINISTRATOR", "iam:SimulatePrincipalPolicy", [NORMAL_ACTIVATION.roleArn], false],
  ["normal-activation-admin-describe-candidate", "administrator-normal-backend-activation-convergence", "ADMINISTRATOR", "ecs:DescribeTaskDefinition", ["*"], false],
  ["normal-activation-admin-describe-service", "administrator-normal-backend-activation-convergence", "ADMINISTRATOR", "ecs:DescribeServices", [NORMAL_ACTIVATION.serviceArn], false],
  ["normal-activation-admin-list-tasks", "administrator-normal-backend-activation-convergence", "ADMINISTRATOR", "ecs:ListTasks", [NORMAL_ACTIVATION.serviceArn], false],
  ["normal-activation-admin-describe-tasks", "administrator-normal-backend-activation-convergence", "ADMINISTRATOR", "ecs:DescribeTasks", [`arn:aws:ecs:${NORMAL_ACTIVATION.region}:${NORMAL_ACTIVATION.account}:task/${NORMAL_ACTIVATION.cluster}/*`], false],
  ["normal-activation-release-identify", "normal-backend-activation", "RELEASE_DEPLOYER", "sts:GetCallerIdentity", ["*"], false],
  ["normal-activation-release-read-state", "normal-backend-activation", "RELEASE_DEPLOYER", "s3:GetObject", [STAGE_B_TERRAFORM_BACKEND.stateArn], false],
  ["normal-activation-release-read-policy", "normal-backend-activation", "RELEASE_DEPLOYER", "iam:GetPolicy", [NORMAL_ACTIVATION.policyArn], false],
  ["normal-activation-release-read-policy-version", "normal-backend-activation", "RELEASE_DEPLOYER", "iam:GetPolicyVersion", [NORMAL_ACTIVATION.policyArn], false],
  ["normal-activation-release-describe-candidate", "normal-backend-activation", "RELEASE_DEPLOYER", "ecs:DescribeTaskDefinition", ["*"], false],
  ["normal-activation-release-describe-service", "normal-backend-activation", "RELEASE_DEPLOYER", "ecs:DescribeServices", [NORMAL_ACTIVATION.serviceArn], false],
  ["normal-activation-release-update-service", "normal-backend-activation", "RELEASE_DEPLOYER", "ecs:UpdateService", [NORMAL_ACTIVATION.serviceArn], true],
  ["normal-activation-release-list-tasks", "normal-backend-activation", "RELEASE_DEPLOYER", "ecs:ListTasks", [NORMAL_ACTIVATION.serviceArn], false],
  ["normal-activation-release-describe-tasks", "normal-backend-activation", "RELEASE_DEPLOYER", "ecs:DescribeTasks", [`arn:aws:ecs:${NORMAL_ACTIVATION.region}:${NORMAL_ACTIVATION.account}:task/${NORMAL_ACTIVATION.cluster}/*`], false],
]);

const STAGE_A_PRODUCTION_ARTIFACTS_CAPABILITIES = Object.freeze([
  ["stage-a-artifacts-recovery-root-identify", "stage-a-production-artifacts-policy-recovery", "ROOT_OPERATOR", "sts:GetCallerIdentity", ["*"], false, "scripts/aws/run-production-stage-a-production-artifacts-recovery.mjs"],
  ["stage-a-artifacts-recovery-root-read-versioning", "stage-a-production-artifacts-policy-recovery", "ROOT_OPERATOR", "s3:GetBucketVersioning", [`arn:aws:s3:::${PRODUCTION_ACTIVATION_LIFECYCLE.bucket}`], false, "scripts/aws/run-production-stage-a-production-artifacts-recovery.mjs"],
  ["stage-a-artifacts-recovery-root-read-lifecycle", "stage-a-production-artifacts-policy-recovery", "ROOT_OPERATOR", "s3:GetBucketLifecycleConfiguration", [`arn:aws:s3:::${PRODUCTION_ACTIVATION_LIFECYCLE.bucket}`], false, "scripts/aws/run-production-stage-a-production-artifacts-recovery.mjs"],
  ["stage-a-artifacts-recovery-root-put-policy", "stage-a-production-artifacts-policy-recovery", "ROOT_OPERATOR", "s3:PutBucketPolicy", [`arn:aws:s3:::${PRODUCTION_ACTIVATION_LIFECYCLE.bucket}`], true, "scripts/aws/run-production-stage-a-production-artifacts-recovery.mjs"],
  ["stage-a-artifacts-recovery-release-identify", "stage-a-production-artifacts-policy-recovery", "RELEASE_DEPLOYER", "sts:GetCallerIdentity", ["*"], false, "scripts/aws/run-production-stage-a-production-artifacts-recovery.mjs"],
  ["stage-a-artifacts-recovery-release-read-policy", "stage-a-production-artifacts-policy-recovery", "RELEASE_DEPLOYER", "s3:GetBucketPolicy", [`arn:aws:s3:::${PRODUCTION_ACTIVATION_LIFECYCLE.bucket}`], false, "scripts/aws/run-production-stage-a-production-artifacts-recovery.mjs"],
  ["stage-a-artifacts-recovery-root-journal-read", "stage-a-production-artifacts-policy-recovery", "ROOT_OPERATOR", "s3:GetObject", [PRODUCTION_ACTIVATION_LIFECYCLE.stageAProductionArtifactsReconciliationArn], false, "scripts/aws/production-stage-a-production-artifacts-journal.mjs"],
  ["stage-a-artifacts-recovery-root-journal-conditional-create", "stage-a-production-artifacts-policy-recovery", "ROOT_OPERATOR", "s3:PutObject", [PRODUCTION_ACTIVATION_LIFECYCLE.stageAProductionArtifactsReconciliationArn], true, "scripts/aws/production-stage-a-production-artifacts-journal.mjs"],
  ["stage-a-artifacts-recovery-root-sign", "stage-a-production-artifacts-policy-recovery", "ROOT_OPERATOR", "kms:Sign", [ROOT_ATTESTATION_KEY_ALIAS_ARN], true, "scripts/aws/production-root-attestation-signer.mjs"],
  ["stage-a-artifacts-recovery-release-lock-acquire", "stage-a-production-artifacts-policy-recovery", "RELEASE_DEPLOYER", "s3:PutObject", [STAGE_A_TERRAFORM_LOCK_ARN], true, "scripts/aws/production-stage-a-root-drop-orphan-recovery.mjs"],
  ["stage-a-artifacts-recovery-release-lock-release", "stage-a-production-artifacts-policy-recovery", "RELEASE_DEPLOYER", "s3:DeleteObject", [STAGE_A_TERRAFORM_LOCK_ARN], true, "scripts/aws/production-stage-a-root-drop-orphan-recovery.mjs"],
  ["stage-a-artifacts-journal-read", "stage-a-production-artifacts-state-reconciliation", "RELEASE_DEPLOYER", "s3:GetObject", [PRODUCTION_ACTIVATION_LIFECYCLE.stageAProductionArtifactsReconciliationArn], false, "scripts/aws/production-stage-a-production-artifacts-journal.mjs"],
  ["stage-a-artifacts-journal-conditional-create", "stage-a-production-artifacts-state-reconciliation", "RELEASE_DEPLOYER", "s3:PutObject", [PRODUCTION_ACTIVATION_LIFECYCLE.stageAProductionArtifactsReconciliationArn], true, "scripts/aws/production-stage-a-production-artifacts-journal.mjs"],
  ["stage-a-artifacts-reconciliation-release-identify", "stage-a-production-artifacts-state-reconciliation", "RELEASE_DEPLOYER", "sts:GetCallerIdentity", ["*"], false, "scripts/aws/run-production-stage-a-production-artifacts-reconciliation.mjs"],
  ["stage-a-artifacts-reconciliation-release-read-policy", "stage-a-production-artifacts-state-reconciliation", "RELEASE_DEPLOYER", "s3:GetBucketPolicy", [`arn:aws:s3:::${PRODUCTION_ACTIVATION_LIFECYCLE.bucket}`], false, "scripts/aws/run-production-stage-a-production-artifacts-reconciliation.mjs"],
  ["stage-a-artifacts-reconciliation-terraform-read-bucket-location", "stage-a-production-artifacts-state-reconciliation", "RELEASE_DEPLOYER", "s3:GetBucketLocation", [STAGE_B_TERRAFORM_BACKEND.bucketArn], false, "scripts/aws/run-production-stage-a-production-artifacts-reconciliation.mjs"],
  ["stage-a-artifacts-reconciliation-terraform-read-state", "stage-a-production-artifacts-state-reconciliation", "RELEASE_DEPLOYER", "s3:GetObject", [stageATerraformStateArn], false, "scripts/aws/production-stage-a-control-plane.mjs"],
  ["stage-a-artifacts-reconciliation-terraform-write-state", "stage-a-production-artifacts-state-reconciliation", "RELEASE_DEPLOYER", "s3:PutObject", [stageATerraformStateArn], true, "scripts/aws/production-stage-a-control-plane.mjs"],
  ["stage-a-artifacts-reconciliation-terraform-read-lock", "stage-a-production-artifacts-state-reconciliation", "RELEASE_DEPLOYER", "s3:GetObject", [STAGE_A_TERRAFORM_LOCK_ARN], false, "scripts/aws/run-production-stage-a-production-artifacts-reconciliation.mjs"],
]);

const FIXED = Object.freeze([
  ["admin-image-repositories", "schema-v4-image-evidence", "ADMINISTRATOR", "ecr:DescribeRepositories", "ADMIN_DIRECT_READ", "scripts/aws/production-green-stage-b-image-evidence.mjs"],
  ["admin-image-records", "schema-v4-image-evidence", "ADMINISTRATOR", "ecr:DescribeImages", "ADMIN_DIRECT_READ", "scripts/aws/production-green-stage-b-image-evidence.mjs"],
  ["admin-role", "administrator-iam-simulation", "ADMINISTRATOR", "iam:GetRole", "ADMIN_DIRECT_READ", "scripts/aws/validate-production-green-stage-b-permissions.mjs"],
  ["admin-role-inline-list", "administrator-iam-simulation", "ADMINISTRATOR", "iam:ListRolePolicies", "ADMIN_DIRECT_READ", "scripts/aws/validate-production-green-stage-b-permissions.mjs"],
  ["admin-role-inline-read", "administrator-iam-simulation", "ADMINISTRATOR", "iam:GetRolePolicy", "ADMIN_DIRECT_READ", "scripts/aws/validate-production-green-stage-b-permissions.mjs"],
  ["admin-role-attachments", "administrator-iam-simulation", "ADMINISTRATOR", "iam:ListAttachedRolePolicies", "ADMIN_DIRECT_READ", "scripts/aws/validate-production-green-stage-b-permissions.mjs"],
  ["admin-managed-policy", "administrator-iam-simulation", "ADMINISTRATOR", "iam:GetPolicy", "ADMIN_DIRECT_READ", "scripts/aws/validate-production-green-stage-b-permissions.mjs"],
  ["admin-managed-policy-version", "administrator-iam-simulation", "ADMINISTRATOR", "iam:GetPolicyVersion", "ADMIN_DIRECT_READ", "scripts/aws/validate-production-green-stage-b-permissions.mjs"],
  ["admin-simulate-release", "administrator-iam-simulation", "ADMINISTRATOR", "iam:SimulatePrincipalPolicy", "ADMIN_SIMULATION", "scripts/aws/validate-production-green-stage-b-permissions.mjs"],
  ["admin-cloudtrail-denials", "administrator-iam-simulation", "ADMINISTRATOR", "cloudtrail:LookupEvents", "ADMIN_DIRECT_READ", "scripts/aws/validate-production-green-stage-b-permissions.mjs"],
  ["admin-sign-evidence", "administrator-kms-signing", "ADMINISTRATOR", "kms:Sign", "ADMIN_SIGN", "scripts/aws/validate-production-green-stage-b-permissions.mjs"],
  ["admin-image-evidence-describe-key", "schema-v4-image-evidence", "ADMINISTRATOR", "kms:DescribeKey", "ADMIN_DIRECT_READ", "scripts/aws/production-root-attestation-key.mjs"],
  ["admin-image-evidence-read-key-policy", "schema-v4-image-evidence", "ADMINISTRATOR", "kms:GetKeyPolicy", "ADMIN_DIRECT_READ", "scripts/aws/production-root-attestation-key.mjs"],
  ["admin-image-evidence-read-key-tags", "schema-v4-image-evidence", "ADMINISTRATOR", "kms:ListResourceTags", "ADMIN_DIRECT_READ", "scripts/aws/production-root-attestation-key.mjs"],
  ["admin-verify-image-evidence", "schema-v4-image-evidence", "ADMINISTRATOR", "kms:Verify", "ADMIN_DIRECT_READ", "scripts/aws/run-production-green-stage-b-preflight.mjs"],
  ["admin-release-oidc-identify", "administrator-release-oidc-trust-convergence", "ADMINISTRATOR", "sts:GetCallerIdentity", "ADMIN_DIRECT_READ", "scripts/aws/production-release-oidc-contract.mjs"],
  ["admin-release-oidc-trust-read", "administrator-release-oidc-trust-convergence", "ADMINISTRATOR", "iam:GetRole", "ADMIN_DIRECT_READ", "scripts/aws/production-release-oidc-contract.mjs"],
  ["admin-release-oidc-trust-update", "administrator-release-oidc-trust-convergence", "ADMINISTRATOR", "iam:UpdateAssumeRolePolicy", "ADMIN_IAM_MUTATION", "scripts/aws/production-release-oidc-contract.mjs"],
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

const ROOT_ATTESTATION_RELEASE_CAPABILITIES = Object.freeze([
  ["release-root-attestation-describe-key", "kms:DescribeKey"],
  ["release-root-attestation-read-key-policy", "kms:GetKeyPolicy"],
  ["release-root-attestation-read-key-tags", "kms:ListResourceTags"],
  ["release-root-attestation-verify", "kms:Verify"],
]);

const RUNTIME_ADMIN_CAPABILITIES = Object.freeze([
  ["runtime-admin-identify", "runtime-consumability-evidence", "sts:GetCallerIdentity", ["*"] , false],
  ["runtime-admin-get-role", "runtime-consumability-evidence", "iam:GetRole", ["arn:aws:iam::368992683803:role/mscqr-ecs-execution-role", "arn:aws:iam::368992683803:role/mscqr-ecs-task-role"], false],
  ["runtime-admin-list-inline", "runtime-consumability-evidence", "iam:ListRolePolicies", ["arn:aws:iam::368992683803:role/mscqr-ecs-execution-role", "arn:aws:iam::368992683803:role/mscqr-ecs-task-role"], false],
  ["runtime-admin-get-inline", "runtime-consumability-evidence", "iam:GetRolePolicy", ["arn:aws:iam::368992683803:role/mscqr-ecs-execution-role", "arn:aws:iam::368992683803:role/mscqr-ecs-task-role"], false],
  ["runtime-admin-list-attached", "runtime-consumability-evidence", "iam:ListAttachedRolePolicies", ["*"], false],
  ["runtime-admin-get-managed", "runtime-consumability-evidence", "iam:GetPolicy", ["arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"], false],
  ["runtime-admin-get-managed-version", "runtime-consumability-evidence", "iam:GetPolicyVersion", ["arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"], false],
  ["runtime-admin-describe-secret", "runtime-consumability-evidence", "secretsmanager:DescribeSecret", ["arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/*", "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/*"], false],
  ["runtime-admin-get-secret-value", "runtime-consumability-evidence", "secretsmanager:GetSecretValue", ["arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/*", "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/*"], false],
  ["runtime-admin-list-secret-versions", "runtime-consumability-evidence", "secretsmanager:ListSecretVersionIds", ["arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/*", "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/*"], false],
  ["runtime-admin-read-secret-resource-policy", "runtime-consumability-evidence", "secretsmanager:GetResourcePolicy", ["arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/*", "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/*"], false],
  ["runtime-admin-read-repository-policy", "runtime-consumability-evidence", "ecr:GetRepositoryPolicy", ["arn:aws:ecr:eu-west-2:368992683803:repository/mscqr-backend", "arn:aws:ecr:eu-west-2:368992683803:repository/mscqr-web", "arn:aws:ecr:eu-west-2:368992683803:repository/mscqr-worker"], false],
  ["runtime-admin-describe-log-groups", "runtime-consumability-evidence", "logs:DescribeLogGroups", ["*"], false],
  ["runtime-admin-describe-runtime-image", "runtime-consumability-evidence", "ecr:DescribeImages", ["arn:aws:ecr:eu-west-2:368992683803:repository/mscqr-backend", "arn:aws:ecr:eu-west-2:368992683803:repository/mscqr-web", "arn:aws:ecr:eu-west-2:368992683803:repository/mscqr-worker"], false],
  ["runtime-admin-describe-runtime-key", "runtime-consumability-evidence", "kms:DescribeKey", [ROOT_ATTESTATION_KEY_ALIAS_ARN], false],
  ["runtime-admin-read-runtime-key-policy", "runtime-consumability-evidence", "kms:GetKeyPolicy", [ROOT_ATTESTATION_KEY_ALIAS_ARN], false],
  ["runtime-admin-simulate", "runtime-consumability-evidence", "iam:SimulatePrincipalPolicy", ["arn:aws:iam::368992683803:role/mscqr-ecs-execution-role", "arn:aws:iam::368992683803:role/mscqr-ecs-task-role"], false],
  ["runtime-admin-sign", "runtime-consumability-evidence", "kms:Sign", [ROOT_ATTESTATION_KEY_ALIAS_ARN], true],
  ["runtime-admin-verify-inventory-evidence", "runtime-consumability-evidence", "kms:Verify", [ROOT_ATTESTATION_KEY_ALIAS_ARN], false],
  ["runtime-admin-verify-inventory-convergence", "runtime-consumability-convergence", "kms:Verify", [ROOT_ATTESTATION_KEY_ALIAS_ARN], false],
  ["runtime-admin-converge-inline", "runtime-consumability-convergence", "iam:PutRolePolicy", ["arn:aws:iam::368992683803:role/mscqr-ecs-execution-role"], true],
]);

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
    "manifest-backend-health-recovery-list-service-deployments",
    "manifest-backend-health-recovery-describe-service-deployments",
    "manifest-backend-health-recovery-describe-service-revisions",
    "manifest-backend-health-recovery-describe-images",
    "manifest-backend-health-recovery-describe-repositories",
    "manifest-backend-health-recovery-register-legacy-task-definition",
    "manifest-backend-health-recovery-update-service",
  ],
  "existing-revision-forward-recovery": FORWARD_RECOVERY_CAPABILITIES.map(([id]) => id),
  "stage-a-production-artifacts-state-reconciliation": STAGE_A_PRODUCTION_ARTIFACTS_CAPABILITIES.filter(([, phase]) => phase === "stage-a-production-artifacts-state-reconciliation").map(([id]) => id),
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
    const taskDefinitionValues = (entry.context || []).find(({ key }) => key === "ecs:task-definition")?.values || [];
    const taskDefinitionCondition = statement.Condition?.ArnEquals?.["ecs:task-definition"] ?? statement.Condition?.ArnLike?.["ecs:task-definition"];
    const taskDefinitionMatches = taskDefinitionValues.length === 0 || asArray(taskDefinitionCondition).filter((pattern) => typeof pattern === "string").some((pattern) => taskDefinitionValues.every((value) => pattern === value || (pattern.endsWith("*") && value.startsWith(pattern.slice(0, -1)))));
    if (statement.Effect === (forbidden ? "Deny" : "Allow") && actions.includes(entry.action)
      && taskDefinitionMatches && asArray(entry.resources).every((resource) => resources.some((allowed) => allowed === "*" || allowed === resource || (allowed.endsWith("*") && resource.startsWith(allowed.slice(0, -1)))))) {
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

function administratorAttestationAuthority() {
  const source = fs.readFileSync(path.join(root, rootAttestationPolicyPath), "utf8");
  const administratorStatement = '{ Sid = "AccountAdministration", Effect = "Allow", Principal = { AWS = "arn:aws:iam::368992683803:root" }, Action = "kms:*", Resource = "*" }';
  if (!source.includes('resource "aws_kms_key" "root_attestation"') || !source.includes(administratorStatement)
    || !source.includes('Sid = "DenyNonRootAttestationSigning"')) {
    throw new Error("No reviewed root administrator authority can attest release-preflight checker trust before Stage A.");
  }
  return { sourceFile: rootAttestationPolicyPath, sid: "AccountAdministration", livePolicyArn: null, expectedVersion: "protected-main-source", expectedPolicySha256: sha256(Buffer.from(source)) };
}

function rootAttestationVerifyAuthority() {
  const source = fs.readFileSync(path.join(root, rootAttestationPolicyPath), "utf8");
  if (!source.includes('Sid = "ReleaseVerifiesRootAttestations"') || !source.includes('"kms:Verify"')) throw new Error("No reviewed release authority verifies root attestations.");
  return { sourceFile: rootAttestationPolicyPath, sid: "ReleaseVerifiesRootAttestations", livePolicyArn: null, expectedVersion: "protected-main-source", expectedPolicySha256: sha256(Buffer.from(source)) };
}

function terraformRuntimeActions() {
  const text = fs.readFileSync(path.join(root, terraformPath), "utf8");
  return [...text.matchAll(/Action\s*=\s*(?:\[([^\]]+)\]|"([^"]+)")/g)]
    .flatMap((match) => match[2] ? [match[2]] : [...match[1].matchAll(/"([^"]+)"/g)].map((item) => item[1]))
    .filter((action) => /^[a-z0-9-]+:[A-Z]/.test(action))
    .filter((action, index, actions) => actions.indexOf(action) === index)
    .sort();
}

export function discoverAwsCliActions() {
  const serviceNames = "sts|iam|kms|ecr|ec2|ecs|rds|lambda|logs|cloudtrail|secretsmanager|dynamodb|s3api";
  const calls = [];
  for (const sourceFile of awsCliSourceFiles) {
    const source = fs.readFileSync(path.join(root, sourceFile), "utf8");
    const pattern = sourceFile.endsWith(".sh")
      ? new RegExp(`\\baws\\s+(${serviceNames})\\s+([a-z0-9-]+)`, "g")
      : new RegExp(`\\[\\s*["'](${serviceNames})["']\\s*,\\s*["']([a-z0-9-]+)["']`, "g");
    for (const match of source.matchAll(pattern)) {
      const service = match[1] === "s3api" ? "s3" : match[1];
      const operation = match[2].split("-").map((part) => part[0].toUpperCase() + part.slice(1)).join("").replaceAll("Db", "DB").replaceAll("Vpc", "VPC").replaceAll("Url", "URL");
      const action = service === "ecs" && operation === "Wait" ? "ecs:DescribeServices"
        : `${service}:${service === "lambda" && operation === "Invoke" ? "InvokeFunction" : operation}`;
      if (sourceFile === "scripts/aws/production-stage-a-production-artifacts-journal.mjs" && ["s3:GetObject", "s3:PutObject"].includes(action)) {
        calls.push({ sourceFile, action, identity: "RELEASE_DEPLOYER" }, { sourceFile, action, identity: "ROOT_OPERATOR" });
      } else if (sourceFile === "scripts/aws/production-root-attestation-signer.mjs" && action === "kms:Sign") {
        calls.push({ sourceFile, action, identity: "ADMINISTRATOR" }, { sourceFile, action, identity: "ROOT_OPERATOR" });
      } else {
        calls.push(sourceFile === "scripts/aws/produce-production-root-drop-evidence.mjs" && action === "kms:Sign"
          ? { sourceFile, sourceFunction: "produce-production-root-drop-evidence", phase: "root-drop-evidence-signing", identity: "ROOT_OPERATOR", action, resources: [ROOT_DROP_SIGNING_KEY_ARN], capabilityId: "root-drop-sign-evidence" }
          : { sourceFile, action });
      }
    }
  }
  calls.push(
    { sourceFile: "scripts/aws/production-stage-a-root-drop-orphan-recovery.mjs", action: "s3:PutObject" },
    { sourceFile: "scripts/aws/production-stage-a-root-drop-orphan-recovery.mjs", action: "s3:DeleteObject" },
    { sourceFile: "scripts/aws/run-production-stage-a-production-artifacts-reconciliation.mjs", action: "s3:GetBucketLocation" },
    { sourceFile: "scripts/aws/run-production-stage-a-production-artifacts-reconciliation.mjs", action: "s3:GetObject" },
    { sourceFile: "scripts/aws/production-stage-a-control-plane.mjs", action: "s3:GetObject" },
    { sourceFile: "scripts/aws/production-stage-a-control-plane.mjs", action: "s3:PutObject" },
  );
  return calls.filter((call, index) => calls.findIndex((candidate) => candidate.sourceFile === call.sourceFile && candidate.action === call.action && (candidate.identity || "RELEASE_DEPLOYER") === (call.identity || "RELEASE_DEPLOYER")) === index)
    .sort((left, right) => `${left.sourceFile}:${left.action}`.localeCompare(`${right.sourceFile}:${right.action}`));
}

export function buildStageBDeploymentCapabilityGraph() {
  const manifest = readJson(manifestPath); const policies = sourcePolicies(); const probesByAction = new Map();
  assertProductionReleaseOidcSourceContract(manifest);
  for (const probe of RELEASE_READ_PROBES) probesByAction.set(probe.action, [...(probesByAction.get(probe.action) || []), probe.id]);
  for (const probe of [
    { id: "audit-service-details", action: "ecs:DescribeServices" },
    { id: "audit-task-details", action: "ecs:DescribeTasks" },
    { id: "backend-health-recovery-service-deployment-details", action: "ecs:DescribeServiceDeployments" },
    { id: "backend-health-recovery-service-revision-details", action: "ecs:DescribeServiceRevisions" },
    { id: "runtime-candidate-secret-metadata", action: "secretsmanager:DescribeSecret" },
    { id: "runtime-candidate-secret-json-key", action: "secretsmanager:GetSecretValue" },
    { id: "runtime-candidate-secret-versions", action: "secretsmanager:ListSecretVersionIds" },
    { id: "runtime-candidate-secret-resource-policy", action: "secretsmanager:GetResourcePolicy" },
    { id: "runtime-candidate-log-group", action: "logs:DescribeLogGroups" },
    { id: "runtime-candidate-kms-key", action: "kms:DescribeKey" },
    { id: "runtime-candidate-kms-key-policy", action: "kms:GetKeyPolicy" },
    { id: "runtime-legacy-inline-policy", action: "iam:GetRolePolicy" },
    { id: "runtime-ecs-managed-policy-version", action: "iam:GetPolicyVersion" },
    { id: "runtime-consumability-signature", action: "kms:Verify" },
  ]) probesByAction.set(probe.action, [...(probesByAction.get(probe.action) || []), probe.id]);
  const manifestCapabilities = [[manifest.required, false], [manifest.forbidden, true]].flatMap(([entries, forbidden]) => entries.map((entry) => ({
    id: `manifest-${entry.id}`, phase: entry.phase === "apply" ? "wrapper-apply" : ["recovery", "recovery-read"].includes(entry.phase) ? "backend-health-recovery" : entry.phase === "normal-activation-read" ? "normal-backend-activation" : entry.phase === "reference-audit" ? "reference-audit" : entry.phase === "preflight" ? "release-direct-read-preflight" : "refresh-only",
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
  checkerCapabilities.push({
    id: "administrator-release-preflight-trust-attestation-identify", phase: "release-preflight-checker-trust-attestation", identity: "ADMINISTRATOR", executor: "aws-cli",
    sourceFile: "scripts/aws/production-release-preflight-checker-attestation.mjs", sourceFunction: "runReleasePreflightCheckerTrustAttestationCli",
    action: "sts:GetCallerIdentity", resources: ["*"], context: { account: STAGE_B.account, region: STAGE_B.region }, classification: "ADMIN_RELEASE_PREFLIGHT_ATTESTATION_READ",
    probe: "administrator-live-read", probeIds: [], policy: administratorAttestationAuthority(), required: true, mutation: false,
  });
  const rootAttestationRelease = ROOT_ATTESTATION_RELEASE_CAPABILITIES.map(([id, action]) => ({
    id, phase: "release-direct-read-preflight", identity: "RELEASE_DEPLOYER", executor: "aws-cli",
    sourceFile: "scripts/aws/production-root-attestation-key.mjs", sourceFunction: id, action, resources: [ROOT_ATTESTATION_KEY_ALIAS_ARN],
    context: { account: STAGE_B.account, region: STAGE_B.region }, classification: "RELEASE_DIRECT_READ", probe: "direct", probeIds: [`root-attestation-${action.toLowerCase().replace(':', '-')}`],
    policy: rootAttestationVerifyAuthority(), required: true, mutation: false,
  }));
  checkerCapabilities.push({
    id: "administrator-release-preflight-trust-attestation-sign", phase: "release-preflight-checker-trust-attestation", identity: "ADMINISTRATOR", executor: "aws-cli",
    sourceFile: "scripts/aws/production-release-preflight-checker-attestation.mjs", sourceFunction: "runReleasePreflightCheckerTrustAttestationCli",
    action: "kms:Sign", resources: [ROOT_ATTESTATION_KEY_ALIAS_ARN], context: { account: STAGE_B.account, region: STAGE_B.region }, classification: "ADMIN_RELEASE_PREFLIGHT_ATTESTATION_SIGNING",
    probe: "structural", probeIds: [], policy: administratorAttestationAuthority(), required: true, mutation: true,
  });
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
  const fixed = FIXED.map(([id, phase, identity, action, actionClass, sourceFile]) => ({ id, phase, identity, executor: sourceFile.endsWith(".yml") ? "github-actions" : "aws-cli", sourceFile, sourceFunction: id, action, resources: id === "admin-release-oidc-identify" ? ["*"] : id.startsWith("admin-release-oidc-trust-") ? [PRODUCTION_RELEASE_ROLE_ARN] : ["release-verify-signature", "admin-image-evidence-describe-key", "admin-image-evidence-read-key-policy", "admin-image-evidence-read-key-tags", "admin-verify-image-evidence"].includes(id) ? [IMAGE_EVIDENCE_SIGNING_KEY_ARN] : ["reviewed-exact-resource"], context: { account: "368992683803", region: "eu-west-2" }, classification: actionClass, probe: actionClass === "RELEASE_DIRECT_READ" ? "direct" : actionClass === "ADMIN_SIMULATION" ? "administrator-simulation" : "structural", probeIds: probesByAction.get(action) || [], policy: { sourceFile: identity === "RELEASE_DEPLOYER" ? manifestPath : sourceFile, sid: "identity-boundary", livePolicyArn: identity === "RELEASE_DEPLOYER" ? "signed-administrator-evidence" : null, expectedVersion: "source-bound", expectedPolicySha256: null }, required: true, mutation: ["ADMIN_SIGN", "ADMIN_IAM_MUTATION", "GITHUB_IMAGE_MUTATION"].includes(actionClass) }));
  const normalActivation = NORMAL_ACTIVATION_CAPABILITIES.map(([id, phase, identity, action, resources, mutation]) => {
    const policy = identity === "ADMINISTRATOR" || action === "ecs:UpdateService"
      ? { sourceFile: "scripts/aws/production-normal-backend-activation-policy.mjs", sid: id, livePolicyArn: action === "ecs:UpdateService" ? NORMAL_ACTIVATION.policyArn : null, expectedVersion: "state-derived-exact-revision", expectedPolicySha256: null }
      : action === "sts:GetCallerIdentity"
        ? { sourceFile: "aws-sts", sid: "self-identity", livePolicyArn: null, expectedVersion: "aws-authenticated", expectedPolicySha256: null }
        : authority({ id, action, resources, context: [] }, false, policies);
    return { id, phase, identity, executor: "aws-cli", sourceFile: "scripts/aws/production-normal-backend-activation.mjs", sourceFunction: id, action, resources, context: { account: NORMAL_ACTIVATION.account, region: NORMAL_ACTIVATION.region, releaseMode: "normal", targetBinding: "authenticated-stage-b-state-exact-revision" }, classification: mutation ? identity === "ADMINISTRATOR" ? "ADMIN_IAM_MUTATION" : "NORMAL_ACTIVATION_MUTATION" : identity === "ADMINISTRATOR" ? "ADMIN_DIRECT_READ" : "RELEASE_DIRECT_READ", probe: identity === "ADMINISTRATOR" ? "administrator-live-read-or-simulation" : "direct-live-read", probeIds: probesByAction.get(action) || [], policy, required: true, mutation };
  });
  const stageABackendPolicySid = Object.freeze({
    "stage-a-artifacts-reconciliation-terraform-read-bucket-location": "ReadExactStageABackendBucketLocation",
    "stage-a-artifacts-reconciliation-terraform-read-state": "ReadExactStageAStateForHandoff",
    "stage-a-artifacts-reconciliation-terraform-write-state": "WriteExactStageAState",
    "stage-a-artifacts-reconciliation-terraform-read-lock": "ReadExactStageALock",
    "stage-a-artifacts-recovery-release-lock-acquire": "WriteExactStageALock",
    "stage-a-artifacts-recovery-release-lock-release": "ReleaseExactStageALock",
  });
  const stageAProductionArtifacts = STAGE_A_PRODUCTION_ARTIFACTS_CAPABILITIES.map(([id, phase, identity, action, resources, mutation, sourceFile]) => ({
    id, phase, identity, executor: id.startsWith("stage-a-artifacts-reconciliation-terraform-") ? "terraform" : "aws-cli", sourceFile, sourceFunction: id, action, resources,
    context: { account: STAGE_B.account, region: STAGE_B.region, bucket: stageABackendPolicySid[id] ? STAGE_A_TERRAFORM_BACKEND.bucket : PRODUCTION_ACTIVATION_LIFECYCLE.bucket },
    classification: id === "stage-a-artifacts-reconciliation-terraform-write-state" ? "TERRAFORM_STATE_MUTATION" : id === "stage-a-artifacts-reconciliation-terraform-read-lock" ? "TERRAFORM_BACKEND_LOCK_READ" : id.startsWith("stage-a-artifacts-reconciliation-terraform-") ? "TERRAFORM_BACKEND_READ" : mutation ? action === "s3:PutBucketPolicy" ? "ROOT_GOVERNED_POLICY_RECOVERY" : action === "kms:Sign" ? "ROOT_GOVERNED_ATTESTATION_SIGNING" : id.endsWith("-lock-acquire") ? "TERRAFORM_BACKEND_LOCK_ACQUIRE" : id.endsWith("-lock-release") ? "TERRAFORM_BACKEND_LOCK_RELEASE" : identity === "ROOT_OPERATOR" ? "ROOT_CONDITIONAL_JOURNAL_CREATE" : "RELEASE_CONDITIONAL_JOURNAL_CREATE" : identity === "ROOT_OPERATOR" ? "ROOT_GOVERNED_RECOVERY_READ" : "RELEASE_DIRECT_READ",
    probe: identity === "RELEASE_DEPLOYER" ? "direct" : "structural", probeIds: identity === "RELEASE_DEPLOYER" ? [`${id}-authenticated`] : [],
    policy: { sourceFile: stageABackendPolicySid[id] ? stageAReleaseS3ContractPath : "infra/aws/terraform/production-green-stage-a/main.tf", sid: stageABackendPolicySid[id] || id, livePolicyArn: null, expectedVersion: "protected-main-source", expectedPolicySha256: null },
    required: true, mutation,
  }));
  const recovery = RECOVERY_CAPABILITIES.map(([id, action, resources]) => {
    const entry = { id, action, resources };
    return { id, phase: "canonical-backend-recovery", identity: "RELEASE_DEPLOYER", executor: "aws-cli-or-terraform", sourceFile: "scripts/aws/recover-stage-b-backend-task-definition.mjs", sourceFunction: id, action, resources, context: { account: "368992683803", region: "eu-west-2" }, classification: /^(?:ecs:RegisterTaskDefinition|ecs:TagResource|s3:PutObject|s3:DeleteObject)$/.test(action) ? "CANONICAL_RECOVERY_MUTATION" : "CANONICAL_RECOVERY_READ", probe: "administrator-simulation", probeIds: [], policy: authority(entry, false, policies), required: true, mutation: /^(?:ecs:RegisterTaskDefinition|ecs:TagResource|s3:PutObject|s3:DeleteObject)$/.test(action) };
  });
  const forwardRecovery = FORWARD_RECOVERY_CAPABILITIES.map(([id, action, resources]) => {
    const entry = { id, action, resources };
    const policy = id === "forward-recovery-verify-image-evidence" ? rootAttestationVerifyAuthority() : authority(entry, false, policies);
    return { id, phase: "existing-revision-forward-recovery", identity: "RELEASE_DEPLOYER", executor: "terraform", sourceFile: "scripts/aws/forward-recover-stage-b-existing-revision.mjs", sourceFunction: id, action, resources, context: { account: "368992683803", region: "eu-west-2" }, classification: /^(?:s3:PutObject|s3:DeleteObject)$/.test(action) ? "FORWARD_RECOVERY_IMPORT_MUTATION" : "FORWARD_RECOVERY_READ", probe: "administrator-simulation", probeIds: [], policy, required: true, mutation: /^(?:s3:PutObject|s3:DeleteObject)$/.test(action) };
  });
  const runtime = terraformRuntimeActions().map((action) => ({ id: `runtime-${action.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`, phase: "runtime-activation-boundary", identity: "SERVICE_RUNTIME", executor: "lambda-or-ecs-role", sourceFile: terraformPath, sourceFunction: "generated runtime IAM policy", action, resources: ["terraform-derived-runtime-resource"], context: {}, classification: "SERVICE_RUNTIME_ACTION", probe: "structural", policy: { sourceFile: terraformPath, sid: "terraform-generated", livePolicyArn: "created-or-updated-by-stage-b", expectedVersion: "saved-plan", expectedPolicySha256: null }, required: false, mutation: !/^(?:ecr:|kms:Verify|secretsmanager:Get|s3:Get)/.test(action) }));
  const runtimeAdmin = RUNTIME_ADMIN_CAPABILITIES.map(([id, phase, action, resources, mutation]) => ({ id, phase, identity: "ADMINISTRATOR", executor: "aws-cli", sourceFile: phase === "runtime-consumability-convergence" ? "scripts/aws/converge-production-ecs-runtime-policy.mjs" : "scripts/aws/prepare-production-ecs-runtime-consumability.mjs", sourceFunction: id, action, resources, context: { account: STAGE_B.account, region: STAGE_B.region }, classification: mutation ? "ADMIN_IAM_OR_SIGNING_MUTATION" : "ADMIN_RUNTIME_CLOSURE_READ", probe: action === "iam:SimulatePrincipalPolicy" ? "administrator-simulation" : "administrator-live-read", probeIds: [], policy: { sourceFile: phase === "runtime-consumability-convergence" ? "scripts/aws/converge-production-ecs-runtime-policy.mjs" : "scripts/aws/production-ecs-runtime-consumability.mjs", sid: id, livePolicyArn: null, expectedVersion: "protected-main-source", expectedPolicySha256: null }, required: true, mutation }));
  const capabilities = [...fixed, ...normalActivation, ...stageAProductionArtifacts, ROOT_DROP_SIGNING, ...rootAttestationRelease, ...recovery, ...forwardRecovery, ...publisher, ...manifestCapabilities, ...checkerCapabilities, ...operatorCapabilities, ...runtimeAdmin, ...runtime].sort((a, b) => a.id.localeCompare(b.id));
  return {
    schemaVersion: 1, deployment: "production-green-stage-b", account: "368992683803", region: "eu-west-2",
    phases: PHASES.map(([id, sourceFile], index) => ({ order: index + 1, id, sourceFile })),
    identities: ["GITHUB_IMAGE_PUBLISHER", "ADMINISTRATOR", "ROOT_OPERATOR", "BOOTSTRAP_OPERATOR", "RELEASE_DEPLOYER", "INDEPENDENT_CHECKER", "ECS_EXEC_VERIFIER_OPERATOR", "SERVICE_RUNTIME"], capabilities,
    directProbes: [...RELEASE_READ_PROBES.map(({ id, action }) => ({ id, action })),
      { id: "audit-service-details", action: "ecs:DescribeServices" },
      { id: "audit-task-details", action: "ecs:DescribeTasks" },
      { id: "backend-health-recovery-service-deployment-details", action: "ecs:DescribeServiceDeployments" },
      { id: "backend-health-recovery-service-revision-details", action: "ecs:DescribeServiceRevisions" },
      { id: "runtime-candidate-secret-resource-policy", action: "secretsmanager:GetResourcePolicy" }], sourceScan: discoverAwsCliActions(),
    artifactContracts: ["protected-checkout", "image-impact", "schema-v4-image-evidence", "stage-a-handoff", "tfvars-binding-report", "refresh-only", "saved-plan", "canonical-plan-json", "reference-audit", "plan-capability-manifest", "signed-permission-report"],
    stateContracts: ["stage-a-exact-object-lineage-minimum-serial-sha", "stage-b-direct-key-lineage-minimum-serial-sha", "stage-b-serial-stable-plan-to-apply"],
    freshnessContracts: [{ artifact: "image-evidence", maxAgeSeconds: 86400 }, { artifact: "reference-audit", maxAgeSeconds: STAGE_B_DEPLOYMENT_EVIDENCE_TTL_SECONDS }, { artifact: "permission-report", maxAgeSeconds: STAGE_B_DEPLOYMENT_EVIDENCE_TTL_SECONDS }],
    configurationContracts: ["head-equals-origin-main", "clean-non-shallow-checkout", "direct-production-s3-key", "strict-backend-metadata", "tf-workspace-default", "no-workspace-select-or-migration", "checker-user-mfa-live-trust-to-independent-role-chain", "release-gate-exact-production-environment-oidc-to-release-deployer", "structural-normal-resource-universe-append-only-retained-history", "no-service-database-alb-dns-traffic-or-secret-value-change"],
  };
}

export function assertStageBDeploymentCapabilityGraph(graph = readJson(CAPABILITY_GRAPH_PATH)) {
  const expected = buildStageBDeploymentCapabilityGraph();
  if (canonicalizeJson(graph) !== canonicalizeJson(expected)) throw new Error("Stage B deployment capability graph is stale or incomplete.");
  if (graph.phases.length !== PHASES.length || new Set(graph.phases.map(({ id }) => id)).size !== PHASES.length) throw new Error("Stage B capability graph phase coverage is incomplete.");
  if (new Set(graph.capabilities.map(({ id }) => id)).size !== graph.capabilities.length) throw new Error("Stage B capability IDs are not unique.");
  if (graph.capabilities.some(({ identity, action }) => !identity || !action)) throw new Error("Stage B capability identity is ambiguous.");
  for (const [phase, ids] of Object.entries(PHASE_CAPABILITY_REQUIREMENTS)) {
    const phaseCapabilities = graph.capabilities.filter((capability) => capability.phase === phase);
    if (ids.some((id) => !phaseCapabilities.some((capability) => capability.id === id))) throw new Error(`Stage B phase capability coverage is incomplete: ${phase}.`);
  }
  const forwardCapabilities = graph.capabilities.filter(({ phase }) => phase === "existing-revision-forward-recovery");
  if (forwardCapabilities.some(({ action, identity, sourceFile }) => identity !== "RELEASE_DEPLOYER" || sourceFile !== "scripts/aws/forward-recover-stage-b-existing-revision.mjs" || ["ecs:RegisterTaskDefinition", "ecs:DeregisterTaskDefinition", "ecs:UpdateService", "iam:PutRolePolicy", "iam:AttachRolePolicy"].includes(action))) throw new Error("Forward recovery capability boundary is broader than zero-registration Terraform import.");
  if (graph.capabilities.some(({ identity, action }) => identity === "RELEASE_DEPLOYER" && action === "iam:SimulatePrincipalPolicy")) throw new Error("Release-deployer cannot own IAM simulation.");
  const administratorImageEvidenceCapabilities = graph.capabilities.filter(({ id }) => id.startsWith("admin-image-evidence-") || id === "admin-verify-image-evidence");
  const expectedAdministratorImageEvidenceCapabilities = [
    ["admin-image-evidence-describe-key", "kms:DescribeKey", "scripts/aws/production-root-attestation-key.mjs"],
    ["admin-image-evidence-read-key-policy", "kms:GetKeyPolicy", "scripts/aws/production-root-attestation-key.mjs"],
    ["admin-image-evidence-read-key-tags", "kms:ListResourceTags", "scripts/aws/production-root-attestation-key.mjs"],
    ["admin-verify-image-evidence", "kms:Verify", "scripts/aws/run-production-green-stage-b-preflight.mjs"],
  ];
  if (administratorImageEvidenceCapabilities.length !== expectedAdministratorImageEvidenceCapabilities.length
    || expectedAdministratorImageEvidenceCapabilities.some(([id, action, sourceFile]) => !administratorImageEvidenceCapabilities.some((capability) => capability.id === id && capability.phase === "schema-v4-image-evidence" && capability.identity === "ADMINISTRATOR" && capability.action === action && JSON.stringify(capability.resources) === JSON.stringify([IMAGE_EVIDENCE_SIGNING_KEY_ARN]) && capability.sourceFile === sourceFile))) throw new Error("Administrator image-evidence capability coverage is absent or not exact.");
  const normal = graph.capabilities.filter(({ phase }) => phase === "normal-backend-activation");
  if (normal.some(({ identity, action }) => identity !== "RELEASE_DEPLOYER" || ["ecs:RegisterTaskDefinition", "ecs:DeregisterTaskDefinition"].includes(action)) || normal.filter(({ action }) => action === "ecs:UpdateService").length !== 1) throw new Error("Normal backend activation capability boundary is not exact or reuses registration authority.");
  const checkerPublication = graph.capabilities.filter(({ identity, action, resources }) => identity === "INDEPENDENT_CHECKER" && action === "secretsmanager:PutSecretValue" && resources.includes(STAGE_B.approvalSecretArn));
  if (checkerPublication.length !== 1) throw new Error("Exact checker approval publication capability is absent or duplicated.");
  const administratorAttestation = graph.capabilities.filter(({ id, identity, action, resources }) => id === "administrator-release-preflight-trust-attestation-sign" && identity === "ADMINISTRATOR" && action === "kms:Sign" && JSON.stringify(resources) === JSON.stringify([ROOT_ATTESTATION_KEY_ALIAS_ARN]));
  if (administratorAttestation.length !== 1 || graph.capabilities.some(({ identity, action }) => identity === "RELEASE_DEPLOYER" && action === "kms:Sign")) throw new Error("Release-preflight checker-trust signing boundary is not exact.");
  if (graph.capabilities.some(({ identity, action, resources }) => identity === "RELEASE_DEPLOYER" && ["secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue"].includes(action) && resources.includes(STAGE_B.approvalSecretArn))) throw new Error("Release-deployer approval secret authority is present.");
  if (graph.capabilities.some(({ identity, action, resources }) => identity === "INDEPENDENT_CHECKER" && action === "secretsmanager:GetSecretValue" && resources.includes(STAGE_B.approvalSecretArn))) throw new Error("Checker approval secret read authority is present.");
  if (graph.capabilities.some(({ identity, action }) => identity === "RELEASE_DEPLOYER" && action === "ecs:ExecuteCommand" && !graph.capabilities.some(({ id }) => id === "manifest-release-deployer-ecs-exec"))) throw new Error("Release-deployer ECS Exec boundary is not represented.");
  if (!graph.capabilities.some(({ identity, action, resources }) => identity === "ECS_EXEC_VERIFIER_OPERATOR" && action === "ecs:ExecuteCommand" && resources.includes(`arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/*`))) throw new Error("Dedicated ECS Exec operator capability is absent.");
  const rootDropSigning = graph.capabilities.find(({ id }) => id === "root-drop-sign-evidence");
  if (!rootDropSigning || rootDropSigning.phase !== "root-drop-evidence-signing" || rootDropSigning.identity !== "ROOT_OPERATOR" || rootDropSigning.sourceFile !== "scripts/aws/produce-production-root-drop-evidence.mjs" || rootDropSigning.action !== "kms:Sign" || JSON.stringify(rootDropSigning.resources) !== JSON.stringify([ROOT_DROP_SIGNING_KEY_ARN])) throw new Error("Root-drop signing capability is not exact.");
  for (const [id, action, mutation] of [["stage-a-artifacts-recovery-root-journal-read", "s3:GetObject", false], ["stage-a-artifacts-recovery-root-journal-conditional-create", "s3:PutObject", true]]) {
    const capability = graph.capabilities.find(({ id: candidate }) => candidate === id);
    if (!capability || capability.phase !== "stage-a-production-artifacts-policy-recovery" || capability.identity !== "ROOT_OPERATOR" || capability.sourceFile !== "scripts/aws/production-stage-a-production-artifacts-journal.mjs" || capability.action !== action || capability.mutation !== mutation || JSON.stringify(capability.resources) !== JSON.stringify([PRODUCTION_ACTIVATION_LIFECYCLE.stageAProductionArtifactsReconciliationArn])) throw new Error("Stage-A root journal capability boundary is not exact.");
  }
  const rootSigning = graph.capabilities.find(({ id }) => id === "stage-a-artifacts-recovery-root-sign");
  if (!rootSigning || rootSigning.phase !== "stage-a-production-artifacts-policy-recovery" || rootSigning.identity !== "ROOT_OPERATOR" || rootSigning.sourceFile !== "scripts/aws/production-root-attestation-signer.mjs" || rootSigning.action !== "kms:Sign" || rootSigning.mutation !== true || JSON.stringify(rootSigning.resources) !== JSON.stringify([ROOT_ATTESTATION_KEY_ALIAS_ARN])) throw new Error("Stage-A root signing capability boundary is not exact.");
  for (const [id, action] of [["stage-a-artifacts-recovery-release-lock-acquire", "s3:PutObject"], ["stage-a-artifacts-recovery-release-lock-release", "s3:DeleteObject"]]) {
    const capability = graph.capabilities.find(({ id: candidate }) => candidate === id);
    if (!capability || capability.phase !== "stage-a-production-artifacts-policy-recovery" || capability.identity !== "RELEASE_DEPLOYER" || capability.sourceFile !== "scripts/aws/production-stage-a-root-drop-orphan-recovery.mjs" || capability.action !== action || JSON.stringify(capability.resources) !== JSON.stringify([STAGE_A_TERRAFORM_LOCK_ARN]) || capability.mutation !== true) throw new Error("Stage-A recovery lock capability boundary is not exact.");
  }
  for (const [id, action, resources, mutation, sid] of [
    ["stage-a-artifacts-reconciliation-terraform-read-bucket-location", "s3:GetBucketLocation", [STAGE_B_TERRAFORM_BACKEND.bucketArn], false, "ReadExactStageABackendBucketLocation"],
    ["stage-a-artifacts-reconciliation-terraform-read-state", "s3:GetObject", [stageATerraformStateArn], false, "ReadExactStageAStateForHandoff"],
    ["stage-a-artifacts-reconciliation-terraform-write-state", "s3:PutObject", [stageATerraformStateArn], true, "WriteExactStageAState"],
    ["stage-a-artifacts-reconciliation-terraform-read-lock", "s3:GetObject", [STAGE_A_TERRAFORM_LOCK_ARN], false, "ReadExactStageALock"],
  ]) {
    const capability = graph.capabilities.find(({ id: candidate }) => candidate === id);
    if (!capability || capability.phase !== "stage-a-production-artifacts-state-reconciliation" || capability.identity !== "RELEASE_DEPLOYER" || capability.executor !== "terraform" || capability.action !== action || JSON.stringify(capability.resources) !== JSON.stringify(resources) || capability.mutation !== mutation || capability.policy?.sourceFile !== stageAReleaseS3ContractPath || capability.policy?.sid !== sid) throw new Error("Stage-A reconciliation Terraform backend capability boundary is not exact.");
  }
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

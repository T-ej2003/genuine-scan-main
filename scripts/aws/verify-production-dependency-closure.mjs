#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ARTIFACT_SIGNING_BINDINGS } from "./production-artifact-signing-domain.mjs";
import { CAPABILITY_GRAPH_PATH, assertStageBDeploymentCapabilityGraph, discoverAwsCliActions } from "./generate-production-green-stage-b-capability-graph.mjs";
import { canonicalizeJson } from "./validate-production-green-stage-b-permissions.mjs";
import { STAGE_A_TERRAFORM_BACKEND, STAGE_A_TERRAFORM_LOCK_ARN } from "./production-stage-a-root-drop-orphan-recovery.mjs";
import { STAGE_B_TERRAFORM_BACKEND } from "./stage-b-terraform-backend-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
export const PRODUCTION_DEPENDENCY_CLOSURE_PATH = "documents/ops/iam/MSCQRProductionDependencyClosure-v1.json";
const BASE_PROTECTED_SHA = "e35c0bd0447eff85ec78ab46b18ab2d2e018cbcb";
const BASE_CALL_COUNT = 105;
const BASE_CALL_SHA256 = "6375adfa99abc59a847b125a2654e7b5224a7fa80302364ec61a0c6a1a8875fe";
const SERVICE = "arn:aws:ecs:eu-west-2:368992683803:service/mscqr-prod-euw2-main/mscqr-backend-servi-euw2";
const REPOSITORY = "arn:aws:ecr:eu-west-2:368992683803:repository/mscqr-backend";
const RUNTIME_REPOSITORIES = [REPOSITORY, "arn:aws:ecr:eu-west-2:368992683803:repository/mscqr-web", "arn:aws:ecr:eu-west-2:368992683803:repository/mscqr-worker"];
const TASKS = "*";
const RUNTIME_KMS_KEY = "arn:aws:kms:eu-west-2:368992683803:key/437cdebd-95e7-4aba-8f0f-2ca08edb0478";
const ROOT_ATTESTATION_KEY = "arn:aws:kms:eu-west-2:368992683803:alias/mscqr-production-root-attestation";
const PRODUCTION_ARTIFACTS_BUCKET = "arn:aws:s3:::mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an";
const STAGE_A_RECONCILIATION_JOURNAL = `${PRODUCTION_ARTIFACTS_BUCKET}/production-stage-a-production-artifacts-reconciliation/*`;
const INITIAL_ACTIVATION_RESERVATION = `${PRODUCTION_ARTIFACTS_BUCKET}/production-initial-activation-lifecycle-policy-reconciliation/reservations/*`;
const STAGE_A_TERRAFORM_STATE_ARN = `${STAGE_B_TERRAFORM_BACKEND.bucketArn}/${STAGE_A_TERRAFORM_BACKEND.key}`;

const CALLS = Object.freeze([
  ["scripts/aws/authorize-production-stage-a-production-artifacts-reconciliation.mjs", "sts:GetCallerIdentity", "stage-a-artifacts-reconciliation-release-identify", ["*"]],
  ["scripts/aws/production-stage-a-production-artifacts-journal.mjs", "s3:GetObject", "stage-a-artifacts-journal-read", [STAGE_A_RECONCILIATION_JOURNAL]],
  ["scripts/aws/production-stage-a-production-artifacts-journal.mjs", "s3:PutObject", "stage-a-artifacts-journal-conditional-create", [STAGE_A_RECONCILIATION_JOURNAL]],
  ["scripts/aws/production-stage-a-production-artifacts-journal.mjs", "s3:GetObject", "stage-a-artifacts-recovery-root-journal-read", [STAGE_A_RECONCILIATION_JOURNAL], "ROOT_OPERATOR"],
  ["scripts/aws/production-stage-a-production-artifacts-journal.mjs", "s3:PutObject", "stage-a-artifacts-recovery-root-journal-conditional-create", [STAGE_A_RECONCILIATION_JOURNAL], "ROOT_OPERATOR"],
  ["scripts/aws/production-root-attestation-signer.mjs", "kms:Sign", "stage-a-artifacts-recovery-root-sign", [ROOT_ATTESTATION_KEY], "ROOT_OPERATOR"],
  ["scripts/aws/run-production-stage-a-production-artifacts-reconciliation.mjs", "s3:GetBucketPolicy", "stage-a-artifacts-reconciliation-release-read-policy", [PRODUCTION_ARTIFACTS_BUCKET]],
  ["scripts/aws/run-production-stage-a-production-artifacts-reconciliation.mjs", "sts:GetCallerIdentity", "stage-a-artifacts-reconciliation-release-identify", ["*"]],
  ["scripts/aws/run-production-stage-a-production-artifacts-reconciliation.mjs", "sts:GetCallerIdentity", "stage-a-artifacts-reconciliation-root-identify", ["*"], "ROOT_OPERATOR", "stage-a-artifacts-reconciliation-root-identify"],
  ["scripts/aws/run-production-stage-a-production-artifacts-reconciliation.mjs", "s3:GetObject", "stage-a-artifacts-reconciliation-root-journal-read", [STAGE_A_RECONCILIATION_JOURNAL], "ROOT_OPERATOR", "stage-a-artifacts-reconciliation-root-journal-read"],
  ["scripts/aws/run-production-stage-a-production-artifacts-reconciliation.mjs", "s3:GetObject", "stage-a-artifacts-reconciliation-release-read-raw-state", [STAGE_A_TERRAFORM_STATE_ARN], "RELEASE_DEPLOYER", "stage-a-artifacts-reconciliation-release-read-raw-state"],
  ["scripts/aws/run-production-stage-a-production-artifacts-reconciliation.mjs", "s3:GetBucketLocation", "stage-a-artifacts-reconciliation-terraform-read-bucket-location", [STAGE_B_TERRAFORM_BACKEND.bucketArn]],
  ["scripts/aws/production-stage-a-control-plane.mjs", "s3:GetObject", "stage-a-artifacts-reconciliation-terraform-read-state", [STAGE_A_TERRAFORM_STATE_ARN]],
  ["scripts/aws/production-stage-a-control-plane.mjs", "s3:PutObject", "stage-a-artifacts-reconciliation-terraform-write-state", [STAGE_A_TERRAFORM_STATE_ARN]],
  ["scripts/aws/run-production-stage-a-production-artifacts-reconciliation.mjs", "s3:GetObject", "stage-a-artifacts-reconciliation-terraform-read-lock", [STAGE_A_TERRAFORM_LOCK_ARN]],
  ["scripts/aws/run-production-stage-a-production-artifacts-recovery.mjs", "s3:GetBucketLifecycleConfiguration", "stage-a-artifacts-recovery-root-read-lifecycle", [PRODUCTION_ARTIFACTS_BUCKET], "ROOT_OPERATOR"],
  ["scripts/aws/run-production-stage-a-production-artifacts-recovery.mjs", "s3:GetBucketPolicy", "stage-a-artifacts-recovery-release-read-policy", [PRODUCTION_ARTIFACTS_BUCKET]],
  ["scripts/aws/run-production-stage-a-production-artifacts-recovery.mjs", "s3:GetObject", "stage-a-artifacts-recovery-release-read-raw-state", [STAGE_A_TERRAFORM_STATE_ARN], "RELEASE_DEPLOYER", "stage-a-artifacts-recovery-release-read-raw-state"],
  ["scripts/aws/run-production-stage-a-production-artifacts-recovery.mjs", "s3:GetBucketVersioning", "stage-a-artifacts-recovery-root-read-versioning", [PRODUCTION_ARTIFACTS_BUCKET], "ROOT_OPERATOR"],
  ["scripts/aws/run-production-stage-a-production-artifacts-recovery.mjs", "s3:PutBucketPolicy", "stage-a-artifacts-recovery-root-put-policy", [PRODUCTION_ARTIFACTS_BUCKET], "ROOT_OPERATOR"],
  ["scripts/aws/run-production-stage-a-production-artifacts-recovery.mjs", "s3:GetBucketLocation", "stage-a-artifacts-reconciliation-terraform-read-bucket-location", [STAGE_B_TERRAFORM_BACKEND.bucketArn]],
  ["scripts/aws/run-production-stage-a-production-artifacts-recovery.mjs", "sts:GetCallerIdentity", "stage-a-artifacts-recovery-release-identify", ["*"]],
  ["scripts/aws/run-production-stage-a-production-artifacts-recovery.mjs", "sts:GetCallerIdentity", "stage-a-artifacts-recovery-root-identify", ["*"], "ROOT_OPERATOR"],
  ["scripts/aws/production-stage-a-root-drop-orphan-recovery.mjs", "s3:PutObject", "stage-a-artifacts-recovery-release-lock-acquire", [STAGE_A_TERRAFORM_LOCK_ARN]],
  ["scripts/aws/production-stage-a-root-drop-orphan-recovery.mjs", "s3:DeleteObject", "stage-a-artifacts-recovery-release-lock-release", [STAGE_A_TERRAFORM_LOCK_ARN]],
  ["scripts/aws/production-release-preflight-checker-attestation.mjs", "sts:GetCallerIdentity", "administrator-release-preflight-trust-attestation-identify", ["*"], "ADMINISTRATOR"],
  ["scripts/aws/production-ecs-rollback-viability.mjs", "ecr:DescribeImages", "manifest-backend-health-recovery-describe-images", [REPOSITORY]],
  ["scripts/aws/production-ecs-rollback-viability.mjs", "ecs:DescribeServiceDeployments", "manifest-backend-health-recovery-describe-service-deployments", [SERVICE, "arn:aws:ecs:eu-west-2:368992683803:service-deployment/mscqr-prod-euw2-main/mscqr-backend-servi-euw2/*"]],
  ["scripts/aws/production-ecs-rollback-viability.mjs", "ecs:DescribeServiceRevisions", "manifest-backend-health-recovery-describe-service-revisions", [SERVICE, "arn:aws:ecs:eu-west-2:368992683803:service-revision/mscqr-prod-euw2-main/mscqr-backend-servi-euw2/*"]],
  ["scripts/aws/production-ecs-rollback-viability.mjs", "ecs:DescribeServices", "manifest-reference-audit-ecs-service-details", [SERVICE]],
  ["scripts/aws/production-ecs-rollback-viability.mjs", "ecs:DescribeTaskDefinition", "manifest-reference-audit-ecs-task-definitions", [TASKS]],
  ["scripts/aws/production-ecs-task-census.mjs", "ecs:DescribeTasks", "manifest-reference-audit-ecs-task-details", [TASKS]],
  ["scripts/aws/production-ecs-rollback-viability.mjs", "ecs:ListServiceDeployments", "manifest-backend-health-recovery-list-service-deployments", [SERVICE]],
  ["scripts/aws/production-ecs-task-census.mjs", "ecs:ListTasks", "manifest-reference-audit-ecs-tasks", [TASKS]],
  ["scripts/aws/production-green-stage-b-identity-capabilities.mjs", "ecs:DescribeServiceDeployments", "manifest-backend-health-recovery-describe-service-deployments", [SERVICE, "arn:aws:ecs:eu-west-2:368992683803:service-deployment/mscqr-prod-euw2-main/mscqr-backend-servi-euw2/*"]],
  ["scripts/aws/production-green-stage-b-identity-capabilities.mjs", "ecs:DescribeServiceRevisions", "manifest-backend-health-recovery-describe-service-revisions", [SERVICE, "arn:aws:ecs:eu-west-2:368992683803:service-revision/mscqr-prod-euw2-main/mscqr-backend-servi-euw2/*"]],
  ["scripts/aws/production-green-stage-b-identity-capabilities.mjs", "ecs:ListServiceDeployments", "manifest-backend-health-recovery-list-service-deployments", [SERVICE]],
  ["scripts/aws/production-green-stage-b-identity-capabilities.mjs", "ecr:GetRepositoryPolicy", "manifest-backend-health-recovery-runtime-repository-policy", RUNTIME_REPOSITORIES],
  ["scripts/aws/production-normal-backend-activation.mjs", "ecr:DescribeImages", "manifest-backend-health-recovery-describe-images", [REPOSITORY]],
  ["scripts/aws/deploy-ecs-service.sh", "ecr:DescribeImages", "manifest-backend-health-recovery-describe-images", [REPOSITORY]],
  ["scripts/aws/converge-production-ecs-runtime-policy.mjs", "iam:GetRole", "runtime-admin-get-role", ["arn:aws:iam::368992683803:role/mscqr-ecs-execution-role"], "ADMINISTRATOR"],
  ["scripts/aws/converge-production-ecs-runtime-policy.mjs", "iam:GetRolePolicy", "runtime-admin-get-inline", ["arn:aws:iam::368992683803:role/mscqr-ecs-execution-role"], "ADMINISTRATOR"],
  ["scripts/aws/converge-production-ecs-runtime-policy.mjs", "iam:ListAttachedRolePolicies", "runtime-admin-list-attached", ["*"], "ADMINISTRATOR"],
  ["scripts/aws/converge-production-ecs-runtime-policy.mjs", "iam:PutRolePolicy", "runtime-admin-converge-inline", ["arn:aws:iam::368992683803:role/mscqr-ecs-execution-role"], "ADMINISTRATOR"],
  ["scripts/aws/converge-production-ecs-runtime-policy.mjs", "sts:GetCallerIdentity", "runtime-admin-identify", ["*"], "ADMINISTRATOR"],
  ["scripts/aws/production-root-attestation-signer.mjs", "kms:Sign", "runtime-admin-sign", [ROOT_ATTESTATION_KEY], "ADMINISTRATOR"],
  ["scripts/aws/production-root-attestation-key.mjs", "kms:Verify", "release-root-attestation-verify", [ROOT_ATTESTATION_KEY]],
  ["scripts/aws/prepare-production-ecs-runtime-consumability.mjs", "sts:GetCallerIdentity", "runtime-admin-identify", ["*"], "ADMINISTRATOR"],
  ["scripts/aws/production-ecs-runtime-consumability.mjs", "iam:GetPolicy", "manifest-backend-health-recovery-runtime-get-managed", ["arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"]],
  ["scripts/aws/production-ecs-runtime-consumability.mjs", "iam:GetPolicyVersion", "manifest-backend-health-recovery-runtime-get-managed-version", ["arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"]],
  ["scripts/aws/production-ecs-runtime-consumability.mjs", "iam:GetRole", "manifest-backend-health-recovery-runtime-get-role", ["arn:aws:iam::368992683803:role/mscqr-ecs-execution-role"]],
  ["scripts/aws/production-ecs-runtime-consumability.mjs", "iam:GetRolePolicy", "manifest-backend-health-recovery-runtime-get-inline", ["arn:aws:iam::368992683803:role/mscqr-ecs-execution-role"]],
  ["scripts/aws/production-ecs-runtime-consumability.mjs", "iam:ListAttachedRolePolicies", "manifest-backend-health-recovery-runtime-list-attached", ["*"]],
  ["scripts/aws/production-ecs-runtime-consumability.mjs", "iam:ListRolePolicies", "manifest-backend-health-recovery-runtime-list-inline", ["arn:aws:iam::368992683803:role/mscqr-ecs-execution-role"]],
  ["scripts/aws/production-ecs-runtime-consumability.mjs", "iam:SimulatePrincipalPolicy", "runtime-admin-simulate", ["arn:aws:iam::368992683803:role/mscqr-ecs-execution-role"], "ADMINISTRATOR"],
  ["scripts/aws/production-ecs-runtime-consumability.mjs", "secretsmanager:DescribeSecret", "manifest-backend-health-recovery-runtime-describe-secrets", ["arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/*", "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/*"]],
  ["scripts/aws/production-ecs-runtime-consumability.mjs", "secretsmanager:GetSecretValue", "manifest-backend-health-recovery-runtime-get-secret-values", ["arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/*", "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/*"]],
  ["scripts/aws/production-ecs-runtime-consumability.mjs", "secretsmanager:ListSecretVersionIds", "manifest-backend-health-recovery-runtime-list-secret-versions", ["arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/*", "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/*"]],
  ["scripts/aws/production-ecs-runtime-consumability.mjs", "secretsmanager:GetResourcePolicy", "manifest-backend-health-recovery-runtime-secret-resource-policy", ["arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/*", "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/*"]],
  ["scripts/aws/production-ecs-runtime-consumability.mjs", "ecr:DescribeImages", "runtime-admin-describe-runtime-image", RUNTIME_REPOSITORIES, "ADMINISTRATOR"],
  ["scripts/aws/production-ecs-runtime-consumability.mjs", "ecr:GetRepositoryPolicy", "manifest-backend-health-recovery-runtime-repository-policy", RUNTIME_REPOSITORIES],
  ["scripts/aws/production-ecs-runtime-consumability.mjs", "logs:DescribeLogGroups", "manifest-refresh-stage-a-provider-log-groups", ["*"]],
  ["scripts/aws/production-root-attestation-key.mjs", "kms:DescribeKey", "release-root-attestation-describe-key", [ROOT_ATTESTATION_KEY]],
  ["scripts/aws/production-root-attestation-key.mjs", "kms:GetKeyPolicy", "release-root-attestation-read-key-policy", [ROOT_ATTESTATION_KEY]],
  ["scripts/aws/production-root-attestation-key.mjs", "kms:ListResourceTags", "release-root-attestation-read-key-tags", [ROOT_ATTESTATION_KEY]],
  ["scripts/aws/recover-production-backend-health.mjs", "kms:DescribeKey", "manifest-refresh-stage-a-storage-approval-key-describe", [RUNTIME_KMS_KEY]],
  ["scripts/aws/recover-production-backend-health.mjs", "kms:GetKeyPolicy", "manifest-refresh-stage-a-storage-approval-key-policy", [RUNTIME_KMS_KEY]],
  ["scripts/aws/run-production-initial-activation-lifecycle-policy-reconciliation.mjs", "sts:GetCallerIdentity", "initial-activation-policy-reconciliation-root-identify", ["*"], "ROOT_OPERATOR"],
  ["scripts/aws/run-production-initial-activation-lifecycle-policy-reconciliation.mjs", "iam:GetPolicy", "initial-activation-policy-reconciliation-root-read-policy", ["arn:aws:iam::368992683803:policy/MSCQRProductionInitialActivationLifecycle"], "ROOT_OPERATOR"],
  ["scripts/aws/run-production-initial-activation-lifecycle-policy-reconciliation.mjs", "iam:GetPolicyVersion", "initial-activation-policy-reconciliation-root-read-policy-version", ["arn:aws:iam::368992683803:policy/MSCQRProductionInitialActivationLifecycle"], "ROOT_OPERATOR"],
  ["scripts/aws/run-production-initial-activation-lifecycle-policy-reconciliation.mjs", "iam:ListPolicyVersions", "initial-activation-policy-reconciliation-root-list-policy-versions", ["arn:aws:iam::368992683803:policy/MSCQRProductionInitialActivationLifecycle"], "ROOT_OPERATOR"],
  ["scripts/aws/run-production-initial-activation-lifecycle-policy-reconciliation.mjs", "iam:GetRole", "initial-activation-policy-reconciliation-root-read-release-role", ["arn:aws:iam::368992683803:role/mscqr-production-release-deployer"], "ROOT_OPERATOR"],
  ["scripts/aws/run-production-initial-activation-lifecycle-policy-reconciliation.mjs", "iam:ListAttachedRolePolicies", "initial-activation-policy-reconciliation-root-read-policy-attachment", ["arn:aws:iam::368992683803:role/mscqr-production-release-deployer"], "ROOT_OPERATOR"],
  ["scripts/aws/run-production-initial-activation-lifecycle-policy-reconciliation.mjs", "iam:ListEntitiesForPolicy", "initial-activation-policy-reconciliation-root-list-policy-entities", ["arn:aws:iam::368992683803:policy/MSCQRProductionInitialActivationLifecycle"], "ROOT_OPERATOR"],
  ["scripts/aws/run-production-initial-activation-lifecycle-policy-reconciliation.mjs", "iam:CreatePolicyVersion", "initial-activation-policy-reconciliation-root-create-policy-version", ["arn:aws:iam::368992683803:policy/MSCQRProductionInitialActivationLifecycle"], "ROOT_OPERATOR"],
  ["scripts/aws/production-initial-activation-policy-reconciliation.mjs", "s3:GetObject", "initial-activation-policy-reconciliation-root-read-reservation-exact", [INITIAL_ACTIVATION_RESERVATION], "ROOT_OPERATOR", "initial-activation-policy-reconciliation-root-read-reservation-exact"],
  ["scripts/aws/production-initial-activation-policy-reconciliation.mjs", "s3:PutObject", "initial-activation-policy-reconciliation-root-conditional-create-reservation-exact", [INITIAL_ACTIVATION_RESERVATION], "ROOT_OPERATOR", "initial-activation-policy-reconciliation-root-conditional-create-reservation-exact"],
].map(([sourceFile, action, capabilityId, resources, identity = "RELEASE_DEPLOYER", sourceFunction]) => Object.freeze({ sourceFile, action, capabilityId, identity, resources: Object.freeze(resources), ...(sourceFunction ? { sourceFunction } : {}) })));
const stageARootVerifierCapability = (capabilityId) => ["release-root-attestation-verify", "release-root-attestation-describe-key", "release-root-attestation-read-key-policy", "release-root-attestation-read-key-tags"].includes(capabilityId);

const STAGE_A_RECOVERY_MODE = "STAGE_A_PRODUCTION_ARTIFACTS_POLICY_RECOVERY";
const STAGE_A_RECONCILIATION_MODE = "STAGE_A_PRODUCTION_ARTIFACTS_STATE_RECONCILIATION";
const INITIAL_ACTIVATION_POLICY_RECONCILIATION_MODE = "INITIAL_ACTIVATION_POLICY_RECONCILIATION";
const STAGE_A_CAPABILITY_MODES = Object.freeze({
  "stage-a-artifacts-recovery-root-identify": [STAGE_A_RECOVERY_MODE],
  "stage-a-artifacts-recovery-root-read-versioning": [STAGE_A_RECOVERY_MODE],
  "stage-a-artifacts-recovery-root-read-lifecycle": [STAGE_A_RECOVERY_MODE],
  "stage-a-artifacts-recovery-root-put-policy": [STAGE_A_RECOVERY_MODE],
  "stage-a-artifacts-recovery-release-identify": [STAGE_A_RECOVERY_MODE],
  "stage-a-artifacts-recovery-release-read-policy": [STAGE_A_RECOVERY_MODE],
  "stage-a-artifacts-recovery-release-read-raw-state": [STAGE_A_RECOVERY_MODE],
  "stage-a-artifacts-recovery-root-journal-read": [STAGE_A_RECOVERY_MODE],
  "stage-a-artifacts-recovery-root-journal-conditional-create": [STAGE_A_RECOVERY_MODE],
  "stage-a-artifacts-recovery-root-sign": [STAGE_A_RECOVERY_MODE],
  "stage-a-artifacts-recovery-release-lock-acquire": [STAGE_A_RECOVERY_MODE, STAGE_A_RECONCILIATION_MODE],
  "stage-a-artifacts-recovery-release-lock-release": [STAGE_A_RECOVERY_MODE, STAGE_A_RECONCILIATION_MODE],
  "stage-a-artifacts-journal-read": [STAGE_A_RECOVERY_MODE, STAGE_A_RECONCILIATION_MODE],
  "stage-a-artifacts-journal-conditional-create": [STAGE_A_RECOVERY_MODE, STAGE_A_RECONCILIATION_MODE],
  "stage-a-artifacts-reconciliation-release-identify": [STAGE_A_RECONCILIATION_MODE],
  "stage-a-artifacts-reconciliation-root-identify": [STAGE_A_RECONCILIATION_MODE],
  "stage-a-artifacts-reconciliation-root-journal-read": [STAGE_A_RECONCILIATION_MODE],
  "stage-a-artifacts-reconciliation-release-read-policy": [STAGE_A_RECONCILIATION_MODE],
  "stage-a-artifacts-reconciliation-release-read-raw-state": [STAGE_A_RECONCILIATION_MODE],
  "stage-a-artifacts-reconciliation-terraform-read-bucket-location": [STAGE_A_RECOVERY_MODE, STAGE_A_RECONCILIATION_MODE],
  "stage-a-artifacts-reconciliation-terraform-read-state": [STAGE_A_RECOVERY_MODE, STAGE_A_RECONCILIATION_MODE],
  "stage-a-artifacts-reconciliation-terraform-write-state": [STAGE_A_RECONCILIATION_MODE],
  "stage-a-artifacts-reconciliation-terraform-read-lock": [STAGE_A_RECONCILIATION_MODE],
  "release-root-attestation-verify": [STAGE_A_RECOVERY_MODE, STAGE_A_RECONCILIATION_MODE],
  "release-root-attestation-describe-key": [STAGE_A_RECOVERY_MODE, STAGE_A_RECONCILIATION_MODE],
  "release-root-attestation-read-key-policy": [STAGE_A_RECOVERY_MODE, STAGE_A_RECONCILIATION_MODE],
  "release-root-attestation-read-key-tags": [STAGE_A_RECOVERY_MODE, STAGE_A_RECONCILIATION_MODE],
});
const STAGE_A_MUTATING_CAPABILITIES = new Set(["stage-a-artifacts-recovery-root-put-policy", "stage-a-artifacts-recovery-root-journal-conditional-create", "stage-a-artifacts-recovery-root-sign", "stage-a-artifacts-recovery-release-lock-acquire", "stage-a-artifacts-recovery-release-lock-release", "stage-a-artifacts-journal-conditional-create", "stage-a-artifacts-reconciliation-terraform-write-state"]);
const stageACapabilitiesFor = (mode) => Object.entries(STAGE_A_CAPABILITY_MODES).filter(([, modes]) => modes.includes(mode)).map(([id]) => id);

const MODE_CAPABILITIES = Object.freeze({
  [INITIAL_ACTIVATION_POLICY_RECONCILIATION_MODE]: ["initial-activation-policy-reconciliation-root-identify", "initial-activation-policy-reconciliation-root-read-policy", "initial-activation-policy-reconciliation-root-read-policy-version", "initial-activation-policy-reconciliation-root-list-policy-versions", "initial-activation-policy-reconciliation-root-read-release-role", "initial-activation-policy-reconciliation-root-read-policy-attachment", "initial-activation-policy-reconciliation-root-list-policy-entities", "initial-activation-policy-reconciliation-root-create-policy-version"],
  NORMAL: ["manifest-backend-health-recovery-describe-images", "manifest-backend-health-recovery-runtime-repository-policy", "normal-activation-release-describe-candidate", "normal-activation-release-describe-service", "normal-activation-release-list-tasks", "normal-activation-release-describe-tasks", "normal-activation-release-update-service"],
  BACKEND_HEALTH_RECOVERY_LEGACY_RUNTIME: ["manifest-backend-health-recovery-describe-images", "manifest-backend-health-recovery-describe-repositories", "manifest-reference-audit-ecs-service-details", "manifest-reference-audit-ecs-task-definitions", "manifest-reference-audit-ecs-tasks", "manifest-reference-audit-ecs-task-details", "manifest-backend-health-recovery-list-service-deployments", "manifest-backend-health-recovery-describe-service-deployments", "manifest-backend-health-recovery-describe-service-revisions", "manifest-artifact-signing-bootstrap-describe-secret", "manifest-artifact-signing-bootstrap-get-secret-value", "manifest-backend-health-recovery-runtime-get-role", "manifest-backend-health-recovery-runtime-list-inline", "manifest-backend-health-recovery-runtime-get-inline", "manifest-backend-health-recovery-runtime-list-attached", "manifest-backend-health-recovery-runtime-get-managed", "manifest-backend-health-recovery-runtime-get-managed-version", "manifest-backend-health-recovery-runtime-describe-secrets", "manifest-backend-health-recovery-runtime-get-secret-values", "manifest-backend-health-recovery-runtime-list-secret-versions", "manifest-backend-health-recovery-runtime-secret-resource-policy", "manifest-backend-health-recovery-runtime-repository-policy", "manifest-refresh-stage-a-provider-log-groups", "manifest-refresh-stage-a-storage-approval-key-describe", "manifest-refresh-stage-a-storage-approval-key-policy", "release-verify-signature", "manifest-backend-health-recovery-register-legacy-task-definition", "manifest-backend-health-recovery-update-service", "release-root-attestation-verify", "release-root-attestation-describe-key", "release-root-attestation-read-key-policy", "release-root-attestation-read-key-tags"],
  [STAGE_A_RECOVERY_MODE]: stageACapabilitiesFor(STAGE_A_RECOVERY_MODE),
  [STAGE_A_RECONCILIATION_MODE]: stageACapabilitiesFor(STAGE_A_RECONCILIATION_MODE),
  ROTATION_OVERLAP: ["manifest-backend-health-recovery-describe-images", "manifest-backend-health-recovery-runtime-repository-policy", "manifest-reference-audit-ecs-service-details", "manifest-reference-audit-ecs-task-definitions", "manifest-reference-audit-ecs-tasks", "manifest-reference-audit-ecs-task-details", "manifest-activate-exact-ecs-service", "manifest-rollback-exact-ecs-service"],
  ROTATION_CLEANUP: ["manifest-backend-health-recovery-describe-images", "manifest-backend-health-recovery-runtime-repository-policy", "manifest-reference-audit-ecs-service-details", "manifest-reference-audit-ecs-task-definitions", "manifest-reference-audit-ecs-tasks", "manifest-reference-audit-ecs-task-details", "manifest-activate-exact-ecs-service", "manifest-rollback-exact-ecs-service"],
  ROLLBACK_RECONCILIATION: ["manifest-backend-health-recovery-list-service-deployments", "manifest-backend-health-recovery-describe-service-deployments", "manifest-backend-health-recovery-describe-service-revisions", "manifest-reference-audit-ecs-service-details", "manifest-reference-audit-ecs-task-definitions", "manifest-reference-audit-ecs-tasks", "manifest-reference-audit-ecs-task-details", "manifest-backend-health-recovery-describe-images"],
  POST_DEPLOY_VERIFY: ["operator-operator-describe-production-backend-service", "operator-operator-list-production-backend-tasks", "operator-operator-describe-production-backend-tasks", "operator-operator-describe-production-task-definition", "operator-operator-execute-production-backend"],
});

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const read = (file) => fs.readFileSync(path.join(root, file), "utf8");
const same = (left, right) => canonicalizeJson(left) === canonicalizeJson(right);
const requireTokens = (file, tokens) => {
  const source = read(file);
  for (const token of tokens) if (!source.includes(token)) throw new Error(`Production runtime dependency is missing from ${file}: ${token}.`);
};

export function assertNoUnknownRollbackDependency(source = read("scripts/aws/production-ecs-rollback-viability.mjs")) {
  const nonLocalImports = [...source.matchAll(/from\s+["']([^"']+)["']/g)].map((match) => match[1]).filter((value) => !value.startsWith(".") && !value.startsWith("node:"));
  if (nonLocalImports.length) throw new Error("Rollback viability introduced an undeclared external Node dependency.");
  if (/process\.env/.test(source)) throw new Error("Rollback viability introduced an unclassified environment dependency.");
  return true;
}

export function assertRollbackSemanticBoundary(source = read("scripts/aws/production-ecs-rollback-viability.mjs")) {
  for (const token of [
    "const forwardArn = deployment?.targetServiceRevision?.arn",
    "const rollbackArn = deployment?.rollback?.serviceRevisionArn",
    "const sourceArns = (deployment?.sourceServiceRevisions || [])",
    "forwardTargetServiceRevisionArn", "rollbackServiceRevisionArn", "sourceServiceRevisions",
    "service?.deployments", "rollbackEcsServiceDeploymentId", "ECS_SERVICE_DEPLOYMENT_ID", "attempt.startedBy === rollbackEcsServiceDeploymentId", "Date.parse(attempt.createdAt) >= rollbackStartedAt", "failureReasonSha256",
  ]) if (!source.includes(token)) throw new Error(`Rollback service-revision semantic boundary is missing: ${token}.`);
  if (/rollbackArn\s*=\s*deployment\?\.targetServiceRevision|rollbackServiceRevisionArn:\s*deployment\?\.targetServiceRevision/.test(source)) {
    throw new Error("Rollback viability must never derive rollback authority from targetServiceRevision.");
  }
  if (/failures\.length\s*>=\s*2/.test(source)) throw new Error("Rollback viability must never count failures without current deployment identity.");
  if (/DEPLOYMENT_ARN\.exec\([^\n]+\)\?\.\[1\].*startedBy|startedBy.*DEPLOYMENT_ARN\.exec/.test(source)) throw new Error("Task.startedBy must never be derived from a service-deployment ARN suffix.");
  return true;
}

export function buildProductionDependencyClosure() {
  const graph = JSON.parse(read(CAPABILITY_GRAPH_PATH));
  assertStageBDeploymentCapabilityGraph(graph);
  const newAwsCalls = assertChangedAwsCallClosure(discoverAwsCliActions(), graph);
  assertStageAProductionArtifactsCapabilityClosure(newAwsCalls, graph);

  const capabilityById = new Map(graph.capabilities.map((capability) => [capability.id, capability]));
  for (const [mode, ids] of Object.entries(MODE_CAPABILITIES)) for (const id of ids) {
    const capability = capabilityById.get(id);
    if (!capability || !capability.identity || !capability.action || !capability.resources?.length || !capability.policy?.sourceFile) throw new Error(`Production mode ${mode} lacks exact capability ${id}.`);
  }
  for (const { reachableMode } of newAwsCalls) for (const mode of reachableMode) {
    if (!Object.hasOwn(MODE_CAPABILITIES, mode)) throw new Error(`Reachable production mode ${mode} is undeclared.`);
  }
  const workflow = read(".github/workflows/release-gate.yml");
  const workflowDispatchInputCount = [...workflow.matchAll(/^      [a-z0-9_]+:$/gm)].length;
  if (workflowDispatchInputCount > 25) throw new Error(`Release Gate exceeds GitHub's 25-input workflow_dispatch limit: ${workflowDispatchInputCount}.`);
  const workflowInputs = [...workflow.matchAll(/^      (backend_recovery_[a-z0-9_]+):$/gm)].map((match) => match[1]).sort();
  const expectedInputs = ["backend_recovery_current_task_definition_arn", "backend_recovery_evidence_bundle_json", "backend_recovery_evidence_bundle_sha256", "backend_recovery_image_digest"];
  if (!same(workflowInputs, expectedInputs)) throw new Error("Backend recovery workflow input contract is incomplete or has an unknown input.");
  if (!same([...ARTIFACT_SIGNING_BINDINGS].sort(), ["ARTIFACT_SIGN_ACTIVE_KEY_VERSION", "ARTIFACT_SIGN_PRIVATE_KEY_CURRENT", "ARTIFACT_SIGN_PUBLIC_KEYS_JSON", "ARTIFACT_SIGN_PUBLIC_KEY_CURRENT"])) throw new Error("Artifact-signing runtime dependency set is incomplete.");
  requireTokens("scripts/aws/production-ecs-rollback-viability.mjs", ["targetServiceRevision?.arn", "rollback?.serviceRevisionArn", "sourceServiceRevisions", "describe-service-revisions", "serviceRevisions", "revision?.taskDefinition", "forwardTargetTaskDefinitionFingerprint", "taskDefinitionFingerprint", "ImageNotFoundException", "ECR_LOOKUP_FAILED"]);
  requireTokens("scripts/aws/production-backend-health-recovery-contract.mjs", ["rollbackProof", "rollbackDeploymentArn", "rollbackTargetTaskDefinitionArn", "rollbackTargetDigest", "forwardTargetTaskDefinitionFingerprint", "recoveryHistory", "predecessorHistoryReferenceSha256", "predecessorHistoryLineageSha256", "recoveryHistoryLineageSha256", "reconcileAuthenticatedRevisionLineage", "openInterruptedRecoveryHistory", "knownFailedRevisions", "interruptedRecoveries", "classifyInterruptedRecoveryState", "Interrupted recovery live state changed before mutation", "Legacy backend revision census changed before recovery registration", "assertFreshRollbackEquivalence", "assertFreshRuntimeConsumabilityVerification", "TASK_DEFINITION_REGISTRATION_ATTEMPTED", "SERVICE_UPDATE_ATTEMPTED"]);
  requireTokens("scripts/aws/production-backend-failed-recovery-evidence.mjs", ["AUTHENTICATED_BACKEND_FAILED_RECOVERY_EVIDENCE", "PRE_RUNTIME_CLOSURE_LEGACY_EVIDENCE", "NOT_PART_OF_SCHEMA", "requiresLiveFailureReconciliation", "recoveryEvidence", "environmentApproval", "runtimeConsumability", "evidenceFileSha256", "workflowRunId", "taskDefinitionFingerprint", "SERVICE_STABILIZATION_FAILED", "assertRuntimeConsumabilityEnvelopeSignature"]);
  requireTokens("scripts/aws/prepare-production-backend-failed-recovery-evidence.mjs", ["PRE_RUNTIME_CLOSURE_LEGACY_EVIDENCE", "backend-health-recovery-evidence", "workflow_dispatch", "describe-task-definition", "TAGS", "taskDefinitionFingerprint", "log_url", "NOT_PART_OF_SCHEMA"]);
  requireTokens("scripts/aws/recover-production-backend-health.mjs", ["rollbackProofSha256", "authenticatedFailedRecoveryEvidence", "assertAuthenticatedFailedRecoveryEvidence", "await record();", "resolveArtifactSigning", "readFreshRollbackViability"]);
  requireTokens("scripts/aws/dispatch-production-backend-health-recovery.mjs", ["failedRecoveryEvidenceReference", "failedRecoveryEvidenceReferenceSha256", "schemaVersion: 3", "WORKFLOW_DISPATCH_INTERNAL_BUDGET", "measureWorkflowDispatchInputs"]);
  requireTokens("scripts/aws/production-backend-failed-recovery-evidence-reference.mjs", ["IMMUTABLE_GITHUB_RELEASE_FAILED_RECOVERY_EVIDENCE", "immutable", "assetDigest", "evidenceByteSha256", "referenceSha256"]);
  requireTokens("scripts/aws/publish-production-backend-failed-recovery-evidence.mjs", ["inspectRemote", "ABSENT", "MUTABLE_DRAFT_EMPTY", "MUTABLE_DRAFT_READY", "IMMUTABLE_PUBLISHED", "release", "create", "release", "upload", "release", "edit", "--draft=false"]);
  requireTokens("scripts/aws/resolve-production-backend-failed-recovery-evidence.mjs", ["assertFailedRecoveryEvidenceReleaseReadback", "Accept: application/octet-stream"]);
  requireTokens("scripts/aws/dispatch-production-backend-health-recovery.mjs", ["ROLLBACK_APPROVAL_FIELDS", "BACKEND_HEALTH_RECOVERY_DISPATCH_BUNDLE", "backend_recovery_evidence_bundle_json", "backend_recovery_evidence_bundle_sha256"]);
  requireTokens(".github/workflows/release-gate.yml", ["contents: read", "resolve-production-backend-failed-recovery-evidence.mjs", "failed-recovery-evidence-reference-sha256"]);
  requireTokens("scripts/aws/production-ecs-runtime-dependencies.mjs", ["deriveEcsRuntimeDependencies", "parseEcsSecretsManagerReference", "secretSelector", "EXECUTION_ROLE", "TASK_ROLE", "secretsmanager:GetSecretValue"]);
  requireTokens("scripts/aws/production-ecs-runtime-consumability.mjs", ["kms:Decrypt", "assertSignedRuntimeDependencyInventory", "buildRuntimeDependencyInventory", "assertSignedRuntimeConsumabilityEvidence", "assertFreshRuntimeConsumabilityVerification", "RUNTIME_AUTHORIZATION_MAX_AGE_MS", "LIVE_RUNTIME_EVIDENCE_MAX_AGE_MS", "signedBindingSha256", "simulateRuntimeDependencies", "secretsmanager", "get-resource-policy", "get-repository-policy", "list-secret-version-ids", "--include-deprecated", "DeletedDate", "VersionIdsToStages", "secretVersions", "selectorResolutions", "refreshRuntimeResourceMetadata"]);
  requireTokens("scripts/aws/production-ecs-task-census.mjs", ["--starting-token", "NextToken", "maxPages", "describeBatchSize", "collectEcsServiceTasks"]);
  requireTokens("scripts/aws/converge-production-ecs-runtime-policy.mjs", ["candidateFileSha256", "candidateCanonicalSha256", "runtimeInventorySha256", "expectedLivePolicySha256", "LIVE_POLICY_CHANGED_SINCE_APPROVAL", "Final prewrite runtime policy", "POSTWRITE_POLICY_READBACK_MISMATCH"]);
  requireTokens("scripts/aws/prepare-production-backend-recovery-candidate.mjs", ["candidateFileSha256", "candidateCanonicalSha256", "candidateFingerprint"]);
  requireTokens("scripts/aws/prepare-production-ecs-runtime-consumability.mjs", ["prepareProductionEcsRuntimeInventory", "prepareProductionEcsRuntimeConsumability", "--candidate-file-sha256", "--runtime-inventory"]);
  requireTokens("package.json", ["production-ecs-recovery-runtime-rehearsal.test.mjs"]);
  for (const file of ["scripts/aws/production-green-stage-b-task-definitions.mjs", "scripts/aws/production-overlap-task-definition.mjs", "scripts/aws/production-predeployment-inventory-task.mjs"]) requireTokens(file, ["deriveEcsRuntimeDependencies"]);
  requireTokens("scripts/aws/recover-production-backend-health.mjs", ["verifyRuntimeClosure", "refreshRuntimeResourceMetadata", "collectLiveRolePolicyIdentity"]);
  requireTokens("scripts/aws/deploy-ecs-service.sh", ["ROLLBACK_IMAGE_DIGEST", "ecr describe-images", "Rollback candidate image viability could not be authenticated"]);
  const deploy = read("scripts/aws/deploy-ecs-service.sh");
  if (deploy.indexOf("aws ecr describe-images") > deploy.indexOf("update_args=(aws ecs update-service")) throw new Error("Existing-task deployment can mutate before rollback image viability is authenticated.");
  if (!workflow.includes("node scripts/aws/run-production-cutover.mjs") || !workflow.includes("--mode rotation-overlap")) throw new Error("Rotation workflow no longer routes through the governed existing-task cutover.");
  requireTokens("scripts/aws/production-normal-backend-activation.mjs", ["assertRollbackImageAvailable", "rollbackImageVerified: true"]);
  assertNoUnknownRollbackDependency();
  assertRollbackSemanticBoundary();
  const recoveryTest = read("scripts/tests/production-ecs-rollback-viability.test.mjs");
  for (const token of ["AccessDeniedException", "request timeout", "future-revision-N-minus-1", "describe-service-revisions", "pre-mutation equivalence", "ecs-svc/3599551810517927503", "foo/3599551810517927503", "task-attempt identity changed"]) if (!recoveryTest.includes(token)) throw new Error(`Rollback boundary lacks negative coverage: ${token}.`);
  if (!/const rollbackEcsServiceDeploymentId = "ecs-svc\/[1-9][0-9]*"/.test(recoveryTest)
    || !/startedBy: rollbackEcsServiceDeploymentId/.test(recoveryTest) || /startedBy: "future-deployment/.test(recoveryTest)) {
    throw new Error("Authorization-bearing ECS task fixtures must use the real ecs-svc/<numeric-id> Task.startedBy contract.");
  }
  const futureTest = read("scripts/tests/production-backend-health-recovery-contract.test.mjs");
  for (const token of ["future failed revision N", 'targetArn.replace(":998", ":1000")', "readRollbackViability", "global revision census admits only this transaction's exact registration", "unknown revision after own registration fails before update"]) if (!futureTest.includes(token)) throw new Error(`Future recovery revision closure lacks coverage: ${token}.`);

  return {
    schemaVersion: 1,
    baseProtectedSha: BASE_PROTECTED_SHA,
    status: "PASS",
    newAwsCalls,
    counters: { unmappedAwsActions: 0, iamActionMismatches: 0, iamResourceMismatches: 0, principalCapabilityMismatches: 0, missingRuntimeBindings: 0, missingWorkflowInputs: 0, missingEvidenceBindings: 0, unsupportedApiFixtures: 0 },
    runtimeDependencies: [
      { id: "ecs-service-deployment-shape", producer: "authenticated ECS API", consumer: "rollback viability collector", authority: "distinct targetServiceRevision, sourceServiceRevisions, and rollback.serviceRevisionArn resolved through DescribeServiceRevisions", failClosed: true },
      { id: "rollback-proof", producer: "bounded authenticated reconciliation", consumer: "approval authorization and recovery executor", authority: "live ECS and ECR with exact DescribeServices deployment id equal to Task.startedBy plus rollback-time-bound stopped-task evidence; the serviceDeploymentArn remains a separate identity", failClosed: true },
      { id: "artifact-signing-bindings", producer: "canonical Secrets Manager binding resolver", consumer: "recovery task-definition builder", authority: "exact four protected names and live secret references", failClosed: true },
      { id: "ecs-final-candidate-runtime-consumability", producer: "final candidate-derived runtime dependency graph plus governed administrator simulation", consumer: "every production ECS candidate builder and the recovery executor before registration and service update", authority: "exact execution/task role, action, resource, source policy, live policy identity, resource/key policy, and IAM simulation", failClosed: true },
      { id: "workflow-json-transport", producer: "canonical recovery dispatcher", consumer: "Release Gate recovery preparation", authority: "byte-identical JSON and SHA-256 transport", failClosed: true },
      { id: "rollback-image-viability", producer: "exact ECR digest readback", consumer: "normal, rotation, and recovery pre-mutation gates", authority: "canonical repository plus immutable digest", failClosed: true },
    ],
    modes: Object.fromEntries(Object.keys(MODE_CAPABILITIES).map((mode) => [mode, "PASS"])),
    runtimeModeClosure: {
      NORMAL: "Terraform-rendered final candidates and exact execution policies are jointly authenticated by Stage-B plan/closure before apply; normal activation registers nothing",
      BACKEND_HEALTH_RECOVERY_LEGACY_RUNTIME: "signed candidate-derived closure is re-read before RegisterTaskDefinition and before UpdateService",
      STAGE_A_PRODUCTION_ARTIFACTS_POLICY_RECOVERY: "the governed P0-to-P2 production-artifacts recovery uses its exact root/release journal, policy, lock, and attestation boundaries",
      STAGE_A_PRODUCTION_ARTIFACTS_STATE_RECONCILIATION: "the independently authorized exact refresh-only plan uses its exact release journal, live-policy read, Stage-A state object, and canonical outer lock boundary",
      INITIAL_ACTIVATION_POLICY_RECONCILIATION: "the independently approved root-operator reconciliation reads and atomically publishes only the exact InitialActivationLifecycle managed-policy version",
      ROTATION_OVERLAP: "the source-owned overlap candidate builder derives the complete runtime dependency graph before its governed registration",
      ROTATION_CLEANUP: "cleanup activates an already authenticated overlap/cleanup candidate and registers nothing",
      ROLLBACK_RECONCILIATION: "rollback viability uses immutable image/resource identity and performs no candidate registration",
      POST_DEPLOY_VERIFY: "post-deploy verification consumes the authenticated running task definition and registers nothing",
    },
    pathClosure: { forward: "PASS", rollback: "PASS", reconciliation: "PASS" },
  };
}

export function assertChangedAwsCallClosure(scanned, graph) {
  const identityBound = (sourceFile) => ["scripts/aws/production-stage-a-production-artifacts-journal.mjs", "scripts/aws/production-root-attestation-signer.mjs", "scripts/aws/run-production-stage-a-production-artifacts-recovery.mjs", "scripts/aws/run-production-stage-a-production-artifacts-reconciliation.mjs", "scripts/aws/production-initial-activation-policy-reconciliation.mjs"].includes(sourceFile);
  const key = ({ sourceFile, action, identity = "RELEASE_DEPLOYER", sourceFunction = "", capabilityId = "" }) => `${sourceFile}\t${action}\t${identityBound(sourceFile) ? identity : ""}\t${capabilityId.endsWith("-read-raw-state") ? sourceFunction : ""}`;
  const callKeys = new Set(CALLS.map(key));
  const normalized = scanned.map(({ sourceFile, action, identity, sourceFunction, capabilityId }) => {
    const rawStateSource = capabilityId?.endsWith("-read-raw-state");
    return identityBound(sourceFile) ? { sourceFile, action, identity, ...(rawStateSource ? { sourceFunction, capabilityId } : {}) } : { sourceFile, action, ...(rawStateSource ? { sourceFunction, capabilityId } : {}) };
  });
  const additions = normalized.filter((call) => callKeys.has(key(call)));
  if (additions.length !== CALLS.length || new Set(additions.map(key)).size !== CALLS.length) throw new Error("Changed production AWS calls differ from the reviewed closure contract.");
  const baseline = normalized.filter((call) => !callKeys.has(key(call))).sort((a, b) => `${a.sourceFile}:${a.action}`.localeCompare(`${b.sourceFile}:${b.action}`));
  if (baseline.length !== BASE_CALL_COUNT || sha256(JSON.stringify(baseline)) !== BASE_CALL_SHA256) throw new Error("Unknown production AWS call requires capability classification.");

  const capabilityById = new Map(graph.capabilities.map((capability) => [capability.id, capability]));
  return CALLS.map((contract) => {
    const capability = capabilityById.get(contract.capabilityId);
    const stageAModes = STAGE_A_CAPABILITY_MODES[contract.capabilityId];
    const resourcesCompatible = stageAModes ? same(capability?.resources, contract.resources) : contract.resources.every((resource) => capability?.resources?.includes(resource)
      || (resource === SERVICE && capability?.resources?.includes("arn:aws:ecs:eu-west-2:368992683803:service/mscqr-prod-euw2-main/*")));
    const releaseProbe = contract.identity !== "RELEASE_DEPLOYER" || ["direct", "direct-live-read"].includes(capability?.probe) && capability?.probeIds?.length;
    if (!capability || capability.action !== contract.action || capability.identity !== contract.identity || !resourcesCompatible
      || !capability.policy?.sourceFile || !releaseProbe || stageAModes && capability.mutation !== STAGE_A_MUTATING_CAPABILITIES.has(contract.capabilityId)) {
      throw new Error(`Production AWS call lacks exact IAM/capability/preflight closure: ${contract.sourceFile} ${contract.action}.`);
    }
    if (contract.sourceFile.endsWith("deploy-ecs-service.sh")) {
      const rotation = capabilityById.get("manifest-backend-health-recovery-describe-images");
      if (!rotation || rotation.identity !== "RELEASE_DEPLOYER" || rotation.action !== contract.action || !same(rotation.resources, contract.resources) || !rotation.policy?.sourceFile) throw new Error("Rotation rollback-image read lacks exact IAM/capability closure.");
    }
    const reachableMode = stageAModes
      ? [...stageAModes, ...(stageARootVerifierCapability(contract.capabilityId) ? ["BACKEND_HEALTH_RECOVERY_LEGACY_RUNTIME"] : [])]
      : contract.sourceFile.endsWith("deploy-ecs-service.sh")
      ? ["NORMAL", "ROTATION_OVERLAP", "ROTATION_CLEANUP"]
      : contract.sourceFile.endsWith("production-normal-backend-activation.mjs") ? ["NORMAL"]
      : contract.sourceFile.endsWith("run-production-initial-activation-lifecycle-policy-reconciliation.mjs") || contract.sourceFile.endsWith("production-initial-activation-policy-reconciliation.mjs") ? [INITIAL_ACTIVATION_POLICY_RECONCILIATION_MODE] : ["BACKEND_HEALTH_RECOVERY_LEGACY_RUNTIME"];
    return { ...contract, reachableMode, executionPrincipal: contract.identity, sourcePolicyPresent: true, generatedManifestPresent: true, capabilityGraphPresent: true, administratorPreflightPresent: true, runtimePreflightPresent: true, negativeTestPresent: true };
  });
}

export function assertStageAProductionArtifactsCapabilityClosure(calls, graph) {
  const capabilityById = new Map(graph.capabilities.map((capability) => [capability.id, capability]));
  const stageACalls = calls.filter(({ capabilityId }) => STAGE_A_CAPABILITY_MODES[capabilityId]);
  if (new Set(stageACalls.map(({ capabilityId }) => capabilityId)).size !== Object.keys(STAGE_A_CAPABILITY_MODES).length) throw new Error("Stage A production-artifacts capability inventory is incomplete.");
  for (const call of stageACalls) {
    const capability = capabilityById.get(call.capabilityId); const modes = STAGE_A_CAPABILITY_MODES[call.capabilityId];
    const expectedModes = [...modes, ...(stageARootVerifierCapability(call.capabilityId) ? ["BACKEND_HEALTH_RECOVERY_LEGACY_RUNTIME"] : [])];
    if (!capability || !same(call.reachableMode, expectedModes) || call.identity !== capability.identity || call.action !== capability.action
      || !same(call.resources, capability.resources) || capability.mutation !== STAGE_A_MUTATING_CAPABILITIES.has(call.capabilityId)) throw new Error(`Stage A production-artifacts capability tuple is incomplete: ${call.capabilityId}.`);
  }
  for (const [id, modes] of Object.entries(STAGE_A_CAPABILITY_MODES)) {
    if (!stageACalls.some(({ capabilityId }) => capabilityId === id) || !modes.length) throw new Error(`Stage A production-artifacts capability is unreachable: ${id}.`);
  }
  for (const [mode, ids] of Object.entries(MODE_CAPABILITIES)) {
    const expected = Object.entries(STAGE_A_CAPABILITY_MODES).filter(([, modes]) => modes.includes(mode)).map(([id]) => id);
    if (expected.length && !same(ids.filter((id) => STAGE_A_CAPABILITY_MODES[id]), expected)) throw new Error(`Stage A production-artifacts mode attribution is incomplete: ${mode}.`);
  }
  return true;
}

export function assertProductionDependencyClosure(report = JSON.parse(read(PRODUCTION_DEPENDENCY_CLOSURE_PATH))) {
  const expected = buildProductionDependencyClosure();
  if (!same(report, expected)) throw new Error("Production dependency closure report is stale or incomplete.");
  return { status: "valid", newAwsCalls: report.newAwsCalls.length, runtimeDependencies: report.runtimeDependencies.length, unmappedAwsActions: 0, missingRuntimeBindings: 0 };
}

export function writeProductionDependencyClosure() {
  const report = buildProductionDependencyClosure();
  fs.writeFileSync(path.join(root, PRODUCTION_DEPENDENCY_CLOSURE_PATH), `${JSON.stringify(report, null, 2)}\n`);
  return assertProductionDependencyClosure(report);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) process.stdout.write(`${JSON.stringify(process.argv.includes("--write") ? writeProductionDependencyClosure() : assertProductionDependencyClosure())}\n`);

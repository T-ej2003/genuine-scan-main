import fs from "node:fs";
import path from "node:path";
import { ensureStageBPrivateDirectory, ensureStageBPrivateFile } from "./stage-b-artifact-contract.mjs";

const bucketName = "mscqr-production-terraform-state-368992683803-eu-west-2";
const bucketArn = `arn:aws:s3:::${bucketName}`;
const legacyWorkspaceKey = "mscqr/production/rls-green/stage-b/terraform.tfstate";
const stateKey = `env:/production/${legacyWorkspaceKey}`;
const lockKey = `${stateKey}.tflock`;
const applyAttemptPrefix = "env:/production/mscqr/production/rls-green/stage-b/apply-attempts";
const legacyWorkspaceLockKey = `${legacyWorkspaceKey}.tflock`;

export const STAGE_B_TERRAFORM_BACKEND = Object.freeze({
  bucketName,
  bucketArn,
  configuredKey: stateKey,
  workspaceName: "default",
  stateKey,
  stateArn: `${bucketArn}/${stateKey}`,
  lockKey,
  lockArn: `${bucketArn}/${lockKey}`,
  applyAttemptPrefix,
  applyAttemptPrefixArn: `${bucketArn}/${applyAttemptPrefix}/*`,
  legacyWorkspaceKey,
  legacyWorkspaceArn: `${bucketArn}/${legacyWorkspaceKey}`,
  legacyWorkspaceLockKey,
  legacyWorkspaceLockArn: `${bucketArn}/${legacyWorkspaceLockKey}`,
  region: "eu-west-2",
  encrypt: true,
  useLockfile: true,
  dynamoDbLocking: false,
  headBucketRequired: false,
});

export const STAGE_B_TERRAFORM_BACKEND_CONFIG = Object.freeze({
  bucket: bucketName,
  key: stateKey,
  region: "eu-west-2",
  encrypt: true,
  use_lockfile: true,
});

const initializedBackendMetadataKeys = Object.freeze(["config", "hash", "type"]);
const initializedBackendOptionalConfigKeys = Object.freeze([
  "access_key", "acl", "allowed_account_ids", "assume_role", "assume_role_with_web_identity",
  "custom_ca_bundle", "dynamodb_endpoint", "dynamodb_table", "ec2_metadata_service_endpoint",
  "ec2_metadata_service_endpoint_mode", "endpoint", "endpoints", "forbidden_account_ids",
  "force_path_style", "http_proxy", "https_proxy", "iam_endpoint", "insecure", "kms_key_id",
  "max_retries", "no_proxy", "profile", "retry_mode", "secret_key", "shared_config_files",
  "shared_credentials_file", "shared_credentials_files", "skip_credentials_validation",
  "skip_metadata_api_check", "skip_region_validation", "skip_requesting_account_id", "skip_s3_checksum",
  "sse_customer_key", "sts_endpoint", "sts_region", "token", "use_dualstack_endpoint",
  "use_fips_endpoint", "use_path_style", "workspace_key_prefix",
]);
const initializedBackendConfigKeys = Object.freeze([...Object.keys(STAGE_B_TERRAFORM_BACKEND_CONFIG), ...initializedBackendOptionalConfigKeys]);

export const STAGE_B_TERRAFORM_DATA_DIR_MODE = 0o700;
export const STAGE_B_TERRAFORM_BACKEND_METADATA_MODE = 0o600;

const privatePathError = "Stage B Terraform backend metadata must be a regular non-symlink file at <terraform-data-dir>/terraform.tfstate with mode 0600.";

export function ensureStageBTerraformBackendMetadataPrivate({ terraformDataDir, backendMetadataPath, repositoryRoot, normalize = false, fsOps = fs } = {}) {
  const resolvedDataDir = ensureStageBPrivateDirectory({ directory: terraformDataDir, repositoryRoot, create: normalize, normalize, fsOps, label: "Stage B Terraform data directory" });
  const expectedMetadataPath = path.join(resolvedDataDir, "terraform.tfstate");
  const resolvedMetadataPath = path.resolve(backendMetadataPath || expectedMetadataPath);
  if (resolvedMetadataPath !== expectedMetadataPath) throw new Error("Stage B backend metadata must be <terraform-data-dir>/terraform.tfstate.");
  const metadata = ensureStageBPrivateFile({ filePath: expectedMetadataPath, repositoryRoot, normalize, fsOps, label: "Stage B Terraform backend metadata" });
  if (metadata.mode !== "0600") throw new Error(privatePathError);
  return {
    terraformDataDir: resolvedDataDir,
    backendMetadataPath: expectedMetadataPath,
    backendMetadataMode: "0600",
    backendMetadataSha256: metadata.sha256,
    privateModeValidated: true,
  };
}

export const assertStageBTerraformBackendMetadataPrivate = (options = {}) => ensureStageBTerraformBackendMetadataPrivate({ ...options, normalize: false });

function assertKnownKeys(value, allowed, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`Stage B initialized backend ${label} is malformed.`);
  const unknown = Object.keys(value).filter((key) => !allowed.includes(key)).sort();
  if (unknown.length) throw new Error(`Stage B initialized backend ${label} has unreviewed key: ${unknown[0]}.`);
}

export const renderStageBTerraformBackendConfig = () => Object.entries(STAGE_B_TERRAFORM_BACKEND_CONFIG)
  .map(([key, value]) => `${key} = ${typeof value === "string" ? JSON.stringify(value) : value}`)
  .join("\n") + "\n";

export function assertStageBTerraformBackendConfig(config) {
  assertKnownKeys(config, Object.keys(STAGE_B_TERRAFORM_BACKEND_CONFIG), "config");
  for (const [key, expected] of Object.entries(STAGE_B_TERRAFORM_BACKEND_CONFIG)) {
    if (config?.[key] !== expected) throw new Error(`Stage B Terraform backend ${key} is outside the direct production-state contract.`);
  }
  return true;
}

export function assertStageBTerraformInitializedBackendMetadata(metadata) {
  assertKnownKeys(metadata, initializedBackendMetadataKeys, "metadata");
  if (metadata.type !== "s3") throw new Error("Stage B initialized backend type must be s3.");
  if (!Number.isSafeInteger(metadata.hash)) throw new Error("Stage B initialized backend metadata hash is malformed.");
  assertKnownKeys(metadata.config, initializedBackendConfigKeys, "config");
  for (const [key, expected] of Object.entries(STAGE_B_TERRAFORM_BACKEND_CONFIG)) {
    if (metadata.config[key] !== expected) throw new Error(`Stage B initialized backend ${key} is outside the direct production-state contract.`);
  }
  for (const key of initializedBackendOptionalConfigKeys) {
    const value = metadata.config[key];
    if (value !== undefined && value !== null && value !== "") throw new Error(`Stage B initialized backend ${key} must use the Terraform default.`);
  }
  return true;
}

export function stageBTerraformBackendIdentity(metadata) {
  assertStageBTerraformInitializedBackendMetadata(metadata);
  return Object.freeze({
    type: metadata.type,
    bucket: metadata.config.bucket,
    key: metadata.config.key,
    region: metadata.config.region,
    encrypt: metadata.config.encrypt,
    useLockfile: metadata.config.use_lockfile,
  });
}

export const STAGE_B_TERRAFORM_BACKEND_POLICY = Object.freeze({
  Version: "2012-10-17",
  Statement: Object.freeze([
    Object.freeze({
      Sid: "GetStageBTerraformStateBucketLocation",
      Effect: "Allow",
      Action: "s3:GetBucketLocation",
      Resource: bucketArn,
    }),
    Object.freeze({
      Sid: "ReadWriteStageBProductionStateOnly",
      Effect: "Allow",
      Action: Object.freeze(["s3:GetObject", "s3:PutObject"]),
      Resource: `${bucketArn}/${stateKey}`,
    }),
    Object.freeze({
      Sid: "ManageStageBProductionLockOnly",
      Effect: "Allow",
      Action: Object.freeze(["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]),
      Resource: `${bucketArn}/${lockKey}`,
    }),
    Object.freeze({
      Sid: "DenyStageBProductionStateDeletion",
      Effect: "Deny",
      Action: "s3:DeleteObject",
      Resource: `${bucketArn}/${stateKey}`,
    }),
    Object.freeze({
      Sid: "ReadStageBApplyAttempts",
      Effect: "Allow",
      Action: "s3:GetObject",
      Resource: `${bucketArn}/${applyAttemptPrefix}/*`,
    }),
    Object.freeze({
      Sid: "CreateStageBApplyAttemptsOnly",
      Effect: "Allow",
      Action: "s3:PutObject",
      Resource: `${bucketArn}/${applyAttemptPrefix}/*`,
      Condition: Object.freeze({ Null: Object.freeze({ "s3:if-none-match": "false" }) }),
    }),
    Object.freeze({
      Sid: "DenyNonConditionalStageBApplyAttempts",
      Effect: "Deny",
      Action: "s3:PutObject",
      Resource: `${bucketArn}/${applyAttemptPrefix}/*`,
      Condition: Object.freeze({ Null: Object.freeze({ "s3:if-none-match": "true" }) }),
    }),
    Object.freeze({
      Sid: "DenyStageBApplyAttemptDeletion",
      Effect: "Deny",
      Action: Object.freeze(["s3:DeleteObject", "s3:DeleteObjectVersion"]),
      Resource: `${bucketArn}/${applyAttemptPrefix}/*`,
    }),
    Object.freeze({
      Sid: "DenyStageBLegacyWorkspaceLockAccess",
      Effect: "Deny",
      Action: Object.freeze(["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]),
      Resource: `${bucketArn}/${legacyWorkspaceLockKey}`,
    }),
    Object.freeze({
      Sid: "DenyStageBLegacyWorkspaceStateAccess",
      Effect: "Deny",
      Action: Object.freeze(["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]),
      Resource: `${bucketArn}/${legacyWorkspaceKey}`,
    }),
  ]),
});

export const STAGE_B_TERRAFORM_BACKEND_MANIFEST = Object.freeze({
  policyPath: "documents/ops/iam/MSCQRProductionGreenStageBWorkspaceState-v2.json",
  bucketArn,
  workspaceName: "default",
  backendConfig: STAGE_B_TERRAFORM_BACKEND_CONFIG,
  stateArn: `${bucketArn}/${stateKey}`,
  lockArn: `${bucketArn}/${lockKey}`,
  applyAttemptPrefixArn: `${bucketArn}/${applyAttemptPrefix}/*`,
  applyAttemptKeyTemplate: `${applyAttemptPrefix}/<artifact-set-identity>.json`,
  applyAttemptTransitionKeyTemplate: `${applyAttemptPrefix}/<attempt-id>/<sequence>.json`,
  legacyWorkspaceKeyAccess: "read-write-delete-denied",
  headBucketRequired: false,
  requiredActions: Object.freeze([
    "s3:GetBucketLocation",
    "s3:GetObject(state)",
    "s3:PutObject(state)",
    "s3:GetObject(lock)",
    "s3:PutObject(lock)",
    "s3:DeleteObject(lock)",
    "s3:GetObject(apply-attempt)",
    "s3:PutObject(apply-attempt,If-None-Match:*)",
  ]),
});

export function stageBApplyAttemptS3Key(artifactSetIdentity) {
  if (!/^[a-f0-9]{64}$/.test(artifactSetIdentity || "")) throw new Error("Stage B apply artifact-set identity is malformed.");
  return `${applyAttemptPrefix}/${artifactSetIdentity}.json`;
}

export function stageBAttemptStepS3ObjectKey(attemptId, sequence) {
  if (!/^[a-f0-9]{64}$/.test(attemptId || "") || !Number.isSafeInteger(sequence) || sequence < 1 || sequence > 3) throw new Error("Stage B apply-attempt transition identity is malformed.");
  return `${applyAttemptPrefix}/${attemptId}/${String(sequence).padStart(4, "0")}.json`;
}

export function assertStageBTerraformBackendPolicy(policy) {
  if (JSON.stringify(policy) !== JSON.stringify(STAGE_B_TERRAFORM_BACKEND_POLICY)) {
    throw new Error("Stage B Terraform backend policy is outside the exact least-privilege contract.");
  }
  return true;
}

export function assertStageBTerraformBackendManifest(manifest) {
  if (JSON.stringify(manifest?.backendContract) !== JSON.stringify(STAGE_B_TERRAFORM_BACKEND_MANIFEST)) {
    throw new Error("Stage B permission manifest backend contract is missing or incorrect.");
  }
  return true;
}

const bucketName = "mscqr-production-terraform-state-368992683803-eu-west-2";
const bucketArn = `arn:aws:s3:::${bucketName}`;
const legacyWorkspaceKey = "mscqr/production/rls-green/stage-b/terraform.tfstate";
const stateKey = `env:/production/${legacyWorkspaceKey}`;
const lockKey = `${stateKey}.tflock`;
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

export const renderStageBTerraformBackendConfig = () => Object.entries(STAGE_B_TERRAFORM_BACKEND_CONFIG)
  .map(([key, value]) => `${key} = ${typeof value === "string" ? JSON.stringify(value) : value}`)
  .join("\n") + "\n";

export function assertStageBTerraformBackendConfig(config) {
  for (const [key, expected] of Object.entries(STAGE_B_TERRAFORM_BACKEND_CONFIG)) {
    if (config?.[key] !== expected) throw new Error(`Stage B Terraform backend ${key} is outside the direct production-state contract.`);
  }
  return true;
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
  legacyWorkspaceKeyAccess: "read-write-delete-denied",
  headBucketRequired: false,
  requiredActions: Object.freeze([
    "s3:GetBucketLocation",
    "s3:GetObject(state)",
    "s3:PutObject(state)",
    "s3:GetObject(lock)",
    "s3:PutObject(lock)",
    "s3:DeleteObject(lock)",
  ]),
});

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

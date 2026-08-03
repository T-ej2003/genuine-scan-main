const bucketName = "mscqr-production-terraform-state-368992683803-eu-west-2";
const bucketArn = `arn:aws:s3:::${bucketName}`;
const configuredKey = "mscqr/production/rls-green/stage-b/terraform.tfstate";
const workspacePrefix = "env:/";
const stateKey = `${workspacePrefix}production/${configuredKey}`;
const lockKey = `${stateKey}.tflock`;
const baseLockKey = `${configuredKey}.tflock`;

export const STAGE_B_TERRAFORM_BACKEND = Object.freeze({
  bucketName,
  bucketArn,
  configuredKey,
  workspacePrefix,
  workspaceDiscoveryPrefixes: Object.freeze([workspacePrefix]),
  stateKey,
  stateArn: `${bucketArn}/${stateKey}`,
  lockKey,
  lockArn: `${bucketArn}/${lockKey}`,
  baseStateKey: configuredKey,
  baseStateArn: `${bucketArn}/${configuredKey}`,
  baseLockKey,
  baseLockArn: `${bucketArn}/${baseLockKey}`,
  region: "eu-west-2",
  encrypt: true,
  useLockfile: true,
  dynamoDbLocking: false,
  headBucketRequired: false,
});

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
      Sid: "ListStageBTerraformWorkspacePrefix",
      Effect: "Allow",
      Action: "s3:ListBucket",
      Resource: bucketArn,
      Condition: Object.freeze({ StringEquals: Object.freeze({ "s3:prefix": workspacePrefix }) }),
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
      Sid: "DenyStageBConfiguredDefaultKeyAccess",
      Effect: "Deny",
      Action: Object.freeze(["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]),
      Resource: Object.freeze([`${bucketArn}/${configuredKey}`, `${bucketArn}/${baseLockKey}`]),
    }),
  ]),
});

export const STAGE_B_TERRAFORM_BACKEND_MANIFEST = Object.freeze({
  policyPath: "documents/ops/iam/MSCQRProductionGreenStageBWorkspaceState-v2.json",
  bucketArn,
  workspaceDiscoveryPrefixes: Object.freeze([workspacePrefix]),
  stateArn: `${bucketArn}/${stateKey}`,
  lockArn: `${bucketArn}/${lockKey}`,
  configuredDefaultKeyAccess: "denied",
  headBucketRequired: false,
  requiredActions: Object.freeze([
    "s3:GetBucketLocation",
    "s3:ListBucket(env:/)",
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

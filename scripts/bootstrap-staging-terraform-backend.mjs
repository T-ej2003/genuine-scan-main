#!/usr/bin/env node
import process from "node:process";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

import { parseAwsArn } from "./check-staging-aws-identity.mjs";
import { hasNameMarker } from "./check-staging-aws-apply-identity.mjs";

export const backendConfig = Object.freeze({
  accountId: "368992683803",
  region: "eu-west-2",
  bucket: "mscqr-staging-terraform-state-368992683803",
  key: "staging-api/terraform.tfstate",
  lockKey: "staging-api/terraform.tfstate.tflock",
});

const requiredEnabled = "true";
const requiredConfirm = "MSCQR_BOOTSTRAP_STAGING_TERRAFORM_BACKEND_ONCE";

export function usage() {
  return `Usage: node scripts/bootstrap-staging-terraform-backend.mjs

Creates or reconciles only the staging Terraform S3 backend bucket.

Required gates:
  MSCQR_STAGING_TERRAFORM_BACKEND_BOOTSTRAP_ENABLED=true
  MSCQR_STAGING_TERRAFORM_BACKEND_BOOTSTRAP_CONFIRM=MSCQR_BOOTSTRAP_STAGING_TERRAFORM_BACKEND_ONCE

Required identity:
  AWS_REGION or AWS_DEFAULT_REGION must be eu-west-2.
  Caller account must be 368992683803.
  Caller must be a staging Terraform provisioning or apply role, not root.

This script does not create, update, delete, or recreate ECS, RDS, Redis, ALB,
application S3, KMS, IAM app resources, production resources, RLS, tfvars,
Terraform state files, or plan files.`;
}

export function checkBootstrapEnvGates(env = process.env) {
  const failures = [];
  if (env.MSCQR_STAGING_TERRAFORM_BACKEND_BOOTSTRAP_ENABLED !== requiredEnabled) {
    failures.push("MSCQR_STAGING_TERRAFORM_BACKEND_BOOTSTRAP_ENABLED must be true.");
  }
  if (env.MSCQR_STAGING_TERRAFORM_BACKEND_BOOTSTRAP_CONFIRM !== requiredConfirm) {
    failures.push(`MSCQR_STAGING_TERRAFORM_BACKEND_BOOTSTRAP_CONFIRM must be ${requiredConfirm}.`);
  }
  return failures;
}

export function validateBackendProfile(env = process.env) {
  const profile = String(env.AWS_PROFILE || "").toLowerCase();
  const failures = [];
  if (!profile) failures.push("AWS_PROFILE is required for staging backend bootstrap.");
  if (profile && !hasNameMarker(profile, ["staging", "stg"])) {
    failures.push("AWS_PROFILE must contain staging/stg.");
  }
  if (profile && !hasNameMarker(profile, ["terraform"])) {
    failures.push("AWS_PROFILE must contain terraform.");
  }
  if (profile && !hasNameMarker(profile, ["provision", "apply"]) && !profile.includes("provision")) {
    failures.push("AWS_PROFILE must contain provisioning/provision or apply.");
  }
  if (profile && hasNameMarker(profile, ["prod", "production"])) {
    failures.push("AWS_PROFILE must not be production-looking.");
  }
  if (profile && hasNameMarker(profile, ["root", "admin", "administrator"])) {
    failures.push("AWS_PROFILE must not be root/admin-looking.");
  }
  return failures;
}

export function evaluateBackendBootstrapIdentity({ identity, env = process.env } = {}) {
  const region = env.AWS_REGION || env.AWS_DEFAULT_REGION || null;
  const account = identity?.Account || null;
  const parsed = parseAwsArn(identity?.Arn);
  const name = parsed.identityName.toLowerCase();
  const isRoleLike = parsed.arnType === "assumed-role" || parsed.arnType === "role";
  const hasStagingMarker = hasNameMarker(name, ["staging", "stg"]);
  const hasTerraformMarker = hasNameMarker(name, ["terraform"]);
  const hasBootstrapRoleMarker = hasNameMarker(name, ["apply", "provision"]) || name.includes("provision");
  const hasProductionMarker = hasNameMarker(name, ["prod", "production"]);
  const hasAdminMarker = hasNameMarker(name, ["admin", "administrator"]);

  let refusalReason = null;
  let classification = "staging-terraform-backend-role";

  if (!region) {
    refusalReason = "AWS_REGION or AWS_DEFAULT_REGION is required.";
    classification = "missing-region";
  } else if (region !== backendConfig.region) {
    refusalReason = "AWS region does not match the expected staging region.";
    classification = "wrong-region";
  } else if (parsed.arnType === "root" || name === "root") {
    refusalReason = "Root identity is refused.";
    classification = "root";
  } else if (account !== backendConfig.accountId || parsed.accountFromArn !== backendConfig.accountId) {
    refusalReason = "Caller account does not match the expected staging account.";
    classification = "wrong-account";
  } else if (!isRoleLike) {
    refusalReason = "Caller must be a staging Terraform provisioning or apply role.";
    classification = parsed.arnType;
  } else if (hasProductionMarker) {
    refusalReason = "Production-looking role names are refused.";
    classification = "production-looking-role";
  } else if (hasAdminMarker) {
    refusalReason = "Admin-looking role names are refused for backend bootstrap.";
    classification = "admin-looking-role";
  } else if (!hasStagingMarker || !hasTerraformMarker || !hasBootstrapRoleMarker) {
    refusalReason = "Role name must contain staging/stg, terraform, and provisioning/provision or apply markers.";
    classification = "unmarked-backend-role";
  }

  return {
    account,
    arnType: parsed.arnType,
    classification,
    region,
    allowed: refusalReason === null,
    refusalReason,
  };
}

function safeBlocked(reason, details = {}) {
  return {
    status: "blocked_before_backend_bootstrap",
    reason,
    ...details,
    mutatesAppResources: false,
    mutatesBackendStorage: false,
    rawSecretValuesPrinted: false,
  };
}

function runAwsJson(args, env) {
  const result = spawnSync("aws", args, {
    env,
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.error?.code === "ENOENT") throw new Error("AWS CLI is not installed or is not on PATH.");
  if (result.error) throw new Error(`AWS CLI failed: ${result.error.message}`);
  if (result.status !== 0) {
    const error = new Error(`aws ${args.slice(0, 2).join(" ")} failed.`);
    error.status = result.status;
    error.stderr = result.stderr || "";
    throw error;
  }
  if (!result.stdout.trim()) return {};
  return JSON.parse(result.stdout);
}

function runAws(args, env, { allowFailure = false } = {}) {
  const result = spawnSync("aws", args, {
    env,
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.error?.code === "ENOENT") throw new Error("AWS CLI is not installed or is not on PATH.");
  if (result.error) throw new Error(`AWS CLI failed: ${result.error.message}`);
  if (result.status !== 0 && !allowFailure) {
    const error = new Error(`aws ${args.slice(0, 2).join(" ")} failed.`);
    error.status = result.status;
    error.stderr = result.stderr || "";
    throw error;
  }
  return result;
}

export function buildBucketPolicy() {
  return {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "DenyInsecureTransport",
        Effect: "Deny",
        Principal: "*",
        Action: "s3:*",
        Resource: [
          `arn:aws:s3:::${backendConfig.bucket}`,
          `arn:aws:s3:::${backendConfig.bucket}/*`,
        ],
        Condition: {
          Bool: {
            "aws:SecureTransport": "false",
          },
        },
      },
    ],
  };
}

function buildLifecycleConfiguration() {
  return {
    Rules: [
      {
        ID: "RetainRecentNoncurrentTerraformStateVersions",
        Status: "Enabled",
        Filter: { Prefix: "staging-api/" },
        NoncurrentVersionExpiration: { NoncurrentDays: 90 },
        AbortIncompleteMultipartUpload: { DaysAfterInitiation: 7 },
      },
    ],
  };
}

function createOrConfigureBucket(env) {
  const head = runAws(["s3api", "head-bucket", "--bucket", backendConfig.bucket], env, { allowFailure: true });
  const bucketExisted = head.status === 0;

  if (!bucketExisted) {
    runAws([
      "s3api",
      "create-bucket",
      "--bucket",
      backendConfig.bucket,
      "--region",
      backendConfig.region,
      "--create-bucket-configuration",
      `LocationConstraint=${backendConfig.region}`,
    ], env);
  }

  runAws([
    "s3api",
    "put-public-access-block",
    "--bucket",
    backendConfig.bucket,
    "--public-access-block-configuration",
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
  ], env);
  runAws([
    "s3api",
    "put-bucket-ownership-controls",
    "--bucket",
    backendConfig.bucket,
    "--ownership-controls",
    JSON.stringify({ Rules: [{ ObjectOwnership: "BucketOwnerEnforced" }] }),
  ], env);
  runAws([
    "s3api",
    "put-bucket-versioning",
    "--bucket",
    backendConfig.bucket,
    "--versioning-configuration",
    "Status=Enabled",
  ], env);
  runAws([
    "s3api",
    "put-bucket-encryption",
    "--bucket",
    backendConfig.bucket,
    "--server-side-encryption-configuration",
    JSON.stringify({
      Rules: [
        {
          ApplyServerSideEncryptionByDefault: { SSEAlgorithm: "AES256" },
          BucketKeyEnabled: false,
        },
      ],
    }),
  ], env);
  runAws([
    "s3api",
    "put-bucket-lifecycle-configuration",
    "--bucket",
    backendConfig.bucket,
    "--lifecycle-configuration",
    JSON.stringify(buildLifecycleConfiguration()),
  ], env);
  runAws([
    "s3api",
    "put-bucket-policy",
    "--bucket",
    backendConfig.bucket,
    "--policy",
    JSON.stringify(buildBucketPolicy()),
  ], env);

  return { bucketExisted };
}

export function runBootstrapWorkflow({
  argv = [],
  env = process.env,
  deps = {
    getIdentity: () => runAwsJson(["sts", "get-caller-identity", "--output", "json"], env),
    configureBucket: createOrConfigureBucket,
  },
} = {}) {
  if (argv.includes("--help") || argv.includes("-h")) return { exitCode: 0, payload: { usage: usage() } };
  if (argv.length > 0) {
    return { exitCode: 1, payload: safeBlocked("Unsupported arguments. Use --help for usage.") };
  }

  const profileFailures = validateBackendProfile(env);
  if (profileFailures.length > 0) {
    return { exitCode: 1, payload: safeBlocked("Staging backend bootstrap profile guard failed.", { failures: profileFailures }) };
  }

  let identityCheck;
  try {
    identityCheck = evaluateBackendBootstrapIdentity({ identity: deps.getIdentity(), env });
  } catch (error) {
    return { exitCode: 1, payload: safeBlocked("AWS identity guard failed before backend bootstrap.", {
      identityCheck: {
        account: null,
        arnType: "unknown",
        classification: "blocked",
        region: env.AWS_REGION || env.AWS_DEFAULT_REGION || null,
        allowed: false,
        refusalReason: error.message,
      },
    }) };
  }

  if (!identityCheck.allowed) {
    return { exitCode: 1, payload: safeBlocked("AWS identity guard failed before backend bootstrap.", { identityCheck }) };
  }

  const gateFailures = checkBootstrapEnvGates(env);
  if (gateFailures.length > 0) {
    return { exitCode: 1, payload: safeBlocked("Missing explicit staging Terraform backend bootstrap confirmation.", {
      identityCheck,
      gateFailures,
    }) };
  }

  try {
    const bucket = deps.configureBucket(env);
    return {
      exitCode: 0,
      payload: {
        status: "backend_bootstrap_ok",
        checkedAt: new Date().toISOString(),
        backend: {
          bucket: backendConfig.bucket,
          key: backendConfig.key,
          region: backendConfig.region,
          encrypt: true,
          lockMechanism: "s3_lockfile",
          lockKey: backendConfig.lockKey,
        },
        bucketExisted: Boolean(bucket.bucketExisted),
        configuredControls: [
          "versioning",
          "sse_s3_encryption",
          "public_access_block",
          "bucket_owner_enforced_ownership",
          "noncurrent_version_lifecycle",
          "deny_insecure_transport_policy",
        ],
        identityCheck,
        mutatesBackendStorage: true,
        mutatesAppResources: false,
        rawSecretValuesPrinted: false,
      },
    };
  } catch (error) {
    return { exitCode: 1, payload: safeBlocked("Backend bucket bootstrap failed; raw AWS output was not printed.", {
      identityCheck,
      backend: {
        bucket: backendConfig.bucket,
        key: backendConfig.key,
        region: backendConfig.region,
        lockMechanism: "s3_lockfile",
      },
      errorMessage: error.message,
    }) };
  }
}

export function main(argv = process.argv.slice(2), env = process.env) {
  const result = runBootstrapWorkflow({ argv, env });
  if (result.payload.usage) console.log(result.payload.usage);
  else console.log(JSON.stringify(result.payload, null, 2));
  return result.exitCode;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(main());
}

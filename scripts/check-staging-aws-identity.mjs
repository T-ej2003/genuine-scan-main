#!/usr/bin/env node
import process from "node:process";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

const DEFAULT_REGION = "eu-west-2";
const DEFAULT_ACCOUNT_ID = "368992683803";
const REQUIRED_ROLE_MARKERS = ["staging", "stg", "terraform", "provision"];
const PRODUCTION_ROLE_MARKERS = ["prod", "production"];
const ADMIN_ROLE_MARKERS = ["admin", "administrator"];

export function usage() {
  return `Usage: node scripts/check-staging-aws-identity.mjs

Runs aws sts get-caller-identity and prints safe JSON only.

Required defaults:
  AWS_REGION or AWS_DEFAULT_REGION must be eu-west-2.
  Expected account defaults to 368992683803.

Staging-only overrides:
  STAGING_AWS_REGION may override the expected region.
  STAGING_AWS_ACCOUNT_ID may override the expected account ID.
  MSCQR_STAGING_AWS_IDENTITY_ADMIN_REVIEWED=true may allow an admin-looking
  staging Terraform role after explicit human review.

The output never includes credentials, access keys, session tokens, env values,
or the full caller ARN.`;
}

export function parseAwsArn(arn) {
  if (typeof arn !== "string" || arn.length === 0) {
    return { arnType: "unknown", identityName: "", accountFromArn: null };
  }

  const rootMatch = arn.match(/^arn:aws:iam::([0-9]{12}):root$/);
  if (rootMatch) {
    return { arnType: "root", identityName: "root", accountFromArn: rootMatch[1] };
  }

  const assumedRoleMatch = arn.match(/^arn:aws:sts::([0-9]{12}):assumed-role\/([^/]+)\/.+$/);
  if (assumedRoleMatch) {
    return {
      arnType: "assumed-role",
      identityName: assumedRoleMatch[2],
      accountFromArn: assumedRoleMatch[1],
    };
  }

  const roleMatch = arn.match(/^arn:aws:iam::([0-9]{12}):role\/(.+)$/);
  if (roleMatch) {
    return { arnType: "role", identityName: roleMatch[2], accountFromArn: roleMatch[1] };
  }

  const userMatch = arn.match(/^arn:aws:iam::([0-9]{12}):user\/(.+)$/);
  if (userMatch) {
    return { arnType: "user", identityName: userMatch[2], accountFromArn: userMatch[1] };
  }

  const genericMatch = arn.match(/^arn:aws:[^:]+::([0-9]{12}):(.+)$/);
  return {
    arnType: "unknown",
    identityName: genericMatch?.[2] || "",
    accountFromArn: genericMatch?.[1] || null,
  };
}

export function evaluateStagingAwsIdentity({ identity, env = process.env } = {}) {
  const expectedRegion = env.STAGING_AWS_REGION || DEFAULT_REGION;
  const expectedAccount = env.STAGING_AWS_ACCOUNT_ID || DEFAULT_ACCOUNT_ID;
  const region = env.AWS_REGION || env.AWS_DEFAULT_REGION || null;
  const account = identity?.Account || null;
  const parsed = parseAwsArn(identity?.Arn);
  const name = parsed.identityName.toLowerCase();
  const isRoleLike = parsed.arnType === "assumed-role" || parsed.arnType === "role";
  const hasRequiredMarker = REQUIRED_ROLE_MARKERS.some((marker) => name.includes(marker));
  const hasProductionMarker = PRODUCTION_ROLE_MARKERS.some((marker) => name.includes(marker));
  const hasAdminMarker = ADMIN_ROLE_MARKERS.some((marker) => name.includes(marker));
  const adminReviewed = env.MSCQR_STAGING_AWS_IDENTITY_ADMIN_REVIEWED === "true";

  let refusalReason = null;
  let classification = "staging-provisioning-role";

  if (!region) {
    refusalReason = "AWS_REGION or AWS_DEFAULT_REGION is required.";
    classification = "missing-region";
  } else if (region !== expectedRegion) {
    refusalReason = "AWS region does not match the expected staging region.";
    classification = "wrong-region";
  } else if (!/^[0-9]{12}$/.test(expectedAccount)) {
    refusalReason = "Expected staging account ID must be 12 digits.";
    classification = "invalid-expected-account";
  } else if (parsed.arnType === "root" || name === "root") {
    refusalReason = "Root identity is refused.";
    classification = "root";
  } else if (account !== expectedAccount || parsed.accountFromArn !== expectedAccount) {
    refusalReason = "Caller account does not match the expected staging account.";
    classification = "wrong-account";
  } else if (!isRoleLike) {
    refusalReason = "Caller must be a staging Terraform provisioning role.";
    classification = parsed.arnType;
  } else if (!hasRequiredMarker) {
    refusalReason = "Role name must contain a staging/provisioning marker.";
    classification = "unmarked-role";
  } else if (hasProductionMarker) {
    refusalReason = "Production-looking role names are refused for staging Terraform planning.";
    classification = "production-looking-role";
  } else if (name.includes("root")) {
    refusalReason = "Root-looking role names are refused for staging Terraform planning.";
    classification = "root-looking-role";
  } else if (hasAdminMarker && !adminReviewed) {
    refusalReason = "Admin-looking role names require explicit review before staging Terraform planning.";
    classification = "admin-looking-role";
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

function safeBlocked(reason, env = process.env) {
  return {
    account: null,
    arnType: "unknown",
    classification: "blocked",
    region: env.AWS_REGION || env.AWS_DEFAULT_REGION || null,
    allowed: false,
    refusalReason: reason,
  };
}

export function runAwsCallerIdentity({ env = process.env } = {}) {
  const result = spawnSync("aws", ["sts", "get-caller-identity", "--output", "json"], {
    encoding: "utf8",
    env,
    maxBuffer: 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });

  if (result.error?.code === "ENOENT") {
    return safeBlocked("AWS CLI is not installed or is not on PATH.", env);
  }
  if (result.error) {
    return safeBlocked("aws sts get-caller-identity failed.", env);
  }
  if (result.status !== 0) {
    return safeBlocked("aws sts get-caller-identity failed.", env);
  }

  try {
    return evaluateStagingAwsIdentity({ identity: JSON.parse(result.stdout), env });
  } catch {
    return safeBlocked("aws sts get-caller-identity did not return valid JSON.", env);
  }
}

export function main(argv = process.argv.slice(2), env = process.env) {
  if (argv.includes("--help") || argv.includes("-h")) {
    console.log(usage());
    return 0;
  }
  if (argv.length > 0) {
    const output = safeBlocked("Unsupported arguments. Use --help for usage.", env);
    console.log(JSON.stringify(output, null, 2));
    return 1;
  }

  const output = runAwsCallerIdentity({ env });
  console.log(JSON.stringify(output, null, 2));
  return output.allowed ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(main());
}

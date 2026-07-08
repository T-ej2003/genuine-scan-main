#!/usr/bin/env node
import process from "node:process";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

import { parseAwsArn } from "./check-staging-aws-identity.mjs";

const DEFAULT_REGION = "eu-west-2";
const DEFAULT_ACCOUNT_ID = "368992683803";
const PRODUCTION_ROLE_MARKERS = ["prod", "production"];

export function nameSegments(value) {
  return String(value || "")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

export function hasNameMarker(value, markers) {
  const segments = new Set(nameSegments(value));
  return markers.some((marker) => segments.has(marker));
}

export function usage() {
  return `Usage: node scripts/check-staging-aws-apply-identity.mjs

Runs aws sts get-caller-identity and prints safe JSON only.

Required defaults:
  AWS_REGION or AWS_DEFAULT_REGION must be eu-west-2.
  Expected account defaults to 368992683803.
  Caller must be an assumed staging Terraform apply role.

Staging-only overrides:
  STAGING_AWS_ACCOUNT_ID may override the expected account ID.
  STAGING_AWS_REGION may override the expected region.

The output never includes credentials, access keys, session tokens, env values,
or the full caller ARN.`;
}

export function evaluateStagingAwsApplyIdentity({ identity, env = process.env } = {}) {
  const expectedRegion = env.STAGING_AWS_REGION || DEFAULT_REGION;
  const expectedAccount = env.STAGING_AWS_ACCOUNT_ID || DEFAULT_ACCOUNT_ID;
  const region = env.AWS_REGION || env.AWS_DEFAULT_REGION || null;
  const account = identity?.Account || null;
  const parsed = parseAwsArn(identity?.Arn);
  const name = parsed.identityName.toLowerCase();
  const hasStagingMarker = hasNameMarker(name, ["staging", "stg"]);
  const hasApplyMarker = hasNameMarker(name, ["apply"]);
  const hasTerraformMarker = hasNameMarker(name, ["terraform", "provision"]);
  const hasProductionMarker = hasNameMarker(name, PRODUCTION_ROLE_MARKERS);
  const hasPlanMarker = hasNameMarker(name, ["plan", "read"]);

  let refusalReason = null;
  let classification = "staging-apply-role";

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
  } else if (parsed.arnType !== "assumed-role") {
    refusalReason = "Caller must be an assumed staging Terraform apply role.";
    classification = parsed.arnType;
  } else if (hasProductionMarker) {
    refusalReason = "Production-looking role names are refused for staging Terraform apply.";
    classification = "production-looking-role";
  } else if (hasNameMarker(name, ["root"])) {
    refusalReason = "Root-looking role names are refused for staging Terraform apply.";
    classification = "root-looking-role";
  } else if (hasPlanMarker) {
    refusalReason = "Plan/read-only role names are refused for staging Terraform apply.";
    classification = "plan-role";
  } else if (!hasStagingMarker || !hasApplyMarker || !hasTerraformMarker) {
    refusalReason = "Role name must contain staging/stg, apply, and terraform/provision markers.";
    classification = "unmarked-apply-role";
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

export function runAwsApplyCallerIdentity({ env = process.env } = {}) {
  const result = spawnSync("aws", ["sts", "get-caller-identity", "--output", "json"], {
    encoding: "utf8",
    env,
    maxBuffer: 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });

  if (result.error?.code === "ENOENT") return safeBlocked("AWS CLI is not installed or is not on PATH.", env);
  if (result.error || result.status !== 0) return safeBlocked("aws sts get-caller-identity failed.", env);

  try {
    return evaluateStagingAwsApplyIdentity({ identity: JSON.parse(result.stdout), env });
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

  const output = runAwsApplyCallerIdentity({ env });
  console.log(JSON.stringify(output, null, 2));
  return output.allowed ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(main());
}

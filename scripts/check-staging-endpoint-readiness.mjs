#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);
const checklistPath = path.join(repoRoot, "documents/security/mscqr_staging_endpoint_readiness_checklist.json");

const usage = `Usage:
  node scripts/check-staging-endpoint-readiness.mjs --help
  node scripts/check-staging-endpoint-readiness.mjs --print-checklist
  node scripts/check-staging-endpoint-readiness.mjs --dry-run

Read-only readiness guard for the MSCQR staging API endpoint.

Inspects environment values only. It does not call AWS, does not mutate resources,
does not read secret values, and does not run the RLS collector.

Useful environment keys:
  STAGING_BASE_URL
  STAGING_SMOKE_BASE_URL
  STAGING_SMOKE_API_BASE_URL
  AWS_REGION
  STAGING_ECS_CLUSTER
  STAGING_ECS_SERVICE
  STAGING_TASK_DEFINITION
  STAGING_DATABASE_HOST
  STAGING_REDIS_URL
  STAGING_REDIS_HOST
  STAGING_OBJECT_STORAGE_BUCKET
  STAGING_OBJECT_STORAGE_PREFIX
`;

const args = new Set(process.argv.slice(2));

if (args.has("--help") || args.has("-h")) {
  console.log(usage);
  process.exit(0);
}

const read = (key) => String(process.env[key] || "").trim();

const prodHostLabels = [
  "mscqr.com",
  "www.mscqr.com",
  "mscqr-prod-db",
  "mscqr-prod-db-proxy",
  "mscqr-redis-euw2-primary",
  "mscqr-prod-euw2-main",
  "mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an",
];

const productionNameFragments = [
  "prod",
  "production",
  "mscqr-prod",
];

const urlKeys = [
  "STAGING_BASE_URL",
  "STAGING_SMOKE_BASE_URL",
  "STAGING_SMOKE_API_BASE_URL",
];

const resourceKeys = [
  "STAGING_ECS_CLUSTER",
  "STAGING_ECS_SERVICE",
  "STAGING_TASK_DEFINITION",
  "STAGING_DATABASE_HOST",
  "STAGING_REDIS_URL",
  "STAGING_REDIS_HOST",
  "STAGING_OBJECT_STORAGE_BUCKET",
  "STAGING_OBJECT_STORAGE_PREFIX",
];

const getUrlIssue = (key, raw) => {
  if (!raw) return { severity: "missing", message: `${key} is not set.` };
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    return { severity: "blocker", message: `${key} is not a valid URL.` };
  }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    return { severity: "blocker", message: `${key} must use http or https.` };
  }
  const host = parsed.hostname.toLowerCase();
  if (host === "mscqr.com" || host.endsWith(".mscqr.com")) {
    return { severity: "blocker", message: `${key} points at mscqr.com or a default MSCQR subdomain.` };
  }
  if (host.includes("production") || host.includes("prod")) {
    return { severity: "blocker", message: `${key} host contains production/prod.` };
  }
  return null;
};

const getResourceIssue = (key, raw) => {
  if (!raw) return { severity: "missing", message: `${key} is not set.` };
  const normalized = raw.toLowerCase();
  for (const forbidden of prodHostLabels) {
    if (normalized.includes(forbidden)) {
      return { severity: "blocker", message: `${key} appears to reference production identifier ${forbidden}.` };
    }
  }
  if (key !== "STAGING_OBJECT_STORAGE_PREFIX") {
    for (const fragment of productionNameFragments) {
      if (normalized.includes(fragment)) {
        return { severity: "blocker", message: `${key} contains production-looking fragment ${fragment}.` };
      }
    }
  }
  return null;
};

const evaluate = () => {
  const checks = [];

  for (const key of urlKeys) {
    const value = read(key);
    const issue = getUrlIssue(key, value);
    checks.push({
      key,
      configured: Boolean(value),
      valuePreview: value ? value.replace(/\/\/[^:@/]+:[^@/]+@/, "//<redacted>@") : null,
      status: issue ? issue.severity : "pass",
      message: issue ? issue.message : `${key} is a non-production-looking URL.`,
    });
  }

  if (read("AWS_REGION") && read("AWS_REGION") !== "eu-west-2") {
    checks.push({
      key: "AWS_REGION",
      configured: true,
      valuePreview: read("AWS_REGION"),
      status: "blocker",
      message: "AWS_REGION must be eu-west-2 for this staging endpoint plan unless explicitly reviewed.",
    });
  } else {
    checks.push({
      key: "AWS_REGION",
      configured: Boolean(read("AWS_REGION")),
      valuePreview: read("AWS_REGION") || null,
      status: read("AWS_REGION") ? "pass" : "missing",
      message: read("AWS_REGION") ? "AWS_REGION is eu-west-2." : "AWS_REGION is not set.",
    });
  }

  for (const key of resourceKeys) {
    const value = read(key);
    const issue = getResourceIssue(key, value);
    checks.push({
      key,
      configured: Boolean(value),
      valuePreview: value || null,
      status: issue ? issue.severity : "pass",
      message: issue ? issue.message : `${key} does not match known production identifiers.`,
    });
  }

  const blockers = checks.filter((check) => check.status === "blocker");
  const missing = checks.filter((check) => check.status === "missing");

  return {
    schemaVersion: 1,
    readOnly: true,
    mutatesAws: false,
    mutatesDatabase: false,
    commitsSecrets: false,
    checkedAt: new Date().toISOString(),
    status: blockers.length > 0 ? "blocked" : missing.length > 0 ? "incomplete" : "ready",
    blockers: blockers.length,
    missing: missing.length,
    checks,
  };
};

if (args.has("--print-checklist")) {
  console.log(fs.readFileSync(checklistPath, "utf8"));
  process.exit(0);
}

if (!args.has("--dry-run")) {
  console.log(usage);
  process.exit(0);
}

const result = evaluate();
console.log(JSON.stringify(result, null, 2));
if (result.blockers > 0) process.exit(1);

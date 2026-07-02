#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);
const checklistPath = path.join(repoRoot, "documents/security/mscqr_staging_endpoint_readiness_checklist.json");

const usage = `Usage:
  node scripts/check-staging-endpoint-readiness.mjs --help
  node scripts/check-staging-endpoint-readiness.mjs --print-checklist
  node scripts/check-staging-endpoint-readiness.mjs --self-check-redaction
  node scripts/check-staging-endpoint-readiness.mjs --dry-run

Read-only readiness guard for the MSCQR staging API endpoint.

Inspects environment values only. It does not call AWS, does not mutate resources,
does not run the RLS collector, and redacts URL credentials before printing previews.

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
const MAX_PREVIEW_LENGTH = 160;
const secretKeyPattern = /(SECRET|TOKEN|PASSWORD|PRIVATE_KEY|ACCESS_KEY|AUTH)/i;

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

const truncatePreview = (value) => {
  if (value.length <= MAX_PREVIEW_LENGTH) return value;
  return `${value.slice(0, MAX_PREVIEW_LENGTH)}...<truncated>`;
};

const buildUrlPreview = (parsed) => {
  const auth = parsed.username || parsed.password ? "<redacted>@" : "";
  return `${parsed.protocol}//${auth}${parsed.host}${parsed.pathname}${parsed.search}${parsed.hash}`;
};

const redactPossibleUrlUserinfo = (value) => {
  const schemeMatch = value.match(/^([A-Za-z][A-Za-z0-9+.-]*:\/\/)(.*)$/);
  if (!schemeMatch) return value;

  const [, scheme, rest] = schemeMatch;
  const pathStart = rest.search(/[/?#]/);
  const authority = pathStart === -1 ? rest : rest.slice(0, pathStart);
  const suffix = pathStart === -1 ? "" : rest.slice(pathStart);
  const atIndex = authority.lastIndexOf("@");

  if (atIndex === -1) return value;
  return `${scheme}<redacted>@${authority.slice(atIndex + 1)}${suffix}`;
};

const safeValuePreview = (key, raw) => {
  if (!raw) return null;

  if (secretKeyPattern.test(key) && !/REDIS_URL$/i.test(key) && !/BASE_URL$/i.test(key)) {
    return "<redacted>";
  }

  let preview;
  try {
    preview = buildUrlPreview(new URL(raw));
  } catch {
    preview = redactPossibleUrlUserinfo(raw);
  }

  return truncatePreview(preview);
};

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

const getAlternativeResourceIssue = (key, raw) => {
  if (key === "STAGING_REDIS_URL" && !raw && read("STAGING_REDIS_HOST")) {
    return { severity: "pass", message: "STAGING_REDIS_HOST is set; STAGING_REDIS_URL is optional for readiness metadata." };
  }
  if (key === "STAGING_REDIS_HOST" && !raw && read("STAGING_REDIS_URL")) {
    return { severity: "pass", message: "STAGING_REDIS_URL is set; STAGING_REDIS_HOST is optional for readiness metadata." };
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
      valuePreview: safeValuePreview(key, value),
      status: issue ? issue.severity : "pass",
      message: issue ? issue.message : `${key} is a non-production-looking URL.`,
    });
  }

  if (read("AWS_REGION") && read("AWS_REGION") !== "eu-west-2") {
    checks.push({
      key: "AWS_REGION",
      configured: true,
      valuePreview: safeValuePreview("AWS_REGION", read("AWS_REGION")),
      status: "blocker",
      message: "AWS_REGION must be eu-west-2 for this staging endpoint plan unless explicitly reviewed.",
    });
  } else {
    checks.push({
      key: "AWS_REGION",
      configured: Boolean(read("AWS_REGION")),
      valuePreview: safeValuePreview("AWS_REGION", read("AWS_REGION")),
      status: read("AWS_REGION") ? "pass" : "missing",
      message: read("AWS_REGION") ? "AWS_REGION is eu-west-2." : "AWS_REGION is not set.",
    });
  }

  for (const key of resourceKeys) {
    const value = read(key);
    const issue = getAlternativeResourceIssue(key, value) || getResourceIssue(key, value);
    checks.push({
      key,
      configured: Boolean(value),
      valuePreview: safeValuePreview(key, value),
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

const runRedactionSelfCheck = () => {
  const redactionCases = [
    {
      name: "redis credentials",
      key: "STAGING_REDIS_URL",
      value: "redis://:password@staging-redis.internal:6379",
      expectedPreview: "redis://<redacted>@staging-redis.internal:6379",
      forbidden: ["password"],
    },
    {
      name: "postgres credentials",
      key: "STAGING_DATABASE_URL",
      value: "postgres://user:pass@staging-db.internal/db",
      expectedPreview: "postgres://<redacted>@staging-db.internal/db",
      forbidden: ["user", "pass"],
    },
    {
      name: "postgresql credentials",
      key: "STAGING_DATABASE_URL",
      value: "postgresql://user:pass@staging-db.internal/db",
      expectedPreview: "postgresql://<redacted>@staging-db.internal/db",
      forbidden: ["user", "pass"],
    },
    {
      name: "https basic auth",
      key: "STAGING_BASE_URL",
      value: "https://user:pass@staging.example.internal/api",
      expectedPreview: "https://<redacted>@staging.example.internal/api",
      forbidden: ["user", "pass"],
    },
    {
      name: "normal host",
      key: "STAGING_DATABASE_HOST",
      value: "staging-db.internal",
      expectedPreview: "staging-db.internal",
      forbidden: [],
    },
  ];

  const redactionResults = redactionCases.map((testCase) => {
    const preview = safeValuePreview(testCase.key, testCase.value);
    const leaked = testCase.forbidden.filter((token) => preview.includes(token));
    return {
      name: testCase.name,
      key: testCase.key,
      preview,
      expectedPreview: testCase.expectedPreview,
      passed: preview === testCase.expectedPreview && leaked.length === 0,
      leakedForbiddenTokenCount: leaked.length,
    };
  });

  const productionBlockResults = [
    {
      name: "production base URL blocked",
      passed: getUrlIssue("STAGING_BASE_URL", "https://www.mscqr.com")?.severity === "blocker",
    },
    {
      name: "production ECS cluster blocked",
      passed: getResourceIssue("STAGING_ECS_CLUSTER", "mscqr-prod-euw2-main")?.severity === "blocker",
    },
  ];

  const originalRedisHost = process.env.STAGING_REDIS_HOST;
  delete process.env.STAGING_REDIS_HOST;
  const missingRedisUrlIssue = getResourceIssue("STAGING_REDIS_URL", "");
  process.env.STAGING_REDIS_HOST = "staging-redis.internal";
  const alternateRedisIssue = getAlternativeResourceIssue("STAGING_REDIS_URL", "");
  if (originalRedisHost === undefined) {
    delete process.env.STAGING_REDIS_HOST;
  } else {
    process.env.STAGING_REDIS_HOST = originalRedisHost;
  }

  const alternativeResourceResults = [
    {
      name: "redis host satisfies redis readiness metadata",
      passed: missingRedisUrlIssue?.severity === "missing" && alternateRedisIssue?.severity === "pass",
    },
  ];

  const allResults = [...redactionResults, ...productionBlockResults, ...alternativeResourceResults];
  const failed = allResults.filter((result) => !result.passed);

  console.log(
    JSON.stringify(
      {
        selfCheck: failed.length === 0 ? "passed" : "failed",
        rawSecretValuesPrinted: false,
        redactionResults,
        productionBlockResults,
        alternativeResourceResults,
      },
      null,
      2,
    ),
  );

  if (failed.length > 0) process.exit(1);
};

if (args.has("--print-checklist")) {
  console.log(fs.readFileSync(checklistPath, "utf8"));
  process.exit(0);
}

if (args.has("--self-check-redaction")) {
  runRedactionSelfCheck();
  process.exit(0);
}

if (!args.has("--dry-run")) {
  console.log(usage);
  process.exit(0);
}

const result = evaluate();
console.log(JSON.stringify(result, null, 2));
if (result.blockers > 0) process.exit(1);

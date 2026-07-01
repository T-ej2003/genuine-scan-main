#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { performance } from "node:perf_hooks";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);
const evidenceDir = path.join(repoRoot, "documents/qa/evidence");

const approvedRoutes = [
  {
    key: "batches_read",
    route: "GET /api/qr/batches",
    path: "/api/qr/batches",
    flag: "MSCQR_STAGING_RLS_BATCHES_READ_ENABLED",
  },
  {
    key: "batch_allocation_map",
    route: "GET /api/qr/batches/:id/allocation-map",
    pathFromEnv: "STAGING_BATCH_ID",
    flag: "MSCQR_STAGING_RLS_BATCH_ALLOCATION_MAP_ENABLED",
  },
  {
    key: "manufacturer_printers",
    route: "GET /api/manufacturer/printers",
    path: "/api/manufacturer/printers",
    flag: "MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED",
  },
];

const usage = `Usage:
  node scripts/collect-rls-staging-validation-evidence.mjs --dry-run
  node scripts/collect-rls-staging-validation-evidence.mjs --self-check-host-guard
  STAGING_BASE_URL=https://staging.example.internal \\
  STAGING_AUTH_TOKEN=<bearer-token> \\
  STAGING_BATCH_ID=<safe-staging-batch-id> \\
  RLS_VALIDATION_SAMPLES=5 \\
  node scripts/collect-rls-staging-validation-evidence.mjs

This collector:
  - requires explicit STAGING_BASE_URL for real collection
  - refuses mscqr.com and *.mscqr.com by default
  - refuses production/prod-looking hosts
  - accepts bearer auth through STAGING_AUTH_TOKEN only
  - never prints auth tokens
  - sends GET requests only to the three approved staged RLS routes
  - uses manual redirect handling and never follows 3xx responses
  - records only whether a Location header was present, not its value
  - does not enable flags and does not mutate data
  - writes safe status, shape, timing, and count summaries only
`;

const args = new Set(process.argv.slice(2));

if (args.has("--help") || args.has("-h")) {
  console.log(usage);
  process.exit(0);
}

const fail = (message) => {
  console.error(`RLS staging evidence collector refused to run: ${message}`);
  process.exit(1);
};

const isDryRun = args.has("--dry-run");
const isHostGuardSelfCheck = args.has("--self-check-host-guard");
const samples = Number.parseInt(process.env.RLS_VALIDATION_SAMPLES || "1", 10);
if (!Number.isInteger(samples) || samples < 1 || samples > 20) {
  fail("RLS_VALIDATION_SAMPLES must be an integer between 1 and 20.");
}

const getBaseUrlValidationError = (raw) => {
  if (!raw) return "STAGING_BASE_URL is required for real collection.";
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    return "STAGING_BASE_URL must be a valid URL.";
  }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    return "STAGING_BASE_URL must use http or https.";
  }
  const host = parsed.hostname.toLowerCase();
  if (host === "mscqr.com" || host.endsWith(".mscqr.com")) {
    return "STAGING_BASE_URL points at the mscqr.com parent domain, which is refused by default.";
  }
  if (host.includes("production") || host.includes("prod")) {
    return "STAGING_BASE_URL contains production/prod in the host.";
  }
  return null;
};

const validateBaseUrl = (raw) => {
  const error = getBaseUrlValidationError(raw);
  if (error) fail(error);
  return new URL(raw);
};

const buildRoutes = () =>
  approvedRoutes.map((route) => {
    if (!route.pathFromEnv) return route;
    const batchId = process.env[route.pathFromEnv];
    if (!batchId) fail(`${route.pathFromEnv} is required for ${route.route}.`);
    if (batchId.includes("/") || batchId.includes("?") || batchId.includes("#")) {
      fail(`${route.pathFromEnv} must be a single safe path segment.`);
    }
    return {
      ...route,
      path: `/api/qr/batches/${encodeURIComponent(batchId)}/allocation-map`,
    };
  });

const percentile = (values, p) => {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const index = Math.ceil((p / 100) * sorted.length) - 1;
  return sorted[Math.max(0, Math.min(sorted.length - 1, index))];
};

const safeJsonType = (value) => {
  if (Array.isArray(value)) return "array";
  if (value === null) return "null";
  return typeof value;
};

const countNestedArrays = (value, prefix = "", depth = 0, out = {}) => {
  if (depth > 2 || value === null || typeof value !== "object") return out;
  if (Array.isArray(value)) {
    if (prefix) out[prefix] = value.length;
    if (value.length > 0) countNestedArrays(value[0], `${prefix}[]`, depth + 1, out);
    return out;
  }
  for (const key of Object.keys(value).slice(0, 20)) {
    const nextPrefix = prefix ? `${prefix}.${key}` : key;
    countNestedArrays(value[key], nextPrefix, depth + 1, out);
  }
  return out;
};

const summarizeJson = (value) => {
  const type = safeJsonType(value);
  const summary = { type };
  if (Array.isArray(value)) {
    summary.topLevelCount = value.length;
    summary.sampleItemType = value.length > 0 ? safeJsonType(value[0]) : null;
    if (value.length > 0 && value[0] && typeof value[0] === "object" && !Array.isArray(value[0])) {
      summary.sampleItemKeys = Object.keys(value[0]).sort().slice(0, 30);
    }
    return summary;
  }
  if (value && typeof value === "object") {
    summary.topLevelKeys = Object.keys(value).sort().slice(0, 30);
    summary.arrayCounts = countNestedArrays(value);
    for (const key of ["data", "items", "results", "rows", "batches", "printers"]) {
      if (Array.isArray(value[key])) summary.safeCount = value[key].length;
    }
  }
  return summary;
};

const summarizeBody = (text, contentType) => {
  if (!text) return { type: "empty", responseBytes: 0 };
  if (contentType.includes("application/json")) {
    try {
      const parsed = JSON.parse(text);
      return { ...summarizeJson(parsed), responseBytes: text.length };
    } catch {
      return { type: "invalid_json", responseBytes: text.length };
    }
  }
  return { type: "non_json", responseBytes: text.length };
};

const getStatusCategory = (status) => {
  if (status >= 200 && status <= 299) return "2xx";
  if (status >= 300 && status <= 399) return "3xx";
  if (status >= 400 && status <= 499) return "4xx";
  if (status >= 500 && status <= 599) return "5xx";
  return "other";
};

const getStatusOutcome = (status) => {
  const category = getStatusCategory(status);
  if (category === "2xx") return "success_2xx";
  if (category === "3xx") return "redirect_3xx";
  if (category === "4xx") return "client_error_4xx";
  if (category === "5xx") return "server_error_5xx";
  return "other_status";
};

const countBy = (items, getKey) =>
  items.reduce((counts, item) => {
    const key = getKey(item);
    counts[key] = (counts[key] || 0) + 1;
    return counts;
  }, {});

const buildRouteFetchOptions = (token) => ({
  method: "GET",
  redirect: "manual",
  headers: {
    Authorization: `Bearer ${token}`,
    Accept: "application/json",
    "User-Agent": "mscqr-rls-staging-validation-evidence-collector",
  },
});

const summarizeResponseAttempt = async (response, durationMs) => {
  const statusCategory = getStatusCategory(response.status);
  const isRedirect = statusCategory === "3xx";
  const contentType = response.headers.get("content-type") || "";
  const text = await response.text();
  const attempt = {
    status: response.status,
    statusCategory,
    statusOutcome: getStatusOutcome(response.status),
    ok: response.ok,
    durationMs,
    contentType: contentType.split(";")[0],
    shapeSummary: summarizeBody(text, contentType),
    rawBodyStored: false,
    authTokenPrinted: false,
    redacted: true,
  };
  if (isRedirect) {
    attempt.redirected = true;
    attempt.redirectStatusCategory = "3xx";
    attempt.locationPresent = response.headers.has("location");
  }
  return attempt;
};

const collectRoute = async (baseUrl, token, route, fetchImpl = fetch) => {
  const timings = [];
  const attempts = [];
  for (let i = 0; i < samples; i += 1) {
    const url = new URL(route.path, baseUrl);
    const started = performance.now();
    const response = await fetchImpl(url, buildRouteFetchOptions(token));
    const durationMs = Math.round(performance.now() - started);
    timings.push(durationMs);
    attempts.push(await summarizeResponseAttempt(response, durationMs));
  }
  return {
    key: route.key,
    route: route.route,
    flag: route.flag,
    method: "GET",
    mutatesData: false,
    samples,
    statusSet: [...new Set(attempts.map((attempt) => attempt.status))],
    statusCategoryCounts: countBy(attempts, (attempt) => attempt.statusCategory),
    statusOutcomeCounts: countBy(attempts, (attempt) => attempt.statusOutcome),
    hasRedirects: attempts.some((attempt) => attempt.statusCategory === "3xx"),
    allSamples2xx: attempts.every((attempt) => attempt.statusCategory === "2xx"),
    redirectPolicy: "manual",
    followsRedirects: false,
    timingMs: {
      p50: percentile(timings, 50),
      p95: percentile(timings, 95),
      min: Math.min(...timings),
      max: Math.max(...timings),
    },
    attempts,
  };
};

if (isDryRun) {
  const plannedRoutes = approvedRoutes.map((route) => ({
    route: route.route,
    flag: route.flag,
    method: "GET",
    mutatesData: false,
    requiresEnv: route.pathFromEnv || null,
  }));
  console.log(
    JSON.stringify(
      {
        dryRun: true,
        requires: ["STAGING_BASE_URL", "STAGING_AUTH_TOKEN", "STAGING_BATCH_ID for allocation-map route"],
        refusesProductionLookingHosts: ["mscqr.com", "*.mscqr.com", "production", "prod"],
        approvedRoutes: plannedRoutes,
        routeFetchPolicy: {
          redirect: buildRouteFetchOptions("<redacted>").redirect,
          followsRedirects: false,
          rawLocationRecorded: false,
          locationPresentRecordedFor3xx: true,
        },
        output: "documents/qa/evidence/rls-staging-validation-safe-summary-<timestamp>.json",
        enablesFlags: false,
        mutatesData: false,
      },
      null,
      2,
    ),
  );
  process.exit(0);
}

if (isHostGuardSelfCheck) {
  const cases = [
    ["https://mscqr.com", false],
    ["https://www.mscqr.com", false],
    ["https://api.mscqr.com", false],
    ["https://staging.mscqr.com", false],
    ["https://prod.example.internal", false],
    ["https://staging.example.internal", true],
  ];
  const results = cases.map(([url, shouldPass]) => {
    const error = getBaseUrlValidationError(url);
    return {
      url,
      expected: shouldPass ? "accept" : "reject",
      actual: error ? "reject" : "accept",
      passed: shouldPass ? !error : Boolean(error),
      reason: error,
    };
  });
  const failed = results.filter((result) => !result.passed);
  const routeFetchOptions = buildRouteFetchOptions("<redacted>");
  const redirectPolicySelfCheck = {
    expected: "manual",
    actual: routeFetchOptions.redirect,
    followsRedirects: routeFetchOptions.redirect !== "manual",
    passed: routeFetchOptions.redirect === "manual",
  };
  console.log(
    JSON.stringify(
      {
        hostGuardSelfCheck: failed.length === 0 ? "passed" : "failed",
        redirectPolicySelfCheck: redirectPolicySelfCheck.passed ? "passed" : "failed",
        results,
        redirectPolicy: redirectPolicySelfCheck,
      },
      null,
      2,
    ),
  );
  if (failed.length > 0 || !redirectPolicySelfCheck.passed) process.exit(1);
  process.exit(0);
}

const baseUrl = validateBaseUrl(process.env.STAGING_BASE_URL);
const authToken = process.env.STAGING_AUTH_TOKEN;
if (!authToken) fail("STAGING_AUTH_TOKEN is required for real collection.");

const routes = buildRoutes();
const collectedAt = new Date().toISOString();
const routeResults = [];
for (const route of routes) {
  routeResults.push(await collectRoute(baseUrl, authToken, route));
}

fs.mkdirSync(evidenceDir, { recursive: true });
const safeTimestamp = collectedAt.replace(/[:.]/g, "-");
const outputPath = path.join(evidenceDir, `rls-staging-validation-safe-summary-${safeTimestamp}.json`);
const summary = {
  schemaVersion: 1,
  collectedAt,
  baseHost: baseUrl.hostname,
  routeScope: "three_approved_staged_rls_routes_only",
  flagsEnabledByScript: false,
  mutatesData: false,
  rawResponsesStored: false,
  authTokenPrinted: false,
  safeSummaryOnly: true,
  samples,
  results: routeResults,
};

fs.writeFileSync(outputPath, `${JSON.stringify(summary, null, 2)}\n`);
console.log(
  JSON.stringify(
    {
      wrote: path.relative(repoRoot, outputPath),
      routesCollected: routeResults.map((result) => result.route),
      rawResponsesStored: false,
      authTokenPrinted: false,
      flagsEnabledByScript: false,
      mutatesData: false,
    },
    null,
    2,
  ),
);

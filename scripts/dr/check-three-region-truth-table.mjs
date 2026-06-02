#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";
import { gzipSync } from "node:zlib";

import {
  DEFAULT_REGIONAL_DNS_POLICY,
  evaluateRoute53RegionalPolicy,
  regionalPolicyFromEnv,
} from "../lib/route53-regional-rollback-core.mjs";

const usage = `Usage:
  HOSTED_ZONE_ID=Z... npm run ops:three-region-truth-table

Optional:
  MUMBAI_HEALTHZ_URL, CAPETOWN_HEALTHZ_URL, LONDON_HEALTHZ_URL
  MUMBAI_READY_URL, CAPETOWN_READY_URL, LONDON_READY_URL
  LONDON_SSH_HOST, LONDON_SSH_USER, LONDON_SSH_KEY, LONDON_SSH_PORT
  HEALTH_TIMEOUT_MS
`;

function parseArgs(argv) {
  for (const arg of argv) {
    if (arg === "-h" || arg === "--help") {
      console.log(usage);
      process.exit(0);
    }
    throw new Error(`Unknown option: ${arg}\n${usage}`);
  }
}

const utcTimestamp = () => new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
const isMain = import.meta.url === pathToFileURL(process.argv[1] || "").href;
const localCommand = (name) => {
  const commonPath = `/usr/bin/${name}`;
  return existsSync(commonPath) ? commonPath : name;
};

function ensureArtifactDir() {
  const artifactRoot = path.resolve(process.cwd(), "artifacts", "dr");
  if (!existsSync(artifactRoot)) mkdirSync(artifactRoot, { recursive: true });
  writeFileSync(path.join(artifactRoot, ".gitignore"), "*\n!.gitignore\n");
  const runDir = path.join(artifactRoot, utcTimestamp(), "three-region-truth-table");
  mkdirSync(runDir, { recursive: true });
  return runDir;
}

function gzipJson(filePath, payload) {
  writeFileSync(filePath, gzipSync(`${JSON.stringify(payload, null, 2)}\n`));
}

export function awsJson(args) {
  const stdout = execFileSync("aws", [...args, "--output", "json"], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 60000,
  });
  return JSON.parse(stdout || "{}");
}

function readResponseBody(response, maxBytes = 4000) {
  return new Promise((resolve) => {
    const chunks = [];
    let totalBytes = 0;
    response.on("data", (chunk) => {
      if (totalBytes < maxBytes) chunks.push(chunk.slice(0, Math.max(0, maxBytes - totalBytes)));
      totalBytes += chunk.length;
    });
    response.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    response.on("error", (error) => resolve(`response read error: ${error.message || String(error)}`));
  });
}

function requestOnce(url, timeoutMs) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const isHttps = parsed.protocol === "https:";
    const transport = isHttps ? https : http;
    const allowRawAlbTls = isHttps && parsed.hostname.endsWith(".elb.amazonaws.com");
    const request = transport.request(
      parsed,
      {
        method: "GET",
        headers: { Accept: "application/json,text/plain,*/*" },
        timeout: timeoutMs,
        ...(isHttps ? { rejectUnauthorized: !allowRawAlbTls } : {}),
      },
      async (response) => {
        resolve({
          status: response.statusCode || 0,
          headers: response.headers,
          body: await readResponseBody(response),
          tlsVerification: allowRawAlbTls ? "disabled-for-raw-alb-hostname" : "default",
        });
      },
    );
    request.on("timeout", () => {
      request.destroy(new Error(`request timed out after ${timeoutMs}ms`));
    });
    request.on("error", reject);
    request.end();
  });
}

export async function httpCheck(check, scope, url, timeoutMs, options = {}) {
  if (!url) return { check, scope, status: "SKIP", detail: "URL not configured" };
  const evidence = {
    url,
    hops: [],
    finalUrl: url,
  };
  let currentUrl = url;
  let readyRedirectedToProduction = false;
  try {
    for (let redirectCount = 0; redirectCount <= 5; redirectCount += 1) {
      const response = await requestOnce(currentUrl, timeoutMs);
      const location = response.headers.location
        ? new URL(response.headers.location, currentUrl).toString()
        : "";
      evidence.hops.push({
        url: currentUrl,
        status: response.status,
        location,
        contentType: response.headers["content-type"] || "",
        tlsVerification: response.tlsVerification,
        body: response.body,
      });

      if (response.status >= 300 && response.status < 400 && location) {
        const nextUrl = new URL(location);
        if (
          options.kind === "ready" &&
          !options.explicitOverride &&
          nextUrl.hostname === "www.mscqr.com" &&
          nextUrl.pathname === "/api/health/ready"
        ) {
          readyRedirectedToProduction = true;
          evidence.finalUrl = location;
          return {
            check,
            scope,
            status: "WARN",
            detail: `raw ALB ready redirected to production hostname; use ${options.overrideEnvName || "READY_URL"} for region-specific readiness`,
            evidence,
          };
        }
        currentUrl = location;
        evidence.finalUrl = currentUrl;
        continue;
      }

      evidence.finalUrl = currentUrl;
      const detail = `${response.status} ${response.headers["content-type"] || ""}`.trim();
      if (options.kind === "ready" && options.explicitOverride && check === "london_ready") {
        const readyEvidence = extractReadyObjectStorageEvidence(response.body);
        Object.assign(evidence, readyEvidence);
        const readyOk =
          response.status >= 200 &&
          response.status < 300 &&
          readyEvidence.backendObjectStorageMode === "default-credentials" &&
          readyEvidence.backendObjectStorageReady === true &&
          (!readyEvidence.backendObjectStorageRegion || readyEvidence.backendObjectStorageRegion === "eu-west-2") &&
          (!readyEvidence.backendObjectStorageBucket ||
            /(^|[-_])eu[-_]?west[-_]?2($|[-_])|(^|[-_])euw2($|[-_])/.test(readyEvidence.backendObjectStorageBucket));
        return {
          check,
          scope,
          status: readyOk ? "PASS" : "FAIL",
          detail: readyOk ? detail : `${detail}; London ready override did not prove default-credentials object storage`,
          evidence,
        };
      }
      if (readyRedirectedToProduction) {
        return {
          check,
          scope,
          status: "WARN",
          detail: `raw ALB ready redirected to production hostname; use ${options.overrideEnvName || "READY_URL"} for region-specific readiness`,
          evidence,
        };
      }
      return {
        check,
        scope,
        status: response.status >= 200 && response.status < 300 ? "PASS" : "FAIL",
        detail,
        evidence,
      };
    }

    return {
      check,
      scope,
      status: "FAIL",
      detail: "too many redirects",
      evidence,
    };
  } catch (error) {
    return {
      check,
      scope,
      status: "FAIL",
      detail: error.message || String(error),
      evidence: {
        ...evidence,
        error: {
          name: error.name || "Error",
          code: error.code || "",
          message: error.message || String(error),
        },
      },
    };
  }
}

function extractReadyObjectStorageEvidence(body) {
  try {
    const data = JSON.parse(body || "{}");
    const storage = data.dependencies?.objectStorage || data.objectStorage || {};
    return {
      backendObjectStorageMode: String(storage.mode || ""),
      backendObjectStorageReady: storage.ready === true,
      backendObjectStorageBucket: String(storage.bucket || ""),
      backendObjectStorageRegion: String(storage.region || ""),
    };
  } catch (error) {
    return {
      backendObjectStorageMode: "",
      backendObjectStorageReady: false,
      backendObjectStorageBucket: "",
      backendObjectStorageRegion: "",
      readyJsonParseError: error.message || String(error),
    };
  }
}

export function sshLondonMinioCheck(env = process.env) {
  const host = env.LONDON_SSH_HOST || "";
  const key = env.LONDON_SSH_KEY || "";
  if (!host || !key) {
    return {
      check: "london_no_active_minio_ssh",
      scope: "London",
      status: "SKIP",
      detail: "LONDON_SSH_HOST and LONDON_SSH_KEY not provided",
    };
  }
  const user = env.LONDON_SSH_USER || "ubuntu";
  const port = env.LONDON_SSH_PORT || "22";
  const destination = `${user}@${host}`;
  const args = [
    "-o",
    "BatchMode=yes",
    "-o",
    "ConnectTimeout=10",
    "-p",
    port,
    "-i",
    key,
  ];
  const remoteCommand = [
    "set -eu",
    "if docker ps >/dev/null 2>&1; then docker_cmd=docker; elif sudo -n docker ps >/dev/null 2>&1; then docker_cmd='sudo -n docker'; else docker_cmd=docker; fi",
    "minio_containers=$($docker_cmd ps --format '{{.Names}}\t{{.Image}}\t{{.Status}}' | awk 'BEGIN{IGNORECASE=1} $0 ~ /minio\\/minio/ || $1 ~ /^minio([._-]|$)/ { print }' || true)",
    "minio_processes=$(ps -eo comm=,args= | awk 'BEGIN{IGNORECASE=1} $1 == \"minio\" && $0 ~ /(^|[[:space:]])minio[[:space:]]+server([[:space:]]|$)/ { print }' || true)",
    "backend_probe='",
    "const endpointSet = Boolean(process.env.OBJECT_STORAGE_ENDPOINT);",
    "const forcePathStyle = process.env.OBJECT_STORAGE_FORCE_PATH_STYLE || \"\";",
    "fetch(\"http://127.0.0.1:4000/health/ready\")",
    "  .then(async (response) => {",
    "    const text = await response.text();",
    "    let data = {};",
    "    try { data = JSON.parse(text); } catch {}",
    "    const storage = data.dependencies?.objectStorage || data.objectStorage || {};",
    "    console.log(`OBJECT_STORAGE_ENDPOINT_SET=${endpointSet}`);",
    "    console.log(`OBJECT_STORAGE_FORCE_PATH_STYLE=${forcePathStyle}`);",
    "    console.log(`BACKEND_READY_STATUS_CODE=${response.status}`);",
    "    console.log(`BACKEND_OBJECT_STORAGE_MODE=${String(storage.mode || \"\")}`);",
    "    console.log(`BACKEND_OBJECT_STORAGE_READY=${String(storage.ready === true)}`);",
    "    console.log(`BACKEND_OBJECT_STORAGE_BUCKET=${String(storage.bucket || \"\")}`);",
    "    console.log(`BACKEND_OBJECT_STORAGE_REGION=${String(storage.region || \"\")}`);",
    "  })",
    "  .catch((error) => {",
    "    console.log(\"OBJECT_STORAGE_ENDPOINT_SET=false\");",
    "    console.log(`OBJECT_STORAGE_FORCE_PATH_STYLE=${forcePathStyle}`);",
    "    console.log(\"BACKEND_READY_STATUS_CODE=0\");",
    "    console.log(\"BACKEND_OBJECT_STORAGE_MODE=\");",
    "    console.log(\"BACKEND_OBJECT_STORAGE_READY=false\");",
    "    console.log(\"BACKEND_OBJECT_STORAGE_BUCKET=\");",
    "    console.log(\"BACKEND_OBJECT_STORAGE_REGION=\");",
    "    console.log(`BACKEND_READY_ERROR=${String(error.message || error).replace(/[\\r\\n]/g, \" \")}`);",
    "  });",
    "'",
    "backend_storage=$($docker_cmd exec genuine-scan-backend node -e \"$backend_probe\" 2>/dev/null || $docker_cmd compose exec -T backend node -e \"$backend_probe\" 2>/dev/null || true)",
    "printf '__MINIO_CONTAINERS__\\n%s\\n' \"$minio_containers\"",
    "printf '__MINIO_PROCESSES__\\n%s\\n' \"$minio_processes\"",
    "printf '__BACKEND_STORAGE__\\n%s\\n' \"$backend_storage\"",
  ].join("\n");
  args.push(destination, remoteCommand);
  try {
    const stdout = execFileSync(localCommand("ssh"), args, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 30000,
    });
    return evaluateLondonSshMinioEvidence(stdout);
  } catch (error) {
    return { check: "london_no_active_minio_ssh", scope: "London", status: "FAIL", detail: error.message || String(error) };
  }
}

export function evaluateLondonSshMinioEvidence(stdout) {
  const minioContainers = filterRealMinioContainers(
    extractSection(stdout, "__MINIO_CONTAINERS__")
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean),
  );
  const minioProcesses = filterRealMinioServerProcesses(
    extractSection(stdout, "__MINIO_PROCESSES__")
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean),
  );
  const backendStorage = extractSection(stdout, "__BACKEND_STORAGE__").trim();
  const backendStorageLines = new Map(
    backendStorage
      .split("\n")
      .map((line) => line.split("="))
      .filter(([key]) => key)
      .map(([key, ...value]) => [key, value.join("=")]),
  );
  const backendReadyStatusCode = Number(backendStorageLines.get("BACKEND_READY_STATUS_CODE") || 0);
  const backendObjectStorageMode = backendStorageLines.get("BACKEND_OBJECT_STORAGE_MODE") || "";
  const backendObjectStorageReady = backendStorageLines.get("BACKEND_OBJECT_STORAGE_READY") === "true";
  const backendObjectStorageBucket = backendStorageLines.get("BACKEND_OBJECT_STORAGE_BUCKET") || "";
  const backendObjectStorageRegion = backendStorageLines.get("BACKEND_OBJECT_STORAGE_REGION") || "";
  const backendEndpointUnset = backendStorageLines.get("OBJECT_STORAGE_ENDPOINT_SET") === "false";
  const backendForcePathStyleSafe = ["", "false"].includes(backendStorageLines.get("OBJECT_STORAGE_FORCE_PATH_STYLE") || "");
  const backendLondonRegion = !backendObjectStorageRegion || backendObjectStorageRegion === "eu-west-2";
  const backendLondonBucket =
    !backendObjectStorageBucket ||
    /(^|[-_])eu[-_]?west[-_]?2($|[-_])|(^|[-_])euw2($|[-_])/.test(backendObjectStorageBucket);
  const backendDefaultCredentials =
    backendEndpointUnset &&
    backendForcePathStyleSafe &&
    backendReadyStatusCode >= 200 &&
    backendReadyStatusCode < 300 &&
    backendObjectStorageMode === "default-credentials" &&
    backendObjectStorageReady &&
    backendLondonRegion &&
    backendLondonBucket;
  const failed = Boolean(minioContainers.length > 0 || minioProcesses.length > 0 || !backendDefaultCredentials);

  return {
    check: "london_no_active_minio_ssh",
    scope: "London",
    status: failed ? "FAIL" : "PASS",
    detail: failed
      ? "review MinIO/process/default-credentials evidence"
      : "no MinIO containers/processes and backend readiness reports default credentials",
    evidence: {
      activeMinioContainers: minioContainers,
      activeMinioProcesses: minioProcesses,
      backendReadyStatusCode,
      backendObjectStorageMode,
      backendObjectStorageReady,
      backendObjectStorageBucket,
      backendObjectStorageRegion,
      backendStorageDefaultCredentials: backendDefaultCredentials,
    },
  };
}

export function filterRealMinioServerProcesses(lines) {
  return lines.filter((line) => {
    const normalized = line.toLowerCase().replace(/\s+/g, " ").trim();
    if (!normalized) return false;
    const [command = ""] = normalized.split(" ");
    return command === "minio" && /\bminio\s+server\b/.test(normalized);
  });
}

export function filterRealMinioContainers(lines) {
  return lines.filter((line) => {
    const fields = line.toLowerCase().split(/\t+/).map((field) => field.trim());
    const [name = "", image = ""] = fields;
    return /^minio([._-]|$)/.test(name) || image.includes("minio/minio");
  });
}

function extractSection(source, marker) {
  const start = source.indexOf(`${marker}\n`);
  if (start === -1) return "";
  const rest = source.slice(start + marker.length + 1);
  const next = rest.search(/\n__[A-Z_]+__\n/);
  return next === -1 ? rest : rest.slice(0, next);
}

function csvEscape(value) {
  const text = String(value ?? "");
  return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function printSummary(rows) {
  console.log("check,scope,status,detail");
  for (const row of rows) {
    console.log([row.check, row.scope, row.status, row.detail].map(csvEscape).join(","));
  }
  const verdict = rows.some((row) => row.status === "FAIL" || row.status === "WARN") ? "REVIEW_REQUIRED" : "PASS";
  console.log(`verdict,three-region-policy,${verdict},${verdict === "PASS" ? "all required checks passed" : "review FAIL/WARN rows"}`);
  return verdict;
}

export async function main() {
  parseArgs(process.argv.slice(2));
  const outDir = ensureArtifactDir();
  const policy = regionalPolicyFromEnv();
  const timeoutMs = Number(process.env.HEALTH_TIMEOUT_MS || 8000);
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new Error("HEALTH_TIMEOUT_MS must be a positive number.");

  const rows = [];
  const hostedZoneId = process.env.HOSTED_ZONE_ID || "";
  if (hostedZoneId) {
    const route53Payload = awsJson(["route53", "list-resource-record-sets", "--hosted-zone-id", hostedZoneId]);
    gzipJson(path.join(outDir, "route53-records.json.gz"), route53Payload);
    rows.push(...evaluateRoute53RegionalPolicy(route53Payload.ResourceRecordSets || [], policy));
  } else {
    rows.push({ check: "route53_three_region_policy", scope: "Route 53", status: "FAIL", detail: "HOSTED_ZONE_ID not provided" });
  }

  const records = policy.records;
  const healthChecks = [
    httpCheck(
      "mumbai_alb_healthz",
      "Mumbai",
      process.env.MUMBAI_HEALTHZ_URL || `http://${records.defaultMumbai.albDnsName}/healthz`,
      timeoutMs,
      { kind: "healthz", explicitOverride: Boolean(process.env.MUMBAI_HEALTHZ_URL), overrideEnvName: "MUMBAI_HEALTHZ_URL" },
    ),
    httpCheck(
      "capetown_alb_healthz",
      "Cape Town",
      process.env.CAPETOWN_HEALTHZ_URL || `http://${records.africaCapeTown.albDnsName}/healthz`,
      timeoutMs,
      { kind: "healthz", explicitOverride: Boolean(process.env.CAPETOWN_HEALTHZ_URL), overrideEnvName: "CAPETOWN_HEALTHZ_URL" },
    ),
    httpCheck(
      "london_alb_healthz",
      "London",
      process.env.LONDON_HEALTHZ_URL || `http://${records.europeLondon.albDnsName}/healthz`,
      timeoutMs,
      { kind: "healthz", explicitOverride: Boolean(process.env.LONDON_HEALTHZ_URL), overrideEnvName: "LONDON_HEALTHZ_URL" },
    ),
    httpCheck(
      "mumbai_ready",
      "Mumbai",
      process.env.MUMBAI_READY_URL || `http://${records.defaultMumbai.albDnsName}/api/health/ready`,
      timeoutMs,
      { kind: "ready", explicitOverride: Boolean(process.env.MUMBAI_READY_URL), overrideEnvName: "MUMBAI_READY_URL" },
    ),
    httpCheck(
      "capetown_ready",
      "Cape Town",
      process.env.CAPETOWN_READY_URL || `http://${records.africaCapeTown.albDnsName}/api/health/ready`,
      timeoutMs,
      { kind: "ready", explicitOverride: Boolean(process.env.CAPETOWN_READY_URL), overrideEnvName: "CAPETOWN_READY_URL" },
    ),
    httpCheck(
      "london_ready",
      "London",
      process.env.LONDON_READY_URL || `http://${records.europeLondon.albDnsName}/api/health/ready`,
      timeoutMs,
      { kind: "ready", explicitOverride: Boolean(process.env.LONDON_READY_URL), overrideEnvName: "LONDON_READY_URL" },
    ),
  ];
  const healthRows = await Promise.all(healthChecks);
  rows.push(...healthRows.map(({ evidence, ...row }) => row));
  gzipJson(path.join(outDir, "http-health-evidence.json.gz"), healthRows);

  const sshRow = sshLondonMinioCheck();
  const { evidence: _sshEvidence, ...sshSummaryRow } = sshRow;
  rows.push(sshSummaryRow);
  gzipJson(path.join(outDir, "london-minio-ssh-evidence.json.gz"), sshRow);

  gzipJson(path.join(outDir, "truth-table-summary.json.gz"), {
    generatedAt: new Date().toISOString(),
    expectedPolicy: DEFAULT_REGIONAL_DNS_POLICY,
    rows,
  });
  const verdict = printSummary(rows);
  console.log(`evidence_dir,artifacts,INFO,${outDir}`);
  process.exit(verdict === "PASS" ? 0 : 1);
}

if (isMain) {
  try {
    await main();
  } catch (error) {
    console.error(error.message || String(error));
    process.exit(2);
  }
}

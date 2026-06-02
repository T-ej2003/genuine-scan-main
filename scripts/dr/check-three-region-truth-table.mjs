#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import process from "node:process";
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

function awsJson(args) {
  const stdout = execFileSync("aws", [...args, "--output", "json"], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 60000,
  });
  return JSON.parse(stdout || "{}");
}

async function httpCheck(check, scope, url, timeoutMs) {
  if (!url) return { check, scope, status: "SKIP", detail: "URL not configured" };
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { signal: controller.signal });
    const body = await response.text();
    return {
      check,
      scope,
      status: response.status >= 200 && response.status < 300 ? "PASS" : "FAIL",
      detail: `${response.status} ${response.headers.get("content-type") || ""}`.trim(),
      evidence: { url, status: response.status, contentType: response.headers.get("content-type") || "", body: body.slice(0, 4000) },
    };
  } catch (error) {
    return { check, scope, status: "FAIL", detail: error.message || String(error), evidence: { url } };
  } finally {
    clearTimeout(timeout);
  }
}

function sshLondonMinioCheck() {
  const host = process.env.LONDON_SSH_HOST || "";
  if (!host) {
    return { check: "london_no_active_minio_ssh", scope: "London", status: "SKIP", detail: "LONDON_SSH_HOST not provided" };
  }
  const user = process.env.LONDON_SSH_USER || "ubuntu";
  const key = process.env.LONDON_SSH_KEY || "";
  const port = process.env.LONDON_SSH_PORT || "22";
  const destination = `${user}@${host}`;
  const args = [
    "-o",
    "BatchMode=yes",
    "-o",
    "ConnectTimeout=10",
    "-p",
    port,
  ];
  if (key) args.push("-i", key);
  args.push(destination, "docker ps --format '{{.Names}}\t{{.Status}}' | grep -i minio || true");
  try {
    const stdout = execFileSync("ssh", args, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 30000,
    });
    const activeMinio = stdout.trim();
    return {
      check: "london_no_active_minio_ssh",
      scope: "London",
      status: activeMinio ? "FAIL" : "PASS",
      detail: activeMinio ? "active MinIO container listed" : "no active MinIO container listed",
      evidence: activeMinio ? { activeMinioContainers: activeMinio.split("\n") } : { activeMinioContainers: [] },
    };
  } catch (error) {
    return { check: "london_no_active_minio_ssh", scope: "London", status: "FAIL", detail: error.message || String(error) };
  }
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

try {
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
    ),
    httpCheck(
      "capetown_alb_healthz",
      "Cape Town",
      process.env.CAPETOWN_HEALTHZ_URL || `http://${records.africaCapeTown.albDnsName}/healthz`,
      timeoutMs,
    ),
    httpCheck(
      "london_alb_healthz",
      "London",
      process.env.LONDON_HEALTHZ_URL || `http://${records.europeLondon.albDnsName}/healthz`,
      timeoutMs,
    ),
    httpCheck(
      "mumbai_ready",
      "Mumbai",
      process.env.MUMBAI_READY_URL || `http://${records.defaultMumbai.albDnsName}/api/health/ready`,
      timeoutMs,
    ),
    httpCheck(
      "capetown_ready",
      "Cape Town",
      process.env.CAPETOWN_READY_URL || `http://${records.africaCapeTown.albDnsName}/api/health/ready`,
      timeoutMs,
    ),
    httpCheck(
      "london_ready",
      "London",
      process.env.LONDON_READY_URL || `http://${records.europeLondon.albDnsName}/api/health/ready`,
      timeoutMs,
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
} catch (error) {
  console.error(error.message || String(error));
  process.exit(2);
}

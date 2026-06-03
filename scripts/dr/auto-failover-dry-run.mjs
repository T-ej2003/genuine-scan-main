#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";
import { gunzipSync } from "node:zlib";

import { evaluateAutoFailover } from "../lib/auto-failover-core.mjs";
import { buildRegionalRollbackPlan, regionalPolicyFromEnv } from "../lib/route53-regional-rollback-core.mjs";

const usage = `Usage:
  npm run ops:auto-failover-dry-run -- --evidence <truth-table-summary.json.gz|truth-table-dir> [--evidence <...>]

Options:
  --evidence <path>     Repeatable. File path to truth-table-summary.json.gz or a three-region-truth-table directory.
  --evidence-dir <dir>  Directory tree to scan for truth-table-summary.json.gz samples.
  --threshold <n>       Consecutive failure samples required before recommending failover. Default: 2.
  --strict-warn         Treat WARN rows as failures. Default: WARN-only rows are ignored.

Environment:
  AUTO_FAILOVER_EVIDENCE_PATHS   Comma-separated evidence paths.
  AUTO_FAILOVER_EVIDENCE_DIR     Directory tree to scan for truth-table-summary.json.gz.
  AUTO_FAILOVER_FAILURE_THRESHOLD
  AUTO_FAILOVER_STRICT_WARN=true
  TARGET_SHA

This is dry-run/plan-only. It never calls AWS and never applies Route 53 changes.
`;

const utcTimestamp = () => new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");

function parseArgs(argv, env = process.env) {
  const options = {
    evidencePaths: (env.AUTO_FAILOVER_EVIDENCE_PATHS || "")
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean),
    evidenceDir: env.AUTO_FAILOVER_EVIDENCE_DIR || "",
    threshold: Number(env.AUTO_FAILOVER_FAILURE_THRESHOLD || 2),
    strictWarn: env.AUTO_FAILOVER_STRICT_WARN === "true",
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    const nextValue = () => {
      const value = argv[index + 1];
      if (!value || value.startsWith("--")) throw new Error(`Missing value for ${arg}`);
      index += 1;
      return value;
    };
    if (arg === "--evidence") options.evidencePaths.push(nextValue());
    else if (arg === "--evidence-dir") options.evidenceDir = nextValue();
    else if (arg === "--threshold") options.threshold = Number(nextValue());
    else if (arg === "--strict-warn") options.strictWarn = true;
    else if (arg === "-h" || arg === "--help") {
      console.log(usage);
      process.exit(0);
    } else {
      throw new Error(`Unknown option: ${arg}\n${usage}`);
    }
  }

  if (!Number.isInteger(options.threshold) || options.threshold < 2) {
    throw new Error("--threshold must be an integer >= 2.");
  }
  return options;
}

function ensureArtifactDir() {
  const artifactRoot = path.resolve(process.cwd(), "artifacts", "dr");
  if (!existsSync(artifactRoot)) mkdirSync(artifactRoot, { recursive: true });
  writeFileSync(path.join(artifactRoot, ".gitignore"), "*\n!.gitignore\n");
  const runDir = path.join(artifactRoot, utcTimestamp(), "auto-failover-dry-run");
  mkdirSync(runDir, { recursive: true });
  return runDir;
}

function sha256File(filePath) {
  return createHash("sha256").update(readFileSync(filePath)).digest("hex");
}

function sha256Text(text) {
  return createHash("sha256").update(text).digest("hex");
}

function targetSha(env = process.env) {
  if (env.TARGET_SHA) return env.TARGET_SHA;
  try {
    return execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    return "unknown";
  }
}

export function resolveEvidenceFiles(options) {
  const files = [];
  for (const evidencePath of options.evidencePaths || []) {
    files.push(resolveOneEvidencePath(evidencePath));
  }
  if (options.evidenceDir) {
    files.push(...findTruthTableSummaries(path.resolve(process.cwd(), options.evidenceDir)));
  }
  return [...new Set(files)].sort();
}

function resolveOneEvidencePath(evidencePath) {
  const absolute = path.resolve(process.cwd(), evidencePath);
  if (!existsSync(absolute)) throw new Error(`Evidence path does not exist: ${evidencePath}`);
  if (statSync(absolute).isDirectory()) {
    const summary = path.join(absolute, "truth-table-summary.json.gz");
    if (!existsSync(summary)) throw new Error(`Evidence directory is missing truth-table-summary.json.gz: ${evidencePath}`);
    return summary;
  }
  return absolute;
}

function findTruthTableSummaries(rootDir) {
  if (!existsSync(rootDir)) throw new Error(`Evidence directory does not exist: ${rootDir}`);
  const found = [];
  const visit = (dir) => {
    for (const name of readdirSync(dir)) {
      const fullPath = path.join(dir, name);
      const stat = statSync(fullPath);
      if (stat.isDirectory()) visit(fullPath);
      else if (name === "truth-table-summary.json.gz") found.push(fullPath);
    }
  };
  visit(rootDir);
  return found;
}

export function readTruthTableSummary(filePath) {
  const payload = JSON.parse(gunzipSync(readFileSync(filePath)).toString("utf8"));
  return { ...payload, path: filePath };
}

function writeSelectedPlan({ decision, outDir }) {
  if (decision.decisionStatus !== "RECOMMEND_FAILOVER") {
    return { recommendedPlanJsonPath: "", recommendedRollbackJsonPath: "", recommendedPlanJsonSha256: "" };
  }
  const plan = buildRegionalRollbackPlan({
    operation: decision.selectedOperation,
    policy: regionalPolicyFromEnv(),
  });
  const cutoverPath = path.join(outDir, `${decision.selectedOperation}-cutover.json`);
  const rollbackPath = path.join(outDir, `${decision.selectedOperation}-rollback.json`);
  writeFileSync(cutoverPath, `${JSON.stringify(plan.cutoverBatch, null, 2)}\n`);
  writeFileSync(rollbackPath, `${JSON.stringify(plan.rollbackBatch, null, 2)}\n`);
  return {
    recommendedPlanJsonPath: cutoverPath,
    recommendedRollbackJsonPath: rollbackPath,
    recommendedPlanJsonSha256: sha256File(cutoverPath),
  };
}

export function buildDecisionArtifact({ decision, evidenceFiles, planInfo, sha, generatedAt = new Date().toISOString() }) {
  return {
    timestamp: generatedAt,
    targetSha: sha,
    inputEvidencePath: evidenceFiles.at(-1) || "",
    inputEvidencePaths: evidenceFiles,
    failedChecks: decision.failedChecks,
    selectedOperation: decision.selectedOperation,
    recommendedPlanJsonPath: planInfo.recommendedPlanJsonPath,
    recommendedPlanJsonSha256: planInfo.recommendedPlanJsonSha256,
    decisionStatus: decision.decisionStatus,
    reason: decision.reason,
    threshold: decision.threshold,
    strictWarn: decision.strictWarn,
    regionEvaluations: decision.regionEvaluations,
  };
}

export async function main() {
  const options = parseArgs(process.argv.slice(2));
  const evidenceFiles = resolveEvidenceFiles(options);
  const samples = evidenceFiles.map(readTruthTableSummary);
  const decision = evaluateAutoFailover(samples, {
    threshold: options.threshold,
    strictWarn: options.strictWarn,
  });
  const outDir = ensureArtifactDir();
  const planInfo = writeSelectedPlan({ decision, outDir });
  const artifact = buildDecisionArtifact({
    decision,
    evidenceFiles,
    planInfo,
    sha: targetSha(),
  });
  const decisionJson = `${JSON.stringify(artifact, null, 2)}\n`;
  const decisionPath = path.join(outDir, "decision.json");
  const decisionShaPath = path.join(outDir, "decision.json.sha256");
  writeFileSync(decisionPath, decisionJson);
  writeFileSync(decisionShaPath, `${sha256Text(decisionJson)}  decision.json\n`);

  console.log("MSCQR automatic regional failover dry-run decision generated.");
  console.log(`Decision status: ${artifact.decisionStatus}`);
  console.log(`Selected operation: ${artifact.selectedOperation || "none"}`);
  console.log(`Reason: ${artifact.reason}`);
  console.log(`Decision JSON: ${decisionPath}`);
  console.log(`Decision SHA256: ${decisionShaPath}`);
  if (artifact.recommendedPlanJsonPath) {
    console.log(`Recommended plan JSON: ${artifact.recommendedPlanJsonPath}`);
    console.log(`Recommended plan SHA256: ${artifact.recommendedPlanJsonSha256}`);
  }
  console.log("No AWS calls were made. No Route 53 changes were applied.");
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  try {
    await main();
  } catch (error) {
    console.error(error.message || String(error));
    process.exit(2);
  }
}

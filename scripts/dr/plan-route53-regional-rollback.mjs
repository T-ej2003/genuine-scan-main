#!/usr/bin/env node

import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import process from "node:process";

import {
  buildRegionalRollbackPlan,
  regionalPolicyFromEnv,
  route53BatchChangedSetIdentifiers,
  SUPPORTED_REGIONAL_ROLLBACK_OPERATIONS,
} from "../lib/route53-regional-rollback-core.mjs";

const usage = `Usage: npm run ops:route53-regional-rollback-plan -- --operation <operation>

Plan-only Route 53 regional rollback/failover batch generator. It never calls AWS.

Operations:
  rollback-europe          Delete only europe-london.
  rollback-africa          Delete only africa-capetown.
  restore-default-mumbai   UPSERT only default-mumbai.

Optional environment:
  DOMAIN_NAME
  MUMBAI_ALB_DNS_NAME, MUMBAI_ALB_HOSTED_ZONE_ID
  CAPETOWN_ALB_DNS_NAME, CAPETOWN_ALB_HOSTED_ZONE_ID
  LONDON_ALB_DNS_NAME, LONDON_ALB_HOSTED_ZONE_ID
`;

function parseArgs(argv) {
  const options = { operation: process.env.OPERATION || process.env.ROUTE53_ROLLBACK_OPERATION || "" };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    const nextValue = () => {
      const value = argv[index + 1];
      if (!value || value.startsWith("--")) throw new Error(`Missing value for ${arg}`);
      index += 1;
      return value;
    };
    if (arg === "--operation") options.operation = nextValue();
    else if (arg === "-h" || arg === "--help") {
      console.log(usage);
      process.exit(0);
    } else {
      throw new Error(`Unknown option: ${arg}\n${usage}`);
    }
  }
  return options;
}

const utcTimestamp = () => new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");

function ensureArtifactDir() {
  const artifactRoot = path.resolve(process.cwd(), "artifacts", "dr");
  if (!existsSync(artifactRoot)) mkdirSync(artifactRoot, { recursive: true });
  writeFileSync(path.join(artifactRoot, ".gitignore"), "*\n!.gitignore\n");
  const runDir = path.join(artifactRoot, utcTimestamp(), "route53-regional-rollback-plan");
  mkdirSync(runDir, { recursive: true });
  return runDir;
}

try {
  const options = parseArgs(process.argv.slice(2));
  if (!SUPPORTED_REGIONAL_ROLLBACK_OPERATIONS.has(options.operation)) {
    throw new Error(`--operation must be one of: ${[...SUPPORTED_REGIONAL_ROLLBACK_OPERATIONS].join(", ")}`);
  }

  const policy = regionalPolicyFromEnv();
  const plan = buildRegionalRollbackPlan({ operation: options.operation, policy });
  const outDir = ensureArtifactDir();
  const cutoverPath = path.join(outDir, `${options.operation}-cutover.json`);
  const rollbackPath = path.join(outDir, `${options.operation}-rollback.json`);
  const summaryPath = path.join(outDir, "summary.md");

  writeFileSync(cutoverPath, `${JSON.stringify(plan.cutoverBatch, null, 2)}\n`);
  writeFileSync(rollbackPath, `${JSON.stringify(plan.rollbackBatch, null, 2)}\n`);
  writeFileSync(
    summaryPath,
    [
      "# Route 53 Regional Rollback Plan",
      "",
      `- Operation: \`${options.operation}\``,
      `- Requested target: \`${plan.targetSetIdentifier}\``,
      `- Cutover JSON: \`${cutoverPath}\``,
      `- Rollback JSON: \`${rollbackPath}\``,
      `- Cutover touches only: \`${route53BatchChangedSetIdentifiers(plan.cutoverBatch).join(", ")}\``,
      `- Inverse rollback touches only: \`${route53BatchChangedSetIdentifiers(plan.rollbackBatch).join(", ")}\``,
      "",
      plan.summary,
      "",
      "This is plan-only. It does not call AWS and cannot apply Route 53 changes.",
      "Unrelated DNS records such as MX, TXT, NS, SOA, and www CNAME are intentionally absent from both batches.",
      "",
    ].join("\n"),
  );

  console.log("MSCQR Route 53 regional rollback/failover plan generated.");
  console.log(`Operation: ${options.operation}`);
  console.log(`Cutover JSON: ${cutoverPath}`);
  console.log(`Rollback JSON: ${rollbackPath}`);
  console.log(plan.summary);
  console.log("No AWS calls were made. Review JSON before any approved apply.");
} catch (error) {
  console.error(error.message || String(error));
  process.exit(2);
}

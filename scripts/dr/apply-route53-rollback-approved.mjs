#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import process from "node:process";

import { validateApprovedRegionalRollbackBatch } from "../lib/route53-regional-rollback-core.mjs";

const usage = `Usage:
  APPROVED_ROUTE53_ROLLBACK=true HOSTED_ZONE_ID=Z... CHANGE_BATCH_JSON=artifacts/dr/<timestamp>/...json npm run ops:route53-rollback-apply-approved

This is the guarded Route 53 rollback apply path. It refuses to run without approval
and accepts only Route 53 geolocation A-record batches.
`;

function parseArgs(argv) {
  const options = {
    hostedZoneId: process.env.HOSTED_ZONE_ID || "",
    changeBatchJson: process.env.CHANGE_BATCH_JSON || "",
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    const nextValue = () => {
      const value = argv[index + 1];
      if (!value || value.startsWith("--")) throw new Error(`Missing value for ${arg}`);
      index += 1;
      return value;
    };
    if (arg === "--hosted-zone-id") options.hostedZoneId = nextValue();
    else if (arg === "--change-batch-json") options.changeBatchJson = nextValue();
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
  const runDir = path.join(artifactRoot, utcTimestamp(), "route53-regional-rollback-apply");
  mkdirSync(runDir, { recursive: true });
  return runDir;
}

function runAws(args) {
  return execFileSync("aws", args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 120000,
  });
}

function route53Records(hostedZoneId) {
  return runAws(["route53", "list-resource-record-sets", "--hosted-zone-id", hostedZoneId, "--output", "json"]);
}

try {
  if (process.env.APPROVED_ROUTE53_ROLLBACK !== "true") {
    throw new Error("Refusing Route 53 rollback apply. Set APPROVED_ROUTE53_ROLLBACK=true only after explicit manual approval.");
  }

  const options = parseArgs(process.argv.slice(2));
  if (!options.hostedZoneId) throw new Error("HOSTED_ZONE_ID is required.");
  if (!options.changeBatchJson) throw new Error("CHANGE_BATCH_JSON is required.");
  if (!existsSync(options.changeBatchJson)) throw new Error(`CHANGE_BATCH_JSON file not found: ${options.changeBatchJson}`);

  const changeBatchPath = path.resolve(process.cwd(), options.changeBatchJson);
  const changeBatch = JSON.parse(readFileSync(changeBatchPath, "utf8"));
  const validationFindings = validateApprovedRegionalRollbackBatch(changeBatch, { env: process.env });
  if (validationFindings.length > 0) {
    throw new Error(`Refusing Route 53 rollback apply:\n- ${validationFindings.join("\n- ")}`);
  }

  const outDir = ensureArtifactDir();
  writeFileSync(path.join(outDir, "change-batch-reviewed.json"), `${JSON.stringify(changeBatch, null, 2)}\n`);
  writeFileSync(path.join(outDir, "before-route53-records.json"), route53Records(options.hostedZoneId));

  const applyResponse = JSON.parse(
    runAws([
      "route53",
      "change-resource-record-sets",
      "--hosted-zone-id",
      options.hostedZoneId,
      "--change-batch",
      `file://${changeBatchPath}`,
      "--output",
      "json",
    ]),
  );
  const changeId = applyResponse?.ChangeInfo?.Id;
  if (!changeId) throw new Error("Route 53 apply response did not include ChangeInfo.Id.");

  writeFileSync(path.join(outDir, "change-response.json"), `${JSON.stringify(applyResponse, null, 2)}\n`);
  writeFileSync(path.join(outDir, "change-id.txt"), `${changeId}\n`);
  writeFileSync(path.join(outDir, "change-status-submitted.json"), runAws(["route53", "get-change", "--id", changeId, "--output", "json"]));

  runAws(["route53", "wait", "resource-record-sets-changed", "--id", changeId]);
  const finalStatus = runAws(["route53", "get-change", "--id", changeId, "--output", "json"]);
  writeFileSync(path.join(outDir, "change-status.json"), finalStatus);
  writeFileSync(path.join(outDir, "after-route53-records.json"), route53Records(options.hostedZoneId));

  const parsedFinalStatus = JSON.parse(finalStatus);
  if (parsedFinalStatus?.ChangeInfo?.Status !== "INSYNC") {
    throw new Error(`Route 53 change did not reach INSYNC. Evidence: ${path.join(outDir, "change-status.json")}`);
  }

  console.log("Approved Route 53 regional rollback apply completed.");
  console.log(`Change ID: ${changeId}`);
  console.log(`Final status: ${parsedFinalStatus.ChangeInfo.Status}`);
  console.log(`Evidence directory: ${outDir}`);
} catch (error) {
  console.error(error.message || String(error));
  process.exit(2);
}

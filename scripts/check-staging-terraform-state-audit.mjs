#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

const stateBucketArn = "arn:aws:s3:::mscqr-staging-terraform-state-368992683803";
const stateObjectPrefixArn = `${stateBucketArn}/`;

function usage() {
  return `Usage: node scripts/check-staging-terraform-state-audit.mjs --event-selectors-json <path>

Validates CloudTrail event selector JSON from:
  aws cloudtrail get-event-selectors --trail-name <trail-name>

The check requires S3 object data event coverage for the staging Terraform
state bucket. It is read-only and never calls AWS directly.`;
}

function asArray(value) {
  if (Array.isArray(value)) return value;
  if (typeof value === "string") return [value];
  return [];
}

function valueCoversStateBucket(value) {
  if (typeof value !== "string") return false;
  return value === stateBucketArn || value === stateObjectPrefixArn || stateObjectPrefixArn.startsWith(value);
}

function selectorCoversDataResources(selector) {
  const readWriteType = selector.ReadWriteType || "All";
  const coversReadWrite = readWriteType === "All";
  const coversBucket = asArray(selector.DataResources).some((resource) =>
    resource?.Type === "AWS::S3::Object" && asArray(resource.Values).some(valueCoversStateBucket));
  return { coversBucket, coversReadWrite };
}

function fieldSelectorValues(selector, fieldName, valueKey) {
  return asArray(selector.FieldSelectors)
    .filter((field) => field?.Field === fieldName)
    .flatMap((field) => asArray(field?.[valueKey]));
}

function advancedSelectorCoversStateBucket(selector) {
  const categoryValues = fieldSelectorValues(selector, "eventCategory", "Equals");
  const resourceTypeValues = fieldSelectorValues(selector, "resources.type", "Equals");
  const arnEquals = fieldSelectorValues(selector, "resources.ARN", "Equals");
  const arnStartsWith = fieldSelectorValues(selector, "resources.ARN", "StartsWith");
  const coversData = categoryValues.length === 0 || categoryValues.includes("Data");
  const coversS3Object = resourceTypeValues.length === 0 || resourceTypeValues.includes("AWS::S3::Object");
  const coversBucket = [...arnEquals, ...arnStartsWith].some(valueCoversStateBucket);
  return coversData && coversS3Object && coversBucket;
}

export function evaluateStateBucketAuditSelectors(selectorsJson) {
  const selectors = asArray(selectorsJson?.EventSelectors);
  const advancedSelectors = asArray(selectorsJson?.AdvancedEventSelectors);
  const classicCoverage = selectors.map(selectorCoversDataResources);
  const classicReadWriteCoverage = classicCoverage.some((coverage) => coverage.coversBucket && coverage.coversReadWrite);
  const advancedCoverage = advancedSelectors.some(advancedSelectorCoversStateBucket);
  const blockers = [];

  if (!classicReadWriteCoverage && !advancedCoverage) {
    blockers.push("missing_state_bucket_s3_data_event_selector");
  }

  return {
    status: blockers.length === 0 ? "ok" : "blocked_state_bucket_audit_missing",
    stateBucketArn,
    eventSelectorCount: selectors.length,
    advancedEventSelectorCount: advancedSelectors.length,
    classicReadWriteCoverage,
    advancedCoverage,
    blockerCodes: blockers,
    rawSecretValuesPrinted: false,
  };
}

export function main(argv = process.argv.slice(2)) {
  if (argv.includes("--help") || argv.includes("-h")) {
    console.log(usage());
    return 0;
  }
  const index = argv.indexOf("--event-selectors-json");
  const filePath = index >= 0 ? argv[index + 1] : null;
  if (!filePath || argv.length !== 2) {
    console.log(JSON.stringify({
      status: "blocked_invalid_arguments",
      reason: "--event-selectors-json <path> is required.",
      rawSecretValuesPrinted: false,
    }, null, 2));
    return 1;
  }

  let selectorsJson;
  try {
    selectorsJson = JSON.parse(fs.readFileSync(path.resolve(process.cwd(), filePath), "utf8"));
  } catch {
    console.log(JSON.stringify({
      status: "blocked_invalid_event_selectors_json",
      reason: "Event selectors JSON is missing or invalid.",
      rawSecretValuesPrinted: false,
    }, null, 2));
    return 1;
  }

  const result = evaluateStateBucketAuditSelectors(selectorsJson);
  console.log(JSON.stringify(result, null, 2));
  return result.status === "ok" ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(main());
}

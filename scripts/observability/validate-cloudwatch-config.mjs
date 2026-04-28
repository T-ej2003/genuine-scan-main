import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

const root = process.cwd();
const filtersPath = path.join(root, "documents", "observability", "cloudwatch", "verification-trust-metric-filters.json");
const alarmsPath = path.join(root, "documents", "observability", "cloudwatch", "verification-trust-alarms.json");

const requiredFilterNames = [
  "mscqr-trust-replay-review-required",
  "mscqr-trust-changed-context-repeat",
  "mscqr-trust-limited-provenance",
  "mscqr-trust-challenge-required",
  "mscqr-trust-challenge-completed",
  "mscqr-trust-break-glass-usage",
  "mscqr-trust-signing-fallback",
];

const requiredAlarmNames = [
  "mscqr-trust-replay-review-spike",
  "mscqr-trust-changed-context-repeat-spike",
  "mscqr-trust-limited-provenance-spike",
  "mscqr-trust-break-glass-usage",
  "mscqr-trust-signing-fallback",
  "mscqr-trust-challenge-completion-drop",
];
const enforceDestinations = String(process.env.ENFORCE_CLOUDWATCH_DESTINATIONS || "").trim().toLowerCase() === "true";

const failures = [];

if (!existsSync(filtersPath)) failures.push(`Missing CloudWatch metric filter config: ${path.relative(root, filtersPath)}`);
if (!existsSync(alarmsPath)) failures.push(`Missing CloudWatch alarm config: ${path.relative(root, alarmsPath)}`);

let filtersPayload = null;
let alarmsPayload = null;

if (existsSync(filtersPath)) {
  try {
    filtersPayload = JSON.parse(readFileSync(filtersPath, "utf8"));
  } catch (error) {
    failures.push(`Invalid JSON in ${path.relative(root, filtersPath)}: ${error?.message || error}`);
  }
}
if (existsSync(alarmsPath)) {
  try {
    alarmsPayload = JSON.parse(readFileSync(alarmsPath, "utf8"));
  } catch (error) {
    failures.push(`Invalid JSON in ${path.relative(root, alarmsPath)}: ${error?.message || error}`);
  }
}

if (filtersPayload) {
  const names = new Set((Array.isArray(filtersPayload.filters) ? filtersPayload.filters : []).map((entry) => String(entry?.name || "").trim()));
  for (const name of requiredFilterNames) {
    if (!names.has(name)) failures.push(`CloudWatch metric filter is missing required entry: ${name}`);
  }
}

if (alarmsPayload) {
  const alarms = Array.isArray(alarmsPayload.alarms) ? alarmsPayload.alarms : [];
  const names = new Set(alarms.map((entry) => String(entry?.alarmName || "").trim()));
  for (const name of requiredAlarmNames) {
    if (!names.has(name)) failures.push(`CloudWatch alarm config is missing required entry: ${name}`);
  }

  const snsTopicArn = String(alarmsPayload.snsTopicArn || "").trim();
  if (enforceDestinations && (!snsTopicArn || snsTopicArn.includes("123456789012"))) {
    failures.push("CloudWatch alarm config must set a real snsTopicArn (placeholder account ID is not allowed).");
  }
}

if (failures.length > 0) {
  console.error("CloudWatch observability config validation failed:");
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log("CloudWatch observability config validation passed.");

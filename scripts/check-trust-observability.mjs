import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

const repoRoot = process.cwd();
const files = {
  catalog: path.join(repoRoot, "documents", "observability", "VERIFICATION_TRUST_EVENT_CATALOG.md"),
  alertRules: path.join(repoRoot, "documents", "observability", "verification_trust_metric.alert-rules.yml"),
  metricsMap: path.join(repoRoot, "documents", "observability", "verification_trust_metric.metrics.yml"),
  examples: path.join(repoRoot, "documents", "observability", "verification_trust_metric.examples.json"),
  savedSearches: path.join(repoRoot, "documents", "observability", "verification_trust_metric.saved-searches.json"),
  cloudwatchDeployGuide: path.join(repoRoot, "documents", "observability", "CLOUDWATCH_DEPLOY.md"),
  cloudwatchFilters: path.join(
    repoRoot,
    "documents",
    "observability",
    "cloudwatch",
    "verification-trust-metric-filters.json"
  ),
  cloudwatchAlarms: path.join(repoRoot, "documents", "observability", "cloudwatch", "verification-trust-alarms.json"),
};

const failures = [];

for (const [name, filePath] of Object.entries(files)) {
  if (!existsSync(filePath)) {
    failures.push(`Missing observability artifact: ${name} (${path.relative(repoRoot, filePath)})`);
  }
}

const parseYamlAlertNames = (content) =>
  content
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.startsWith("- name:"))
    .map((line) => line.replace("- name:", "").trim());

if (existsSync(files.alertRules)) {
  const alertNames = parseYamlAlertNames(readFileSync(files.alertRules, "utf8"));
  const requiredAlerts = [
    "mscqr-trust-break-glass-usage",
    "mscqr-trust-replay-review-spike",
    "mscqr-trust-limited-provenance-rate",
    "mscqr-trust-signing-fallback",
    "mscqr-trust-challenge-abandonment",
  ];
  for (const alertName of requiredAlerts) {
    if (!alertNames.includes(alertName)) {
      failures.push(`Missing required trust alert template: ${alertName}`);
    }
  }
}

if (existsSync(files.examples)) {
  try {
    const examples = JSON.parse(readFileSync(files.examples, "utf8"));
    if (!Array.isArray(examples) || examples.length === 0) {
      failures.push("verification_trust_metric.examples.json must contain at least one example event.");
    } else {
      for (const [index, example] of examples.entries()) {
        const serialized = JSON.stringify(example).toLowerCase();
        if (serialized.includes("token") || serialized.includes("password") || serialized.includes("cookie")) {
          failures.push(`Example event #${index + 1} contains sensitive token/password/cookie terms.`);
        }
        if ("decisionId" in example || "qrCodeId" in example || "licenseeId" in example || "batchId" in example) {
          failures.push(`Example event #${index + 1} exposes raw identifiers. Use hashed refs only.`);
        }
      }
    }
  } catch (error) {
    failures.push(`verification_trust_metric.examples.json is invalid JSON: ${(error && error.message) || error}`);
  }
}

if (existsSync(files.savedSearches)) {
  try {
    const savedSearches = JSON.parse(readFileSync(files.savedSearches, "utf8"));
    const searches = Array.isArray(savedSearches?.searches) ? savedSearches.searches : [];
    if (!searches.length) {
      failures.push("verification_trust_metric.saved-searches.json must include at least one search query.");
    }
  } catch (error) {
    failures.push(`verification_trust_metric.saved-searches.json is invalid JSON: ${(error && error.message) || error}`);
  }
}

if (failures.length > 0) {
  console.error("Trust observability check failed:");
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log("Trust observability check passed.");

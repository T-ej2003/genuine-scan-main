import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

const repoRoot = process.cwd();
const files = {
  matrix: path.join(repoRoot, "documents", "architecture", "RATE_LIMIT_SECURITY_MATRIX.md"),
  catalog: path.join(repoRoot, "documents", "observability", "RATE_LIMIT_EVENT_CATALOG.md"),
  metricsMap: path.join(repoRoot, "documents", "observability", "rate_limit_metric.metrics.yml"),
  alertRules: path.join(repoRoot, "documents", "observability", "rate_limit_metric.alert-rules.yml"),
  examples: path.join(repoRoot, "documents", "observability", "rate_limit_metric.examples.json"),
  savedSearches: path.join(repoRoot, "documents", "observability", "rate_limit_metric.saved-searches.json"),
};

const failures = [];

for (const [name, filePath] of Object.entries(files)) {
  if (!existsSync(filePath)) {
    failures.push(`Missing rate-limit observability artifact: ${name} (${path.relative(repoRoot, filePath)})`);
  }
}

if (existsSync(files.matrix)) {
  const matrix = readFileSync(files.matrix, "utf8");
  const requiredMatrixTerms = [
    "Route family",
    "Auth model",
    "Pre-auth limiter",
    "Post-auth limiter",
    "CSRF",
    "licensees.read",
    "governance.read",
    "audit.read",
    "verify.claim",
    "printer-agent.heartbeat",
    "support.read",
  ];

  for (const term of requiredMatrixTerms) {
    if (!matrix.includes(term)) {
      failures.push(`Rate-limit security matrix is missing required term: ${term}`);
    }
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
    "mscqr-rate-limit-licensee-burst",
    "mscqr-rate-limit-governance-spike",
    "mscqr-rate-limit-audit-export-abuse",
    "mscqr-rate-limit-verify-claim-abuse",
    "mscqr-rate-limit-printer-agent-heartbeat-burst",
    "mscqr-rate-limit-support-abuse",
  ];

  for (const alertName of requiredAlerts) {
    if (!alertNames.includes(alertName)) {
      failures.push(`Missing required rate-limit alert template: ${alertName}`);
    }
  }
}

if (existsSync(files.examples)) {
  try {
    const examples = JSON.parse(readFileSync(files.examples, "utf8"));
    if (!Array.isArray(examples) || examples.length === 0) {
      failures.push("rate_limit_metric.examples.json must contain at least one example event.");
    } else {
      for (const [index, example] of examples.entries()) {
        const serialized = JSON.stringify(example).toLowerCase();
        if (serialized.includes("token") || serialized.includes("password") || serialized.includes("cookie")) {
          failures.push(`Rate-limit example event #${index + 1} contains sensitive token/password/cookie terms.`);
        }
        if ("licenseeId" in example || "userId" in example || "transferId" in example) {
          failures.push(`Rate-limit example event #${index + 1} exposes raw identifiers. Use hashed refs only.`);
        }
      }
    }
  } catch (error) {
    failures.push(`rate_limit_metric.examples.json is invalid JSON: ${(error && error.message) || error}`);
  }
}

if (existsSync(files.savedSearches)) {
  try {
    const savedSearches = JSON.parse(readFileSync(files.savedSearches, "utf8"));
    const searches = Array.isArray(savedSearches?.searches) ? savedSearches.searches : [];
    if (!searches.length) {
      failures.push("rate_limit_metric.saved-searches.json must include at least one search query.");
    }
  } catch (error) {
    failures.push(`rate_limit_metric.saved-searches.json is invalid JSON: ${(error && error.message) || error}`);
  }
}

if (failures.length > 0) {
  console.error("Rate-limit observability check failed:");
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log("Rate-limit observability check passed.");

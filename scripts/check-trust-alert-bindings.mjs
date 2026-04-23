import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

const repoRoot = process.cwd();
const defaultTemplatePath = path.join(
  repoRoot,
  "docs",
  "observability",
  "verification_trust_metric.alert-bindings.template.json"
);
const bindingsPath = path.resolve(
  repoRoot,
  String(process.env.TRUST_ALERT_BINDINGS_PATH || defaultTemplatePath)
);

if (!existsSync(bindingsPath)) {
  throw new Error(`Missing trust alert bindings file: ${path.relative(repoRoot, bindingsPath)}`);
}

const payload = JSON.parse(readFileSync(bindingsPath, "utf8"));
const bindings = Array.isArray(payload?.bindings) ? payload.bindings : [];
const failures = [];

const requiredNames = [
  "mscqr-trust-break-glass-usage",
  "mscqr-trust-replay-review-spike",
  "mscqr-trust-limited-provenance-rate",
  "mscqr-trust-signing-fallback",
  "mscqr-trust-challenge-abandonment",
];

for (const alertName of requiredNames) {
  const entry = bindings.find((item) => String(item?.name || "").trim() === alertName);
  if (!entry) {
    failures.push(`Missing trust alert binding: ${alertName}`);
    continue;
  }
  if (!String(entry.destination || "").trim()) {
    failures.push(`Trust alert binding ${alertName} is missing destination`);
  }
  if (!String(entry.runbook || "").trim()) {
    failures.push(`Trust alert binding ${alertName} is missing runbook`);
  } else {
    const runbookRef = String(entry.runbook).trim();
    const runbookPath = runbookRef.split("#")[0];
    const resolvedRunbookPath = path.resolve(repoRoot, runbookPath);
    if (!existsSync(resolvedRunbookPath)) {
      failures.push(`Trust alert binding ${alertName} points to missing runbook file: ${runbookPath}`);
    }
  }
}

if (failures.length > 0) {
  console.error("Trust alert binding check failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(`Trust alert binding check passed (${path.relative(repoRoot, bindingsPath)}).`);

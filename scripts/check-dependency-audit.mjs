import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const defaultAllowlistPath = path.join(repoRoot, ".security", "dependency-audit-allowlist.json");
const severities = new Set(["high", "critical"]);

const pathWithSystemBins = () => {
  const segments = String(process.env.PATH || "").split(":").filter(Boolean);
  for (const bin of ["/bin", "/usr/bin", "/opt/homebrew/bin", "/usr/local/bin"]) {
    if (!segments.includes(bin)) segments.unshift(bin);
  }
  return segments.join(":");
};

const parseReport = (source, label) => {
  try {
    return JSON.parse(String(source || "").trim());
  } catch (error) {
    throw new Error(`Could not parse npm audit JSON for ${label}: ${error instanceof Error ? error.message : error}`);
  }
};

const runAudit = (scope, cwd) => {
  const fixturePath = process.env[`DEPENDENCY_AUDIT_REPORT_${scope.toUpperCase()}`];
  if (fixturePath) return parseReport(readFileSync(fixturePath, "utf8"), scope);

  const result = spawnSync("npm", ["audit", "--omit=dev", "--json"], {
    cwd,
    encoding: "utf8",
    env: { ...process.env, PATH: pathWithSystemBins() },
  });
  const source = String(result.stdout || result.stderr || "").trim();
  if (!source) throw new Error(`npm audit returned no JSON output for ${scope}`);
  return parseReport(source, scope);
};

const advisoryId = (via) => {
  const ghsa = String(via?.url || "").match(/GHSA-[a-z0-9-]+/i)?.[0];
  return ghsa?.toUpperCase() || (via?.source ? `npm:${via.source}` : null);
};

const advisoryIdsFor = (report, packageName, seen = new Set()) => {
  if (seen.has(packageName)) return [];
  seen.add(packageName);
  const vulnerability = report?.vulnerabilities?.[packageName];
  if (!vulnerability) return [];
  return [...new Set((vulnerability.via || []).flatMap((via) =>
    typeof via === "string"
      ? advisoryIdsFor(report, via, seen)
      : advisoryId(via) ? [advisoryId(via)] : []
  ))];
};

const productionFindings = (scope, report) =>
  Object.entries(report?.vulnerabilities || {}).flatMap(([packageName, vulnerability]) => {
    if (!severities.has(String(vulnerability?.severity || "").toLowerCase())) return [];
    const advisories = advisoryIdsFor(report, packageName);
    return (advisories.length ? advisories : ["npm:unknown"]).map((advisory) => ({
      scope,
      package: packageName,
      advisory,
      severity: String(vulnerability.severity).toLowerCase(),
    }));
  });

const loadAllowlist = (allowlistPath) => {
  if (!existsSync(allowlistPath)) return { schemaVersion: 1, entries: [] };
  const parsed = parseReport(readFileSync(allowlistPath, "utf8"), allowlistPath);
  if (parsed?.schemaVersion !== 1 || !Array.isArray(parsed.entries)) {
    throw new Error(`Invalid dependency audit exception file at ${allowlistPath}`);
  }
  return parsed;
};

const validateException = (entry, today) => {
  const required = ["scope", "package", "advisory", "rationale", "owner", "expiresOn"];
  const missing = required.find((key) => !String(entry?.[key] || "").trim());
  if (missing) return `missing ${missing}`;
  if (!["root", "backend"].includes(entry.scope)) return "scope must be root or backend";
  if (/[*?]/.test(entry.package) || /[*?]/.test(entry.advisory)) return "wildcards are forbidden";
  if (!/^(?:GHSA-[A-Z0-9-]+|npm:\d+)$/i.test(entry.advisory)) return "advisory must be an exact GHSA or npm ID";
  if (!/^\d{4}-\d{2}-\d{2}$/.test(entry.expiresOn)) return "expiresOn must be YYYY-MM-DD";
  if (entry.expiresOn < today) return `expired on ${entry.expiresOn}`;
  return null;
};

const today = new Date().toISOString().slice(0, 10);
const allowlistPath = path.resolve(process.env.DEPENDENCY_AUDIT_ALLOWLIST || defaultAllowlistPath);
const allowlist = loadAllowlist(allowlistPath);
const scopes = [
  { scope: "root", cwd: repoRoot },
  { scope: "backend", cwd: path.join(repoRoot, "backend") },
];
const findings = scopes.flatMap(({ scope, cwd }) => productionFindings(scope, runAudit(scope, cwd)));
const failures = [];

for (const entry of allowlist.entries) {
  const invalid = validateException(entry, today);
  if (invalid) failures.push(`invalid exception ${entry?.scope || "?"}/${entry?.package || "?"}: ${invalid}`);
  const matches = findings.some((finding) =>
    finding.scope === entry.scope &&
    finding.package === entry.package &&
    finding.advisory.toUpperCase() === String(entry.advisory).toUpperCase()
  );
  if (!invalid && !matches) failures.push(`stale exception ${entry.scope}/${entry.package}/${entry.advisory}`);
}

for (const finding of findings) {
  const excepted = allowlist.entries.some((entry) =>
    entry.scope === finding.scope &&
    entry.package === finding.package &&
    String(entry.advisory).toUpperCase() === finding.advisory.toUpperCase() &&
    !validateException(entry, today)
  );
  if (!excepted) {
    failures.push(`${finding.scope}: ${finding.severity} ${finding.package} (${finding.advisory})`);
  }
}

if (failures.length) {
  console.error("Production dependency audit gate failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(`Production dependency audit gate passed for frontend and backend (${findings.length} reviewed high/critical finding(s)).`);

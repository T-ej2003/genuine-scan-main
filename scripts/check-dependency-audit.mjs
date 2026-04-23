import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const repoRoot = process.cwd();
const allowlistPath = path.join(repoRoot, ".security", "dependency-audit-allowlist.json");
const now = new Date();

const pathWithSystemBins = () => {
  const segments = String(process.env.PATH || "")
    .split(":")
    .filter(Boolean);
  for (const bin of ["/bin", "/usr/bin", "/opt/homebrew/bin", "/usr/local/bin"]) {
    if (!segments.includes(bin)) segments.unshift(bin);
  }
  return segments.join(":");
};

const runAudit = ({ cwd, omitDev }) => {
  const args = ["audit", "--json"];
  if (omitDev) args.splice(1, 0, "--omit=dev");

  const result = spawnSync("npm", args, {
    cwd,
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: pathWithSystemBins(),
    },
  });

  const source = String(result.stdout || result.stderr || "").trim();
  if (!source) {
    throw new Error(`npm audit returned no JSON output for ${cwd}`);
  }

  try {
    return JSON.parse(source);
  } catch (error) {
    throw new Error(`Could not parse npm audit JSON for ${cwd}: ${(error && error.message) || error}`);
  }
};

const loadAllowlist = () => {
  if (!existsSync(allowlistPath)) return { entries: [] };
  try {
    const parsed = JSON.parse(readFileSync(allowlistPath, "utf8"));
    if (!Array.isArray(parsed?.entries)) return { entries: [] };
    return parsed;
  } catch (error) {
    throw new Error(`Invalid allowlist JSON at ${allowlistPath}: ${(error && error.message) || error}`);
  }
};

const highOrCriticalPackages = (report) =>
  Object.entries(report?.vulnerabilities || {})
    .filter(([, value]) => {
      const severity = String(value?.severity || "").toLowerCase();
      return severity === "high" || severity === "critical";
    })
    .map(([name]) => name);

const validateAllowlistEntry = (entry) => {
  const scope = String(entry?.scope || "").trim();
  const pkg = String(entry?.package || "").trim();
  const owner = String(entry?.owner || "").trim();
  const expiresOnRaw = String(entry?.expiresOn || "").trim();

  if (!scope || !pkg || !owner || !expiresOnRaw) {
    return { valid: false, reason: "missing scope/package/owner/expiresOn fields" };
  }

  if (scope !== "root" && scope !== "backend") {
    return { valid: false, reason: "scope must be root or backend" };
  }

  const expiresOn = new Date(expiresOnRaw);
  if (Number.isNaN(expiresOn.getTime())) {
    return { valid: false, reason: "expiresOn must be a valid ISO date" };
  }
  if (expiresOn <= now) {
    return { valid: false, reason: `allowlist entry expired on ${expiresOnRaw}` };
  }

  return { valid: true };
};

const allowlist = loadAllowlist();
const scopes = [
  { scope: "root", cwd: repoRoot },
  { scope: "backend", cwd: path.join(repoRoot, "backend") },
];

const failures = [];
const notes = [];

for (const { scope, cwd } of scopes) {
  const runtimeReport = runAudit({ cwd, omitDev: true });
  const fullReport = runAudit({ cwd, omitDev: false });

  const runtimeRisky = new Set(highOrCriticalPackages(runtimeReport));
  const fullRisky = new Set(highOrCriticalPackages(fullReport));
  const devOnlyRisky = [...fullRisky].filter((pkg) => !runtimeRisky.has(pkg));

  if (runtimeRisky.size > 0) {
    failures.push(
      `${scope}: runtime high/critical packages detected (${[...runtimeRisky].sort().join(", ")})`
    );
  }

  for (const pkg of devOnlyRisky) {
    const matched = allowlist.entries.filter((entry) => String(entry?.scope) === scope && String(entry?.package) === pkg);
    if (!matched.length) {
      failures.push(`${scope}: dev-only high/critical package ${pkg} is missing allowlist owner/expiry entry`);
      continue;
    }
    for (const entry of matched) {
      const validation = validateAllowlistEntry(entry);
      if (!validation.valid) {
        failures.push(`${scope}: allowlist entry for ${pkg} is invalid (${validation.reason})`);
      }
    }
  }

  for (const entry of allowlist.entries.filter((item) => String(item?.scope) === scope)) {
    const pkg = String(entry?.package || "").trim();
    if (!pkg) continue;
    if (!devOnlyRisky.includes(pkg)) {
      notes.push(`${scope}: allowlist entry for ${pkg} is no longer required and can be removed`);
    }
  }
}

if (failures.length > 0) {
  console.error("Dependency audit gate failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log("Dependency audit gate passed.");
if (notes.length > 0) {
  for (const note of notes) console.log(`note: ${note}`);
}

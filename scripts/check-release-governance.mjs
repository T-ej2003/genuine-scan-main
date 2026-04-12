const repo = String(process.env.GITHUB_REPOSITORY || "").trim();
const token = String(process.env.GITHUB_TOKEN || "").trim();
const branch = String(process.env.RELEASE_PROTECTED_BRANCH || "main").trim();
const requiredChecks = String(
  process.env.REQUIRED_RELEASE_CHECKS || "Release Candidate Gate / rc-trust-critical,Release Candidate Gate / rc-staging-smoke"
)
  .split(",")
  .map((entry) => entry.trim())
  .filter(Boolean);
const runningInGitHubActions = String(process.env.GITHUB_ACTIONS || "").trim().toLowerCase() === "true";

const skipLocalCheck = (reason) => {
  const summary = {
    skipped: true,
    reason,
    repository: repo || null,
    branch,
    requiredChecks,
    checkedAt: new Date().toISOString(),
  };
  console.log(JSON.stringify(summary, null, 2));
  process.exit(0);
};

if (!repo) {
  if (!runningInGitHubActions) {
    skipLocalCheck("GITHUB_REPOSITORY is not set outside GitHub Actions.");
  }
  throw new Error("GITHUB_REPOSITORY is required for release governance checks in GitHub Actions.");
}

if (!token) {
  if (!runningInGitHubActions) {
    skipLocalCheck("GITHUB_TOKEN is not set outside GitHub Actions.");
  }
  throw new Error("GITHUB_TOKEN is required for release governance checks in GitHub Actions.");
}

if (!requiredChecks.length) {
  throw new Error("REQUIRED_RELEASE_CHECKS produced an empty check list.");
}

const headers = {
  Accept: "application/vnd.github+json",
  Authorization: `Bearer ${token}`,
  "X-GitHub-Api-Version": "2022-11-28",
};

const githubApi = async (url) => {
  const response = await fetch(url, { headers });
  if (response.status === 404) return null;
  if (!response.ok) {
    const body = await response.text();
    throw new Error(`GitHub API ${response.status} for ${url}: ${body || response.statusText}`);
  }
  return response.json();
};

const normalizeCheckContext = (value) => String(value || "").trim();

const branchProtectionUrl = `https://api.github.com/repos/${repo}/branches/${encodeURIComponent(branch)}/protection`;
const branchProtection = await githubApi(branchProtectionUrl);

const branchProtectionContexts = new Set();
if (branchProtection?.required_status_checks?.contexts) {
  for (const context of branchProtection.required_status_checks.contexts) {
    const normalized = normalizeCheckContext(context);
    if (normalized) branchProtectionContexts.add(normalized);
  }
}
if (Array.isArray(branchProtection?.required_status_checks?.checks)) {
  for (const check of branchProtection.required_status_checks.checks) {
    const normalized = normalizeCheckContext(check?.context);
    if (normalized) branchProtectionContexts.add(normalized);
  }
}

const rulesetsUrl = `https://api.github.com/repos/${repo}/rulesets?includes_parents=true&targets=branch`;
const rulesets = (await githubApi(rulesetsUrl)) || [];

const includeRuleRefMatchesBranch = (includeRule, branchName) => {
  const normalized = String(includeRule || "").trim();
  if (!normalized) return false;
  return (
    normalized === "~ALL" ||
    normalized === "~DEFAULT_BRANCH" ||
    normalized === branchName ||
    normalized === `refs/heads/${branchName}`
  );
};

const rulesetTargetsBranch = (ruleset, branchName) => {
  if (!ruleset || ruleset.target !== "branch") return false;
  if (String(ruleset.enforcement || "").toLowerCase() !== "active") return false;

  const include = Array.isArray(ruleset?.conditions?.ref_name?.include) ? ruleset.conditions.ref_name.include : [];
  const exclude = Array.isArray(ruleset?.conditions?.ref_name?.exclude) ? ruleset.conditions.ref_name.exclude : [];

  const included = include.length === 0 ? true : include.some((entry) => includeRuleRefMatchesBranch(entry, branchName));
  const excluded = exclude.some((entry) => includeRuleRefMatchesBranch(entry, branchName));

  return included && !excluded;
};

const rulesetContexts = new Set();
for (const ruleset of rulesets) {
  if (!rulesetTargetsBranch(ruleset, branch)) continue;
  for (const rule of Array.isArray(ruleset.rules) ? ruleset.rules : []) {
    if (String(rule?.type || "") !== "required_status_checks") continue;
    const checks = Array.isArray(rule?.parameters?.required_status_checks) ? rule.parameters.required_status_checks : [];
    for (const check of checks) {
      const normalized = normalizeCheckContext(check?.context);
      if (normalized) rulesetContexts.add(normalized);
    }
  }
}

const configuredChecks = new Set([...branchProtectionContexts, ...rulesetContexts]);
const missing = requiredChecks.filter((check) => !configuredChecks.has(check));

const summary = {
  repository: repo,
  branch,
  requiredChecks,
  branchProtectionContexts: [...branchProtectionContexts].sort(),
  rulesetContexts: [...rulesetContexts].sort(),
  configuredChecks: [...configuredChecks].sort(),
  missing,
  checkedAt: new Date().toISOString(),
};

console.log(JSON.stringify(summary, null, 2));

if (missing.length > 0) {
  console.error(
    `Release governance check failed: missing required status checks for ${branch}: ${missing.join(", ")}`
  );
  process.exit(1);
}

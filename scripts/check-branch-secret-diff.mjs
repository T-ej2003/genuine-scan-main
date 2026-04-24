import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

const repoRoot = process.cwd();

const readGitOutput = (args) =>
  execFileSync("git", args, {
    cwd: repoRoot,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  }).trim();

const tryGitOutput = (args) => {
  try {
    return readGitOutput(args);
  } catch {
    return "";
  }
};

const baseRefCandidates = [
  process.env.SECRET_GUARD_BASE_REF,
  process.env.GITHUB_BASE_REF ? `origin/${String(process.env.GITHUB_BASE_REF).trim()}` : "",
  "origin/main",
  "main",
].filter(Boolean);

const resolveBaseRef = () => {
  for (const candidate of baseRefCandidates) {
    if (tryGitOutput(["rev-parse", "--verify", candidate])) return candidate;
  }
  return "";
};

const matchesTarget = (relativePath) =>
  /^docker-compose(?:\.[^/]+)?\.ya?ml$/i.test(relativePath) ||
  relativePath === ".env.example" ||
  relativePath === path.join("backend", ".env.example") ||
  relativePath === "README.md" ||
  relativePath.startsWith("docs/") ||
  relativePath.startsWith(".github/workflows/");

const rules = [
  {
    name: "Legacy MinIO fallback literal",
    regex: /\bmscqrminiochange\b|\bmscqrminio\b/g,
    message: "Legacy MinIO/object-storage fallback literals are forbidden in branch diffs.",
  },
  {
    name: "Fallback default on MinIO root env",
    regex: /\$\{MINIO_ROOT_(?:USER|PASSWORD):-[^}]+\}/g,
    message: "MINIO_ROOT_* must use required env forms, not fallback defaults.",
  },
  {
    name: "Fallback default on object storage credential env",
    regex: /\$\{OBJECT_STORAGE_(?:ACCESS_KEY|SECRET_KEY):-[^}]+\}/g,
    message: "OBJECT_STORAGE_* credentials must use required env forms, not fallback defaults.",
  },
];

const baseRef = resolveBaseRef();
if (!baseRef) {
  console.log("Branch secret-diff guard skipped: no suitable base ref found.");
  process.exit(0);
}

const mergeBase = tryGitOutput(["merge-base", baseRef, "HEAD"]);
if (!mergeBase) {
  console.log(`Branch secret-diff guard skipped: could not determine merge-base against ${baseRef}.`);
  process.exit(0);
}

const changedFiles = tryGitOutput(["diff", "--name-only", "--diff-filter=ACMR", `${mergeBase}...HEAD`])
  .split("\n")
  .map((entry) => entry.trim())
  .filter(Boolean)
  .filter(matchesTarget);

if (changedFiles.length === 0) {
  console.log(`Branch secret-diff guard passed. No tracked infra/config/docs files changed against ${baseRef}.`);
  process.exit(0);
}

const findings = [];

for (const relativePath of changedFiles) {
  const fullPath = path.join(repoRoot, relativePath);
  if (!existsSync(fullPath)) continue;

  const contents = readFileSync(fullPath, "utf8");
  for (const rule of rules) {
    rule.regex.lastIndex = 0;
    let match = rule.regex.exec(contents);
    while (match) {
      const line = contents.slice(0, match.index).split("\n").length;
      findings.push({
        file: relativePath,
        line,
        rule: rule.name,
        message: rule.message,
      });
      match = rule.regex.exec(contents);
    }
  }
}

if (findings.length > 0) {
  console.error(`Branch secret-diff guard failed against ${baseRef}:`);
  for (const finding of findings) {
    console.error(`- ${finding.file}:${finding.line} [${finding.rule}] ${finding.message}`);
  }
  process.exit(1);
}

console.log(`Branch secret-diff guard passed for ${changedFiles.length} changed file(s) against ${baseRef}.`);

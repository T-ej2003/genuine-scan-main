import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
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
  relativePath === ".gitignore" ||
  relativePath === "package.json" ||
  relativePath === ".env.example" ||
  relativePath === path.join("backend", ".env.example") ||
  relativePath === "README.md" ||
  (relativePath.startsWith("infra/terraform/staging-api/") && !relativePath.endsWith("terraform.tfvars.example")) ||
  relativePath.startsWith("scripts/") ||
  relativePath.startsWith("documents/") ||
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
  {
    name: "AWS access key literal",
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
    message: "AWS access key IDs must not appear in branch diffs.",
  },
  {
    name: "Private key block",
    regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g,
    message: "Private key material must not appear in branch diffs.",
  },
  {
    name: "Committed VPC ID",
    regex: /\bvpc-[0-9a-f]{8,17}\b/gi,
    message: "Real VPC IDs must stay in private Terraform inputs or private evidence.",
  },
  {
    name: "Committed subnet ID",
    regex: /\bsubnet-[0-9a-f]{8,17}\b/gi,
    message: "Real subnet IDs must stay in private Terraform inputs or private evidence.",
  },
  {
    name: "Committed Secrets Manager ARN",
    regex: /\barn:aws:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:mscqr\/[^\s"'`]+/gi,
    message: "Secrets Manager ARNs must stay in private Terraform inputs or private evidence.",
  },
];

const baseRef = resolveBaseRef();
if (!baseRef) {
  console.log("Branch secret-diff guard skipped: no suitable base ref found.");
  process.exit(0);
}

const mergeBase = tryGitOutput(["merge-base", baseRef, "HEAD"]);
if (!mergeBase) {
  console.log("Branch secret-diff guard skipped: could not determine a safe merge-base.");
  process.exit(0);
}

const changedFiles = tryGitOutput(["diff", "--name-only", "--diff-filter=ACMR", `${mergeBase}...HEAD`])
  .split("\n")
  .map((entry) => entry.trim())
  .filter(Boolean)
  .filter(matchesTarget);

if (changedFiles.length === 0) {
  console.log("Branch secret-diff guard passed. No tracked infra/config/docs files changed.");
  process.exit(0);
}

const findings = [];

for (const relativePath of changedFiles) {
  const fullPath = path.join(repoRoot, relativePath);
  if (!existsSync(fullPath)) continue;

  const contents = tryGitOutput(["diff", "--unified=0", "--no-ext-diff", "--diff-filter=ACMR", `${mergeBase}...HEAD`, "--", relativePath])
    .split("\n")
    .filter((line) => line.startsWith("+") && !line.startsWith("+++"))
    .map((line) => line.slice(1))
    .join("\n");
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
  console.error("Branch secret-diff guard failed:");
  for (const finding of findings) {
    console.error(`- ${finding.file}:${finding.line} [${finding.rule}] ${finding.message}`);
  }
  process.exit(1);
}

console.log(`Branch secret-diff guard passed for ${changedFiles.length} changed file(s).`);

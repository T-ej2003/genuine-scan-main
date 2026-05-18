#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);

const run = (args) =>
  spawnSync(args[0], args.slice(1), {
    cwd: repoRoot,
    encoding: "utf8",
    shell: false,
  });

const listChangedFiles = () => {
  const tracked = run(["git", "diff", "--name-only", "--diff-filter=ACMR"]);
  const untracked = run(["git", "ls-files", "--others", "--exclude-standard"]);
  if (tracked.status !== 0 || untracked.status !== 0) {
    console.error((tracked.stderr || "") + (untracked.stderr || ""));
    process.exit(1);
  }
  return Array.from(
    new Set(
      [...tracked.stdout.split(/\r?\n/), ...untracked.stdout.split(/\r?\n/)]
        .map((file) => file.trim())
        .filter(Boolean)
    )
  );
};

const isSecurityScopeFile = (file) =>
  file === "package.json" ||
  file === "backend/package.json" ||
  file === "scripts/check-prisma-scope-guardrails.mjs" ||
  file === "scripts/lint-security-scope.mjs" ||
  file === "scripts/security-scope-allowlist.json" ||
  file.startsWith("scripts/tests/") ||
  file.startsWith("documents/security/") ||
  file.startsWith("backend/tests/") ||
  file.startsWith("backend/src/controllers/") ||
  file.startsWith("backend/src/middleware/") ||
  file.startsWith("backend/src/services/");

const changedSecurityFiles = listChangedFiles().filter((file) => isSecurityScopeFile(file) && fs.existsSync(path.join(repoRoot, file)));
const lintable = changedSecurityFiles.filter((file) => /\.(ts|tsx|js|mjs|cjs)$/.test(file));

const patternProblems = [];
for (const file of changedSecurityFiles) {
  const source = fs.readFileSync(path.join(repoRoot, file), "utf8");
  const lines = source.split(/\r?\n/);
  for (const [idx, line] of lines.entries()) {
    const location = `${file}:${idx + 1}`;
    if (/^\s*debugger;?\s*$/.test(line)) {
      patternProblems.push(`${location} contains debugger`);
    }
    if (
      !file.includes("/tests/") &&
      !file.startsWith("scripts/") &&
      !file.startsWith("backend/tests/") &&
      /\bconsole\.log\s*\(/.test(line)
    ) {
      patternProblems.push(`${location} contains console.log outside tests`);
    }
    if (!file.startsWith("docs/") && /^\s*\/\//.test(line) && /\b(TODO|FIXME|HACK)\b/.test(line)) {
      patternProblems.push(`${location} contains temporary marker`);
    }
    if (/^\s*\/\//.test(line) && /scope-guardrail-ignore(?!: .{16,})/.test(line)) {
      patternProblems.push(`${location} has an undocumented scope-guardrail-ignore`);
    }
  }
}

if (patternProblems.length > 0) {
  console.error("Security-scope lint failed:");
  for (const problem of patternProblems) console.error(`- ${problem}`);
  process.exit(1);
}

if (lintable.length > 0) {
  const eslint = run([
    "npx",
    "eslint",
    ...lintable,
    "--rule",
    "@typescript-eslint/no-explicit-any: off",
  ]);
  if (eslint.status !== 0) {
    process.stdout.write(eslint.stdout || "");
    process.stderr.write(eslint.stderr || "");
    process.exit(eslint.status || 1);
  }
}

console.log(`Security-scope lint passed for ${changedSecurityFiles.length} changed security files.`);

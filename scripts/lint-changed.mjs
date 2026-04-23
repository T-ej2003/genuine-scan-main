import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";

const ensurePath = () => {
  const segments = String(process.env.PATH || "")
    .split(":")
    .filter(Boolean);
  for (const entry of ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"]) {
    if (!segments.includes(entry)) segments.unshift(entry);
  }
  return segments.join(":");
};
const parseBool = (value, fallback = false) => {
  const normalized = String(value || "").trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
};

const run = (cmd, args) =>
  spawnSync(cmd, args, {
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: ensurePath(),
    },
  });

const baseRef = String(process.env.LINT_CHANGED_BASE_REF || "origin/main").trim();
const enforce = parseBool(process.env.ENFORCE_LINT_CHANGED, false);

let mergeBaseResult = run("git", ["merge-base", "HEAD", baseRef]);
if (mergeBaseResult.status !== 0 && baseRef.startsWith("origin/")) {
  const remoteBranch = baseRef.replace(/^origin\//, "");
  run("git", ["fetch", "--depth=50", "origin", remoteBranch]);
  mergeBaseResult = run("git", ["merge-base", "HEAD", baseRef]);
}
if (mergeBaseResult.status !== 0) {
  const fallback = run("git", ["rev-parse", "HEAD~1"]);
  if (fallback.status !== 0) {
    console.warn(`lint:changed skipped (unable to compute merge-base with ${baseRef}).`);
    process.exit(0);
  }
  mergeBaseResult = fallback;
}

const mergeBase = String(mergeBaseResult.stdout || "").trim();
const diffResult = run("git", ["diff", "--name-only", "--diff-filter=ACMRTUXB", `${mergeBase}...HEAD`]);
if (diffResult.status !== 0) {
  console.error("Failed to compute changed files.");
  console.error((diffResult.stderr || diffResult.stdout || "").trim());
  process.exit(1);
}

const lintable = String(diffResult.stdout || "")
  .split("\n")
  .map((line) => line.trim())
  .filter(Boolean)
  .filter((file) => /\.(m?[jt]sx?)$/i.test(file))
  .filter((file) => !file.startsWith("dist/") && !file.startsWith("backend/dist/"))
  .filter((file) => existsSync(file));

if (!lintable.length) {
  console.log("lint:changed skipped (no changed JS/TS files).");
  process.exit(0);
}

const runEslint = (files) => run("npx", ["eslint", "--max-warnings=0", ...files]);
const chunkSize = 80;
for (let index = 0; index < lintable.length; index += chunkSize) {
  const chunk = lintable.slice(index, index + chunkSize);
  const result = runEslint(chunk);
  if (result.status !== 0) {
    process.stdout.write(result.stdout || "");
    process.stderr.write(result.stderr || "");
    if (enforce) {
      process.exit(result.status || 1);
    }
    console.warn("lint:changed found issues but is running in report-only mode (ENFORCE_LINT_CHANGED=false).");
    process.exit(0);
  }
}

console.log(`lint:changed passed (${lintable.length} file(s)).`);

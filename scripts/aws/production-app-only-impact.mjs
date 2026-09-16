import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { APP_ONLY_DOMAINS } from "./production-app-only-contract.mjs";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";

// Source impact determines WHICH live proofs are needed, never whether live
// changes have actually been applied. Unknown executable paths fail closed.
export function classifyAppOnlyPaths(paths) {
  const changed = Object.fromEntries(APP_ONLY_DOMAINS.map((domain) => [domain, false]));
  const reasons = Object.fromEntries(APP_ONLY_DOMAINS.map((domain) => [domain, []]));
  const unknown = [], application = [], releaseControl = [];
  const mark = (path, domains) => { for (const domain of domains) { changed[domain] = true; reasons[domain].push(path); } };
  for (const path of [...new Set(paths)].sort()) {
    assert.ok(typeof path === "string" && /^[\x20-\x7e]+$/.test(path) && !path.startsWith("/")
      && !path.split("/").some((part) => part === ".." || part === "." || part === ""), "Invalid source path");
    if (path.endsWith(".md") || path === "backend/.env.example") { /* documentation is not effective runtime configuration */ }
    else if (/^(?:backend\/)?(?:prisma|migrations)\//.test(path)) mark(path, ["DATABASE_SCHEMA", "MIGRATIONS"]);
    else if (/^(?:backend\/src\/rls-waves\/|scripts\/rls\/|documents\/security\/rls-program\/)/.test(path)) mark(path, ["RLS"]);
    else if (/^infra\/aws\//.test(path)) mark(path, ["TERRAFORM_MANAGED_RUNTIME_CONFIGURATION", "IAM", "KMS", "NETWORK"]);
    else if (/^documents\/ops\/iam\//.test(path)) mark(path, ["IAM"]);
    else if (/^backend\/scripts\//.test(path)) mark(path, ["RLS", "DATABASE_SCHEMA", "MIGRATIONS"]);
    else if (/\.(?:sql|psql)$/.test(path)) mark(path, ["RLS", "DATABASE_SCHEMA", "MIGRATIONS"]);
    else if (/^(?:backend\/src\/|backend\/Dockerfile|backend\/package(?:-lock)?\.json|shared\/)/.test(path)) application.push(path);
    else if (/^(?:\.github\/workflows\/|scripts\/aws\/|scripts\/check-|scripts\/validate-)/.test(path)
      || path === "scripts/lib/aws-dr-validation-contract.mjs") releaseControl.push(path);
    else if (/^(?:scripts\/tests\/|backend\/tests\/|documents\/|docs\/)/.test(path) || /\.md$/.test(path)
      || path === "scripts/p2-test-db-tls.mjs") { /* source-only isolated harness; never a production input */ }
    else unknown.push(path);
  }
  return { changed, reasons, application, releaseControl, unknown, sourceClassificationComplete: unknown.length === 0 };
}

export function deriveAppOnlyImpact({ repositoryRoot, liveSourceSha, candidateSourceSha, protectedSourceSha }) {
  for (const sha of [liveSourceSha, candidateSourceSha, protectedSourceSha]) assert.match(sha || "", /^[a-f0-9]{40}$/);
  const git = (args) => {
    const result = spawnSync("git", args, { cwd: repositoryRoot, encoding: "utf8", timeout: 30000, maxBuffer: 8 * 1024 * 1024 });
    assert.equal(result.status, 0, "Cannot authenticate source ancestry/diff");
    return result.stdout;
  };
  git(["merge-base", "--is-ancestor", liveSourceSha, candidateSourceSha]);
  git(["merge-base", "--is-ancestor", candidateSourceSha, protectedSourceSha]);
  // --no-renames includes both removed and added paths, so a moved migration
  // cannot disappear into a benign new path. Full SHAs exclude revision syntax.
  const diff = (base, head) => git(["diff", "--no-renames", "--name-only", "-z", base, head, "--"]).split("\0").filter(Boolean);
  const classify = (base, head) => {
    const result = classifyAppOnlyPaths(diff(base, head));
    if (result.unknown.includes("package.json")) {
      const before = JSON.parse(git(["show", `${base}:package.json`]));
      const after = JSON.parse(git(["show", `${head}:package.json`]));
      if (appOnlyPackageScriptsChanged(before, after)) {
        result.unknown = result.unknown.filter((file) => file !== "package.json");
        result.releaseControl.push("package.json");
        result.sourceClassificationComplete = result.unknown.length === 0;
      }
    }
    return result;
  };
  const result = { schemaVersion: 1, liveSourceSha, candidateSourceSha, protectedSourceSha,
    liveToCandidate: classify(liveSourceSha, candidateSourceSha),
    candidateToProtected: classify(candidateSourceSha, protectedSourceSha) };
  return { ...result, impactSha256: canonicalSha256(result) };
}

export function appOnlyPackageScriptsChanged(before, after) {
  const withoutScripts = (value) => Object.fromEntries(Object.entries(value).filter(([key]) => key !== "scripts"));
  return canonicalSha256(withoutScripts(before)) === canonicalSha256(withoutScripts(after));
}

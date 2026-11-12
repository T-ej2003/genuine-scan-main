import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { classifyAppOnlyPaths, appOnlyPackageScriptsChanged, appOnlyRootPackageVersionOnlyChange,
  deriveAppOnlyImpact } from "../aws/production-app-only-impact.mjs";
for (const [path, domain] of [
  ["backend/prisma/schema.prisma", "DATABASE_SCHEMA"], ["backend/prisma/migrations/1/migration.sql", "MIGRATIONS"],
  ["backend/src/rls-waves/session-a/policy.sql", "RLS"], ["scripts/rls/sql/generated/runtime-policy.sql", "RLS"],
  ["infra/aws/terraform/main.tf", "TERRAFORM_MANAGED_RUNTIME_CONFIGURATION"], ["documents/ops/iam/policy.json", "IAM"],
  ["infra/aws/kms.json", "KMS"], ["infra/aws/network.tf", "NETWORK"],
]) test(`${path} requires ${domain} compatibility evidence`, () => {
  const impact = classifyAppOnlyPaths([path]); assert.equal(impact.changed[domain], true); assert.deepEqual(impact.reasons[domain], [path]);
});
test("backend-only source input does not invent infrastructure changes", () => {
  const impact = classifyAppOnlyPaths(["backend/src/services/auth/sessionRiskService.ts"]);
  assert.equal(impact.sourceClassificationComplete, true); assert.ok(Object.values(impact.changed).every((v) => v === false)); assert.equal(impact.application.length, 1);
});
test("manufacturer frontend changes are application inputs, while auth boundary and SQL retain security impact", () => {
  const impact = classifyAppOnlyPaths([
    "src/lib/api/internal-client-core.ts", "src/lib/api/request-coordinator.ts",
    "src/features/batches/hooks.ts", "src/features/batches/useBatchOperationsController.ts",
    "src/features/batches/components/BatchesWorkspaceTable.tsx", "src/test/internal-client-core.test.ts",
    "backend/src/rls-waves/session-b/b01/canonicalAuthContext.ts",
  ]);
  assert.equal(impact.sourceClassificationComplete, true);
  assert.equal(impact.application.length, 5);
  assert.equal(impact.changed.RLS, true);
  assert.deepEqual(impact.reasons.RLS, ["backend/src/rls-waves/session-b/b01/canonicalAuthContext.ts"]);
  for (const path of ["backend/src/rls-waves/session-b/b01/guard.sql", "documents/ops/iam/grants.json",
    "backend/prisma/schema.prisma", "backend/prisma/migrations/1/migration.sql"])
    assert.ok(Object.values(classifyAppOnlyPaths([path]).changed).some(Boolean), `${path} must require compatibility evidence`);
});
test("unknown paths and malformed paths cannot establish complete source eligibility", () => {
  assert.equal(classifyAppOnlyPaths(["unknown-executable.sh"]).sourceClassificationComplete, false);
  for (const path of ["../backend/code", "/etc/file", "scripts/../migration.sql", "lookаlike/path", "a\nfile"]) assert.throws(() => classifyAppOnlyPaths([path]));
});
test("documentation does not manufacture runtime IAM changes, executable policy files still require proof", () => {
  const result = classifyAppOnlyPaths(["documents/ops/iam/runbook.md", "backend/.env.example"]);
  assert.equal(result.sourceClassificationComplete, true);
  assert.ok(Object.values(result.changed).every((changed) => !changed));
  assert.equal(classifyAppOnlyPaths(["documents/ops/iam/policy.json"]).changed.IAM, true);
});
test("root package classification permits only scripts changes, never dependencies or unknown metadata", () => {
  const before = { scripts: { verify: "old" }, dependencies: { example: "1" }, engines: { node: "24" } };
  assert.equal(appOnlyPackageScriptsChanged(before, { ...before, scripts: { verify: "new" } }), true);
  assert.equal(appOnlyPackageScriptsChanged(before, { ...before, dependencies: { example: "2" } }), false);
  assert.equal(appOnlyPackageScriptsChanged(before, { ...before, arbitrary: "new" }), false);
  assert.equal(classifyAppOnlyPaths(["package.json"]).sourceClassificationComplete, false);
});

test("paired root package versions are release metadata only when all other content is unchanged", () => {
  const before = { name: "app", version: "1.0.0", scripts: { build: "vite" }, dependencies: { example: "1" }, config: { flag: true } };
  const after = { ...before, version: "1.0.1" };
  const beforeLock = { name: "app", version: "1.0.0", packages: { "": { name: "app", version: "1.0.0", dependencies: { example: "1" } } } };
  const afterLock = structuredClone(beforeLock); afterLock.version = "1.0.1"; afterLock.packages[""].version = "1.0.1";
  const allowed = (nextPackage = after, nextLock = afterLock) => appOnlyRootPackageVersionOnlyChange(before, nextPackage, beforeLock, nextLock);
  assert.equal(allowed(), true);
  assert.equal(allowed({ ...after, dependencies: { example: "2" } }), false);
  assert.equal(allowed({ ...after, scripts: { build: "other" } }), false);
  assert.equal(allowed({ ...after, config: { flag: false } }), false);
  assert.equal(allowed(after, { ...afterLock, packages: { "": { ...afterLock.packages[""], dependencies: { example: "2" } } } }), false);
  assert.equal(allowed(after, { ...afterLock, version: "1.0.2" }), false);
  assert.equal(allowed(after, { ...afterLock, packages: { "": { ...afterLock.packages[""], version: "1.0.2" } } }), false);
  assert.equal(allowed(before), false);
});

test("source impact accepts the paired version change but retains unrelated unknown and RLS paths", () => {
  const directory = mkdtempSync(join(tmpdir(), "mscqr-package-impact-"));
  const git = (...args) => execFileSync("git", ["-C", directory, ...args], { encoding: "utf8" }).trim();
  try {
    git("init", "-q"); git("config", "user.name", "Test"); git("config", "user.email", "test@example.invalid");
    const write = (version) => {
      writeFileSync(join(directory, "package.json"), JSON.stringify({ name: "app", version, scripts: { build: "vite" } }));
      writeFileSync(join(directory, "package-lock.json"), JSON.stringify({ name: "app", version, packages: { "": { name: "app", version } } }));
    };
    write("1.0.0"); git("add", "."); git("commit", "-qm", "baseline"); const baseline = git("rev-parse", "HEAD");
    write("1.0.1"); git("add", "."); git("commit", "-qm", "release identity"); const candidate = git("rev-parse", "HEAD");
    const accepted = deriveAppOnlyImpact({ repositoryRoot: directory, liveSourceSha: baseline, candidateSourceSha: candidate, protectedSourceSha: candidate });
    assert.equal(accepted.liveToCandidate.sourceClassificationComplete, true);
    assert.deepEqual(accepted.liveToCandidate.releaseControl, ["package.json", "package-lock.json"]);
    assert.ok(Object.values(accepted.liveToCandidate.changed).every((value) => !value));
    writeFileSync(join(directory, "unknown.sh"), "echo unsafe\n"); git("add", "."); git("commit", "-qm", "unknown");
    const head = git("rev-parse", "HEAD");
    const rejected = deriveAppOnlyImpact({ repositoryRoot: directory, liveSourceSha: baseline, candidateSourceSha: head, protectedSourceSha: head });
    assert.deepEqual(rejected.liveToCandidate.unknown, ["unknown.sh"]);
    assert.equal(rejected.liveToCandidate.sourceClassificationComplete, false);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("only the exact isolated TLS fixture helper is classified as test tooling", () => {
  const result = classifyAppOnlyPaths(["scripts/p2-test-db-tls.mjs"]);
  assert.equal(result.sourceClassificationComplete, true);
  assert.ok(Object.values(result.changed).every((changed) => !changed));
  assert.equal(classifyAppOnlyPaths(["scripts/p2-production-db-tls.mjs"]).sourceClassificationComplete, false);
});

test("historical connector packaging and test paths are classified without waiving live security domains", () => {
  const application = [".dockerignore", "backend/local-print-agent/install/windows/Install Connector.cmd",
    "backend/local-print-agent/packaging/build-connector-release.mjs", "backend/local-print-agent/releases/manifest.json"];
  const result = classifyAppOnlyPaths([...application, "e2e/system-integration.spec.ts",
    "scripts/release/generate-rf7-contract-inventory.mjs", "backend/src/rls-waves/session-c/c02/printingLifecycle.sql"]);
  assert.equal(result.sourceClassificationComplete, true);
  assert.deepEqual(result.application, application);
  assert.deepEqual(result.releaseControl, ["scripts/release/generate-rf7-contract-inventory.mjs"]);
  assert.equal(result.changed.RLS, true);
  assert.equal(classifyAppOnlyPaths(["backend/local-print-agent/unknown-runtime.sh"]).sourceClassificationComplete, false);
});

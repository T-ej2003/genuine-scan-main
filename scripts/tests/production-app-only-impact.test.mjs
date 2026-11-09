import test from "node:test";
import assert from "node:assert/strict";
import { classifyAppOnlyPaths, appOnlyPackageScriptsChanged } from "../aws/production-app-only-impact.mjs";
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

test("only the exact isolated TLS fixture helper is classified as test tooling", () => {
  const result = classifyAppOnlyPaths(["scripts/p2-test-db-tls.mjs"]);
  assert.equal(result.sourceClassificationComplete, true);
  assert.ok(Object.values(result.changed).every((changed) => !changed));
  assert.equal(classifyAppOnlyPaths(["scripts/p2-production-db-tls.mjs"]).sourceClassificationComplete, false);
});

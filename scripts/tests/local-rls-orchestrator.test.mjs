import assert from "node:assert/strict";
import test from "node:test";
import { phasePlan, runLocalRls } from "../rls/local-production-readiness.mjs";

test("local orchestration exposes only safe phases and writes a static report", () => {
  assert.deepEqual(phasePlan("static").map(([name]) => name), ["Git validation", "Backend build", "Named SQL function inventory", "Production access scan", "Context generation", "Workflow partition generation", "SQL generation", "Package verification", "Manifest validation", "Scope guardrails", "Full RLS verification", "Context check"]);
  const report = runLocalRls("static", () => ({ status: 0, stdout: "postgresql://user:secret@host/db", stderr: "" }));
  assert.equal(report.result, "PASS");
  assert.equal(report.databaseMutationOccurred, false);
  assert.match(report.reportPath, /^artifacts\/rls-runs\//);
  assert.throws(() => runLocalRls("staging-certify"), /intentionally not implemented/);
});

test("local orchestration propagates a subprocess failure", () => {
  const report = runLocalRls("repair", () => ({ status: 1, stdout: "failure", stderr: "" }));
  assert.equal(report.result, "FAIL");
  assert.equal(report.failedPhase, "Production access scan");
});

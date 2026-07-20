import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const programRoot = path.join(repoRoot, "documents/security/rls-program");
const read = (name) => JSON.parse(fs.readFileSync(path.join(programRoot, name), "utf8"));
const workflows = read("workflows.json").workflows;
const partition = read("workflow-two-session-partition.json");
const sessionA = read("workflow-ownership-session-a.json");
const sessionB = read("workflow-ownership-session-b.json");

test("two-session partition assigns all 428 workflows exactly once without a catch-all", () => {
  const sourceIds = workflows.map((workflow) => workflow.id).sort();
  const assignedIds = partition.assignments.map((assignment) => assignment.workflowId).sort();
  assert.equal(sourceIds.length, 428);
  assert.equal(new Set(sourceIds).size, 428);
  assert.equal(assignedIds.length, 428);
  assert.equal(new Set(assignedIds).size, 428);
  assert.deepEqual(assignedIds, sourceIds);
  assert.deepEqual(partition.validationSummary.missingWorkflowIds, []);
  assert.deepEqual(partition.validationSummary.duplicateWorkflowIds, []);
  assert.deepEqual(partition.validationSummary.unknownWorkflowIds, []);
  assert.deepEqual(partition.validationSummary.genericCatchAllAssignments, []);
  for (const assignment of partition.assignments) {
    assert.ok(assignment.contract.trim());
    assert.doesNotMatch(`${assignment.waveId}:${assignment.assignmentRuleId}`, /fallback|catch.?all|remaining|misc/i);
  }
});

test("session ownership is exhaustive and editable production files never overlap", () => {
  assert.equal(sessionA.foundationCommit, partition.foundationCommit);
  assert.equal(sessionB.foundationCommit, partition.foundationCommit);
  assert.equal(sessionA.workflowIds.length, 284);
  assert.equal(sessionB.workflowIds.length, 144);
  assert.equal(new Set([...sessionA.workflowIds, ...sessionB.workflowIds]).size, 428);
  assert.deepEqual(sessionA.productionFiles.filter((file) => sessionB.productionFiles.includes(file)), []);
  assert.deepEqual(partition.fileOwnership.sessionAOwnedSharedFiles, [
    "backend/src/controllers/incidentController.ts",
    "backend/src/services/compliancePackService.ts",
    "backend/src/services/governanceService.ts",
    "backend/src/services/replacementChainService.ts",
  ]);
  assert.deepEqual(partition.fileOwnership.sessionBOwnedSharedFiles, ["backend/src/middleware/auth.ts"]);
});

test("Session B is isolated from global generation, certification and staging state", () => {
  assert.equal(sessionB.waveLocalResultManifest, "documents/security/rls-program/waves/session-b-auth-public-workers-result.json");
  assert.ok(sessionB.allowedNewPathRules.includes(sessionB.waveLocalResultManifest));
  for (const requiredBoundary of [
    "documents/security/rls-program/generated/**",
    "scripts/rls/generate-*.mjs",
    "scripts/rls/certify-*.mjs",
    "scripts/rls/sql/**",
    "backend/prisma/migrations/**",
    "infra/terraform/staging-api/**",
  ]) assert.ok(sessionB.forbiddenGlobalPathRules.includes(requiredBoundary));
  for (const file of sessionB.integrationOwnerOnlyFiles) assert.ok(sessionA.productionFiles.includes(file));
  for (const file of sessionB.existingTestFiles) assert.ok(fs.existsSync(path.join(repoRoot, file)), file);
});

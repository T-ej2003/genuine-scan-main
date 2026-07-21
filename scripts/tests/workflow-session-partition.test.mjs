import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  applicationPathCertificationFamilies,
  buildRegisteredCallPathEvidence,
} from "../rls/lib/application-path-certifications.mjs";

const repoRoot = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const programRoot = path.join(repoRoot, "documents/security/rls-program");
const read = (name) => JSON.parse(fs.readFileSync(path.join(programRoot, name), "utf8"));
const workflowManifest = read("workflows.json");
const workflows = workflowManifest.workflows;
const partition = read("workflow-three-session-partition.json");
const sessionA = read("workflow-ownership-session-a.json");
const sessionB = read("workflow-ownership-session-b.json");
const sessionC = read("workflow-ownership-session-c.json");

test("three-session partition assigns all 428 workflows exactly once without a catch-all", () => {
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

test("registered call paths generate all workflow dispositions from executable family evidence", () => {
  const evidence = buildRegisteredCallPathEvidence({ workflowsManifest: workflowManifest, partition, repoRoot });
  assert.equal(evidence.workflowCount, 428);
  assert.equal(evidence.summary.applicationPathCertified, applicationPathCertificationFamilies.flatMap((family) => family.workflowIds).length);
  assert.equal(evidence.workflows.filter((row) => row.productionAccessPath.length === 0).length, 0);
  assert.equal(evidence.workflows.flatMap((row) => row.productionAccessPath).filter((row) => row.registration === "unregistered").length, 0);
  assert.deepEqual(
    evidence.workflows.filter((row) => row.disposition === "application-path-certified").map((row) => row.workflowId).sort(),
    applicationPathCertificationFamilies.flatMap((family) => family.workflowIds).sort()
  );
});

test("session ownership is exhaustive and editable production and test files never overlap", () => {
  assert.equal(sessionA.coordinationBaseCommit, partition.coordinationBaseCommit);
  assert.equal(sessionB.coordinationBaseCommit, partition.coordinationBaseCommit);
  assert.equal(sessionC.coordinationBaseCommit, partition.coordinationBaseCommit);
  assert.equal(sessionA.workflowIds.length, 177);
  assert.equal(sessionB.workflowIds.length, 144);
  assert.equal(sessionC.workflowIds.length, 107);
  assert.equal(sessionA.productionFileCount, 52);
  assert.equal(sessionB.productionFileCount, 76);
  assert.equal(sessionC.productionFileCount, 39);
  assert.equal(sessionB.existingTestFileCount, 47);
  assert.equal(sessionC.existingTestFileCount, 21);
  assert.equal(new Set([...sessionA.workflowIds, ...sessionB.workflowIds, ...sessionC.workflowIds]).size, 428);
  assert.deepEqual(sessionA.productionFiles.filter((file) => sessionB.productionFiles.includes(file)), []);
  assert.deepEqual(sessionA.productionFiles.filter((file) => sessionC.productionFiles.includes(file)), []);
  assert.deepEqual(sessionB.productionFiles.filter((file) => sessionC.productionFiles.includes(file)), []);
  assert.deepEqual(sessionB.existingTestFiles.filter((file) => sessionC.existingTestFiles.includes(file)), []);
  assert.deepEqual(partition.fileOwnership.sessionAOwnedSharedFiles, [
    "backend/src/services/replacementChainService.ts",
    "backend/src/routes/index.ts",
  ]);
  assert.deepEqual(partition.fileOwnership.sessionAAdditionalProductionFiles, ["backend/src/lib/canonicalDbContext.ts"]);
  assert.deepEqual(partition.fileOwnership.sessionBOwnedSharedFiles, ["backend/src/middleware/auth.ts"]);
  assert.deepEqual(partition.fileOwnership.sessionCOwnedSharedFiles, [
    "backend/src/controllers/incidentController.ts",
    "backend/src/controllers/licenseeController.ts",
    "backend/src/controllers/tracePolicyController.ts",
    "backend/src/controllers/userController.ts",
    "backend/src/services/compliancePackService.ts",
    "backend/src/services/governanceService.ts",
    "backend/src/services/manufacturerScopeService.ts",
  ]);
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
  for (const file of sessionB.integrationOwnerOnlyFiles) assert.ok(sessionA.productionFiles.includes(file) || sessionC.productionFiles.includes(file));
  for (const file of sessionB.existingTestFiles) assert.ok(fs.existsSync(path.join(repoRoot, file)), file);
  assert.equal(partition.validationSummary.sessionBWorkflowOwnershipPreserved, true);
  assert.equal(partition.validationSummary.sessionBWorkflowSetSha256, "116815209a0a591ff122a0a7bac9a5958cfa4182742c8483d039261c7ba4e79a");
});

test("Session C owns exact administration, governance and operator families and remains isolated", () => {
  assert.equal(sessionC.waveLocalResultManifest, "documents/security/rls-program/waves/session-c-admin-governance-operator-result.json");
  assert.ok(sessionC.allowedNewPathRules.includes(sessionC.waveLocalResultManifest));
  assert.deepEqual(sessionC.workflowFamilies.map((family) => family.waveId), [
    "c-01-administration-general-mutations",
    "c-02-audit-fraud-trace-alerts",
    "c-03-governance-policies-incidents-compliance",
    "c-04-operator-recovery-startup-migration-cli",
  ]);
  assert.deepEqual(sessionC.workflowFamilies.map((family) => family.workflowIds.length), [8, 17, 55, 27]);
  for (const requiredBoundary of [
    "documents/security/rls-program/generated/**",
    "scripts/rls/generate-*.mjs",
    "scripts/rls/certify-*.mjs",
    "scripts/rls/sql/**",
    "backend/prisma/migrations/**",
    "infra/terraform/staging-api/**",
  ]) assert.ok(sessionC.forbiddenGlobalPathRules.includes(requiredBoundary));
  for (const file of sessionC.prohibitedSharedFiles) assert.ok(!sessionC.productionFiles.includes(file));
  for (const file of sessionC.existingTestFiles) assert.ok(fs.existsSync(path.join(repoRoot, file)), file);
  const integrationRunner = partition.assignments.find((assignment) => assignment.workflowId === "workflow-cli-scripts-run-system-integration-mjs-main");
  assert.equal(integrationRunner.sessionId, "session-a");
  assert.equal(integrationRunner.waveId, "a-09-system-integration-owner");
});

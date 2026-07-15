import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { buildTableManifest, buildWorkflowManifest, decisionManifestPath, identityManifestPath, manifests, parseSchema, repoRoot, scanProductionAccess, sharedApplyIsBlocked, tableManifestPath, validateRuntimeIdentities, workflowManifestPath } from "../rls/lib/program-inventory.mjs";

const snapshot = () => [tableManifestPath, workflowManifestPath, decisionManifestPath].map((file) => fs.readFileSync(file, "utf8"));

test("all Prisma models and production access sites are represented exactly and deterministically", () => {
  const before = snapshot();
  buildTableManifest();
  buildWorkflowManifest();
  assert.deepEqual(snapshot(), before, "generated manifests changed on a second run");
  const { tables, workflows } = manifests();
  const models = parseSchema().map((model) => model.name).sort();
  assert.deepEqual(tables.tables.map((table) => table.prismaModel).sort(), models);
  assert.equal(new Set(tables.tables.map((table) => table.prismaModel)).size, models.length, "a model was duplicated or silently skipped");
  const mapped = new Set(workflows.workflows.flatMap((workflow) => workflow.supportingEvidence.map((item) => item.accessId)));
  const detected = scanProductionAccess().accesses;
  assert.deepEqual([...mapped].sort(), detected.map((item) => item.id).sort());
});

test("stable IDs and references are unique and valid", () => {
  const { tables, workflows, identities, decisions } = manifests();
  for (const items of [tables.tables, workflows.workflows, identities.identities, decisions.decisions]) assert.equal(new Set(items.map((item) => item.id)).size, items.length);
  const tableIds = new Set(tables.tables.map((table) => table.id));
  const workflowIds = new Set(workflows.workflows.map((workflow) => workflow.id));
  const decisionIds = new Set(decisions.decisions.map((decision) => decision.id));
  for (const workflow of workflows.workflows) {
    workflow.tablesTouched.forEach((id) => assert(tableIds.has(id), `${workflow.id} -> ${id}`));
    workflow.unresolvedDecisions.forEach((id) => assert(decisionIds.has(id), `${workflow.id} -> ${id}`));
  }
  for (const table of tables.tables) {
    [...table.productionRuntimeReaders, ...table.productionRuntimeWriters].forEach((id) => assert(workflowIds.has(id), `${table.id} -> ${id}`));
    table.unresolvedDecisions.forEach((id) => assert(decisionIds.has(id), `${table.id} -> ${id}`));
  }
});

test("tests do not inflate production totals and repeated technical calls remain one functional workflow", () => {
  const { accesses } = scanProductionAccess();
  assert(accesses.every((item) => !/(?:^|\/)tests?\//.test(item.sourceFile)), "test-only access leaked into production totals");
  const workflows = manifests().workflows.workflows;
  const keys = workflows.map((workflow) => `${workflow.executionSurface}:${workflow.canonicalSourceFiles.join(",")}:${workflow.entryPoint}`);
  assert.equal(new Set(keys).size, keys.length, "duplicate canonical workflows exist");
  assert(workflows.some((workflow) => workflow.supportingEvidence.length > workflow.tablesTouched.length), "technical call sites were not deduplicated");
});

test("unregistered or legacy classifications require import and registration evidence", () => {
  const { workflows } = manifests();
  for (const item of workflows.generatedEvidence.unregisteredPotentiallyDeadAccesses) {
    assert.equal(item.production, false);
    assert.equal(item.registrationEvidence, "unregistered");
    assert(fs.existsSync(path.join(repoRoot, item.sourceFile)), `${item.id} source evidence is missing`);
  }
  assert(!workflows.workflows.some((workflow) => /dead|legacy/.test(workflow.currentCompatibilityStatus)), "production workflow was automatically declared dead");
});

test("security-sensitive tables and runtime identities fail closed", () => {
  const { tables, identities, decisions } = manifests();
  for (const table of tables.tables.filter((item) => item.category === "security-sensitive")) {
    assert(table.unresolvedDecisions.length || table.policyStatus === "special-boundary-designed");
    assert.notEqual(table.policyStatus, "ordinary-tenant-access");
  }
  for (const identity of identities.identities) {
    assert.equal(identity.mayUseBypassRls, false);
    assert.equal(identity.superuser, false);
  }
  validateRuntimeIdentities(identities, decisions);
});

test("runtime-role validator rejects unsafe ownership, privilege, credential, and break-glass designs", () => {
  const { identities, decisions } = manifests();
  const rejects = (id, mutate, pattern) => {
    const candidate = structuredClone(identities);
    mutate(candidate.identities.find((identity) => identity.id === id), candidate.identities);
    assert.throws(() => validateRuntimeIdentities(candidate, decisions), pattern);
  };
  rejects("identity-authenticated-app", (identity) => { identity.superuser = true; }, /superuser/);
  rejects("identity-worker", (identity) => { identity.mayUseBypassRls = true; }, /BYPASSRLS/);
  rejects("identity-authenticated-app", (identity) => { identity.mayOwnProtectedTables = true; }, /may own protected tables/);
  rejects("identity-table-owner", (identity) => { identity.loginExpectation = "LOGIN"; }, /owner role must be NOLOGIN|runtime identity may own/);
  rejects("identity-pre-auth-app", (identity, candidate) => { identity.credentialSource = candidate.find((item) => item.id === "identity-authenticated-app").credentialSource; }, /must not share credential sources/);
  rejects("identity-pre-auth-app", (identity) => { identity.allowedCommands.push("SELECT"); }, /pre-auth may only/);
  rejects("identity-restricted-read", (identity) => { identity.allowedCommands.push("UPDATE"); }, /restricted read/);
  rejects("identity-migration", (identity) => { identity.maySetRole = true; }, /SET ROLE/);
  rejects("identity-production-break-glass", (identity) => { identity.standingCredential = true; }, /standing credential/);
  rejects("identity-worker", (identity) => { delete identity.environmentRoleNames.production; }, /patterns are incomplete|production role name/);
});

test("activation remains manual and the shared-table apply remains blocked", () => {
  assert(sharedApplyIsBlocked());
  const productionSources = scanProductionAccess().activeFiles.map((file) => fs.readFileSync(path.join(repoRoot, file), "utf8")).join("\n");
  assert(!productionSources.includes("mscqr_staging_rls_shared_batch_phase_apply_2026-07-15.sql"), "production code references blocked apply SQL");
  for (const migrationDirectory of fs.readdirSync(path.join(repoRoot, "backend/prisma/migrations"))) {
    const file = path.join(repoRoot, "backend/prisma/migrations", migrationDirectory, "migration.sql");
    if (fs.existsSync(file)) assert(!fs.readFileSync(file, "utf8").includes("Shared batch RLS apply blocked"), `${file} embeds the blocked apply`);
  }
});

test("human manifests are present and parseable", () => {
  assert(JSON.parse(fs.readFileSync(identityManifestPath, "utf8")).identities.length >= 10);
  assert(JSON.parse(fs.readFileSync(decisionManifestPath, "utf8")).decisions.length > 0);
});

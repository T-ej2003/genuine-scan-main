#!/usr/bin/env node
import assert from "node:assert/strict";
import { boundaries, categories, commands, manifests, parseSchema, scanProductionAccess, sharedApplyIsBlocked, surfaces } from "./lib/program-inventory.mjs";

const { tables, workflows, identities, decisions } = manifests();
assert(tables && workflows && identities && decisions, "all four manifests must exist");
const modelNames = parseSchema().map((model) => model.name);
assert.deepEqual([...tables.tables.map((table) => table.prismaModel)].sort(), [...modelNames].sort(), "every Prisma model must appear exactly once");
assert.equal(new Set(tables.tables.map((table) => table.id)).size, tables.tables.length, "table IDs must be unique");
assert.equal(new Set(workflows.workflows.map((workflow) => workflow.id)).size, workflows.workflows.length, "workflow IDs must be unique");
assert.equal(new Set(identities.identities.map((identity) => identity.id)).size, identities.identities.length, "identity IDs must be unique");
assert.equal(new Set(decisions.decisions.map((decision) => decision.id)).size, decisions.decisions.length, "decision IDs must be unique");

const tableIds = new Set(tables.tables.map((table) => table.id));
const workflowIds = new Set(workflows.workflows.map((workflow) => workflow.id));
const decisionIds = new Set(decisions.decisions.map((decision) => decision.id));
for (const table of tables.tables) {
  assert(categories.has(table.category), `${table.id} category is invalid`);
  assert(table.category !== "intentionally-non-rls" || table.nonRlsSecurityJustification?.trim(), `${table.id} needs a non-RLS security justification`);
  for (const id of [...table.productionRuntimeReaders, ...table.productionRuntimeWriters]) assert(workflowIds.has(id), `${table.id} references missing workflow ${id}`);
  for (const command of table.requiredCommands) assert(commands.has(command), `${table.id} has invalid command ${command}`);
  for (const id of table.unresolvedDecisions) assert(decisionIds.has(id), `${table.id} references missing decision ${id}`);
  if (table.category === "security-sensitive") assert(table.unresolvedDecisions.length || table.policyStatus === "special-boundary-designed", `${table.id} needs a special boundary or blocker`);
}
for (const workflow of workflows.workflows) {
  assert(surfaces.has(workflow.executionSurface), `${workflow.id} surface is invalid`);
  assert(boundaries.has(workflow.authorizationBoundaryType), `${workflow.id} boundary is invalid`);
  assert(workflow.expectedAllowedScenarios.length && workflow.expectedDeniedScenarios.length, `${workflow.id} needs allowed and denied scenarios`);
  assert.notEqual(workflow.implementationStatus, "complete", `${workflow.id} cannot be silently complete`);
  for (const tableId of workflow.tablesTouched) assert(tableIds.has(tableId), `${workflow.id} references missing table ${tableId}`);
  for (const item of workflow.commandsPerTable) {
    assert(tableIds.has(item.tableId), `${workflow.id} references missing table ${item.tableId}`);
    for (const command of item.commands) assert(commands.has(command), `${workflow.id} has invalid command ${command}`);
  }
  for (const id of workflow.unresolvedDecisions) assert(decisionIds.has(id), `${workflow.id} references missing decision ${id}`);
  if (["worker", "scheduled"].includes(workflow.executionSurface)) assert(workflow.contextRequirements.includes("approved restricted system identity"), `${workflow.id} needs an explicit system identity design`);
}
const mappedAccessIds = new Set(workflows.workflows.flatMap((workflow) => workflow.supportingEvidence.map((evidence) => evidence.accessId)));
for (const access of scanProductionAccess().accesses) assert(mappedAccessIds.has(access.id), `production access ${access.id} is not mapped to a workflow`);
for (const identity of identities.identities) {
  assert.equal(identity.mayUseBypassRls, false, `${identity.id} requests BYPASSRLS`);
  assert.equal(identity.superuser, false, `${identity.id} requests superuser`);
}
assert(sharedApplyIsBlocked(), "existing shared-table apply must remain blocked before BEGIN");
console.log(JSON.stringify({ valid: true, tables: tables.tables.length, workflows: workflows.workflows.length, productionAccessSites: mappedAccessIds.size }));

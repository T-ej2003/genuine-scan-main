#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import { boundaries, categories, commands, manifests, parseSchema, policyDependencyGraphPath, scanProductionAccess, sharedApplyIsBlocked, surfaces, validateRuntimeIdentities } from "./lib/program-inventory.mjs";

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
const identityIds = new Set(identities.identities.map((identity) => identity.id));
const identityById = new Map(identities.identities.map((identity) => [identity.id, identity]));
const graph = JSON.parse(fs.readFileSync(policyDependencyGraphPath, "utf8"));
const edgesBySource = new Map(tables.tables.map((table) => [table.id, graph.edges.filter((edge) => edge.sourceTable === table.id)]));
const terminal = (tableId, visiting = new Set()) => {
  assert(!visiting.has(tableId), `authorization dependency cycle includes ${tableId}`);
  const table = tables.tables.find((item) => item.id === tableId);
  assert(table, `dependency graph references unknown table ${tableId}`);
  const edges = edgesBySource.get(tableId) || [];
  if (!edges.length) return table.terminalBoundary;
  visiting.add(tableId);
  const boundariesFound = edges.map((edge) => terminal(edge.dependencyTable, new Set(visiting)));
  assert(boundariesFound.every(Boolean), `${tableId} does not reach a terminal boundary`);
  return boundariesFound[0];
};
for (const table of tables.tables) {
  assert(categories.has(table.primaryCategory), `${table.id} primary category is invalid`);
  assert.equal(table.category, table.primaryCategory, `${table.id} legacy category must match primaryCategory`);
  assert.equal(table.classificationStatus, "resolved", `${table.id} classification is unresolved`);
  assert(table.physicalOwnerRole && identityIds.has(table.physicalOwnerRole), `${table.id} has an unknown physical owner`);
  assert.equal(identityById.get(table.physicalOwnerRole).loginExpectation, "NOLOGIN", `${table.id} protected owner may LOGIN`);
  assert.equal(identityById.get(table.physicalOwnerRole).mayOwnProtectedTables, true, `${table.id} physical owner is not the protected table owner`);
  assert(table.rowOwnershipModel?.trim(), `${table.id} lacks a row ownership model`);
  assert(Array.isArray(table.tenantKeyColumns) && Array.isArray(table.actorKeyColumns), `${table.id} key classifications are missing`);
  assert(Array.isArray(table.allowedCommandsByIdentity), `${table.id} command matrix is missing`);
  assert(Array.isArray(table.policyDependencyTables), `${table.id} dependency classification is missing`);
  assert(typeof table.forceRlsTarget === "boolean", `${table.id} FORCE RLS decision is missing`);
  assert(table.primaryCategory !== "parent-inherited" || table.authorizationParentTable, `${table.id} parent-inherited table lacks a parent`);
  assert(table.primaryCategory !== "intentionally-non-rls" || table.nonRlsJustification?.trim(), `${table.id} needs a non-RLS security justification`);
  assert(table.primaryCategory !== "intentionally-non-rls" || table.nonRlsSecurityJustification?.trim(), `${table.id} needs backward-compatible non-RLS justification`);
  assert(!table.forceRlsTarget || terminal(table.id), `${table.id} FORCE RLS target lacks a terminal tenant/actor/system boundary`);
  if (table.primaryCategory === "parent-inherited") assert(["tenant-root", "tenant-key", "actor-key"].includes(terminal(table.id)), `${table.id} parent chain does not terminate at a tenant or actor boundary`);
  const nullableTenantKeys = table.schemaEvidence.fields.filter((field) => table.tenantKeyColumns.includes(field.name) && field.optional);
  assert(!nullableTenantKeys.length || table.tenantKeyNullSemantics?.trim(), `${table.id} nullable tenant key lacks NULL semantics`);
  if (table.primaryCategory === "security-sensitive") {
    assert.match(table.rowOwnershipModel, /^Special /, `${table.id} security-sensitive table lacks a special boundary`);
    assert(table.preAuthAccessMode && !/^direct/i.test(table.preAuthAccessMode), `${table.id} has broad pre-auth table access`);
  }
  if (table.appendOnly) {
    for (const entry of table.allowedCommandsByIdentity) {
      assert(!entry.commands.includes("UPDATE"), `${table.id} append-only table allows UPDATE`);
      if (entry.commands.includes("DELETE")) assert(entry.conditions.some((condition) => /retention|redaction/i.test(condition)), `${table.id} append-only DELETE lacks retention/redaction boundary`);
    }
  }
  if (table.primaryCategory === "migration-only") {
    assert.equal(table.productionRuntimeReaders.length + table.productionRuntimeWriters.length, 0, `${table.id} migration-only table has production runtime access`);
    assert.equal(table.allowedCommandsByIdentity.length, 0, `${table.id} migration-only table has a runtime command matrix`);
  }
  if (table.productionRuntimeWriters.length) assert(table.allowedCommandsByIdentity.some((entry) => entry.commands.some((command) => ["INSERT", "UPDATE", "DELETE", "RAW_SQL"].includes(command))), `${table.id} has writers but no write command matrix`);
  for (const identityId of [...table.allowedRuntimeReaders, ...table.allowedRuntimeWriters, ...table.allowedCommandsByIdentity.map((entry) => entry.identityId)]) assert(identityIds.has(identityId), `${table.id} references unknown runtime identity ${identityId}`);
  for (const id of [...table.productionRuntimeReaders, ...table.productionRuntimeWriters]) assert(workflowIds.has(id), `${table.id} references missing workflow ${id}`);
  for (const command of table.requiredCommands) assert(commands.has(command), `${table.id} has invalid command ${command}`);
  for (const id of table.unresolvedDecisions) assert(decisionIds.has(id), `${table.id} references missing decision ${id}`);
}
assert.deepEqual([...new Set(graph.nodes.map((node) => node.id))].sort(), [...tableIds].sort(), "dependency graph must contain every table exactly once");
for (const edge of graph.edges) {
  assert.notEqual(edge.sourceTable, edge.dependencyTable, `${edge.sourceTable} has a self-recursive policy dependency`);
  assert(tableIds.has(edge.sourceTable) && tableIds.has(edge.dependencyTable), "dependency edge references an unknown table");
  assert(edge.reason?.trim(), `${edge.sourceTable} dependency lacks a reason`);
  assert(edge.requiredIndexOrJoinKey?.trim(), `${edge.sourceTable} dependency lacks a join key/index requirement`);
  assert(edge.joinKey?.sourceColumns?.length && edge.joinKey?.dependencyColumns?.length, `${edge.sourceTable} dependency join key is incomplete`);
  assert.equal(edge.plannerSensitiveHiddenDependency, false, `${edge.sourceTable} has a planner-sensitive hidden dependency`);
  assert.equal(edge.unrestrictedRuntimeOwnedDependency, false, `${edge.sourceTable} depends on an unrestricted runtime-owned object`);
  assert.equal(edge.dependencyRlsProtected, tables.tables.find((table) => table.id === edge.dependencyTable).forceRlsTarget, `${edge.sourceTable} dependency protection status drifted`);
}
assert.equal(graph.acyclic, true, "policy dependency graph is not certified acyclic");
assert.equal(graph.selfRecursivePolicies, 0, "policy dependency graph contains self-recursion");
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
validateRuntimeIdentities(identities, decisions);
assert(sharedApplyIsBlocked(), "existing shared-table apply must remain blocked before BEGIN");
console.log(JSON.stringify({ valid: true, tables: tables.tables.length, workflows: workflows.workflows.length, productionAccessSites: mappedAccessIds.size }));

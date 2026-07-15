#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import { actorClasses, assuranceLevels, boundaries, categories, commands, manifests, parseSchema, policyCommands, policyDependencyGraphPath, scanProductionAccess, sharedApplyIsBlocked, surfaces, validateRuntimeIdentities } from "./lib/program-inventory.mjs";

const { tables, workflows, identities, decisions, commandSemantics } = manifests();
assert(tables && workflows && identities && decisions && commandSemantics, "all programme manifests must exist");
const modelNames = parseSchema().map((model) => model.name);
assert.deepEqual([...tables.tables.map((table) => table.prismaModel)].sort(), [...modelNames].sort(), "every Prisma model must appear exactly once");
assert.equal(new Set(tables.tables.map((table) => table.id)).size, tables.tables.length, "table IDs must be unique");
assert.equal(new Set(workflows.workflows.map((workflow) => workflow.id)).size, workflows.workflows.length, "workflow IDs must be unique");
assert.equal(new Set(identities.identities.map((identity) => identity.id)).size, identities.identities.length, "identity IDs must be unique");
assert.equal(new Set(decisions.decisions.map((decision) => decision.id)).size, decisions.decisions.length, "decision IDs must be unique");
assert.equal(new Set(commandSemantics.rules.map((rule) => rule.id)).size, commandSemantics.rules.length, "command-rule IDs must be unique");

const tableIds = new Set(tables.tables.map((table) => table.id));
const workflowIds = new Set(workflows.workflows.map((workflow) => workflow.id));
const decisionIds = new Set(decisions.decisions.map((decision) => decision.id));
const identityIds = new Set(identities.identities.map((identity) => identity.id));
const identityById = new Map(identities.identities.map((identity) => [identity.id, identity]));
const commandRuleIds = new Set(commandSemantics.rules.map((rule) => rule.id));
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
  if (table.forceRlsTarget) assert(table.commandRuleIds?.length, `${table.id} lacks exact command rules`);
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
  for (const id of table.commandRuleIds || []) assert(commandRuleIds.has(id), `${table.id} references missing command rule ${id}`);
  for (const entry of table.allowedCommandsByIdentity.filter((item) => identityById.get(item.identityId)?.loginExpectation === "LOGIN")) for (const command of entry.commands.filter((item) => policyCommands.has(item))) assert(commandSemantics.rules.some((rule) => rule.tableId === table.id && rule.command === command && rule.runtimeIdentities.includes(entry.identityId)), `${table.id} ${entry.identityId} ${command} lacks exact semantics`);
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
  assert.equal(workflow.semanticStatus, "mapped", `${workflow.id} command semantics are unresolved`);
  assert(workflow.commandRuleIds?.length, `${workflow.id} lacks command-rule references`);
  assert(workflow.requiredAssurance?.length, `${workflow.id} lacks assurance requirements`);
  assert(workflow.commandActorClasses?.length, `${workflow.id} lacks canonical actor classes`);
  assert(workflow.runtimeIdentities?.length, `${workflow.id} lacks runtime identities`);
  for (const actor of workflow.commandActorClasses) assert(actorClasses.has(actor), `${workflow.id} references unknown actor ${actor}`);
  for (const assurance of workflow.requiredAssurance) assert(assuranceLevels.has(assurance), `${workflow.id} references unknown assurance ${assurance}`);
  for (const identity of workflow.runtimeIdentities) assert(identityIds.has(identity), `${workflow.id} references unknown identity ${identity}`);
  for (const id of workflow.commandRuleIds) assert(commandRuleIds.has(id), `${workflow.id} references missing command rule ${id}`);
  for (const tableId of workflow.tablesTouched) assert(tableIds.has(tableId), `${workflow.id} references missing table ${tableId}`);
  for (const item of workflow.commandsPerTable) {
    assert(tableIds.has(item.tableId), `${workflow.id} references missing table ${item.tableId}`);
    for (const command of item.commands) assert(commands.has(command), `${workflow.id} has invalid command ${command}`);
  }
  for (const id of workflow.unresolvedDecisions) assert(decisionIds.has(id), `${workflow.id} references missing decision ${id}`);
  if (["worker", "scheduled"].includes(workflow.executionSurface)) assert(workflow.contextRequirements.includes("approved restricted system identity"), `${workflow.id} needs an explicit system identity design`);
}
for (const rule of commandSemantics.rules) {
  const table = tables.tables.find((item) => item.id === rule.tableId);
  assert(table?.forceRlsTarget, `${rule.id} references an unknown or non-FORCE table`);
  assert(policyCommands.has(rule.command), `${rule.id} uses an invalid or wildcard command`);
  assert(Array.isArray(rule.actorClasses) && Array.isArray(rule.runtimeIdentities), `${rule.id} lacks actor or identity classification`);
  assert(!rule.actorClasses.some((actor) => /^(?:all|any|\*)$/i.test(actor)), `${rule.id} uses wildcard actor access`);
  assert(!rule.runtimeIdentities.some((identity) => /^(?:all|any|\*)$/i.test(identity)), `${rule.id} uses wildcard identity access`);
  if (rule.authorizationBoundary !== "prohibited") {
    assert(rule.actorClasses.length && rule.runtimeIdentities.length, `${rule.id} allowed rule lacks actors or identities`);
    for (const actor of rule.actorClasses) assert(actorClasses.has(actor), `${rule.id} references unknown actor ${actor}`);
    for (const identity of rule.runtimeIdentities) assert(identityIds.has(identity), `${rule.id} references unknown identity ${identity}`);
  }
  assert(assuranceLevels.has(rule.minimumAssurance), `${rule.id} lacks a valid assurance level`);
  assert(rule.scopeRule?.trim() && rule.allowScenarios?.length && rule.denyScenarios?.length, `${rule.id} lacks scope or allow/deny cases`);
  assert(rule.status === "architecture-resolved", `${rule.id} is unresolved`);
  assert(rule.command === "DELETE" || rule.hardDeleteSemantics === "not-applicable", `${rule.id} has invalid hard-delete semantics`);
  if (["INSERT", "UPDATE"].includes(rule.command)) {
    assert(Array.isArray(rule.allowedColumns) && Array.isArray(rule.protectedColumns), `${rule.id} lacks column semantics`);
    for (const column of [...table.tenantKeyColumns, ...table.actorKeyColumns]) assert(rule.protectedColumns.includes(column), `${rule.id} makes ownership column ${column} generally mutable`);
    assert(rule.withCheckRule && rule.withCheckRule !== "not-applicable", `${rule.id} lacks WITH CHECK semantics`);
  }
  if (table.primaryCategory === "security-sensitive" && rule.command === "SELECT") for (const column of table.sensitiveColumns) assert(!rule.allowedColumns.includes(column), `${rule.id} broadly selects secret column ${column}`);
  assert(!(table.appendOnly && rule.command === "UPDATE" && rule.authorizationBoundary !== "prohibited"), `${rule.id} allows append-only UPDATE`);
  if (rule.command === "DELETE") assert(["prohibited", "soft-delete only", "actor self-delete", "tenant-admin delete", "retention delete", "cascade through approved parent lifecycle", "migration-only", "operator-approved", "break-glass only"].includes(rule.hardDeleteSemantics), `${rule.id} lacks explicit DELETE semantics`);
  if (rule.actorClasses.includes("platform-admin")) {
    assert.notEqual(rule.minimumAssurance, "none", `${rule.id} grants unconditional platform-admin access`);
    assert(rule.requiresAuditEvent, `${rule.id} platform-admin command lacks audit`);
    assert(!/USING\s*\(\s*true\s*\)/i.test(rule.scopeRule), `${rule.id} grants generic platform-admin access`);
  }
  if (rule.actorClasses.includes("licensee-admin") && ["INSERT", "UPDATE"].includes(rule.command) && ["User", "Invite"].includes(table.prismaModel)) assert(rule.protectedColumns.includes("role"), `${rule.id} lets licensee-admin assign platform roles`);
  if (rule.lifecycleColumns.length && rule.authorizationBoundary !== "prohibited") assert(rule.allowedLifecycleStates.length || rule.command === "SELECT", `${rule.id} omits lifecycle restrictions`);
  if (rule.requiresNamedFunction) assert(["named-function", "restricted-worker", "operator-approval"].includes(rule.authorizationBoundary), `${rule.id} degrades a named-function operation to an ordinary policy`);
  if (rule.requiresRestrictedWorkerBoundary) {
    assert.equal(rule.authorizationBoundary, "restricted-worker", `${rule.id} degrades a worker operation to an ordinary policy`);
    assert(rule.actorClasses.every((actor) => ["worker", "scheduled-job"].includes(actor)), `${rule.id} worker operation uses a human actor boundary`);
  }
  for (const workflowId of rule.supportingWorkflowIds) assert(workflowIds.has(workflowId), `${rule.id} references unknown workflow ${workflowId}`);
}
for (const workflow of workflows.workflows) for (const item of workflow.commandsPerTable) {
  const table = tables.tables.find((candidate) => candidate.id === item.tableId);
  if (!table.forceRlsTarget) continue;
  for (const command of item.commands) assert(workflow.commandRuleIds.some((id) => {
    const rule = commandSemantics.rules.find((candidate) => candidate.id === id);
    return rule?.tableId === item.tableId && rule.command === command;
  }), `${workflow.id} ${item.tableId} ${command} lacks an exact command rule`);
}
const mappedAccessIds = new Set(workflows.workflows.flatMap((workflow) => workflow.supportingEvidence.map((evidence) => evidence.accessId)));
for (const access of scanProductionAccess().accesses) assert(mappedAccessIds.has(access.id), `production access ${access.id} is not mapped to a workflow`);
validateRuntimeIdentities(identities, decisions);
assert(sharedApplyIsBlocked(), "existing shared-table apply must remain blocked before BEGIN");
console.log(JSON.stringify({ valid: true, tables: tables.tables.length, workflows: workflows.workflows.length, productionAccessSites: mappedAccessIds.size }));

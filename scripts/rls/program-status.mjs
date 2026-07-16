#!/usr/bin/env node
import fs from "node:fs";
import { manifests, policyDependencyGraphPath } from "./lib/program-inventory.mjs";

const { tables, workflows, decisions, commandSemantics, preAuthFunctions, workerBoundaries, identities, objectOwnershipChain, operatorBoundaries } = manifests();
const graph = JSON.parse(fs.readFileSync(policyDependencyGraphPath, "utf8"));
const bySurface = Object.fromEntries([...new Set(workflows.workflows.map((workflow) => workflow.executionSurface))].sort().map((surface) => [surface, workflows.workflows.filter((workflow) => workflow.executionSurface === surface).length]));
const byCategory = Object.fromEntries([...new Set(tables.tables.map((table) => table.primaryCategory))].sort().map((category) => [category, tables.tables.filter((table) => table.primaryCategory === category).length]));
const byReviewGroup = Object.fromEntries("ABCDEFG".split("").map((group) => [group, tables.tables.filter((table) => table.reviewGroup === group).length]));
const confidence = Object.fromEntries(["high", "medium", "low"].map((level) => [level, tables.tables.filter((table) => table.ownershipConfidence === level).length]));
const compatible = workflows.workflows.filter((workflow) => workflow.currentCompatibilityStatus === "compatible").length;
const unresolvedTables = tables.tables.filter((table) => table.classificationStatus !== "resolved" || table.unresolvedDecisionIds.length).length;
const completed = tables.tables.filter((table) => table.implementationStatus === "complete" && table.verificationStatus === "certified").length + workflows.workflows.filter((workflow) => workflow.implementationStatus === "complete").length;
const denominator = tables.tables.length + workflows.workflows.length;
const ruleCountBy = (field, values) => Object.fromEntries(values.map((value) => [value, commandSemantics.rules.filter((rule) => Array.isArray(rule[field]) ? rule[field].includes(value) : rule[field] === value).length]));
const selectedPreAuth = workflows.workflows.filter((workflow) => workflow.preAuthBoundary);
const preAuthIdentity = identities.identities.find((identity) => identity.id === "identity-pre-auth-app");
console.log(JSON.stringify({
  tablesTotal: tables.tables.length,
  tablesClassified: tables.tables.filter((table) => table.category).length,
  tablesUnresolved: unresolvedTables,
  tablesByCategory: byCategory,
  forceRlsTargets: tables.tables.filter((table) => table.forceRlsTarget).length,
  intentionallyNonRlsTables: tables.tables.filter((table) => table.primaryCategory === "intentionally-non-rls").map((table) => table.id),
  dependencyEdges: graph.edges.length,
  recursionRisks: graph.edges.filter((edge) => edge.recursionRisk !== "none").length,
  tablesByReviewGroup: byReviewGroup,
  ownershipConfidenceTotals: confidence,
  commandRulesTotal: commandSemantics.rules.length,
  commandRulesByCommand: ruleCountBy("command", ["SELECT", "INSERT", "UPDATE", "DELETE"]),
  workflowsMapped: workflows.workflows.filter((workflow) => workflow.semanticStatus === "mapped").length,
  unresolvedWorkflowSemantics: workflows.workflows.filter((workflow) => workflow.semanticStatus !== "mapped").length,
  commandRulesByActor: ruleCountBy("actorClasses", commandSemantics.actorClasses),
  commandRulesByAssurance: ruleCountBy("minimumAssurance", commandSemantics.assuranceLevels),
  namedFunctionsRequired: commandSemantics.rules.filter((rule) => rule.requiresNamedFunction).length,
  workerBoundariesRequired: commandSemantics.rules.filter((rule) => rule.requiresRestrictedWorkerBoundary).length,
  approvalGatedCommands: commandSemantics.rules.filter((rule) => rule.requiresApproval).length,
  prohibitedHardDeletes: commandSemantics.rules.filter((rule) => rule.command === "DELETE" && rule.hardDeleteSemantics === "prohibited").length,
  hardDeleteClassifications: ruleCountBy("hardDeleteSemantics", [...new Set(commandSemantics.rules.filter((rule) => rule.command === "DELETE").map((rule) => rule.hardDeleteSemantics))].sort()),
  preAuthWorkflowsTotal: selectedPreAuth.length,
  exactPreAuthFunctionsTotal: preAuthFunctions.functions.length,
  preAuthWorkflowsMovedBehindContext: selectedPreAuth.filter((workflow) => workflow.preAuthBoundary.boundaryMode === "ordinary-authenticated-context").length,
  preAuthOperatorOnlyWorkflows: selectedPreAuth.filter((workflow) => workflow.preAuthBoundary.boundaryMode === "operator-only").length,
  preAuthRetiredWorkflows: selectedPreAuth.filter((workflow) => workflow.preAuthBoundary.boundaryMode === "retired").length,
  preAuthFunctionsByTable: Object.fromEntries([...new Set(preAuthFunctions.functions.flatMap((fn) => [...fn.tablesRead, ...fn.tablesWritten]))].sort().map((tableId) => [tableId, preAuthFunctions.functions.filter((fn) => fn.tablesRead.includes(tableId) || fn.tablesWritten.includes(tableId)).length])),
  preAuthFunctionsByVolatility: Object.fromEntries(["STABLE", "VOLATILE"].map((value) => [value, preAuthFunctions.functions.filter((fn) => fn.volatility === value).length])),
  oneTimeTokenFunctions: preAuthFunctions.functions.filter((fn) => fn.oneTimeToken).length,
  publicExecuteViolations: preAuthFunctions.functions.filter((fn) => !fn.publicExecutionDenied).length,
  directTablePrivilegeViolations: preAuthIdentity.tablePrivilegeMode === "none" && preAuthIdentity.directTablePrivileges.length === 0 ? 0 : 1,
  workerWorkflowsTotal: workerBoundaries.boundaries.filter((boundary) => boundary.runtimeIdentity === "identity-worker").length,
  scheduledWorkflowsTotal: workerBoundaries.boundaries.filter((boundary) => boundary.runtimeIdentity === "identity-scheduled-job").length,
  workerBoundariesTotal: workerBoundaries.boundaries.length,
  actorDerivedJobs: workerBoundaries.boundaries.filter((boundary) => boundary.workerClass === "actor-derived-job").length,
  tenantScopedJobs: workerBoundaries.boundaries.filter((boundary) => boundary.workerClass === "tenant-scoped-system-job").length,
  platformScopedJobs: workerBoundaries.boundaries.filter((boundary) => boundary.workerClass === "platform-scoped-system-job").length,
  operatorTriggeredJobs: workerBoundaries.boundaries.filter((boundary) => boundary.workerClass === "operator-triggered-job").length,
  namedWorkerFunctionsRequired: workerBoundaries.boundaries.filter((boundary) => boundary.namedFunctionRequirement.required).length,
  idempotentMutationWorkflows: workerBoundaries.boundaries.filter((boundary) => boundary.tablesWritten.length && boundary.idempotencyStrategy?.keySource).length,
  replayProtectedWorkflows: workerBoundaries.boundaries.filter((boundary) => boundary.replayProtection && boundary.conflictingReplayPayloadDenied).length,
  concurrencyProtectedWorkflows: workerBoundaries.boundaries.filter((boundary) => boundary.concurrencyControl?.databaseEnforced).length,
  scopeVerificationViolations: workerBoundaries.boundaries.filter((boundary) => !/durable|table-/i.test(boundary.durableJobTableOrPayloadSource) || /trust (?:the )?json/i.test(boundary.scopeVerificationMethod)).length,
  unresolvedWorkerBoundaries: workflows.workflows.filter((workflow) => ["worker", "scheduled"].includes(workflow.executionSurface) && workflow.authorizationBoundaryType === "restricted-worker" && !workflow.workerBoundaryId).length,
  protectedObjectClasses: objectOwnershipChain.objectClasses.length,
  expectedOwners: Object.fromEntries(objectOwnershipChain.objectClasses.map((rule) => [rule.objectClass, rule.expectedOwner])),
  tableOwnerObjects: objectOwnershipChain.objectClasses.filter((rule) => ["identity-table-owner", "owning-table-owner"].includes(rule.expectedOwner) || /table owner/.test(rule.expectedOwner)).length,
  authOwnerObjects: objectOwnershipChain.approvedFunctionOwnerBoundaries.preAuth.length + 1,
  migrationOwnedResidueAllowed: objectOwnershipChain.migrationCompletionGate.ownershipResidueAllowed,
  runtimeOwnedObjectsAllowed: objectOwnershipChain.migrationCompletionGate.runtimeOwnedObjectsAllowed,
  temporaryMemberships: objectOwnershipChain.recommendedTransferModel.executorTemporaryMembership.roles.length,
  schemaCreateViolations: objectOwnershipChain.schemaOwnershipRules.filter((rule) => rule.publicCreate || rule.runtimeCreate).length,
  defaultPrivilegeViolations: objectOwnershipChain.defaultPrivilegeRules.publicGrants.length + objectOwnershipChain.defaultPrivilegeRules.runtimeGrants.length,
  unresolvedOwnershipChainItems: objectOwnershipChain.status === "architecture-resolved" && decisions.decisions.find((decision) => decision.id === objectOwnershipChain.decisionId)?.status === "resolved" ? 0 : 1,
  operatorBoundariesTotal: operatorBoundaries.boundaries.length,
  stagingOnlyBoundaries: operatorBoundaries.boundaries.filter((boundary) => boundary.environmentAvailability.length === 1 && boundary.environmentAvailability[0] === "staging").length,
  productionBoundaries: operatorBoundaries.boundaries.filter((boundary) => boundary.environmentAvailability.includes("production") && boundary.actionClass !== "prohibited").length,
  breakGlassOnlyBoundaries: operatorBoundaries.boundaries.filter((boundary) => boundary.actorClass === "break-glass" && boundary.actionClass !== "prohibited").length,
  approvalGatedOperatorBoundaries: operatorBoundaries.boundaries.filter((boundary) => boundary.approvalRequirement.required).length,
  ticketBoundOperatorBoundaries: operatorBoundaries.boundaries.filter((boundary) => boundary.ticketRequirement).length,
  purposeBoundOperatorBoundaries: operatorBoundaries.boundaries.filter((boundary) => boundary.purposeRequirement).length,
  expiringOperatorBoundaries: operatorBoundaries.boundaries.filter((boundary) => boundary.expiryBehavior && boundary.automaticRevocation).length,
  namedOperatorProceduresRequired: operatorBoundaries.boundaries.filter((boundary) => boundary.exactCommandOrNamedProcedure.kind === "named-procedure").length,
  prohibitedOperatorActions: operatorBoundaries.prohibitedActions.length,
  arbitrarySqlViolations: operatorBoundaries.boundaries.filter((boundary) => boundary.arbitrarySqlAllowed || boundary.exactCommandOrNamedProcedure.arbitraryArgumentsAllowed).length,
  operatorOwnershipBypassViolations: operatorBoundaries.boundaries.filter((boundary) => boundary.objectOwnershipAllowed || boundary.ownerRoleMembershipAllowed || boundary.setRoleAllowed || boundary.bypassRlsAllowed || boundary.superuserAllowed).length,
  unresolvedOperatorBoundaries: workflows.workflows.filter((workflow) => workflow.commandActorClasses?.some((actor) => ["operator-admin", "break-glass"].includes(actor)) && !workflow.operatorBoundaryId).length,
  workflowsTotal: workflows.workflows.length,
  workflowsByExecutionSurface: bySurface,
  workflowsCompatible: compatible,
  workflowsBlocked: workflows.workflows.length - compatible,
  directPrismaCallersRemaining: workflows.workflows.reduce((total, workflow) => total + workflow.currentDirectPrismaUsage.length, 0),
  preAuthFunctionsRequired: workflows.workflows.filter((workflow) => workflow.authorizationBoundaryType === "pre-auth-security-function" && workflow.currentCompatibilityStatus !== "compatible").length,
  workerRedesignsRequired: workflows.workflows.filter((workflow) => ["worker", "scheduled"].includes(workflow.executionSurface) && workflow.currentCompatibilityStatus !== "compatible").length,
  p2TestsRequired: workflows.workflows.filter((workflow) => workflow.requiredDisposablePostgresqlTests.length && workflow.implementationStatus !== "complete").length,
  unresolvedBlockingDecisions: decisions.decisions.filter((decision) => decision.blockingStatus === "blocking" && decision.status !== "resolved").length,
  percentageComplete: denominator ? Number((completed * 100 / denominator).toFixed(2)) : 0,
}));

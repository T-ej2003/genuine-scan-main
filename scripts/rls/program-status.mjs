#!/usr/bin/env node
import fs from "node:fs";
import { manifests, policyDependencyGraphPath } from "./lib/program-inventory.mjs";

const { tables, workflows, decisions, commandSemantics } = manifests();
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

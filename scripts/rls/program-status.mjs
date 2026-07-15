#!/usr/bin/env node
import { manifests } from "./lib/program-inventory.mjs";

const { tables, workflows, decisions } = manifests();
const bySurface = Object.fromEntries([...new Set(workflows.workflows.map((workflow) => workflow.executionSurface))].sort().map((surface) => [surface, workflows.workflows.filter((workflow) => workflow.executionSurface === surface).length]));
const compatible = workflows.workflows.filter((workflow) => workflow.currentCompatibilityStatus === "compatible").length;
const unresolvedTables = tables.tables.filter((table) => table.unresolvedDecisions.length).length;
const completed = tables.tables.filter((table) => table.implementationStatus === "complete" && table.verificationStatus === "certified").length + workflows.workflows.filter((workflow) => workflow.implementationStatus === "complete").length;
const denominator = tables.tables.length + workflows.workflows.length;
console.log(JSON.stringify({
  tablesTotal: tables.tables.length,
  tablesClassified: tables.tables.filter((table) => table.category).length,
  tablesUnresolved: unresolvedTables,
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

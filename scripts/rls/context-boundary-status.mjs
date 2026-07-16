#!/usr/bin/env node
import fs from "node:fs";
import { contextBoundaryFamiliesPath } from "./context-boundary-plan.mjs";
import { manifests } from "./lib/program-inventory.mjs";

const plan = JSON.parse(fs.readFileSync(contextBoundaryFamiliesPath, "utf8"));
const { workflows } = manifests();
const countWorkflows = (predicate) => plan.families.filter(predicate).reduce((total, family) => total + family.workflowIds.length, 0);
const currentImplemented = workflows.workflows.filter((workflow) => workflow.contextBoundaryStatus === "implemented").map((workflow) => workflow.id);
const baseline = new Set(plan.baselineImplementedWorkflowIds);
const by = (field, values) => Object.fromEntries(values.map((value) => [value, countWorkflows((family) => family[field] === value)]));

console.log(JSON.stringify({
  totalWorkflows: plan.workflowCount,
  alreadyImplementedWorkflows: currentImplemented.filter((id) => baseline.has(id)).length,
  newlyImplementedWorkflows: currentImplemented.filter((id) => !baseline.has(id)).length,
  contractOnlyWorkflows: countWorkflows((family) => family.automationEligibility === "contract-only"),
  blockedWorkflows: countWorkflows((family) => family.automationEligibility === "blocked"),
  familiesTotal: plan.familyCount,
  familiesCompleted: plan.families.filter((family) => family.implementationStatus === "implemented").length,
  familiesBlocked: plan.families.filter((family) => family.implementationStatus === "blocked").length,
  workflowsByFamily: Object.fromEntries(plan.families.map((family) => [family.id, family.workflowIds.length])),
  workflowsByRiskLevel: by("riskLevel", ["low", "medium", "high", "critical"]),
  workflowsStillRequiringCodeChanges: countWorkflows((family) => family.automationEligibility !== "implemented"),
  workflowsPendingPostgresqlCertification: currentImplemented.length,
}));

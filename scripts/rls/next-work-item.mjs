#!/usr/bin/env node
import { manifests } from "./lib/program-inventory.mjs";

const { decisions, workflows, tables } = manifests();
const decisionSections = {
  "decision-policy-command-semantics": ["Canonical transaction context", "Policy generation strategy"],
  "decision-pre-auth-boundary": ["Pre-authentication function rules"],
  "decision-worker-identity-model": ["Worker authorization rules"],
  "decision-object-ownership-chain": ["Physical ownership and row-ownership taxonomy"],
  "decision-operator-administration": ["Administrator ceilings"],
};
const priority = [
  ["architecture-decision", () => decisions.decisions.find((decision) => decision.blockingStatus === "blocking" && decision.status !== "resolved")],
  ["runtime-identity", () => decisions.decisions.find((decision) => /identity|role/i.test(`${decision.id} ${decision.question}`) && decision.status !== "resolved")],
  ["context-boundary", () => workflows.workflows.find((workflow) => workflow.authorizationBoundaryType === "authenticated-context" && workflow.implementationStatus !== "complete")],
  ["pre-auth-boundary", () => workflows.workflows.find((workflow) => workflow.authorizationBoundaryType === "pre-auth-security-function" && workflow.implementationStatus !== "complete")],
  ["authenticated-workflow", () => workflows.workflows.find((workflow) => workflow.authenticationStage === "authenticated" && workflow.implementationStatus !== "complete")],
  ["worker-system-workflow", () => workflows.workflows.find((workflow) => ["worker", "scheduled", "startup", "cli"].includes(workflow.executionSurface) && workflow.implementationStatus !== "complete")],
  ["policy-generation", () => tables.tables.find((table) => table.policyStatus !== "complete")],
  ["disposable-certification", () => tables.tables.find((table) => table.verificationStatus !== "certified")],
];
const manifestSelectors = {
  "decision-pre-auth-boundary": { commandRuleActor: "pre-auth-runtime", workflowBoundary: "pre-auth-security-function", preAuthFunctionIds: "all" },
  "decision-worker-identity-model": { commandRuleBoundary: "restricted-worker", executionSurfaces: ["worker", "scheduled"], workerBoundaryIds: "all" },
  "decision-object-ownership-chain": { physicalOwnerRole: "identity-table-owner" },
  "decision-operator-administration": { commandRuleActors: ["operator-admin", "break-glass"] },
};
for (const [phase, find] of priority) {
  const item = find();
  if (!item) continue;
  const isDecision = "question" in item;
  console.log(JSON.stringify({ phase, id: item.id, objective: isDecision ? item.question : `Complete ${item.name || item.prismaModel}`, canonicalFiles: isDecision ? ["documents/security/rls-program/decisions.json", "documents/security/rls-program/ARCHITECTURE.md", "documents/security/rls-program/command-semantics.json", "documents/security/rls-program/workflows.json"] : item.canonicalSourceFiles || ["documents/security/rls-program/tables.json"], manifestSelector: isDecision ? manifestSelectors[item.id] : undefined, architectureSections: isDecision ? decisionSections[item.id] || ["Completion definition"] : ["Completion definition"], requiredTests: isDecision ? ["scripts/tests/full-database-rls-program.test.mjs"] : item.requiredUnitTests || ["scripts/tests/full-database-rls-program.test.mjs"] }));
  break;
}

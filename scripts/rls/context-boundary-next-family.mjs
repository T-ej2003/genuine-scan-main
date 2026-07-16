#!/usr/bin/env node
import fs from "node:fs";
import { contextBoundaryFamiliesPath } from "./context-boundary-plan.mjs";

const plan = JSON.parse(fs.readFileSync(contextBoundaryFamiliesPath, "utf8"));
const candidates = plan.families.filter((family) => family.implementationStatus === "planned");
const family = candidates[0] || plan.families.find((item) => item.implementationStatus === "blocked");
if (family) console.log(JSON.stringify({
  phase: family.implementationStatus === "planned" ? "implement-family" : "resolve-family-blocker",
  familyId: family.id,
  category: family.category,
  workflows: family.workflowIds.length,
  canonicalFiles: [...family.controllerFiles, ...family.serviceFiles, ...family.repositoryFiles],
  blocker: family.blockers[0] ? { id: family.blockers[0].id, remediation: family.blockers[0].remediation } : undefined,
  requiredTests: [family.testStrategy],
}));

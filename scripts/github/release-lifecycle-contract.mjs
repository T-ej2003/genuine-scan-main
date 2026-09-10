#!/usr/bin/env node

import { pathToFileURL } from "node:url";

const isMain = import.meta.url === pathToFileURL(process.argv[1] || "").href;

const contracts = Object.freeze({
  strict: Object.freeze({
    requiredWorkflows: Object.freeze(["quality-gate.yml", "secret-scan.yml", "deployment-audit.yml", "auth-security-tests.yml", "release-candidate-gate.yml"]),
    lifecycleInputWorkflows: Object.freeze([]),
  }),
  "authenticated-initial-overlap": Object.freeze({
    // release-candidate-gate.yml runs completed-rotation validation on manual/tag
    // dispatches. Quality and deployment audit provide its pre-rotation equivalent.
    requiredWorkflows: Object.freeze(["quality-gate.yml", "secret-scan.yml", "deployment-audit.yml", "auth-security-tests.yml"]),
    lifecycleInputWorkflows: Object.freeze(["quality-gate.yml", "deployment-audit.yml"]),
  }),
});

export function releaseLifecycleContract(lifecycle) {
  const contract = contracts[lifecycle];
  if (!contract) throw new Error(`Unsupported release lifecycle: ${lifecycle || "missing"}`);
  return contract;
}

export function requiredWorkflowFiles(lifecycle) {
  return [...releaseLifecycleContract(lifecycle).requiredWorkflows];
}

export function usesLifecycleInputs(lifecycle, workflowFile) {
  return releaseLifecycleContract(lifecycle).lifecycleInputWorkflows.includes(workflowFile);
}

if (isMain) {
  try {
    const [flag, lifecycle, format = "csv"] = process.argv.slice(2);
    if (flag !== "--lifecycle" || !lifecycle || !["csv", "lines"].includes(format)) throw new Error("Usage: release-lifecycle-contract.mjs --lifecycle <strict|authenticated-initial-overlap> [csv|lines]");
    const workflows = requiredWorkflowFiles(lifecycle);
    process.stdout.write(`${format === "lines" ? workflows.join("\n") : workflows.join(",")}\n`);
  } catch (error) {
    process.stderr.write(`${error.message || String(error)}\n`);
    process.exit(1);
  }
}

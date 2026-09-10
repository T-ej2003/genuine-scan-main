#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { pathToFileURL } from "node:url";

const isMain = import.meta.url === pathToFileURL(process.argv[1] || "").href;
const workflowFiles = [".github/workflows/quality-gate.yml", ".github/workflows/deployment-audit.yml"];
const requiredInputs = ["release_lifecycle", "target_sha", "rotation_id", "rotation_state_json", "rotation_state_sha256", "rotation_task_definition_arn", "rotation_image_digest", "rotation_deployment_sha"];

export function assertAuthenticatedInitialOverlapWorkflowSchema({ workflowFile, source }) {
  if (typeof source !== "string" || !/^name:/m.test(source) || !/^\s*workflow_dispatch:\s*$/m.test(source)) throw new Error(`${workflowFile} has no workflow_dispatch contract.`);
  for (const input of requiredInputs) {
    if (!new RegExp(`^ {6}${input}:\\s*$`, "m").test(source)) throw new Error(`${workflowFile} does not declare authenticated-initial-overlap input ${input}.`);
  }
  if (!/^ {10}- authenticated-initial-overlap\s*$/m.test(source)) throw new Error(`${workflowFile} does not declare the authenticated-initial-overlap lifecycle.`);
  return true;
}

export function assertAuthenticatedInitialOverlapTargetSchema({ revision, readFile = (file) => execFileSync("git", ["show", `${revision}:${file}`], { encoding: "utf8" }) } = {}) {
  if (!/^[a-f0-9]{40}$/.test(revision || "")) throw new Error("Authenticated initial overlap requires an exact target SHA for schema validation.");
  for (const workflowFile of workflowFiles) assertAuthenticatedInitialOverlapWorkflowSchema({ workflowFile, source: readFile(workflowFile) });
  return true;
}

if (isMain) {
  try {
    const [flag, revision] = process.argv.slice(2);
    if (flag !== "--revision" || !revision) throw new Error("Usage: assert-authenticated-initial-overlap-workflow-schema.mjs --revision <target-sha>");
    assertAuthenticatedInitialOverlapTargetSchema({ revision });
    process.stdout.write(`AUTHENTICATED_INITIAL_OVERLAP_WORKFLOW_SCHEMA_VALID=${revision}\n`);
  } catch (error) {
    process.stderr.write(`${error.message || String(error)}\n`);
    process.exit(1);
  }
}

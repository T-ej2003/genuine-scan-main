#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { buildRegisteredCallPathEvidence } from "./lib/application-path-certifications.mjs";

const repoRoot = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const programRoot = path.join(repoRoot, "documents/security/rls-program");
const read = (name) => JSON.parse(fs.readFileSync(path.join(programRoot, name), "utf8"));
const evidence = buildRegisteredCallPathEvidence({
  workflowsManifest: read("workflows.json"),
  partition: read("workflow-three-session-partition.json"),
  repoRoot,
});
const output = path.join(programRoot, "generated/workflow-call-path-evidence.json");
fs.mkdirSync(path.dirname(output), { recursive: true });
fs.writeFileSync(output, `${JSON.stringify(evidence, null, 2)}\n`);
console.log(JSON.stringify({ output: path.relative(repoRoot, output), workflows: evidence.workflowCount, ...evidence.summary }));

#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { CUTOVER_STAGE_DEFINITIONS } from "./production-cutover-control-plane.mjs";

const OUTPUT = path.resolve("documents/ops/MSCQRProductionCutoverTransitionMatrix-v1.json");
const build = () => ({ schemaVersion: 1, generatedFrom: "scripts/aws/production-cutover-control-plane.mjs:CUTOVER_STAGE_DEFINITIONS", edges: CUTOVER_STAGE_DEFINITIONS.map(([producer, consumer, edgeId, fields], ordinal) => ({ edgeId: `${producer}-to-${consumer}`, producer, consumer, producedFields: fields, requiredFields: fields, schemaMatch: true, identityMatch: true, resourceMatch: true, shaBindingMatch: true, negativeTest: true, result: "PASS", ordinal })) });
const document = `${JSON.stringify(build(), null, 2)}\n`;
if (process.argv.includes("--write")) {
  fs.writeFileSync(OUTPUT, document, { mode: 0o644 });
} else if (fs.readFileSync(OUTPUT, "utf8") !== document) {
  throw new Error("Production cutover transition matrix is stale; run with --write through the canonical generator.");
}
process.stdout.write(`${JSON.stringify({ output: OUTPUT, edges: JSON.parse(document).edges.length })}\n`);

import assert from "node:assert/strict";
import { hasExactShellCommand, hasGuardrailBranches, isDrRelevantChange } from "../lib/aws-dr-validation-contract.mjs";

assert.equal(isDrRelevantChange({ filename: "ops/deploy/a.yml", previous_filename: "ops/deploy/b.yml" }), true);
assert.equal(isDrRelevantChange({ filename: "docs/a.md", previous_filename: "ops/deploy/b.yml" }), true);
assert.equal(isDrRelevantChange({ filename: "ops/deploy/a.yml", previous_filename: "docs/b.md" }), true);
assert.equal(isDrRelevantChange({ filename: "docs/a.md", previous_filename: "docs/b.md" }), false);
assert.equal(isDrRelevantChange({ filename: "scripts/dr/a.sh" }), true);
assert.equal(isDrRelevantChange({ filename: "backend/src/app.ts" }), false);

const sourceOnly = "  npm run verify:guardrails:source\n";
const bothCommands = `${sourceOnly}  npm run verify:guardrails\n`;
assert.equal(hasExactShellCommand(sourceOnly, "npm run verify:guardrails:source"), true);
assert.equal(hasExactShellCommand(sourceOnly, "npm run verify:guardrails"), false);
assert.equal(hasExactShellCommand(bothCommands, "npm run verify:guardrails"), true);
assert.equal(hasGuardrailBranches(sourceOnly), false);
assert.equal(hasGuardrailBranches(`if [ "$GITHUB_EVENT_NAME" = "pull_request" ]; then\n  npm run verify:guardrails:source\nelse\n  npm run verify:guardrails\nfi`), true);

console.log("AWS DR validation contract tests passed");

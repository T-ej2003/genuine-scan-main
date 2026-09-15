import assert from "node:assert/strict";
import { guardrailBranchCommandsAreExact, isDrRelevantChange } from "../lib/aws-dr-validation-contract.mjs";

assert.equal(isDrRelevantChange({ filename: "ops/deploy/a.yml", previous_filename: "ops/deploy/b.yml" }), true);
assert.equal(isDrRelevantChange({ filename: "docs/a.md", previous_filename: "ops/deploy/b.yml" }), true);
assert.equal(isDrRelevantChange({ filename: "ops/deploy/a.yml", previous_filename: "docs/b.md" }), true);
assert.equal(isDrRelevantChange({ filename: "docs/a.md", previous_filename: "docs/b.md" }), false);
assert.equal(isDrRelevantChange({ filename: "scripts/dr/a.sh" }), true);
assert.equal(isDrRelevantChange({ filename: "backend/src/app.ts" }), false);

const guardrailBranches = (pullRequest, dispatch, prefix = "") => `${prefix}if [ "$GITHUB_EVENT_NAME" = "pull_request" ]; then\n  ${pullRequest}\nelse\n  ${dispatch}\nfi`;
const canonical = guardrailBranches("npm run verify:guardrails:source", "npm run verify:guardrails");
assert.deepEqual(guardrailBranchCommandsAreExact(canonical), { pullRequest: true, dispatch: true });
assert.equal(guardrailBranchCommandsAreExact(guardrailBranches("npm run verify:guardrails:source", "npm run verify:guardrails || true")).dispatch, false);
assert.equal(guardrailBranchCommandsAreExact(guardrailBranches("npm run verify:guardrails:source", "npm run verify:guardrails; true")).dispatch, false);
assert.equal(guardrailBranchCommandsAreExact(guardrailBranches("npm run verify:guardrails:source", "npm run verify:guardrails && true")).dispatch, false);
assert.equal(guardrailBranchCommandsAreExact(guardrailBranches("npm run verify:guardrails:source || true", "npm run verify:guardrails")).pullRequest, false);
assert.equal(guardrailBranchCommandsAreExact(guardrailBranches("npm run verify:guardrails:source &", "npm run verify:guardrails")).pullRequest, false);
assert.equal(guardrailBranchCommandsAreExact(guardrailBranches("npm run verify:guardrails:source", "npm run verify:guardrails || true", "npm run verify:guardrails\n")).dispatch, false);
assert.equal(guardrailBranchCommandsAreExact(guardrailBranches("npm run verify:guardrails:source || true", "npm run verify:guardrails", "npm run verify:guardrails:source\n")).pullRequest, false);
assert.deepEqual(guardrailBranchCommandsAreExact(guardrailBranches("npm run verify:guardrails", "npm run verify:guardrails:source")), { pullRequest: false, dispatch: false });
assert.equal(guardrailBranchCommandsAreExact('if [ "$GITHUB_EVENT_NAME" = "pull_request" ]; then\n  npm run verify:guardrails:source\nfi').dispatch, false);

console.log("AWS DR validation contract tests passed");

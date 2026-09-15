import assert from "node:assert/strict";
import { extractGuardrailRunBlock, guardrailRunBlockIsCanonical, isDrRelevantChange } from "../lib/aws-dr-validation-contract.mjs";

assert.equal(isDrRelevantChange({ filename: "ops/deploy/a.yml", previous_filename: "ops/deploy/b.yml" }), true);
assert.equal(isDrRelevantChange({ filename: "docs/a.md", previous_filename: "ops/deploy/b.yml" }), true);
assert.equal(isDrRelevantChange({ filename: "ops/deploy/a.yml", previous_filename: "docs/b.md" }), true);
assert.equal(isDrRelevantChange({ filename: "docs/a.md", previous_filename: "docs/b.md" }), false);
assert.equal(isDrRelevantChange({ filename: "scripts/dr/a.sh" }), true);
assert.equal(isDrRelevantChange({ filename: "backend/src/app.ts" }), false);

const canonical = `if [ "$GITHUB_EVENT_NAME" = "pull_request" ]; then
npm run verify:guardrails:source
else
npm run verify:guardrails
fi`;
const withRunBlock = (run, extra = "") => `jobs:
  validate:
    steps:
      - name: Validate DR guardrails
        run: |
${run.split("\n").map((line) => `          ${line}`).join("\n")}
${extra}`;
const isCanonical = (run) => guardrailRunBlockIsCanonical(run);

assert.equal(isCanonical(canonical), true);
assert.equal(extractGuardrailRunBlock(withRunBlock(canonical))?.trimEnd(), canonical);
assert.equal(isCanonical(`set +e
${canonical}`), false);
assert.equal(isCanonical(`set +o errexit
${canonical}`), false);
assert.equal(isCanonical(`echo before
${canonical}`), false);
assert.equal(isCanonical(`false
${canonical}`), false);
assert.equal(isCanonical(`${canonical}
echo success`), false);
assert.equal(isCanonical(`${canonical}
true`), false);
assert.equal(isCanonical(`${canonical}
npm --version`), false);
assert.equal(isCanonical(`set +e
${canonical}
echo success`), false);
assert.equal(isCanonical(canonical.replace("npm run verify:guardrails:source", "set +e\nnpm run verify:guardrails:source")), false);
assert.equal(isCanonical(canonical.replace("npm run verify:guardrails:source", "npm run verify:guardrails:source\necho success")), false);
assert.equal(isCanonical(canonical.replace("npm run verify:guardrails\n", "npm run verify:guardrails || true\n")), false);
assert.equal(isCanonical(canonical.replace("npm run verify:guardrails\n", "npm run verify:guardrails || :\n")), false);
assert.equal(isCanonical(canonical.replace("npm run verify:guardrails\n", "npm run verify:guardrails; true\n")), false);
assert.equal(isCanonical(canonical.replace("npm run verify:guardrails\n", "npm run verify:guardrails &\n")), false);
assert.equal(isCanonical(canonical.replace("npm run verify:guardrails\n", "! npm run verify:guardrails\n")), false);
const invalidWorkflow = withRunBlock(canonical.replace("npm run verify:guardrails\n", "npm run verify:guardrails || true\n"), "      - name: Unrelated\n        run: npm run verify:guardrails");
assert.equal(guardrailRunBlockIsCanonical(extractGuardrailRunBlock(invalidWorkflow)), false);
assert.equal(isCanonical(`if [ "$GITHUB_EVENT_NAME" = "pull_request" ]; then
npm run verify:guardrails
else
npm run verify:guardrails:source
fi`), false);
assert.equal(isCanonical('if [ "$GITHUB_EVENT_NAME" = "pull_request" ]; then\n  npm run verify:guardrails:source\nfi'), false);
assert.equal(isCanonical(`${canonical}\n${canonical}`), false);

console.log("AWS DR validation contract tests passed");

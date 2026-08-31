import assert from "node:assert/strict";
import test from "node:test";
import { addedLinesFromUnifiedDiff, scanAddedDiff } from "../check-branch-secret-diff.mjs";

const accessKey = `AKIA${"0".repeat(16)}`;
const unified = (line) => ["diff --git a/scripts/example.mjs b/scripts/example.mjs", "--- a/scripts/example.mjs", "+++ b/scripts/example.mjs", "@@ -0,0 +1 @@", `+${line}`].join("\n");

test("branch secret diff scans every plus-prefixed added content line", () => {
  for (const prefix of ["+", "++", "+++", "++++"]) {
    const findings = scanAddedDiff(unified(`${prefix}${accessKey}`), "scripts/example.mjs");
    assert.equal(findings.length, 1, `expected ${prefix}-prefixed added content to be scanned`);
    assert.equal(findings[0].rule, "AWS access key literal");
  }
  assert.equal(scanAddedDiff(unified(` ++${accessKey}`), "scripts/example.mjs").length, 1);
  assert.equal(scanAddedDiff(unified(accessKey), "scripts/example.mjs").length, 1);
});

test("branch secret diff parses unified hunks rather than diff-looking source text", () => {
  const diff = [
    "diff --git a/scripts/example.mjs b/scripts/example.mjs",
    "--- a/scripts/example.mjs",
    "+++ b/scripts/example.mjs",
    "@@ -0,0 +4 @@",
    "+--- content",
    "++++ content",
    "+diff --git-like content",
    "+@@-like content",
    "diff --git a/next.mjs b/next.mjs",
    "--- a/next.mjs",
    "+++ b/next.mjs",
  ].join("\n");
  assert.deepEqual(addedLinesFromUnifiedDiff(diff), ["--- content", "+++ content", "diff --git-like content", "@@-like content"]);
  assert.deepEqual(addedLinesFromUnifiedDiff(["diff --git a/a b/a", "--- a/a", "+++ b/a", "Binary files a/a and b/a differ"].join("\n")), []);
});

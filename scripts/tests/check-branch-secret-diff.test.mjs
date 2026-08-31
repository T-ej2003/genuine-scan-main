import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { addedContentDiffArgs, addedLinesFromUnifiedDiff, scanAddedDiff } from "../check-branch-secret-diff.mjs";

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

test("branch secret diff forces Git text hunks for NUL-containing protected files", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-secret-diff-"));
  const git = (args) => execFileSync("git", ["-C", directory, ...args], { encoding: "utf8" });
  try {
    git(["init", "-q", "-b", "main"]); git(["config", "user.email", "test@example.invalid"]); git(["config", "user.name", "test"]);
    fs.mkdirSync(path.join(directory, "scripts"));
    for (const name of ["before", "after", "multiple"]) fs.writeFileSync(path.join(directory, "scripts", `${name}.mjs`), "safe\n");
    git(["add", "scripts"]); git(["commit", "-qm", "baseline"]);
    const cases = {
      added: Buffer.from(`\0${accessKey}`),
      before: Buffer.from(`\0${accessKey}`),
      after: Buffer.from(`${accessKey}\0`),
      multiple: Buffer.from(`\0safe\0${accessKey}\0`),
    };
    for (const [name, bytes] of Object.entries(cases)) fs.writeFileSync(path.join(directory, "scripts", `${name}.mjs`), bytes);
    git(["add", "scripts/added.mjs"]);
    for (const name of Object.keys(cases)) {
      const relativePath = `scripts/${name}.mjs`;
      const binaryDiff = git(["diff", "--unified=0", "HEAD", "--", relativePath]);
      const textDiff = git(["diff", "--text", "--unified=0", "HEAD", "--", relativePath]);
      assert.match(binaryDiff, /Binary files/);
      assert.match(textDiff, /@@/);
      assert.equal(scanAddedDiff(textDiff, relativePath).length, 1, `${name} NUL placement must not hide the added key`);
    }
    assert.ok(addedContentDiffArgs("base", "scripts/example.mjs").includes("--text"));
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";

import { assertAuthenticatedInitialOverlapTargetSchema, assertAuthenticatedInitialOverlapWorkflowSchema } from "../github/assert-authenticated-initial-overlap-workflow-schema.mjs";

const workflowFiles = [".github/workflows/quality-gate.yml", ".github/workflows/deployment-audit.yml"];

test("current lifecycle-aware target schema is accepted and the protected base is rejected", () => {
  assert.equal(assertAuthenticatedInitialOverlapTargetSchema({
    revision: "a".repeat(40),
    readFile: (file) => readFileSync(file, "utf8"),
  }), true);
  assert.throws(() => assertAuthenticatedInitialOverlapWorkflowSchema({ workflowFile: workflowFiles[0], source: "name: Quality\non:\n  workflow_dispatch:\n" }), /does not declare/);
});

test("the pre-repair protected base has no lifecycle dispatch schema", () => {
  const historical = "5115967011177ffa64152fa6be741fac43e40754";
  assert.throws(() => assertAuthenticatedInitialOverlapTargetSchema({
    revision: historical,
    readFile: (file) => execFileSync("git", ["show", `${historical}:${file}`], { encoding: "utf8" }),
  }), /does not declare/);
});

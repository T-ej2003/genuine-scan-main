import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";

const workflow = readFileSync(path.resolve(".github/workflows/authorize-production-green-stage-b-apply-attempt-reconciliation.yml"), "utf8");

test("reconciliation workflow has a protected, review-only authorization boundary", () => {
  assert.match(workflow, /^permissions:\n  actions: read\n  contents: read$/m);
  assert.doesNotMatch(workflow, /^  actions: (?:write|read-all)$/m);
  assert.match(workflow, /workflow_dispatch:/);
  assert.match(workflow, /environment: production/);
  assert.match(workflow, /--require-actual-approval/);
  assert.match(workflow, /stage-b-apply-attempt-reconciliation-authorization/);
  assert.match(workflow, /actions\/upload-artifact@v4/);
  assert.equal(/terraform\s+(plan|apply)|PutSecretValue|UpdateSecretVersionStage|DeleteObject|kms\s+sign/i.test(workflow), false);
  assert.match(workflow, /test "\$SOURCE_SHA" = "\$protected_main_sha"/);
  assert.match(workflow, /test "\$\(git rev-parse HEAD\)" = "\$SOURCE_SHA"/);
  assert.match(workflow, /git status --porcelain=v1 --untracked-files=all/);
});

test("workflow passes non-secret artifact files by digest and keeps inputs out of shell source", () => {
  assert.match(workflow, /reconciliation_artifact_base64:/);
  assert.match(workflow, /reconciliation_artifact_sha256:/);
  assert.match(workflow, /test "\$\(sha256sum "\$workdir\/reconciliation\.json"/);
  assert.match(workflow, /--reconciliation-artifact-sha256 "\$RECONCILIATION_ARTIFACT_SHA256"/);
  assert.equal([...workflow.matchAll(/^[ ]{8}run: \|\n((?:^[ ]{10}.*\n?)*)/gm)].some(([, body]) => body.includes("${{ inputs.")), false);
  assert.match(workflow, /--approved-by "\$APPROVED_BY"/);
  assert.match(workflow, /--approver-role "\$APPROVER_ROLE"/);
});

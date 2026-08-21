import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

const workflow = fs.readFileSync(".github/workflows/release-gate.yml", "utf8");

test("release gate exposes one bounded backend health recovery mode", () => {
  assert.match(workflow, /- backend-health-recovery/);
  assert.match(workflow, /backend-health-recovery\)[\s\S]*BACKEND_RECOVERY_CURRENT_TASK_DEFINITION_ARN[\s\S]*BACKEND_RECOVERY_IMAGE_AUTHORIZATION_SHA256[\s\S]*BACKEND_RECOVERY_APPROVAL_SHA256/);
  const recoveryCase = workflow.match(/backend-health-recovery\)([\s\S]*?)\n\s*;;/u)?.[1] || "";
  assert.doesNotMatch(recoveryCase, /check:rotation-evidence-freshness/);
  assert.match(workflow, /Execute governed legacy backend health recovery[\s\S]*recover-production-backend-health\.mjs[\s\S]*--execute/);
  assert.match(workflow, /if: \$\{\{ inputs\.release_mode == 'backend-health-recovery' \}\}[\s\S]*backend-health-recovery-evidence/);
  assert.match(workflow, /deploy-production-ecs:[\s\S]*environment: production/);
  assert.match(workflow, /Authenticate production environment approval boundary[\s\S]*production-github-environment-approval\.mjs[\s\S]*--environment production[\s\S]*--workflow-ref "\$GITHUB_WORKFLOW_REF"[\s\S]*--event-name "\$GITHUB_EVENT_NAME"[\s\S]*--workflow-run-id "\$GITHUB_RUN_ID"/);
  assert.doesNotMatch(workflow, /production-github-environment-approval\.mjs[^\n]*--github-token/);
  assert.match(workflow, /--environment-approval "\$\{\{ steps\.production-environment-approval\.outputs\.evidence_file \}\}"[\s\S]*--environment-approval-sha256 "\$\{\{ steps\.production-environment-approval\.outputs\.evidence_sha256 \}\}"/);
  assert.ok(workflow.indexOf("Authenticate production environment approval boundary") < workflow.indexOf("Configure AWS credentials via OIDC"));
});

test("backend recovery cannot enter rotation, frontend, worker, or normal release steps", () => {
  assert.doesNotMatch(workflow, /if: \$\{\{ inputs\.release_mode != 'normal' \}\}/);
  assert.match(workflow, /Deploy rotation transition backend ECS service\n\s*if: \$\{\{ inputs\.release_mode == 'rotation-overlap' \|\| inputs\.release_mode == 'rotation-cleanup' \}\}/);
  assert.match(workflow, /Deploy frontend ECS service\n\s*if: \$\{\{ inputs\.release_mode == 'normal'/);
  assert.match(workflow, /Deploy worker ECS service\n\s*if: \$\{\{ inputs\.release_mode == 'normal'/);
});

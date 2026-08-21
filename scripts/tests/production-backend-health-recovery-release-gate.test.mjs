import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import test from "node:test";
import yaml from "js-yaml";

const workflow = fs.readFileSync(".github/workflows/release-gate.yml", "utf8");
const parsedWorkflow = yaml.load(workflow);

test("release gate exposes one bounded backend health recovery mode", () => {
  assert.match(workflow, /- backend-health-recovery/);
  assert.match(workflow, /backend-health-recovery\)[\s\S]*BACKEND_RECOVERY_CURRENT_TASK_DEFINITION_ARN[\s\S]*BACKEND_RECOVERY_IMAGE_AUTHORIZATION_SHA256[\s\S]*BACKEND_RECOVERY_APPROVAL_SHA256/);
  const recoveryCase = workflow.match(/backend-health-recovery\)([\s\S]*?)\n\s*;;/u)?.[1] || "";
  assert.doesNotMatch(recoveryCase, /check:rotation-evidence-freshness/);
  assert.match(workflow, /Execute governed legacy backend health recovery[\s\S]*recover-production-backend-health\.mjs[\s\S]*--execute/);
  assert.match(workflow, /Upload backend health recovery evidence\n\s*if: \$\{\{ always\(\) && inputs\.release_mode == 'backend-health-recovery' \}\}[\s\S]*backend-health-recovery-evidence[\s\S]*if-no-files-found: ignore/);
  assert.match(workflow, /--health-url "\$\{\{ env\.PUBLIC_BASE_URL \}\}\/api\/health\/ready"/);
  assert.match(workflow, /deploy-production-ecs:[\s\S]*environment: production/);
  assert.match(workflow, /Authenticate production environment approval boundary[\s\S]*approval_dir="\$RUNNER_TEMP\/production-environment-approval"[\s\S]*! -d "\$approval_dir" \|\| -L "\$approval_dir"[\s\S]*install -d -m 700 -- "\$approval_dir"[\s\S]*stat -c '%a'[\s\S]*stat -c '%u'[\s\S]*production-github-environment-approval\.mjs[\s\S]*--environment production[\s\S]*--workflow-ref "\$GITHUB_WORKFLOW_REF"[\s\S]*--event-name "\$GITHUB_EVENT_NAME"[\s\S]*--workflow-run-id "\$GITHUB_RUN_ID"/);
  assert.doesNotMatch(workflow, /evidence_file="\$RUNNER_TEMP\/production-environment-approval\.json"/);
  assert.match(workflow, /Generate and verify checksum-bound production RLS package[\s\S]*approval_dir="\$\(dirname "\$\{\{ steps\.production-environment-approval\.outputs\.evidence_file \}\}"\)"[\s\S]*stat -c '%a'[\s\S]*production-rls-approval\.json/);
  assert.doesNotMatch(workflow, /approval_file="\$RUNNER_TEMP\/production-rls-approval\.json"/);
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

test("release gate heredocs parse and backend recovery lifecycle validation executes", () => {
  const heredocSteps = Object.values(parsedWorkflow.jobs).flatMap((job) => job.steps || []).filter((step) => step.run?.includes("<<"));
  for (const step of heredocSteps) {
    const parsed = spawnSync("bash", ["-n"], { input: step.run, encoding: "utf8" });
    assert.equal(parsed.status, 0, `${step.name}: ${parsed.stderr}`);
  }

  const lifecycle = parsedWorkflow.jobs["resolve-deploy-target"].steps.find((step) => step.name === "Validate production release lifecycle mode").run;
  const image = JSON.stringify({ valid: true });
  const approval = JSON.stringify({ approvedBy: "T-ej2003" });
  const env = {
    ...process.env,
    RELEASE_MODE: "backend-health-recovery",
    BACKEND_RECOVERY_CURRENT_TASK_DEFINITION_ARN: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:47",
    BACKEND_RECOVERY_IMAGE_DIGEST: `sha256:${"a".repeat(64)}`,
    BACKEND_RECOVERY_IMAGE_AUTHORIZATION_JSON: image,
    BACKEND_RECOVERY_IMAGE_AUTHORIZATION_SHA256: createHash("sha256").update(image).digest("hex"),
    BACKEND_RECOVERY_APPROVAL_JSON: approval,
    BACKEND_RECOVERY_APPROVAL_SHA256: createHash("sha256").update(approval).digest("hex"),
  };
  assert.equal(spawnSync("bash", ["-e"], { input: lifecycle, env }).status, 0);
  assert.notEqual(spawnSync("bash", ["-e"], { input: lifecycle, env: { ...env, BACKEND_RECOVERY_APPROVAL_SHA256: "0".repeat(64) } }).status, 0);
  assert.notEqual(spawnSync("bash", ["-e"], { input: lifecycle, env: { ...env, RELEASE_MODE: "unsupported" } }).status, 0);
});

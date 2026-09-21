import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import yaml from "js-yaml";

const read = (file) => fs.readFileSync(file, "utf8");
const legacyText = read(".github/workflows/deploy-ecs-release.yml");
const legacy = yaml.load(legacyText);
const releaseGateText = read(".github/workflows/release-gate.yml");
const productionReadinessText = read(".github/workflows/production-deploy.yml");
const releaseTrainText = read(".github/workflows/release-train.yml");

test("release-gate and the normal application lane are the only enabled production mutation writers", () => {
  assert.match(releaseGateText, /group: production-deploy/);
  assert.match(releaseGateText, /Activate exact Stage-B backend candidate/);
  assert.doesNotMatch(releaseGateText, /Deploy backend ECS service|Deploy worker ECS service/);
  assert.match(releaseGateText, /environment: production/);
  assert.equal(legacy.jobs["legacy-disabled"].if, "${{ false }}");
  assert.doesNotMatch(legacyText, /configure-aws-credentials|AWS_ACCESS_KEY_ID|terraform apply|register-task-definition|update-service|deregister-task-definition/i);
  assert.match(productionReadinessText, /configure-aws-credentials/);
  assert.match(productionReadinessText, /Normal Production Deployment/);
  assert.match(productionReadinessText, /deploy-ecs-service\.sh/);
  assert.match(productionReadinessText, /rollback-ecs-service\.sh/);
  assert.match(productionReadinessText, /smoke-release\.mjs/);
  assert.doesNotMatch(productionReadinessText, /AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|terraform apply|PutSecretValue/i);
  assert.doesNotMatch(releaseTrainText, /terraform apply|register-task-definition|update-service|deregister-task-definition/i);
  assert.match(releaseTrainText, /dispatch-protected-main-release-gate\.mjs[\s\\]*--target-ref "\$TARGET_REF" --target-sha "\$TARGET_SHA"/);
});

test("the canonical writer keeps job-scoped OIDC permission", () => {
  const workflow = yaml.load(releaseGateText);
  assert.equal(workflow.permissions["id-token"], undefined);
  assert.deepEqual(workflow.jobs["deploy-production-ecs"].permissions, {
    contents: "read",
    actions: "read",
    deployments: "read",
    "id-token": "write",
  });
});

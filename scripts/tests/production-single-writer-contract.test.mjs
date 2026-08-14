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

test("release-gate is the only enabled production mutation writer", () => {
  assert.match(releaseGateText, /group: production-deploy/);
  assert.match(releaseGateText, /Deploy backend ECS service/);
  assert.match(releaseGateText, /environment: production/);
  assert.equal(legacy.jobs["legacy-disabled"].if, "${{ false }}");
  assert.doesNotMatch(legacyText, /configure-aws-credentials|AWS_ACCESS_KEY_ID|terraform apply|register-task-definition|update-service|deregister-task-definition/i);
  assert.doesNotMatch(productionReadinessText, /configure-aws-credentials|AWS_ACCESS_KEY_ID|terraform apply|register-task-definition|update-service|deregister-task-definition/i);
  assert.doesNotMatch(releaseTrainText, /terraform apply|register-task-definition|update-service|deregister-task-definition/i);
  assert.match(releaseTrainText, /gh workflow run release-gate\.yml/);
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

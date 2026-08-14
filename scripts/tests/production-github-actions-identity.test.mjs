import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

const workflowText = fs.readFileSync(".github/workflows/release-gate.yml", "utf8");
const terraform = fs.readFileSync("infra/aws/terraform/production-github-actions-identity/main.tf", "utf8");
const trust = JSON.parse(fs.readFileSync("infra/aws/terraform/production-github-actions-identity/mutation-trust-policy.json", "utf8"));

test("release gate has one protected production writer and exact CI identity", () => {
  assert.match(workflowText, /concurrency:\s*\n\s+group: production-deploy\s*\n\s+cancel-in-progress: false/);
  assert.match(workflowText, /deploy-production-ecs:[\s\S]*?environment: production/);
  assert.match(workflowText, /deploy-production-ecs:[\s\S]*?id-token: write/);
  assert.match(workflowText, /mscqr-production-github-actions-mutation/);
  assert.doesNotMatch(workflowText, /vars\.AWS_ROLE_TO_ASSUME/);
  assert.doesNotMatch(workflowText, /aws-access-key-id|aws-secret-access-key|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY/);
});

test("mutation trust is repository/environment exact and image publisher is not reused", () => {
  const statement = trust.Statement[0];
  assert.equal(statement.Principal.Federated, "arn:aws:iam::368992683803:oidc-provider/token.actions.githubusercontent.com");
  assert.equal(statement.Condition.StringEquals["token.actions.githubusercontent.com:aud"], "sts.amazonaws.com");
  assert.equal(statement.Condition.StringEquals["token.actions.githubusercontent.com:sub"], "repo:T-ej2003/genuine-scan-main:environment:production");
  assert.match(terraform, /mscqr-production-github-actions-mutation/);
  assert.doesNotMatch(terraform, /github-actions-mscqr-deploy|image-publisher/);
});

test("legacy broad role has a source-managed deny and cannot be a writer", () => {
  const retirement = fs.readFileSync("infra/aws/terraform/production-github-actions-identity/legacy-role-retirement.tf", "utf8");
  assert.match(retirement, /id\s*=\s*"github-actions-mscqr-deploy"/);
  assert.match(retirement, /Effect\s*=\s*"Deny"/);
  assert.match(retirement, /sts:AssumeRoleWithWebIdentity/);
  assert.match(retirement, /prevent_destroy\s*=\s*true/);
});

test("legacy production workflow is disabled and read-only workflow cannot mutate", () => {
  const legacy = fs.readFileSync(".github/workflows/deploy-ecs-release.yml", "utf8");
  const readOnly = fs.readFileSync(".github/workflows/production-deploy.yml", "utf8");
  assert.match(legacy, /if:\s*\$\{\{\s*false\s*\}\}/);
  assert.doesNotMatch(readOnly, /terraform\s+apply|state\s+(?:rm|import|push)|RegisterTaskDefinition|UpdateService|DeregisterTaskDefinition/i);
});

import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

const stageA = fs.readFileSync("infra/aws/terraform/production-green-stage-a/main.tf", "utf8");
const outputs = fs.readFileSync("infra/aws/terraform/production-green-stage-a/outputs.tf", "utf8");
const stageB = fs.readFileSync("infra/aws/terraform/production-green-stage-b/main.tf", "utf8");
const variables = fs.readFileSync("infra/aws/terraform/production-green-stage-b/variables.tf", "utf8");
const resource = stageA.match(/resource "aws_secretsmanager_secret" "read_only_canary" \{[\s\S]*?\n\}/)?.[0] || "";

test("Stage A exclusively owns one empty Phase 4 read-only-canary secret handle", () => {
  assert.equal((stageA.match(/resource "aws_secretsmanager_secret" "read_only_canary"/g) || []).length, 1);
  assert.match(resource, /name\s*=\s*"mscqr\/production\/rls-green\/phase4\/read-only-canary-database-url"/);
  assert.match(resource, /recovery_window_in_days\s*=\s*30/);
  assert.match(resource, /tags\s*=\s*merge\(local\.tags, \{ Role = "read_only_canary" \}\)/);
  assert.doesNotMatch(resource, /kms_key_id|secret_(?:string|binary)|rotation|replica|random_/);
  assert.doesNotMatch(stageA, /resource "aws_secretsmanager_secret_version" "read_only_canary"/);
});

test("Stage B receives the Phase 4 secret only through Stage A prerequisites", () => {
  assert.match(outputs, /read_only_canary_database_secret_arn\s*=\s*aws_secretsmanager_secret\.read_only_canary\.arn/);
  assert.match(variables, /variable "stage_a_read_only_canary_database_secret_arn"/);
  assert.match(variables, /Stage A prerequisites/);
  assert.match(stageB, /var\.stage_a_read_only_canary_database_secret_arn/);
  assert.doesNotMatch(stageB, /resource "aws_secretsmanager_secret(?:_version)?"/);
});

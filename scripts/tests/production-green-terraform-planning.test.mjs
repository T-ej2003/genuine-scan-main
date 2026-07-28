import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

const root = "infra/aws/terraform/production-green-stage-a";
const source = fs.readFileSync(`${root}/main.tf`, "utf8");
const variables = fs.readFileSync(`${root}/variables.tf`, "utf8");
const receiptPattern = /^arn:aws:s3:::mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an$/;

test("Stage A accepts only the reviewed production receipt bucket", () => {
  assert.equal(receiptPattern.test("arn:aws:s3:::mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an"), true);
  for (const value of ["arn:aws:s3:::mscqr-staging-euw2-artifacts-368992683803", "arn:aws:s3:::mscqr-prod-euw2-artifacts-000000000000-eu-west-2-an", "arn:aws:s3:::arbitrary", "arn:aws:s3:::mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an/*"]) assert.equal(receiptPattern.test(value), false);
  assert.match(variables, /mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an/);
});

test("Stage A keeps checker and protected deployer distinct", () => {
  assert.match(variables, /checker_is_independent_of_release_deployer/);
  assert.match(variables, /!contains\(var\.checker_principal_arns, var\.release_role_arn\)/);
  assert.match(variables, /mscqr-production-release-deployer/);
});

test("Stage A owns no blue infrastructure or release activation", () => {
  for (const forbidden of ["aws_ecs_cluster", "aws_ecs_service", "aws_ecs_task_definition", "aws_ecr_repository", "aws_lb", "aws_route53", "mscqr-prod-db", "aws_lambda_function", "traffic-switch", "image ="]) assert.doesNotMatch(source, new RegExp(forbidden));
  assert.match(source, /engine_version\s+=\s+"18\.4"/);
  assert.match(source, /publicly_accessible\s+=\s+false/);
  assert.match(source, /referenced_security_group_id/);
  assert.doesNotMatch(source, /cidr_ipv4/);
});

test("Stage A needs no image digest and Stage B keeps canaries mandatory", () => {
  assert.doesNotMatch(`${source}\n${variables}`, /sha256|image/);
  const stageB = JSON.parse(fs.readFileSync("infra/aws/terraform/production-green-stage-b/release-activation-contract.json", "utf8"));
  assert.equal(stageB.trafficSwitchBeforeCanariesAllowed, false);
  assert.equal(stageB.frontendTaskDefinition, "mscqr-frontend:20");
});

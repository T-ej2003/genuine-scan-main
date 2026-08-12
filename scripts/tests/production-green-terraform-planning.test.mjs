import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

const root = "infra/aws/terraform/production-green-stage-a";
const source = fs.readFileSync(`${root}/main.tf`, "utf8");
const variables = fs.readFileSync(`${root}/variables.tf`, "utf8");
const outputs = fs.readFileSync(`${root}/outputs.tf`, "utf8");
const readme = fs.readFileSync(`${root}/README.md`, "utf8");
const tfvarsExample = fs.readFileSync(`${root}/terraform.tfvars.example`, "utf8");
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

test("Stage A owns the exact MFA checker role chain without wildcard escalation", () => {
  const chain = source.match(/resource "aws_iam_role_policy" "checker_assume_target" \{([\s\S]*?)\n\}/)?.[1] || "";
  assert.match(source, /checker_assumer_role_name\s*=\s*"mscqr-production-independent-checker"/);
  assert.match(tfvarsExample, /checker_principal_arns\s*=\s*\["arn:aws:iam::368992683803:role\/mscqr-production-independent-checker"\]/);
  assert.match(chain, /name\s*=\s*"mscqr-production-independent-checker-role-chain"/);
  assert.match(chain, /role\s*=\s*local\.checker_assumer_role_name/);
  assert.match(chain, /Action\s*=\s*"sts:AssumeRole"/);
  assert.match(chain, /Resource\s*=\s*aws_iam_role\.checker\.arn/);
  assert.doesNotMatch(chain, /sts:\*|Resource\s*=\s*"\*"|release-deployer|bootstrap|root/i);
  const trust = source.match(/resource "aws_iam_role" "checker" \{([\s\S]*?)\n\}/)?.[1] || "";
  assert.match(trust, /Condition\s*=\s*\{ Bool = \{ "aws:MultiFactorAuthPresent" = "true" \} \}/);
  assert.match(trust, /Principal\s*=\s*\{ AWS = var\.checker_principal_arns \}/);
});

test("Stage A owns no blue infrastructure or release activation", () => {
  for (const forbidden of ["aws_ecs_cluster", "aws_ecs_service", "aws_ecs_task_definition", "aws_ecr_repository", "aws_lb", "aws_route53", "mscqr-prod-db", "aws_lambda_function", "traffic-switch", "image ="]) assert.doesNotMatch(source, new RegExp(forbidden));
  assert.match(source, /engine_version\s+=\s+"18\.4"/);
  assert.match(source, /publicly_accessible\s+=\s+false/);
  assert.match(source, /referenced_security_group_id/);
  const databaseIngress = [...source.matchAll(/resource "aws_vpc_security_group_ingress_rule" "(?:executor_database|runtime_database)" \{([\s\S]*?)\n\}/g)].map((match) => match[1]);
  assert.equal(databaseIngress.length, 2);
  for (const rule of databaseIngress) assert.doesNotMatch(rule, /cidr_ipv4|cidr_ipv6/);
});

test("Stage A declares executor egress only through standalone reviewed rules and keeps database ingress SG-to-SG only", () => {
  const executor = source.match(/resource "aws_security_group" "executor" \{([\s\S]*?)\n\}/)?.[1] || "";
  assert.match(executor, /name\s+=\s+"mscqr-production-rls-green-executor"/);
  assert.match(executor, /description\s+=\s+"No-ingress or egress executor security group until reviewed Stage B networking"/);
  assert.match(executor, /vpc_id\s+=\s+var\.vpc_id/);
  assert.doesNotMatch(executor, /name_prefix|lifecycle|ignore_changes|create_before_destroy/);
  assert.doesNotMatch(executor, /egress\s*\{|0\.0\.0\.0\/0|::\/0|cidr_/);
  const ingress = [...source.matchAll(/resource "aws_vpc_security_group_ingress_rule" "(?:executor_database|runtime_database)"[\s\S]*?\n\}/g)].map((match) => match[0]);
  assert.equal(ingress.length, 2);
  for (const rule of ingress) {
    assert.match(rule, /referenced_security_group_id/);
    assert.doesNotMatch(rule, /cidr_ipv4|cidr_ipv6|0\.0\.0\.0\/0|::\/0/);
  }
  assert.doesNotMatch(source, /aws_ecs_task_definition|aws_ecs_service|aws_lambda_function/);
});

test("Stage A preserves the RDS force-SSL parameter's provider-stable apply method", () => {
  const parameterGroup = source.match(/resource "aws_db_parameter_group" "green" \{([\s\S]*?)\n\}/)?.[1] || "";
  const parameter = parameterGroup.match(/parameter \{([\s\S]*?)\n  \}/)?.[1] || "";
  assert.match(parameter, /name\s+=\s+"rds\.force_ssl"/);
  assert.match(parameter, /value\s+=\s+"1"/);
  assert.match(parameter, /apply_method\s+=\s+"pending-reboot"/);
  assert.doesNotMatch(parameterGroup, /lifecycle[\s\S]*ignore_changes/);
});

test("Stage A exposes only the RDS-managed administrator secret ARN", () => {
  assert.match(source, /manage_master_user_password\s+=\s+true/);
  assert.match(outputs, /output "rds_managed_administrator_secret"/);
  assert.match(outputs, /master_user_secret.*secret_arn/);
  assert.doesNotMatch(outputs, /password\s*=/);
  assert.match(readme, /separate\s+from the 15 empty application\/runtime secret handles/);
});

test("Stage A needs no image digest and Stage B keeps canaries mandatory", () => {
  assert.doesNotMatch(`${source}\n${variables}`, /sha256|image/);
  const stageB = JSON.parse(fs.readFileSync("infra/aws/terraform/production-green-stage-b/release-activation-contract.json", "utf8"));
  assert.equal(stageB.trafficSwitchBeforeCanariesAllowed, false);
  assert.equal(stageB.frontendTaskDefinition, "mscqr-frontend:20");
  assert.equal(stageB.networking.requiredBeforeExecutor, true);
  assert.equal(stageB.networking.stageAExecutorEgress, "none");
});

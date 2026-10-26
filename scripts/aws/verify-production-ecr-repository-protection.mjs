#!/usr/bin/env node
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

export const ECR_PROTECTION = Object.freeze({ account: "368992683803", region: "eu-west-2", repositories: ["mscqr-backend", "mscqr-web", "mscqr-worker"] });
const denied = ["ecr:BatchDeleteImage", "ecr:DeleteRepository", "ecr:PutLifecyclePolicy"];

export function assertEcrRepositoryProtection({ repository, description, lifecyclePolicy, repositoryPolicy, caller }) {
  assert.ok(ECR_PROTECTION.repositories.includes(repository), "Unreviewed ECR repository");
  assert.equal(caller?.Account, ECR_PROTECTION.account, "Wrong AWS account");
  assert.equal(description?.repositoryName, repository);
  assert.equal(description?.registryId, ECR_PROTECTION.account);
  assert.equal(description?.repositoryArn, `arn:aws:ecr:${ECR_PROTECTION.region}:${ECR_PROTECTION.account}:repository/${repository}`);
  assert.equal(description?.imageTagMutability, "IMMUTABLE");
  assert.equal(description?.imageScanningConfiguration?.scanOnPush, true);
  assert.equal(lifecyclePolicy, null, "Automated ECR lifecycle expiration remains enabled");
  const policy = typeof repositoryPolicy === "string" ? JSON.parse(repositoryPolicy) : repositoryPolicy;
  assert.ok(policy && Array.isArray(policy.Statement), "Missing repository deletion guard");
  assert.ok(policy.Statement.some((statement) => statement.Effect === "Deny" && (statement.Principal === "*" || statement.Principal?.AWS === "*") &&
    (statement.Resource === "*" || statement.Resource === description.repositoryArn) &&
    denied.every((action) => Array.isArray(statement.Action) && statement.Action.includes(action)) &&
    !statement.Condition && !statement.NotAction && !statement.NotResource && !statement.NotPrincipal),
  "Repository deletion guard is incomplete");
  return true;
}

function aws(args, { allowMissingLifecycle = false } = {}) {
  const result = spawnSync("aws", [...args, "--region", ECR_PROTECTION.region, "--output", "json", "--no-cli-pager"], {
    encoding: "utf8", timeout: 45000, maxBuffer: 4 * 1024 * 1024,
    env: { ...process.env, AWS_MAX_ATTEMPTS: "2", AWS_CLI_AUTO_PROMPT: "off" },
  });
  if (allowMissingLifecycle && result.status !== 0 && /LifecyclePolicyNotFoundException/.test(result.stderr || "")) return null;
  if (result.error || result.status !== 0) throw new Error(`Read-only AWS ${args[0]} ${args[1]} failed: ${result.error?.code || result.status}`);
  return JSON.parse(result.stdout || "{}");
}

export function verifyRepository(repository, read = aws) {
  assert.ok(ECR_PROTECTION.repositories.includes(repository), "Unreviewed ECR repository");
  const caller = read(["sts", "get-caller-identity"]);
  const description = read(["ecr", "describe-repositories", "--repository-names", repository]).repositories?.[0];
  const lifecyclePolicy = read(["ecr", "get-lifecycle-policy", "--repository-name", repository], { allowMissingLifecycle: true });
  const policy = read(["ecr", "get-repository-policy", "--repository-name", repository]);
  assertEcrRepositoryProtection({ repository, description, lifecyclePolicy, repositoryPolicy: policy.policyText, caller });
  return { repository, status: "PROTECTED" };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  assert.equal(process.argv.length, 4, "Usage: verify-production-ecr-repository-protection.mjs <repository> <region>");
  assert.equal(process.argv[3], ECR_PROTECTION.region, "Wrong AWS region");
  process.stdout.write(`${JSON.stringify(verifyRepository(process.argv[2]))}\n`);
}

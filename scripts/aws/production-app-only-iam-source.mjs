import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { APP_ONLY, assertAppOnlyEvidenceIdentity } from "./production-app-only-contract.mjs";
import { canonicalSha256, STAGE_B } from "./production-green-stage-b-contract.mjs";
import { parseEcsSecretsManagerReference } from "./production-ecs-runtime-dependencies.mjs";
import { writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";
import { normalizeIamPolicyDocument } from "./iam-policy-document.mjs";
import { canonicalizeStageAProductionArtifactsPolicy } from "./production-stage-a-control-plane.mjs";
import { ecsTaskTrustSha256, RUNTIME_CONSUMABILITY } from "./production-ecs-runtime-consumability.mjs";
import { APP_ONLY_VERIFIER, appOnlyRuntimeSecretArns } from "./production-app-only-policy.mjs";

// Evaluate the actual protected Terraform policy expressions without loading
// its backend, providers, resources or state. No parallel JS policy model.
// An unfamiliar source expression fails Terraform evaluation rather than
// being guessed from the live IAM policy we are supposed to verify.
export function evaluateAppOnlySourceIam({ repositoryRoot, databaseSecretArn }) {
  const template = JSON.parse(fs.readFileSync(path.join(repositoryRoot, "infra/aws/terraform/production-green-stage-b/task-definitions/green-backend-candidate.json"), "utf8"));
  assert.equal(template.containerDefinitions.length, 1);
  if (databaseSecretArn !== undefined) assert.match(databaseSecretArn, new RegExp(`^arn:aws:secretsmanager:${APP_ONLY.region}:${APP_ONLY.account}:secret:${APP_ONLY_VERIFIER.databaseSecretName}-[A-Za-z0-9]{6}$`));
  const kind = databaseSecretArn === undefined ? "backend" : "read_only_canary";
  const secretArns = databaseSecretArn === undefined ? [...new Set(template.containerDefinitions[0].secrets.map(({ valueFrom }) => parseEcsSecretsManagerReference(valueFrom).resource))].sort() : [databaseSecretArn];
  const source = fs.readFileSync(path.join(repositoryRoot, "infra/aws/terraform/production-green-stage-b/main.tf"), "utf8");
  // This evaluator supports the reviewed Stage-B variable-to-policy wiring,
  // not arbitrary future HCL. A source change must extend and test this model;
  // otherwise it cannot assert that live IAM implements the new source.
  assert.equal(canonicalSha256(source), "c3f4cedb5d8ae7cce99f5c4c4bfc13962373ae066676e193f82a18ee34b79a38", "Stage-B IAM source wiring is unreviewed by the app-only compatibility model");
  const block = (name) => {
    const matches = [...source.matchAll(new RegExp(`^resource "aws_iam_role_policy" "${name}" \\{\\n([\\s\\S]*?)^\\}`, "gm"))];
    assert.equal(matches.length, 1, `Ambiguous source IAM resource ${name}`);
    const match = matches[0][1].match(/^  policy = (jsonencode\([\s\S]*\))\s*$/m);
    assert.ok(match, `Unsupported source IAM expression ${name}`);
    return match[1].replaceAll("each.key", "var.input.kind");
  };
  const local = (name, closing) => {
    const matches = [...source.matchAll(new RegExp(`^  ${name} = ([\\s\\S]*?^  ${closing})$`, "gm"))];
    assert.equal(matches.length, 1, `Ambiguous source IAM local ${name}`);
    return matches[0][1];
  };
  const configuration = `variable "input" { type = any }
variable "receipt_bucket_arn" { type = string }
locals {
  ecr_repository_arns = ${local("ecr_repository_arns", "\\}")}
  stage_b_logs = ${local("stage_b_logs", "\\}")}
  runtime_rotation_and_artifact_secret_arns = ${JSON.stringify(appOnlyRuntimeSecretArns(source))}
  execution_log_group_arns = { ${kind} = "arn:aws:logs:${APP_ONLY.region}:${APP_ONLY.account}:log-group:\${local.stage_b_logs.${kind}}" }
  execution_policy_secret_arns = { ${kind} = ${kind === "backend" ? "distinct(concat(var.input.secret_arns, local.runtime_rotation_and_artifact_secret_arns))" : "var.input.secret_arns"} }
  execution = ${block("execution")}
  object_storage = ${block("candidate_object_storage")}
  ecs_exec = ${block("backend_ecs_exec")}
}
`;
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-app-only-iam-source-"));
  fs.chmodSync(directory, 0o700);
  const write = (name, bytes) => writeStageBPrivateFileAtomic({ filePath: path.join(directory, name), repositoryRoot, bytes: Buffer.from(bytes), label: "App-only source IAM evaluation" });
  write("main.tf", configuration);
  write("input.tfvars.json", JSON.stringify({ receipt_bucket_arn: `arn:aws:s3:::${STAGE_B.receiptBucket}`,
    input: { kind, secret_arns: secretArns } }));
  const result = spawnSync("terraform", [`-chdir=${directory}`, "console", "-state=/dev/null", "-no-color", "-var-file=input.tfvars.json"], {
    env: { PATH: process.env.PATH, HOME: process.env.HOME, TF_IN_AUTOMATION: "1", CHECKPOINT_DISABLE: "1" },
    input: "jsonencode({ execution = jsondecode(local.execution), object_storage = jsondecode(local.object_storage), ecs_exec = jsondecode(local.ecs_exec) })\n",
    encoding: "utf8", timeout: 30000, maxBuffer: 1048576,
  });
  assert.equal(result.status, 0, "Protected source IAM expression evaluation failed; compatibility is unproven");
  const policies = JSON.parse(JSON.parse(result.stdout.trim()));
  assert.deepEqual(Object.keys(policies).sort(), ["ecs_exec", "execution", "object_storage"]);
  return { policies, sourceConfigurationSha256: canonicalSha256(source), evaluationSha256: canonicalSha256({ configuration, secretArns, policies }) };
}

// Scope is the two backend runtime roles, not the whole AWS account. Terraform
// state is neither read nor compared. Source requirements never come from IAM.
export function collectAppOnlyLiveIamCompatibility({ repositoryRoot, identity, run, now = Date.now() }) {
  const expected = evaluateAppOnlySourceIam({ repositoryRoot });
  const rolePolicies = [
    [APP_ONLY.executionRoleArn, { "stage-b-exact-image-logs-and-secrets": expected.policies.execution }],
    [APP_ONLY.taskRoleArn, { "stage-b-object-storage": expected.policies.object_storage, "stage-b-backend-ecs-exec-ssm-channels": expected.policies.ecs_exec }],
  ];
  return collectRoleCompatibility({ expected, rolePolicies, identity, run, now, scope: "BACKEND_RUNTIME_ROLES" });
}

export function collectAppOnlyVerifierIamCompatibility({ repositoryRoot, identity, databaseSecretArn, run, now = Date.now() }) {
  const expected = evaluateAppOnlySourceIam({ repositoryRoot, databaseSecretArn });
  assert.ok(databaseSecretArn, "Verifier secret identity is required");
  return collectRoleCompatibility({ expected, identity, run, now, databaseSecretArn, scope: "READ_ONLY_VERIFIER_ROLES",
    rolePolicies: [[APP_ONLY_VERIFIER.executionRoleArn, { "stage-b-exact-image-logs-and-secrets": expected.policies.execution }], [APP_ONLY_VERIFIER.taskRoleArn, {}]] });
}

function collectRoleCompatibility({ expected, rolePolicies, identity, run, now, scope, databaseSecretArn }) {
  const policyHash = (value) => canonicalSha256(canonicalizeStageAProductionArtifactsPolicy(normalizeIamPolicyDocument(value, "App-only runtime IAM")));
  const aws = (args) => {
    const value = run([...args, "--output", "json", "--no-cli-pager"]);
    return typeof value === "string" ? JSON.parse(value) : value;
  };
  const caller = aws(["sts", "get-caller-identity"]);
  assert.equal(caller.Account, APP_ONLY.account);
  const read = () => rolePolicies.map(([arn, policies]) => {
    const name = arn.split("/").at(-1);
    const { Role: role } = aws(["iam", "get-role", "--role-name", name]);
    assert.equal(role?.Arn, arn); assert.equal(role.RoleName, name);
    assert.equal(role.PermissionsBoundary, undefined, "Runtime permissions boundary is unproven");
    assert.equal(ecsTaskTrustSha256(role.AssumeRolePolicyDocument), RUNTIME_CONSUMABILITY.ecsTaskTrustSha256);
    const inline = aws(["iam", "list-role-policies", "--role-name", name]);
    const attached = aws(["iam", "list-attached-role-policies", "--role-name", name]);
    assert.ok(!inline.IsTruncated && !attached.IsTruncated, "Incomplete runtime IAM census");
    assert.deepEqual(attached.AttachedPolicies, [], "Unreviewed attached runtime IAM policy");
    assert.deepEqual([...inline.PolicyNames].sort(), Object.keys(policies).sort(), "Runtime IAM policy topology differs from source");
    const observed = Object.fromEntries(Object.entries(policies).map(([policyName, sourcePolicy]) => {
      const response = aws(["iam", "get-role-policy", "--role-name", name, "--policy-name", policyName]);
      assert.equal(response.RoleName, name); assert.equal(response.PolicyName, policyName);
      const hash = policyHash(response.PolicyDocument);
      assert.equal(hash, policyHash(sourcePolicy), `Current live IAM differs from protected source: ${name}/${policyName}`);
      return [policyName, hash];
    }));
    assert.ok(typeof role.RoleId === "string" && role.RoleId.length > 0);
    return { arn, roleId: role.RoleId, trustSha256: RUNTIME_CONSUMABILITY.ecsTaskTrustSha256, policies: observed };
  });
  const roles = read();
  assert.deepEqual(read(), roles, "Runtime IAM changed during compatibility collection");
  const body = { schemaVersion: 1, kind: "APP_ONLY_LIVE_IAM_COMPATIBILITY", identity, generatedAt: new Date(now).toISOString(),
    ...(databaseSecretArn === undefined ? {} : { databaseSecretArn }),
    scope, roles, sourceConfigurationSha256: expected.sourceConfigurationSha256,
    sourceEvaluationSha256: expected.evaluationSha256, sourceToLiveIamSemanticDifferences: 0, status: "ALREADY_APPLIED_COMPATIBLE" };
  const evidence = { ...body, evidenceSha256: canonicalSha256(body) };
  assertAppOnlyEvidenceIdentity(evidence, identity, now);
  return evidence;
}

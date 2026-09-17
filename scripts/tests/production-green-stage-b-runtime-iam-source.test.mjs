import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

const source = fs.readFileSync("infra/aws/terraform/production-green-stage-b/main.tf", "utf8");
const exactRuntimeSecrets = [
  "mscqr/prod/rotation/jwt-previous-6rQrqj",
  "mscqr/prod/rotation/qr-current-version-8fNOVE",
  "mscqr/prod/rotation/qr-previous-version-PDFul2",
  "mscqr/prod/rotation/qr-public-previous-rLZwcX",
  "mscqr/prod/smtp-pass-arDHq6",
  "mscqr/production/rls-green/artifact-signing/active-key-version-8oxmeP",
  "mscqr/production/rls-green/artifact-signing/private-key-current-T0AJAW",
  "mscqr/production/rls-green/artifact-signing/public-key-current-VyQhAv",
  "mscqr/production/rls-green/artifact-signing/public-keys-json-SNolaH",
];
const exactExecutorSecretNames = [
  "AUTH_MFA_ENCRYPTION_KEY",
  "MSCQR_CANARY_ORDINARY_EMAIL",
  "MSCQR_CANARY_ORDINARY_PASSWORD",
  "MSCQR_CANARY_ORDINARY_MFA_SECRET",
  "MSCQR_CANARY_ADMIN_EMAIL",
  "MSCQR_CANARY_ADMIN_PASSWORD",
  "MSCQR_CANARY_ADMIN_MFA_SECRET",
];

test("Stage-B execution policies retain the exact live runtime secret closure", () => {
  const block = source.match(/runtime_rotation_and_artifact_secret_arns = \[([\s\S]*?)\n  \]/)?.[1] || "";
  assert.deepEqual([...block.matchAll(/secret:([^"\s]+)/g)].map(([, value]) => value), exactRuntimeSecrets);
  assert.match(source, /executor_canary_auth_secret_arns = \[[\s\S]*?secret\.name == "AUTH_MFA_ENCRYPTION_KEY" \|\| startswith\(secret\.name, "MSCQR_CANARY_"\)/);
  const canaryDefinition = JSON.parse(fs.readFileSync("infra/aws/terraform/production-green-stage-b/task-definitions/green-application-canary.json", "utf8"));
  assert.deepEqual(
    canaryDefinition.containerDefinitions[0].environment.find(({ name }) => name === "CLIENT_IP_TRUST_MODE"),
    { name: "CLIENT_IP_TRUST_MODE", value: "direct-loopback-canary" },
  );
  assert.deepEqual(
    canaryDefinition.containerDefinitions[0].environment.find(({ name }) => name === "MSCQR_PRODUCTION_GREEN_APPLICATION_CANARY"),
    { name: "MSCQR_PRODUCTION_GREEN_APPLICATION_CANARY", value: "true" },
  );
  assert.deepEqual(
    canaryDefinition.containerDefinitions[0].secrets
      .map(({ name }) => name)
      .filter((name) => name === "AUTH_MFA_ENCRYPTION_KEY" || name.startsWith("MSCQR_CANARY_")),
    exactExecutorSecretNames,
  );
  assert.match(source, /execution_policy_secret_arns = var\.stage_b_recovery_only \? local\.active_execution_secret_arns : local\.normal_execution_policy_secret_arns/);
  assert.doesNotMatch(block, /\*/);
});

test("Stage-B candidate object storage grants only exact bucket listing beside object access", () => {
  const block = source.match(/resource "aws_iam_role_policy" "candidate_object_storage" \{([\s\S]*?)\n\}/)?.[1] || "";
  assert.match(block, /Sid\s+= "ListExactProductionArtifactBucket"[\s\S]*?Action\s+= \["s3:ListBucket"\][\s\S]*?Resource = var\.receipt_bucket_arn/);
  assert.match(block, /contains\(\["backend", "canary"\], each\.key\) \? \[/);
  assert.match(block, /Sid\s+= "ReadWriteOnlyProductionArtifactObjects"[\s\S]*?Action\s+= \["s3:GetObject", "s3:PutObject"\][\s\S]*?Resource = "\$\{var\.receipt_bucket_arn\}\/\*"/);
  assert.doesNotMatch(block, /Action\s+=\s+"s3:\*"/);
});

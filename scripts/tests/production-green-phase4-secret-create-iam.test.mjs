import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

const policy = JSON.parse(fs.readFileSync("documents/ops/iam/MSCQRProductionGreenPhase4ReadOnlyCanarySecretCreate-v1.json", "utf8"));
const statement = policy.Statement[0];

test("Phase 4 canary handle creation is restricted to its exact name, region, and reviewed tags", () => {
  assert.equal(policy.Statement.length, 1);
  assert.deepEqual(statement.Action, "secretsmanager:CreateSecret");
  assert.equal(statement.Resource, "*"); // CreateSecret has no pre-existing secret ARN; conditions bind the request.
  assert.deepEqual(statement.Condition.StringEquals, {
    "secretsmanager:Name": "mscqr/production/rls-green/phase4/read-only-canary-database-url",
    "aws:RequestedRegion": "eu-west-2",
    "aws:RequestTag/Role": "read_only_canary",
    "aws:RequestTag/Environment": "production",
    "aws:RequestTag/ManagedBy": "Terraform",
    "aws:RequestTag/Component": "full-rls-green-stage-a",
    "aws:RequestTag/Stack": "production-green-stage-a",
  });
  assert.deepEqual(statement.Condition["ForAllValues:StringEquals"]["aws:TagKeys"], ["Role", "Environment", "ManagedBy", "Component", "Stack"]);
});

test("Phase 4 canary policy grants no secret-value, lifecycle, or KMS authority", () => {
  const serialized = JSON.stringify(policy);
  for (const forbidden of ["GetSecretValue", "PutSecretValue", "DeleteSecret", "UpdateSecret", "RotateSecret", "TagResource", "kms:"]) assert.doesNotMatch(serialized, new RegExp(forbidden));
});

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { canonical, digest, installationDocuments, documentBindings, classifyIamDocument, provisionerTargetPolicy, installationIdentity } from "../aws/component-iam-installation-contract.mjs";

test("exact source documents produce deterministic bindings without caller inputs", () => {
  const targets = installationDocuments();
  assert.equal(targets.length, 3);
  assert.throws(() => installationDocuments({ role: "other", policy: {} }));
  assert.deepEqual(documentBindings().map(({ arn }) => arn), targets.map(({ arn }) => arn));
  for (const target of targets) {
    assert.equal(target.policySha256, digest(target.policy));
    assert.equal(classifyIamDocument(null, target.policy), "ABSENT");
    assert.equal(classifyIamDocument(encodeURIComponent(canonical(target.policy)), target.policy), "EXPECTED");
    assert.equal(classifyIamDocument({ Version: "2012-10-17", Statement: [] }, target.policy), "DIFFERENT");
    assert.equal(classifyIamDocument("malformed", target.policy), "DIFFERENT");
  }
});

test("isolated target capability cannot write its own role or unrelated resources", () => {
  const policy = provisionerTargetPolicy();
  const targets = installationDocuments().map(({ arn }) => arn);
  for (const statement of policy.Statement) {
    assert.equal(statement.Effect, "Allow");
    for (const resource of statement.Resource) {
      assert(targets.includes(resource));
      assert(!resource.includes(installationIdentity.provisionerRole));
      assert(!resource.includes("*"));
    }
    for (const action of [].concat(statement.Action)) assert(!["iam:*", "iam:PassRole", "iam:DeleteRole", "iam:UpdateAssumeRolePolicy", "iam:AttachRolePolicy"].includes(action));
  }
});

test("Terraform owns only the table, not guarded IAM resources", () => {
  const root = "infra/aws/terraform/production-component-deployment-state";
  const source = fs.readFileSync(`${root}/main.tf`, "utf8");
  assert(!/resource\s+"aws_iam_/.test(source));
  assert.deepEqual(JSON.parse(fs.readFileSync(`${root}/state-backend-contract.json`)).expectedManagedAddresses, ["aws_dynamodb_table.component_deployment_state"]);
});

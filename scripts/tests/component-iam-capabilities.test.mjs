import test from "node:test";
import assert from "node:assert/strict";
import { installationCapabilitySet, installationIdentity, installationDocuments, digest } from "../aws/component-iam-installation-contract.mjs";
import { temporaryInstallationPolicies } from "../aws/component-iam-installation.mjs";

const capabilities = installationCapabilitySet();
const actions = (policy) => policy.Statement.flatMap((statement) => [].concat(statement.Action));
const pairs = (policy) => policy.Statement.flatMap((statement) => [].concat(statement.Action).flatMap((action) => [].concat(statement.Resource).map((resource) => ({ action, resource }))));
const permitsPair = (policy, action, resource) => pairs(policy).some((pair) => pair.action === action && pair.resource === resource);
const state = "arn:aws:s3:::mscqr-production-terraform-state-368992683803-eu-west-2/mscqr/production/component-deployment-state/terraform.tfstate";

test("capability split forbids all Terraform IAM mutations and both executors' self-policy changes", () => {
  assert(actions(capabilities.terraform).filter((action) => action.startsWith("iam:")).every((action) => ["iam:GetRole", "iam:GetRolePolicy", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies"].includes(action)));
  for (const policy of [capabilities.terraform, capabilities.provisioner]) {
    assert(!actions(policy).includes("iam:PassRole"));
    for (const pair of pairs(policy)) {
      assert(!pair.action.includes("*"));
      assert(!pair.resource.includes("*"));
      if (pair.action.startsWith("iam:") && !pair.action.startsWith("iam:Get")) {
        assert(installationDocuments().some(({ arn }) => arn === pair.resource));
      }
    }
    for (const role of [installationIdentity.provisionerRole, installationIdentity.terraformRole, "unrelated"]) {
      for (const action of ["iam:PutRolePolicy", "iam:CreateRole", "iam:UpdateAssumeRolePolicy", "iam:AttachRolePolicy"]) assert.equal(permitsPair(policy, action, `arn:aws:iam::368992683803:role/${role}`), false);
    }
  }
});

test("backend grants only exact state/lock/attempt writes; no state or attempt deletion", () => {
  const policy = capabilities.terraform;
  for (const resource of [state, `${state}.tflock`, `${state}.initial-activation-attempt`]) assert(permitsPair(policy, "s3:PutObject", resource));
  assert(permitsPair(policy, "s3:DeleteObject", `${state}.tflock`));
  for (const resource of [state, `${state}.initial-activation-attempt`, `${state}-other`]) assert(!permitsPair(policy, "s3:DeleteObject", resource));
  assert(!permitsPair(policy, "s3:PutObject", `${state}-other`));
  for (const statement of policy.Statement.filter((item) => [].concat(item.Action).includes("s3:PutObject"))) assert.equal(statement.Condition.StringEquals["s3:x-amz-server-side-encryption"], "AES256");
  const listings = policy.Statement.find((item) => [].concat(item.Action).includes("s3:ListBucket"));
  assert.deepEqual(listings.Condition.StringEquals, { "s3:prefix": "mscqr/production/component-deployment-state/terraform.tfstate" });
});

test("runtime grants expire; IAM credentials are restricted to the exact Lambda", () => {
  const expiresAt = "2030-01-01T00:30:00.000Z";
  const policies = temporaryInstallationPolicies({ expiresAt });
  for (const statement of [...policies.provisioner.Statement, ...policies.terraform.Statement]) assert.deepEqual(statement.Condition.DateLessThan, { "aws:CurrentTime": expiresAt });
  for (const statement of policies.provisioner.Statement) assert.deepEqual(statement.Condition.ArnEquals, { "lambda:SourceFunctionArn": "arn:aws:lambda:eu-west-2:368992683803:function:mscqr-production-component-iam-installer" });
  assert.equal(pairs(policies.provisioner).length, pairs(capabilities.provisioner).length);
  assert.equal(pairs(policies.terraform).length, pairs(capabilities.terraform).length);
  const changed = structuredClone(capabilities); changed.terraform.Statement.push({ Effect: "Allow", Action: "iam:PassRole", Resource: "*" });
  assert.notEqual(digest(changed), digest(capabilities));
});

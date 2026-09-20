import test from "node:test";
import assert from "node:assert/strict";
import { installationCapabilitySet, installationIdentity, installationDocuments, digest, terraformExecutorPolicyGeneration } from "../aws/component-iam-installation-contract.mjs";
import { bootstrapManagedIdentities, brokerChangeManagedIdentities, brokerPolicySuccessorManagedIdentities, componentBrokerArn, componentSessionIdentities } from "../aws/component-installation-identity-contract.mjs";

const capabilities = installationCapabilitySet();
const actions = (policy) => policy.Statement.flatMap((statement) => [].concat(statement.Action));
const pairs = (policy) => policy.Statement.flatMap((statement) => [].concat(statement.Action).flatMap((action) => [].concat(statement.Resource).map((resource) => ({ action, resource }))));
const permitsPair = (policy, action, resource) => pairs(policy).some((pair) => pair.action === action && pair.resource === resource);
const state = "arn:aws:s3:::mscqr-production-terraform-state-368992683803-eu-west-2/mscqr/production/component-deployment-state/terraform.tfstate";

test("capability split forbids all Terraform IAM mutations and both executors' self-policy changes", () => {
  assert(!actions(capabilities.terraform).includes("s3:GetObjectVersion"));
  assert(permitsPair(capabilities.terraform, "lambda:InvokeFunction", "arn:aws:lambda:eu-west-2:368992683803:function:mscqr-production-component-iam-installer:1"));
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
  const policy = terraformExecutorPolicyGeneration("7", true);
  for (const resource of [`${state}.tflock`, `${state}.initial-activation-attempt`]) assert(permitsPair(policy, "s3:GetObjectVersion", resource));
  for (const resource of [state, `${state}-other`, `${state}.initial-activation-attempt-other`]) assert(!permitsPair(policy, "s3:GetObjectVersion", resource));
  for (const resource of [state, `${state}.tflock`, `${state}.initial-activation-attempt`]) assert(permitsPair(policy, "s3:PutObject", resource));
  assert(permitsPair(policy, "s3:DeleteObject", `${state}.tflock`));
  for (const resource of [state, `${state}.initial-activation-attempt`, `${state}-other`]) assert(!permitsPair(policy, "s3:DeleteObject", resource));
  assert(!permitsPair(policy, "s3:PutObject", `${state}-other`));
  for (const statement of policy.Statement.filter((item) => [].concat(item.Action).includes("s3:PutObject"))) assert.equal(statement.Condition.StringEquals["s3:x-amz-server-side-encryption"], "AES256");
  const listings = policy.Statement.find((item) => [].concat(item.Action).includes("s3:ListBucket"));
  assert.deepEqual(listings.Condition.StringEquals, { "s3:prefix": "mscqr/production/component-deployment-state/terraform.tfstate" });
});

test("every recovery S3 call is covered only at its fixed backend resource", () => {
  const policy = terraformExecutorPolicyGeneration("7", true);
  const bucket = "arn:aws:s3:::mscqr-production-terraform-state-368992683803-eu-west-2";
  for (const [action, resource] of [
    ["s3:GetBucketVersioning", bucket], ["s3:ListBucket", bucket], ["s3:ListBucketVersions", bucket],
    ["s3:GetObject", state], ["s3:GetObject", `${state}.tflock`],
    ["s3:GetObjectVersion", `${state}.tflock`], ["s3:GetObjectVersion", `${state}.initial-activation-attempt`],
    ["s3:PutObject", state], ["s3:PutObject", `${state}.tflock`], ["s3:DeleteObject", `${state}.tflock`],
  ]) assert(permitsPair(policy, action, resource), `${action} ${resource}`);
});

test("bootstrap owns fixed broker authority; normal sessions cannot replace code or authority", () => {
  const broker = bootstrapManagedIdentities().find(target => target.role === installationIdentity.provisionerRole);
  for (const statement of broker.policy.Statement) assert.deepEqual(statement.Condition.ArnEquals, { "lambda:SourceFunctionArn": "arn:aws:lambda:eu-west-2:368992683803:function:mscqr-production-component-iam-installer" });
  for (const session of componentSessionIdentities()) assert.deepEqual(actions(session.policy), ["lambda:InvokeFunction"]);
  const changed = structuredClone(capabilities); changed.terraform.Statement.push({ Effect: "Allow", Action: "iam:PassRole", Resource: "*" });
  assert.notEqual(digest(changed), digest(capabilities));
});

test("successor broker gains only exact immutable version-7 self-read authority", () => {
  const predecessor = brokerChangeManagedIdentities().find(({ role }) => role === installationIdentity.provisionerRole).policy;
  const successor = brokerPolicySuccessorManagedIdentities().find(({ role }) => role === installationIdentity.provisionerRole).policy;
  const added = pairs(successor).filter(pair => !permitsPair(predecessor, pair.action, pair.resource));
  assert.deepEqual(added.map(({ action, resource }) => [action, resource]), [
    ["lambda:GetFunction", `${componentBrokerArn}:7`], ["lambda:GetFunctionConfiguration", `${componentBrokerArn}:7`],
    ["lambda:GetFunctionCodeSigningConfig", `${componentBrokerArn}:7`], ["lambda:GetRuntimeManagementConfig", `${componentBrokerArn}:7`],
    ["lambda:GetFunctionConcurrency", `${componentBrokerArn}:7`], ["lambda:GetPolicy", `${componentBrokerArn}:7`],
  ]);
  const session = brokerPolicySuccessorManagedIdentities().find(({ role }) => role === "mscqr-production-component-installation-session");
  assert.deepEqual(pairs(session.policy), [{ action: "lambda:InvokeFunction", resource: `${componentBrokerArn}:7` }]);
});

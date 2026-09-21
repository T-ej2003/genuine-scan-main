#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";
import { createProductionCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-cutover-production-adapters.mjs";
import { digest } from "./component-iam-installation-contract.mjs";
import { normalizeIamPolicyDocument } from "./iam-policy-document.mjs";
import { readStageBProtectedMainCheckout } from "./stage-b-deployment-identity.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const sourcePolicy = JSON.parse(fs.readFileSync(path.join(root, "infra/aws/terraform/production-component-deployment-state/normal-deployer-policy.json"), "utf8"));

export const NORMAL_DEPLOYER_POLICY = Object.freeze({
  account: "368992683803",
  role: "mscqr-production-normal-deployer",
  roleArn: "arn:aws:iam::368992683803:role/mscqr-production-normal-deployer",
  policyName: "MSCQRProductionNormalDeployment",
  predecessorSha256: "fca1f79a70d728ee7c522ea2aa12449111d4e7b04600e7bbc070ef96b956084e",
  targetSha256: digest(sourcePolicy),
});

const json = (run, args) => JSON.parse(run([...args, "--output", "json", "--no-cli-pager"]));

export function readNormalDeployerPolicyState({ run } = {}) {
  assert.equal(typeof run, "function", "AWS command runner is required.");
  const role = json(run, ["iam", "get-role", "--role-name", NORMAL_DEPLOYER_POLICY.role]).Role;
  assert.equal(role?.RoleName, NORMAL_DEPLOYER_POLICY.role, "Normal deployer role name changed.");
  assert.equal(role?.Arn, NORMAL_DEPLOYER_POLICY.roleArn, "Normal deployer role ARN changed.");
  const names = json(run, ["iam", "list-role-policies", "--role-name", NORMAL_DEPLOYER_POLICY.role]);
  assert.equal(names.IsTruncated ?? false, false, "Normal deployer inline-policy inventory is incomplete.");
  assert.deepEqual(names.PolicyNames, [NORMAL_DEPLOYER_POLICY.policyName], "Normal deployer has an unexpected inline policy.");
  const attached = json(run, ["iam", "list-attached-role-policies", "--role-name", NORMAL_DEPLOYER_POLICY.role]);
  assert.equal(attached.IsTruncated ?? false, false, "Normal deployer attached-policy inventory is incomplete.");
  assert.deepEqual(attached.AttachedPolicies, [], "Normal deployer has an unexpected attached policy.");
  const policy = json(run, ["iam", "get-role-policy", "--role-name", NORMAL_DEPLOYER_POLICY.role, "--policy-name", NORMAL_DEPLOYER_POLICY.policyName]);
  assert.equal(policy.RoleName, NORMAL_DEPLOYER_POLICY.role);
  assert.equal(policy.PolicyName, NORMAL_DEPLOYER_POLICY.policyName);
  const policySha256 = digest(normalizeIamPolicyDocument(policy.PolicyDocument, "Normal deployer inline policy"));
  return Object.freeze({ roleArn: role.Arn, policySha256 });
}

export function convergeNormalDeployerPolicy({ run, sourceSha } = {}) {
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/, "Protected source SHA is required.");
  const identity = json(run, ["sts", "get-caller-identity"]);
  assert.equal(identity.Account, NORMAL_DEPLOYER_POLICY.account, "Normal deployer policy convergence used the wrong AWS account.");
  assert.equal(identity.Arn, `arn:aws:iam::${NORMAL_DEPLOYER_POLICY.account}:root`, "Normal deployer policy convergence requires the established root configuration authority.");
  const before = readNormalDeployerPolicyState({ run });
  if (before.policySha256 !== NORMAL_DEPLOYER_POLICY.predecessorSha256 && before.policySha256 !== NORMAL_DEPLOYER_POLICY.targetSha256)
    throw new Error("Live normal deployer policy is neither the exact reviewed predecessor nor target.");
  let iamWrites = 0;
  let writeError;
  if (before.policySha256 === NORMAL_DEPLOYER_POLICY.predecessorSha256) {
    iamWrites = 1;
    try {
      run(["iam", "put-role-policy", "--role-name", NORMAL_DEPLOYER_POLICY.role, "--policy-name", NORMAL_DEPLOYER_POLICY.policyName, "--policy-document", JSON.stringify(sourcePolicy), "--no-cli-pager"]);
    } catch (error) { writeError = error; }
  }
  const after = readNormalDeployerPolicyState({ run });
  if (after.policySha256 !== NORMAL_DEPLOYER_POLICY.targetSha256) {
    const error = new Error("Normal deployer policy readback does not match protected source.");
    if (writeError) error.cause = writeError;
    throw error;
  }
  return Object.freeze({ status: "NORMAL_DEPLOYER_POLICY_VERIFIED", sourceSha, predecessorPolicySha256: before.policySha256, policySha256: after.policySha256, iamWrites });
}

function argumentsMap(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index], value = argv[index + 1];
    if (!key?.startsWith("--") || !value || value.startsWith("--") || values.has(key)) throw new Error(`Invalid or duplicate argument: ${key || "<missing>"}`);
    values.set(key, value);
  }
  assert.deepEqual([...values.keys()].sort(), ["--admin-profile", "--source-sha"]);
  return values;
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const values = argumentsMap(process.argv.slice(2));
  const sourceSha = values.get("--source-sha");
  const checkout = readStageBProtectedMainCheckout({ cwd: root, expectedSourceSha: sourceSha, requireCanonicalRepository: true });
  assert.equal(checkout.currentHead, sourceSha, "Normal deployer convergence source is not protected main.");
  const result = convergeNormalDeployerPolicy({
    sourceSha,
    run: createProductionCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: values.get("--admin-profile") }),
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

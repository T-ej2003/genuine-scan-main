import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { digest } from "../aws/component-iam-installation-contract.mjs";
import { NORMAL_DEPLOYER_POLICY, convergeNormalDeployerPolicy } from "../aws/converge-production-normal-deployer-policy.mjs";

const target = JSON.parse(fs.readFileSync("infra/aws/terraform/production-component-deployment-state/normal-deployer-policy.json", "utf8"));
const predecessor = structuredClone(target);
predecessor.Statement = predecessor.Statement.filter(({ Sid }) => Sid !== "ReadDeploymentAlarms");
assert.equal(digest(predecessor), NORMAL_DEPLOYER_POLICY.predecessorSha256);
assert.equal(digest(target), NORMAL_DEPLOYER_POLICY.targetSha256);

function fixture({ policy = predecessor, roleArn = NORMAL_DEPLOYER_POLICY.roleArn, names = [NORMAL_DEPLOYER_POLICY.policyName], attached = [], apply = true, callerArn = "arn:aws:iam::368992683803:root" } = {}) {
  let live = structuredClone(policy);
  const calls = [];
  const run = (args) => {
    calls.push(args);
    const operation = `${args[0]} ${args[1]}`;
    if (operation === "sts get-caller-identity") return JSON.stringify({ Account: "368992683803", Arn: callerArn });
    if (operation === "iam get-role") return JSON.stringify({ Role: { RoleName: NORMAL_DEPLOYER_POLICY.role, Arn: roleArn } });
    if (operation === "iam list-role-policies") return JSON.stringify({ PolicyNames: names, IsTruncated: false });
    if (operation === "iam list-attached-role-policies") return JSON.stringify({ AttachedPolicies: attached, IsTruncated: false });
    if (operation === "iam get-role-policy") return JSON.stringify({ RoleName: NORMAL_DEPLOYER_POLICY.role, PolicyName: NORMAL_DEPLOYER_POLICY.policyName, PolicyDocument: live });
    if (operation === "iam put-role-policy") { if (apply) live = JSON.parse(args[args.indexOf("--policy-document") + 1]); return ""; }
    throw new Error(`Unexpected command: ${operation}`);
  };
  return { run, calls, live: () => live };
}

test("exact reviewed predecessor converges once to the alarm-read policy and verifies readback", () => {
  const value = fixture();
  const result = convergeNormalDeployerPolicy({ run: value.run, sourceSha: "a".repeat(40) });
  assert.equal(result.iamWrites, 1);
  assert.equal(result.predecessorPolicySha256, NORMAL_DEPLOYER_POLICY.predecessorSha256);
  assert.equal(result.policySha256, NORMAL_DEPLOYER_POLICY.targetSha256);
  assert.equal(value.calls.filter(([service, operation]) => service === "iam" && operation === "put-role-policy").length, 1);
  assert.equal(digest(value.live()), NORMAL_DEPLOYER_POLICY.targetSha256);
  assert.ok(target.Statement.some(({ Action }) => Action === "cloudwatch:DescribeAlarms"));
});

test("already-converged policy is read-only and still verifies", () => {
  const value = fixture({ policy: target });
  assert.equal(convergeNormalDeployerPolicy({ run: value.run, sourceSha: "a".repeat(40) }).iamWrites, 0);
  assert.equal(value.calls.some(([service, operation]) => service === "iam" && operation === "put-role-policy"), false);
});

test("unknown predecessor, privilege expansion, identity drift, and unrelated policies fail before a write", () => {
  const expanded = structuredClone(predecessor);
  expanded.Statement.push({ Effect: "Allow", Action: "iam:*", Resource: "*" });
  for (const value of [
    fixture({ policy: expanded }),
    fixture({ roleArn: "arn:aws:iam::368992683803:role/other" }),
    fixture({ names: [NORMAL_DEPLOYER_POLICY.policyName, "Other"] }),
    fixture({ attached: [{ PolicyName: "Other", PolicyArn: "arn:aws:iam::aws:policy/ReadOnlyAccess" }] }),
    fixture({ callerArn: "arn:aws:iam::368992683803:user/other" }),
  ]) {
    assert.throws(() => convergeNormalDeployerPolicy({ run: value.run, sourceSha: "a".repeat(40) }));
    assert.equal(value.calls.some(([service, operation]) => service === "iam" && operation === "put-role-policy"), false);
  }
});

test("missing exact readback fails closed after the single bounded write", () => {
  const value = fixture({ apply: false });
  assert.throws(() => convergeNormalDeployerPolicy({ run: value.run, sourceSha: "a".repeat(40) }), /readback/);
  assert.equal(value.calls.filter(([service, operation]) => service === "iam" && operation === "put-role-policy").length, 1);
});

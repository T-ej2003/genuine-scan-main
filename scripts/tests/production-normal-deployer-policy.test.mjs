import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { digest } from "../aws/component-iam-installation-contract.mjs";
import { NORMAL_DEPLOYER_POLICY, convergeNormalDeployerPolicy } from "../aws/converge-production-normal-deployer-policy.mjs";

const target = JSON.parse(fs.readFileSync("infra/aws/terraform/production-component-deployment-state/normal-deployer-policy.json", "utf8"));
const predecessor = structuredClone(target);
predecessor.Statement = predecessor.Statement.filter(({ Sid }) => !["ReadClientIpTrustTopology", "ReadCloudFrontOriginPrefixListEntries", "RollbackHistoricalBackendPredecessor"].includes(Sid));
assert.equal(digest(predecessor), NORMAL_DEPLOYER_POLICY.predecessorSha256);
assert.equal(digest(target), NORMAL_DEPLOYER_POLICY.targetSha256);
const discoveryActions = [
  "ec2:DescribeManagedPrefixLists",
  "ec2:GetManagedPrefixListEntries",
  "ec2:DescribeSubnets",
  "elasticloadbalancing:DescribeTargetGroups",
  "elasticloadbalancing:DescribeLoadBalancers",
];

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

test("exact reviewed predecessor converges once to topology reads and bounded historical-backend rollback", () => {
  const value = fixture();
  const result = convergeNormalDeployerPolicy({ run: value.run, sourceSha: "a".repeat(40) });
  assert.equal(result.iamWrites, 1);
  assert.equal(result.predecessorPolicySha256, NORMAL_DEPLOYER_POLICY.predecessorSha256);
  assert.equal(result.policySha256, NORMAL_DEPLOYER_POLICY.targetSha256);
  assert.equal(value.calls.filter(([service, operation]) => service === "iam" && operation === "put-role-policy").length, 1);
  assert.equal(digest(value.live()), NORMAL_DEPLOYER_POLICY.targetSha256);
  assert.deepEqual(target.Statement.find(({ Sid }) => Sid === "ReadClientIpTrustTopology"), {
    Sid: "ReadClientIpTrustTopology",
    Effect: "Allow",
    Action: discoveryActions.filter((action) => action !== "ec2:GetManagedPrefixListEntries"),
    Resource: "*",
    Condition: { StringEquals: { "aws:RequestedRegion": "eu-west-2" } },
  });
  assert.deepEqual(target.Statement.find(({ Sid }) => Sid === "ReadCloudFrontOriginPrefixListEntries"), {
    Sid: "ReadCloudFrontOriginPrefixListEntries",
    Effect: "Allow",
    Action: "ec2:GetManagedPrefixListEntries",
    Resource: "arn:aws:ec2:eu-west-2:aws:prefix-list/*",
    Condition: { StringEquals: { "aws:RequestedRegion": "eu-west-2" } },
  });
  assert.deepEqual(target.Statement.find(({ Sid }) => Sid === "RollbackHistoricalBackendPredecessor"), {
    Sid: "RollbackHistoricalBackendPredecessor",
    Effect: "Allow",
    Action: "ecs:UpdateService",
    Resource: "arn:aws:ecs:eu-west-2:368992683803:service/mscqr-prod-euw2-main/mscqr-backend-servi-euw2",
    Condition: {
      StringEquals: { "aws:RequestedRegion": "eu-west-2" },
      ArnEquals: { "ecs:cluster": "arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main" },
      ArnLikeIfExists: { "ecs:task-definition": "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:*" },
    },
  });
});

test("topology discovery adds only five read actions and no representative mutation authority", () => {
  const targetActions = target.Statement.flatMap(({ Action }) => Array.isArray(Action) ? Action : [Action]);
  const predecessorActions = predecessor.Statement.flatMap(({ Action }) => Array.isArray(Action) ? Action : [Action]);
  assert.deepEqual(targetActions.filter((action) => !predecessorActions.includes(action)).sort(), [...discoveryActions].sort());
  for (const action of [
    "ec2:RunInstances", "ec2:CreateSubnet", "ec2:AuthorizeSecurityGroupIngress", "ec2:CreateManagedPrefixList", "ec2:ModifyManagedPrefixList",
    "elasticloadbalancing:CreateLoadBalancer", "elasticloadbalancing:ModifyLoadBalancerAttributes", "elasticloadbalancing:CreateTargetGroup", "elasticloadbalancing:ModifyTargetGroup",
    "iam:PutRolePolicy", "iam:AttachRolePolicy",
  ]) assert.equal(targetActions.includes(action), false, `${action} must remain denied.`);
  assert.deepEqual(
    target.Statement.filter(({ Sid }) => !["ReadClientIpTrustTopology", "ReadCloudFrontOriginPrefixListEntries", "RollbackHistoricalBackendPredecessor"].includes(Sid)),
    predecessor.Statement,
    "existing bounded permissions changed",
  );
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

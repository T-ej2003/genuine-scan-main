import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import yaml from "js-yaml";
import { assertBackendMetadata, assertInitialOwnership, assertInventoryReady, assertMonitorBoundaryDocument, assertPartialOwnershipState, assertPartialRefresh, assertPlan, assertSnsPolicyForOwnership, assertSnsPolicyPredecessor, checkSnsPolicy, STATE } from "../aws/production-ecr-infrastructure-gate.mjs";
import { assertEcrAssumedRole } from "../aws/production-ecr-image-monitor.mjs";

const stack = "infra/aws/terraform/production-ecr-protection";
const read = name => fs.readFileSync(`${stack}/${name}`, "utf8");
const managed = [
  "aws_ecr_repository_policy.backend_delete_guard", "aws_ecr_repository_policy.web_delete_guard", "aws_ecr_repository_policy.worker_delete_guard",
  "aws_iam_role.ecr_monitor", "aws_iam_role_policy.ecr_monitor",
  "aws_sns_topic_policy.ecr_alerts", "aws_cloudwatch_event_rule.ecr_protection_change", "aws_cloudwatch_event_rule.ecr_image_action",
  "aws_cloudwatch_event_target.ecr_protection_change", "aws_cloudwatch_event_target.ecr_image_action", "aws_cloudwatch_metric_alarm.ecr_protection",
];
const basePlan = () => ({
  errored: false, applyable: true, resource_drift: [],
  configuration: { provider_config: { aws: { full_name: "registry.terraform.io/hashicorp/aws", expressions: {
    allowed_account_ids: { constant_value: [STATE.account] }, region: { constant_value: STATE.region },
  } } }, root_module: { resources: [...managed.map(address => ({ address, mode: "managed" })),
    ...["backend", "web", "worker"].map(name => ({ address: `data.aws_ecr_repository.${name}`, mode: "data" })),
    { address: "data.aws_sns_topic.alerts", mode: "data" }] } },
  resource_changes: [], prior_state: { values: { root_module: { resources: [] } } },
});

test("ECR inventory and infrastructure gates require the exact assumed role and one session segment", () => {
  for (const role of ["mscqr-production-ecr-monitor", "mscqr-production-ecr-infrastructure-plan", "mscqr-production-ecr-infrastructure-apply"]) {
    const valid = { Account: STATE.account, Arn: `arn:aws:sts::${STATE.account}:assumed-role/${role}/run-123` };
    assert.doesNotThrow(() => assertEcrAssumedRole(valid, role));
    for (const caller of [
      { ...valid, Account: "000000000000" },
      { ...valid, Arn: valid.Arn.replace(STATE.account, "000000000000") },
      { ...valid, Arn: valid.Arn.replace(`/${role}/`, "/mscqr-production-ecr-other/") },
      { ...valid, Arn: valid.Arn.replace(`/${role}/`, `/${role}-extra/`) },
      { ...valid, Arn: valid.Arn.replace("/run-123", "/") },
      { ...valid, Arn: `${valid.Arn}/extra` },
      { ...valid, Arn: `arn:aws:iam::${STATE.account}:role/${role}` },
      { ...valid, Arn: null },
    ]) assert.throws(() => assertEcrAssumedRole(caller, role));
  }
  assert.throws(() => assertEcrAssumedRole({ Account: STATE.account, Arn: `arn:aws:sts::${STATE.account}:assumed-role/mscqr-production-ecr-monitor/run` }, "mscqr-production-ecr-monitor/other"), /Unreviewed/);
  assert.throws(() => checkSnsPolicy("mscqr-production-ecr-monitor"), /Wrong SNS inspection role/);
});

test("isolated backend and ownership exclude the broad root and existing repositories", () => {
  assertBackendMetadata({ backend: { type: "s3", config: { ...STATE, encrypt: true, use_lockfile: true, allowed_account_ids: [STATE.account] } } });
  assert.throws(() => assertBackendMetadata({ backend: { type: "s3", config: { ...STATE, key: "root.tfstate" } } }));
  assertPlan(basePlan());
  assert.throws(() => assertPlan({ ...basePlan(), configuration: { ...basePlan().configuration, root_module: { resources: [...basePlan().configuration.root_module.resources, { address: "aws_ecs_service.backend", mode: "managed" }] } } }), /scope changed/);
  assert.throws(() => assertPlan({ ...basePlan(), resource_changes: [{ address: managed[0], mode: "managed", provider_name: "registry.terraform.io/hashicorp/aws", change: { actions: ["delete"] } }] }), /Destructive/);
  assert.throws(() => assertPlan({ ...basePlan(), resource_drift: [{}] }), /recorded apply/);
  assert.match(read("main.tf"), /data "aws_ecr_repository" "backend"/);
  assert.match(read("main.tf"), /data "aws_sns_topic" "alerts"/);
  assert.doesNotMatch(read("main.tf") + read("monitor.tf"), /resource "aws_(?:ecr_repository|sns_topic|ecs_service|ecr_lifecycle_policy)"/);
  const root = fs.readFileSync("infra/aws/terraform/main.tf", "utf8");
  assert.doesNotMatch(root, /resource "aws_ecr_repository_policy"/);
  assert.doesNotMatch(root, /aws_ecr_lifecycle_policy/);
  const handoff = fs.readFileSync("infra/aws/terraform/ecr-protection-handoff.tf", "utf8");
  for (const address of managed) assert.ok(handoff.includes(`from = ${address}`));
  assert.equal((handoff.match(/destroy = false/g) || []).length, managed.length + 1); // Legacy publisher policy is relinquished without new IAM ownership.
});

test("the exact failed apply may continue, while substituted or ambiguous state fails closed", () => {
  const resource = (type, name, ids) => ({ mode: "managed", type, name, instances: ids.map(([index_key, id]) => ({
    ...(index_key === null ? {} : { index_key }), attributes: { id },
  })) });
  const topic = "arn:aws:sns:eu-west-2:368992683803:mscqr-prod-alerts";
  const rules = ["ecr_protection_change", "ecr_image_action"];
  const names = ["mscqr-production-ecr-protection-change", "mscqr-production-ecr-image-action"];
  const state = { version: 4, lineage: "578568c5-ffb1-aa44-c941-6f2a4a17c838", serial: 1, resources: [
    resource("aws_iam_role", "ecr_monitor", [[null, "mscqr-production-ecr-monitor"]]),
    resource("aws_iam_role_policy", "ecr_monitor", [[null, "mscqr-production-ecr-monitor:mscqr-production-ecr-monitor"]]),
    resource("aws_sns_topic_policy", "ecr_alerts", [[null, topic]]),
    ...rules.map((key, index) => resource("aws_cloudwatch_event_rule", key, [[null, names[index]]])),
    ...rules.map((key, index) => resource("aws_cloudwatch_event_target", key, [[null, `${names[index]}-existing-production-alerts`]])),
    resource("aws_cloudwatch_metric_alarm", "ecr_protection", ["critical", "high", "warning", "unknown"].map(name => [name, `mscqr-production-ecr-${name}`])),
  ] };
  assert.doesNotThrow(() => assertPartialOwnershipState(state));
  assert.throws(() => assertPartialOwnershipState({ ...state, lineage: "replacement" }), /lineage/);
  assert.throws(() => assertPartialOwnershipState({ ...state, serial: 2 }), /serial/);
  assert.throws(() => assertPartialOwnershipState({ ...state, resources: [...state.resources, resource("aws_ecs_service", "backend", [[null, "service"]])] }), /resource count/);
  assert.throws(() => assertPartialOwnershipState({ ...state, resources: state.resources.map(item => item.type === "aws_sns_topic_policy" ? resource(item.type, item.name, [[null, "other-topic"]]) : item) }), /identities/);
  assert.throws(() => assertPartialOwnershipState({ ...state, resources: state.resources.map(item => item.type === "aws_cloudwatch_metric_alarm" ? resource(item.type, item.name, [["critical", "mscqr-production-ecr-critical"]]) : item) }), /instance count/);
  assert.throws(() => assertPartialOwnershipState({ ...state, resources: state.resources.map(item => item.type === "aws_iam_role" ? { ...item, module: "rogue" } : item) }), /unexpected instance/);
});

test("only the provider's observed partial-apply normalization may accompany three ECR creates", () => {
  const addresses = [
    "aws_iam_role.ecr_monitor", "aws_iam_role_policy.ecr_monitor", "aws_sns_topic_policy.ecr_alerts",
    "aws_cloudwatch_event_rule.ecr_protection_change", "aws_cloudwatch_event_rule.ecr_image_action",
    "aws_cloudwatch_event_target.ecr_protection_change", "aws_cloudwatch_event_target.ecr_image_action",
    ...["critical", "high", "warning", "unknown"].map(name => `aws_cloudwatch_metric_alarm.ecr_protection["${name}"]`),
  ];
  const rolePolicy = JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: "ecr:DescribeImages", Resource: "*" }] });
  const prior = addresses.map(address => ({ address, mode: "managed", values: address === "aws_iam_role_policy.ecr_monitor" ? { policy: rolePolicy } : {} }));
  const beforeRole = { id: "mscqr-production-ecr-monitor", inline_policy: [] };
  const role = { address: "aws_iam_role.ecr_monitor", change: { actions: ["update"], before: beforeRole,
    after: { ...beforeRole, inline_policy: [{ name: "mscqr-production-ecr-monitor", policy: rolePolicy }] } } };
  const alarms = ["critical", "high", "warning", "unknown"].map(name => {
    const before = { id: `mscqr-production-ecr-${name}`, dimensions: null, insufficient_data_actions: null };
    return { address: `aws_cloudwatch_metric_alarm.ecr_protection["${name}"]`, change: { actions: ["update"], before,
      after: { ...before, dimensions: {}, insufficient_data_actions: [] } } };
  });
  const plan = { prior_state: { values: { root_module: { resources: prior } } }, resource_drift: [role, ...alarms],
    resource_changes: ["backend", "web", "worker"].map(name => ({ address: `aws_ecr_repository_policy.${name}_delete_guard`, mode: "managed", change: { actions: ["create"] } })) };
  assert.doesNotThrow(() => assertPartialRefresh(plan));
  assert.throws(() => assertPartialRefresh({ ...plan, resource_drift: [role, { ...alarms[0], change: { ...alarms[0].change, after: { ...alarms[0].change.after, threshold: 9 } } }, ...alarms.slice(1)] }), /Unexpected alarm drift/);
  assert.throws(() => assertPartialRefresh({ ...plan, resource_changes: [...plan.resource_changes, { address: "aws_iam_role.ecr_monitor", mode: "managed", change: { actions: ["update"] } }] }), /already applied/);
  assert.throws(() => assertPartialRefresh({ ...plan, prior_state: { values: { root_module: { resources: prior.slice(1) } } } }), /recorded apply/);
});

test("protected inventory cannot authorize an empty or unreadable rollout", () => {
  const inventory = ["mscqr-backend", "mscqr-web", "mscqr-worker"].map(repository => ({ repository }));
  assert.doesNotThrow(() => assertInventoryReady(inventory, []));
  assert.throws(() => assertInventoryReady(inventory.slice(0, 2), []), /worker/);
  assert.throws(() => assertInventoryReady(inventory, [{ severity: "UNKNOWN" }]), /absent/);
  assert.throws(() => assertInventoryReady([], []), /empty/);
  assert.throws(() => assertSnsPolicyPredecessor({ Statement: [] }), /changed/);
  assert.doesNotThrow(() => assertInitialOwnership({ state: "ABSENT", resources: { monitorRole: "ABSENT" } }));
  assert.throws(() => assertInitialOwnership({ state: "ABSENT", resources: { monitorRole: "PRESENT" } }), /already exists/);
});

test("SNS import preserves the reviewed default statement and exact EventBridge rules", () => {
  const original = {
    Sid: "__default_statement_ID", Effect: "Allow", Principal: { AWS: "*" },
    Action: ["SNS:Publish", "SNS:RemovePermission", "SNS:SetTopicAttributes", "SNS:DeleteTopic", "SNS:ListSubscriptionsByTopic", "SNS:GetTopicAttributes", "SNS:AddPermission", "SNS:Subscribe"],
    Resource: "arn:aws:sns:eu-west-2:368992683803:mscqr-prod-alerts",
    Condition: { StringEquals: { "AWS:SourceAccount": STATE.account } },
  };
  const grant = {
    Sid: "AllowExactEcrProtectionRules", Effect: "Allow", Principal: { Service: "events.amazonaws.com" }, Action: "sns:Publish",
    Condition: { ArnEquals: { "aws:SourceArn": [
      "arn:aws:events:eu-west-2:368992683803:rule/mscqr-production-ecr-protection-change",
      "arn:aws:events:eu-west-2:368992683803:rule/mscqr-production-ecr-image-action",
    ] }, StringEquals: { "aws:SourceAccount": STATE.account } },
  };
  const plan = basePlan();
  plan.resource_changes = [{ address: "aws_sns_topic_policy.ecr_alerts", mode: "managed", provider_name: "registry.terraform.io/hashicorp/aws",
    change: { actions: ["update"], importing: { id: "arn:aws:sns:eu-west-2:368992683803:mscqr-prod-alerts" }, before: null, after: { arn: "arn:aws:sns:eu-west-2:368992683803:mscqr-prod-alerts", policy: JSON.stringify({ Statement: [original, grant] }) } } }];
  assert.doesNotThrow(() => assertPlan(plan));
  assert.throws(() => assertPlan({ ...plan, resource_changes: [{ ...plan.resource_changes[0], change: { ...plan.resource_changes[0].change, importing: { id: "other" } } }] }));
  assert.throws(() => assertPlan({ ...plan, resource_changes: [{ ...plan.resource_changes[0], address: "aws_ecr_repository_policy.backend_delete_guard" }] }), /Only existing SNS/);
  const managedPolicy = { Version: "2008-10-17", Id: "__default_policy_ID", Statement: [original, { ...grant, Resource: "arn:aws:sns:eu-west-2:368992683803:mscqr-prod-alerts" }] };
  assert.doesNotThrow(() => assertSnsPolicyForOwnership(managedPolicy, "COMPLETE_EXISTING_STATE"));
  assert.throws(() => assertSnsPolicyForOwnership(managedPolicy, "ABSENT_AND_UNOWNED"), /changed/);
  assert.throws(() => assertSnsPolicyForOwnership({ ...managedPolicy, Statement: [original, { ...managedPolicy.Statement[1], Action: "sns:*" }] }, "COMPLETE_EXISTING_STATE"));
  plan.resource_changes[0].change.after.policy = JSON.stringify({ Statement: [original, { ...grant, Action: "s3:*" }] });
  assert.throws(() => assertPlan(plan));
});

test("plan rejects weaker ECR guards and monitor privilege expansion", () => {
  const repositoryGuardSource = read("main.tf");
  for (const action of ["ecr:BatchDeleteImage", "ecr:DeleteRepository", "ecr:PutLifecyclePolicy"]) assert.ok(repositoryGuardSource.includes(action));
  assert.ok(!repositoryGuardSource.includes("ecr:UpdateImageStorageClass"));
  const plan = basePlan();
  const guard = { Statement: [
    { Effect: "Deny", Principal: "*", Resource: "*", Action: ["ecr:BatchDeleteImage", "ecr:DeleteRepository", "ecr:PutLifecyclePolicy"] },
    { Sid: "AllowLegacyPublisherProtectionRead", Effect: "Allow", Principal: { AWS: "arn:aws:iam::368992683803:role/github-actions-mscqr-deploy" }, Resource: "*", Action: "ecr:GetRepositoryPolicy" },
  ] };
  plan.resource_changes = [{ address: "aws_ecr_repository_policy.backend_delete_guard", mode: "managed", provider_name: "registry.terraform.io/hashicorp/aws",
    change: { actions: ["create"], after: { repository: "mscqr-backend", policy: JSON.stringify(guard) } } }];
  assert.doesNotThrow(() => assertPlan(plan));
  plan.resource_changes[0].change.after.policy = JSON.stringify({ Statement: [guard.Statement[0], { ...guard.Statement[1], Action: "ecr:*" }] });
  assert.throws(() => assertPlan(plan), /Publisher repository-policy read/);
  plan.resource_changes = [{ address: "aws_ecr_repository_policy.backend_delete_guard", mode: "managed", provider_name: "registry.terraform.io/hashicorp/aws",
    change: { actions: ["create"], after: { repository: "mscqr-backend", policy: JSON.stringify({ Statement: [{ Effect: "Allow", Action: ["ecr:BatchDeleteImage"], Principal: "*", Resource: "*" }] }) } } }];
  assert.throws(() => assertPlan(plan));
  plan.resource_changes = [{ address: "aws_iam_role_policy.ecr_monitor", mode: "managed", provider_name: "registry.terraform.io/hashicorp/aws",
    change: { actions: ["create"], after: { role: "mscqr-production-ecr-monitor", policy: JSON.stringify({ Statement: [{ Effect: "Allow", Action: "ecr:BatchDeleteImage", Resource: "*" }] }) } } }];
  assert.throws(() => assertPlan(plan), /unreviewed operation/);
  plan.resource_changes = [{ address: "aws_iam_role.ecr_monitor", mode: "managed", provider_name: "registry.terraform.io/hashicorp/aws",
    change: { actions: ["create"], after: { name: "mscqr-production-ecr-monitor", permissions_boundary: null } } }];
  assert.throws(() => assertPlan(plan), /MSCQRProductionEcrMonitorBoundary/);
});

test("plan and apply OIDC roles preserve environment and operation separation", () => {
  const workflow = yaml.load(fs.readFileSync(".github/workflows/production-ecr-protection-infrastructure.yml", "utf8"));
  assert.equal(workflow.on.workflow_dispatch.inputs.source_sha.required, true);
  assert.deepEqual(workflow.concurrency, { group: "production-deploy", "cancel-in-progress": false });
  assert.equal(workflow.jobs.plan.environment, "production-ecr-infrastructure-plan");
  assert.equal(workflow.jobs.apply.environment, "production-ecr-infrastructure-apply");
  assert.equal(workflow.jobs.apply.needs, "plan");
  const source = fs.readFileSync(".github/workflows/production-ecr-protection-infrastructure.yml", "utf8");
  for (const action of source.matchAll(/^\s*- uses: ([^\s#]+)/gm)) assert.match(action[1], /^[\w-]+\/[\w-]+@[a-f0-9]{40}$/);
  assert.match(source, /production-ecr-infrastructure-gate\.mjs boundary/g);
  assert.match(source, /terraform .* plan .* -out=/);
  assert.match(source, /terraform .* apply .*plan\.bin/);
  assert.match(source, /needs\.plan\.outputs\.plan_sha256/);
  assert.doesNotMatch(source, /terraform .* -chdir=infra\/aws\/terraform (?:plan|apply)/);
  const environment = JSON.parse(read("github-environment-contract.json"));
  assert.equal(environment.environments[workflow.jobs.apply.environment].requiredReviewers, true);
  for (const mode of ["plan", "apply"]) {
    const trust = JSON.parse(read(`bootstrap-${mode}-trust.json`));
    const condition = trust.Statement[0].Condition.StringEquals;
    assert.equal(condition["token.actions.githubusercontent.com:sub"], `repo:T-ej2003/genuine-scan-main:environment:production-ecr-infrastructure-${mode}`);
    assert.equal(condition["token.actions.githubusercontent.com:workflow"], workflow.name);
    assert.equal(condition["token.actions.githubusercontent.com:ref"], "refs/heads/main");
    assert.equal(condition["token.actions.githubusercontent.com:repository_id"], "1145608538");
    assert.match(source, new RegExp(`role-to-assume: arn:aws:iam::368992683803:role/mscqr-production-ecr-infrastructure-${mode}`));
  }
  const readPolicy = JSON.parse(read("bootstrap-read-policy.json"));
  const applyPolicy = JSON.parse(read("bootstrap-apply-policy.json"));
  const repositoryRead = readPolicy.Statement.find(item => item.Sid === "ReadExactEcrRepositories");
  assert.ok(repositoryRead.Action.includes("ecr:ListTagsForResource"));
  assert.deepEqual(repositoryRead.Resource, ["mscqr-backend", "mscqr-web", "mscqr-worker"].map(name => `arn:aws:ecr:eu-west-2:368992683803:repository/${name}`));
  const topicRead = readPolicy.Statement.find(item => item.Sid === "ReadExactTopic");
  assert.deepEqual(topicRead.Action, ["sns:GetTopicAttributes", "sns:ListTagsForResource"]);
  assert.equal(topicRead.Resource, "arn:aws:sns:eu-west-2:368992683803:mscqr-prod-alerts");
  assert.ok(readPolicy.Statement.some(item => item.Action === "s3:GetObject" && item.Resource.endsWith(STATE.key)));
  assert.ok(applyPolicy.Statement.some(item => item.Action === "s3:PutObject" && item.Resource.endsWith(STATE.key)));
  assert.ok(!JSON.stringify(readPolicy).includes("ecr:SetRepositoryPolicy"));
  assert.ok(!JSON.stringify(applyPolicy).includes("ecr:PutLifecyclePolicy\",\"Resource\":\"arn:aws:ecr"));
  assert.ok(applyPolicy.Statement.some(item => item.Effect === "Deny" && item.Action.includes("ecs:UpdateService")));
});

test("monitor creation requires a fixed boundary and infrastructure cannot rewrite the legacy publisher role", () => {
  const apply = JSON.parse(read("bootstrap-apply-policy.json"));
  const boundary = JSON.parse(read("bootstrap-monitor-boundary.json"));
  assert.doesNotThrow(() => assertMonitorBoundaryDocument(boundary));
  assert.throws(() => assertMonitorBoundaryDocument({ ...boundary, Statement: boundary.Statement.slice(1) }), /changed/);
  const role = "arn:aws:iam::368992683803:role/mscqr-production-ecr-monitor";
  const boundaryArn = "arn:aws:iam::368992683803:policy/MSCQRProductionEcrMonitorBoundary";
  assert.ok(apply.Statement.filter(statement => [statement.Action].flat().some(action => action.startsWith("iam:")))
    .every(statement => statement.Resource === role));
  for (const action of ["iam:CreateRole", "iam:PutRolePolicy"])
    assert.equal(apply.Statement.find(statement => statement.Action === action)?.Condition?.ArnEquals?.["iam:PermissionsBoundary"], boundaryArn);
  assert.ok(!JSON.stringify(apply).includes("iam:UpdateAssumeRolePolicy") && !JSON.stringify(apply).includes("iam:PassRole") && !JSON.stringify(apply).includes("iam:PutRolePermissionsBoundary"));
  assert.ok(!JSON.stringify(apply).includes("github-actions-mscqr-deploy"));
  assert.ok(boundary.Statement.some(statement => statement.Effect === "Deny" && statement.NotAction && statement.Resource === "*"));
  for (const action of ["ecr:DescribeImages", "dynamodb:GetItem", "s3:GetObject"])
    assert.ok(boundary.Statement.some(statement => statement.Effect === "Deny" && [statement.Action].flat().includes(action) && statement.NotResource));
  assert.ok(boundary.Statement.every(statement => !JSON.stringify(statement).includes("iam:PassRole") && !JSON.stringify(statement).includes("iam:CreateRole")));
  assert.match(read("monitor.tf"), /permissions_boundary\s*=\s*"arn:aws:iam::368992683803:policy\/MSCQRProductionEcrMonitorBoundary"/);
  assert.doesNotMatch(read("monitor.tf"), /legacy_image_publisher_protection_read/);
});

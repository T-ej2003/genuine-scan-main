#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { assertEcrAssumedRole, collectProtectedInventory, createAwsRunner, inspectProtectedImages, verifyEcrManifestChildren } from "./production-ecr-image-monitor.mjs";

export const STACK = "infra/aws/terraform/production-ecr-protection";
export const STATE = Object.freeze({
  bucket: "mscqr-production-terraform-state-368992683803-eu-west-2",
  key: "mscqr/production/ecr-protection/terraform.tfstate",
  region: "eu-west-2",
  account: "368992683803",
});
const managed = new Set([
  "aws_ecr_repository_policy.backend_delete_guard", "aws_ecr_repository_policy.web_delete_guard", "aws_ecr_repository_policy.worker_delete_guard",
  "aws_iam_role.ecr_monitor", "aws_iam_role_policy.ecr_monitor",
  "aws_sns_topic_policy.ecr_alerts", "aws_cloudwatch_event_rule.ecr_protection_change", "aws_cloudwatch_event_rule.ecr_image_action",
  "aws_cloudwatch_event_target.ecr_protection_change", "aws_cloudwatch_event_target.ecr_image_action", "aws_cloudwatch_metric_alarm.ecr_protection",
]);
const dataSources = new Set(["data.aws_ecr_repository.backend", "data.aws_ecr_repository.web", "data.aws_ecr_repository.worker", "data.aws_sns_topic.alerts"]);
const alarmNames = new Set(["critical", "high", "warning", "unknown"]);
const digest = bytes => crypto.createHash("sha256").update(bytes).digest("hex");
const canonical = value => JSON.stringify(value, (_, item) => item && !Array.isArray(item) && typeof item === "object" ? Object.fromEntries(Object.entries(item).sort()) : item);
const SNS_PREDECESSOR_SHA256 = "565388f4a06bcbbab56e98208d9ec00f92f8610977d55b91b83c2e6b92d667ad";
const SNS_DEFAULT_STATEMENT_SHA256 = "2baebecb71ebecd47e4418929ba0ee9fc2b6d96c3bb59362a34fe2f9eb245cfa";
const MONITOR_BOUNDARY_ARN = "arn:aws:iam::368992683803:policy/MSCQRProductionEcrMonitorBoundary";
const managedInstances = new Set([...managed].flatMap(address => address === "aws_cloudwatch_metric_alarm.ecr_protection" ?
  [...alarmNames].map(name => `${address}["${name}"]`) : [address]));
const PARTIAL_LINEAGE = "578568c5-ffb1-aa44-c941-6f2a4a17c838";
const PARTIAL_STATE_VERSION = "WTI2o9W_x0Gsab0UoNys9kKyv5EySuQJ";
const partialIds = new Map([
  ["aws_iam_role.ecr_monitor", "mscqr-production-ecr-monitor"],
  ["aws_iam_role_policy.ecr_monitor", "mscqr-production-ecr-monitor:mscqr-production-ecr-monitor"],
  ["aws_sns_topic_policy.ecr_alerts", "arn:aws:sns:eu-west-2:368992683803:mscqr-prod-alerts"],
  ...["ecr_protection_change", "ecr_image_action"].flatMap((key, index) => {
    const name = ["mscqr-production-ecr-protection-change", "mscqr-production-ecr-image-action"][index];
    return [[`aws_cloudwatch_event_rule.${key}`, name], [`aws_cloudwatch_event_target.${key}`, `${name}-existing-production-alerts`]];
  }),
  ...[...alarmNames].map(name => [`aws_cloudwatch_metric_alarm.ecr_protection["${name}"]`, `mscqr-production-ecr-${name}`]),
]);

function aws(args) {
  return spawnSync("aws", [...args, "--region", STATE.region, "--output", "json", "--no-cli-pager"],
    { encoding: "utf8", timeout: 45000, maxBuffer: 1024 * 1024, env: { ...process.env, AWS_MAX_ATTEMPTS: "2", AWS_CLI_AUTO_PROMPT: "off" } });
}

export function assertInitialOwnership(readbacks) {
  assert.equal(readbacks.state, "ABSENT", "Existing ECR state needs exact state-list verification");
  for (const [name, result] of Object.entries(readbacks.resources))
    assert.equal(result, "ABSENT", `Unowned ECR infrastructure already exists: ${name}`);
}

export function assertPartialOwnershipState(state) {
  assert.equal(state.version, 4);
  assert.equal(state.lineage, PARTIAL_LINEAGE, "ECR Terraform state lineage changed");
  assert.equal(state.serial, 2, "ECR partial state serial changed");
  const resources = (state.resources || []).filter(resource => resource.mode === "managed");
  assert.equal(resources.length, 8, "ECR partial state resource count changed");
  assert.ok(resources.every(resource => !resource.module && resource.instances?.length && resource.instances.every(instance => !instance.deposed)), "ECR partial state has an unexpected instance");
  const instances = resources.flatMap(resource => (resource.instances || []).map(instance => [
    `${resource.type}.${resource.name}${instance.index_key === undefined ? "" : `["${instance.index_key}"]`}`,
    instance.attributes?.id,
  ]));
  assert.equal(instances.length, partialIds.size, "ECR partial state instance count changed");
  assert.deepEqual(new Map(instances), partialIds, "ECR partial state owns unexpected resources or identities");
  assert.ok((state.resources || []).every(resource => resource.mode === "managed" || dataSources.has(`data.${resource.type}.${resource.name}`)), "ECR state has an unrelated data source");
}

export function assertPartialMonitorTrust(state, role) {
  const saved = state.resources.find(resource => resource.type === "aws_iam_role" && resource.name === "ecr_monitor").instances[0].attributes.assume_role_policy;
  assert.equal(canonical(role.AssumeRolePolicyDocument), canonical(JSON.parse(saved)), "Monitor OIDC trust changed since partial apply");
}

export function assertPartialRule(saved, live) {
  assert.deepEqual({
    arn: live.Arn, bus: live.EventBusName, description: live.Description || "", state: live.State,
    pattern: JSON.parse(live.EventPattern || "null"), role: live.RoleArn || "", schedule: live.ScheduleExpression || "",
  }, {
    arn: saved.arn, bus: saved.event_bus_name, description: saved.description, state: saved.state,
    pattern: JSON.parse(saved.event_pattern), role: saved.role_arn, schedule: saved.schedule_expression,
  }, "EventBridge rule changed since partial apply");
}

export function assertPartialAlarm(saved, live) {
  assert.deepEqual({
    arn: live.AlarmArn, actionsEnabled: live.ActionsEnabled, alarmActions: live.AlarmActions || [], okActions: live.OKActions || [],
    insufficientActions: live.InsufficientDataActions || [], comparison: live.ComparisonOperator, evaluations: live.EvaluationPeriods,
    threshold: live.Threshold, datapoints: live.DatapointsToAlarm || 0, dimensions: live.Dimensions || [],
    metric: live.MetricName, namespace: live.Namespace, period: live.Period, statistic: live.Statistic,
    missing: live.TreatMissingData, description: live.AlarmDescription || "", metrics: live.Metrics || [],
    thresholdMetric: live.ThresholdMetricId || "", unit: live.Unit || "", extendedStatistic: live.ExtendedStatistic || "",
    lowSampleCount: live.EvaluateLowSampleCountPercentile || "",
  }, {
    arn: saved.arn, actionsEnabled: saved.actions_enabled, alarmActions: saved.alarm_actions, okActions: saved.ok_actions,
    insufficientActions: saved.insufficient_data_actions || [], comparison: saved.comparison_operator, evaluations: saved.evaluation_periods,
    threshold: saved.threshold, datapoints: saved.datapoints_to_alarm || 0, dimensions: saved.dimensions && Object.keys(saved.dimensions).length ? saved.dimensions : [],
    metric: saved.metric_name, namespace: saved.namespace, period: saved.period, statistic: saved.statistic,
    missing: saved.treat_missing_data, description: saved.alarm_description, metrics: saved.metric_query || [],
    thresholdMetric: saved.threshold_metric_id, unit: saved.unit, extendedStatistic: saved.extended_statistic,
    lowSampleCount: saved.evaluate_low_sample_count_percentiles,
  }, "CloudWatch alarm changed since partial apply");
}

export function assertPartialTarget(saved, live) {
  assert.deepEqual(live, {
    Id: saved.target_id, Arn: saved.arn,
    InputTransformer: { InputPathsMap: saved.input_transformer[0].input_paths, InputTemplate: saved.input_transformer[0].input_template },
  }, "EventBridge target changed since partial apply");
}

function checkPartialLiveOwnership(state) {
  const read = (name, args) => {
    const result = aws(args);
    assert.ok(!result.error && result.status === 0, `ECR partial-state ${name} read failed`);
    return JSON.parse(result.stdout);
  };
  const role = read("monitor role", ["iam", "get-role", "--role-name", "mscqr-production-ecr-monitor"]).Role;
  assert.equal(role.Arn, "arn:aws:iam::368992683803:role/mscqr-production-ecr-monitor");
  assert.equal(role.PermissionsBoundary?.PermissionsBoundaryArn, MONITOR_BOUNDARY_ARN);
  assertPartialMonitorTrust(state, role);
  const policy = read("monitor policy", ["iam", "get-role-policy", "--role-name", "mscqr-production-ecr-monitor", "--policy-name", "mscqr-production-ecr-monitor"]);
  assert.equal(policy.RoleName, role.RoleName);
  const statePolicy = state.resources.find(resource => resource.type === "aws_iam_role_policy" && resource.name === "ecr_monitor").instances[0].attributes.policy;
  assert.equal(canonical(policy.PolicyDocument), canonical(JSON.parse(statePolicy)), "Monitor IAM policy changed since partial apply");
  const topic = read("SNS policy", ["sns", "get-topic-attributes", "--topic-arn", partialIds.get("aws_sns_topic_policy.ecr_alerts")]);
  assertSnsPolicyForOwnership(JSON.parse(topic.Attributes.Policy), "PARTIAL_EXISTING_STATE");
  for (const name of ["mscqr-production-ecr-protection-change", "mscqr-production-ecr-image-action"]) {
    const rule = read(name, ["events", "describe-rule", "--name", name]);
    const key = name === "mscqr-production-ecr-protection-change" ? "ecr_protection_change" : "ecr_image_action";
    const savedRule = state.resources.find(resource => resource.type === "aws_cloudwatch_event_rule" && resource.name === key).instances[0].attributes;
    assertPartialRule(savedRule, rule);
    const targets = read(`${name} targets`, ["events", "list-targets-by-rule", "--rule", name]).Targets;
    assert.equal(targets?.length, 1, "EventBridge target changed since partial apply");
    const target = targets[0];
    const savedTarget = state.resources.find(resource => resource.type === "aws_cloudwatch_event_target" && resource.name === key).instances[0].attributes;
    assertPartialTarget(savedTarget, target);
  }
  const names = [...alarmNames].map(name => `mscqr-production-ecr-${name}`);
  const alarms = read("alarms", ["cloudwatch", "describe-alarms", "--alarm-names", ...names]);
  assert.deepEqual(new Set((alarms.MetricAlarms || []).map(alarm => alarm.AlarmName)), new Set(names));
  for (const alarm of alarms.MetricAlarms) {
    const saved = state.resources.find(resource => resource.type === "aws_cloudwatch_metric_alarm" && resource.name === "ecr_protection")
      .instances.find(instance => instance.attributes.alarm_name === alarm.AlarmName).attributes;
    assertPartialAlarm(saved, alarm);
  }
  for (const name of ["mscqr-backend", "mscqr-web", "mscqr-worker"]) {
    const policy = aws(["ecr", "get-repository-policy", "--repository-name", name]);
    assert.ok(!policy.error && policy.status !== 0 && /RepositoryPolicyNotFoundException/.test(policy.stderr || ""), `ECR policy ${name} changed during partial apply`);
  }
}

export function checkStateOwnership() {
  const head = aws(["s3api", "head-object", "--bucket", STATE.bucket, "--key", STATE.key, "--expected-bucket-owner", STATE.account]);
  if (head.error) throw head.error;
  if (head.status === 0) {
    const pulled = spawnSync("terraform", [`-chdir=${STACK}`, "state", "pull"], { encoding: "utf8", timeout: 45000, maxBuffer: 1024 * 1024 });
    assert.ok(!pulled.error && pulled.status === 0, "Existing ECR Terraform state cannot be authenticated");
    const current = JSON.parse(pulled.stdout);
    assert.equal(current.lineage, PARTIAL_LINEAGE, "ECR Terraform state lineage changed");
    const state = spawnSync("terraform", [`-chdir=${STACK}`, "state", "list"], { encoding: "utf8", timeout: 45000, maxBuffer: 1024 * 1024 });
    assert.ok(!state.error && state.status === 0, "Existing ECR Terraform state cannot be authenticated");
    const addresses = new Set(state.stdout.trim().split("\n").filter(line => line && !line.startsWith("data.")));
    if (addresses.size === partialIds.size && [...addresses].every(address => partialIds.has(address))) {
      assert.equal(JSON.parse(head.stdout).VersionId, PARTIAL_STATE_VERSION, "ECR partial state object was replaced");
      assertPartialOwnershipState(current);
      checkPartialLiveOwnership(current);
      const after = aws(["s3api", "head-object", "--bucket", STATE.bucket, "--key", STATE.key, "--expected-bucket-owner", STATE.account]);
      assert.ok(!after.error && after.status === 0 && JSON.parse(after.stdout).VersionId === PARTIAL_STATE_VERSION, "ECR partial state changed during readback");
      return "PARTIAL_EXISTING_STATE";
    }
    assert.deepEqual(addresses, managedInstances, "Existing ECR Terraform state owns an unrelated resource");
    return "COMPLETE_EXISTING_STATE";
  }
  assert.match(head.stderr || "", /(?:404|Not Found)/, "ECR state read failed ambiguously");
  const absent = (name, args, pattern) => {
    const result = aws(args);
    if (result.error) throw result.error;
    assert.ok(result.status !== 0 && pattern.test(result.stderr || ""), `Unowned ECR infrastructure already exists or cannot be read: ${name}`);
    return "ABSENT";
  };
  const resources = {};
  for (const name of ["mscqr-backend", "mscqr-web", "mscqr-worker"])
    resources[`repository-policy:${name}`] = absent(name, ["ecr", "get-repository-policy", "--repository-name", name], /RepositoryPolicyNotFoundException/);
  resources.monitorRole = absent("monitor-role", ["iam", "get-role", "--role-name", "mscqr-production-ecr-monitor"], /NoSuchEntity/);
  for (const name of ["mscqr-production-ecr-protection-change", "mscqr-production-ecr-image-action"])
    resources[`event-rule:${name}`] = absent(name, ["events", "describe-rule", "--name", name], /ResourceNotFoundException/);
  const alarms = aws(["cloudwatch", "describe-alarms", "--alarm-names", ...[...alarmNames].map(name => `mscqr-production-ecr-${name}`)]);
  assert.ok(!alarms.error && alarms.status === 0, "CloudWatch alarm ownership read failed");
  assert.deepEqual(JSON.parse(alarms.stdout).MetricAlarms || [], [], "Unowned ECR metric alarm exists");
  assert.deepEqual(JSON.parse(alarms.stdout).CompositeAlarms || [], [], "Unowned ECR composite alarm exists");
  assertInitialOwnership({ state: "ABSENT", resources });
  return "ABSENT_AND_UNOWNED";
}

export function assertSnsPolicyPredecessor(policy) {
  assert.equal(digest(canonical(policy)), SNS_PREDECESSOR_SHA256, "SNS topic policy changed since reviewed predecessor");
  assert.deepEqual(policy.Statement.map(item => item.Sid), ["__default_statement_ID"]);
}

export function assertSnsPolicyForOwnership(policy, ownership) {
  if (ownership === "ABSENT_AND_UNOWNED") return assertSnsPolicyPredecessor(policy);
  assert.ok(["COMPLETE_EXISTING_STATE", "PARTIAL_EXISTING_STATE"].includes(ownership), "Unrecognized ECR state ownership");
  assert.equal(policy.Version, "2008-10-17");
  assert.equal(policy.Id, "__default_policy_ID");
  assert.deepEqual(policy.Statement.map(item => item.Sid), ["__default_statement_ID", "AllowExactEcrProtectionRules"]);
  assert.equal(digest(canonical(policy.Statement[0])), SNS_DEFAULT_STATEMENT_SHA256, "Managed SNS default permission changed");
  assert.deepEqual(policy.Statement[1], {
    Sid: "AllowExactEcrProtectionRules", Effect: "Allow", Principal: { Service: "events.amazonaws.com" },
    Action: "sns:Publish", Resource: "arn:aws:sns:eu-west-2:368992683803:mscqr-prod-alerts",
    Condition: {
      ArnEquals: { "aws:SourceArn": [
        "arn:aws:events:eu-west-2:368992683803:rule/mscqr-production-ecr-protection-change",
        "arn:aws:events:eu-west-2:368992683803:rule/mscqr-production-ecr-image-action",
      ] },
      StringEquals: { "aws:SourceAccount": STATE.account },
    },
  }, "Managed SNS EventBridge permission changed");
}

export function assertMonitorBoundaryDocument(document) {
  assert.deepEqual(document, JSON.parse(fs.readFileSync(`${STACK}/bootstrap-monitor-boundary.json`, "utf8")), "Monitor permissions boundary changed");
}

export function checkMonitorBoundary() {
  const policy = aws(["iam", "get-policy", "--policy-arn", MONITOR_BOUNDARY_ARN]);
  assert.ok(!policy.error && policy.status === 0, "Monitor permissions boundary is not installed");
  const metadata = JSON.parse(policy.stdout).Policy;
  assert.equal(metadata?.Arn, MONITOR_BOUNDARY_ARN);
  const version = aws(["iam", "get-policy-version", "--policy-arn", MONITOR_BOUNDARY_ARN, "--version-id", metadata.DefaultVersionId]);
  assert.ok(!version.error && version.status === 0, "Monitor permissions boundary version cannot be read");
  assertMonitorBoundaryDocument(JSON.parse(version.stdout).PolicyVersion?.Document);
}

export function checkSnsPolicy(role, ownership) {
  assert.ok(["mscqr-production-ecr-infrastructure-plan", "mscqr-production-ecr-infrastructure-apply"].includes(role), "Wrong SNS inspection role");
  ownership ??= checkStateOwnership();
  const caller = JSON.parse(createAwsRunner()(["sts", "get-caller-identity"]));
  assertEcrAssumedRole(caller, role);
  const result = spawnSync("aws", ["sns", "get-topic-attributes", "--topic-arn", "arn:aws:sns:eu-west-2:368992683803:mscqr-prod-alerts", "--region", STATE.region, "--output", "json", "--no-cli-pager"],
    { encoding: "utf8", timeout: 45000, maxBuffer: 1024 * 1024, env: { ...process.env, AWS_MAX_ATTEMPTS: "2", AWS_CLI_AUTO_PROMPT: "off" } });
  assert.ok(!result.error && result.status === 0, `SNS policy read failed: ${result.error?.code || result.status}`);
  assertSnsPolicyForOwnership(JSON.parse(JSON.parse(result.stdout).Attributes.Policy), ownership);
}

export function assertBackendMetadata(metadata) {
  assert.equal(metadata.backend?.type, "s3");
  const config = metadata.backend.config;
  for (const [key, value] of Object.entries({ bucket: STATE.bucket, key: STATE.key, region: STATE.region, encrypt: true, use_lockfile: true }))
    assert.deepEqual(config[key], value, `Wrong ECR infrastructure backend ${key}`);
  assert.deepEqual(config.allowed_account_ids, [STATE.account]);
  for (const key of ["profile", "assume_role", "assume_role_with_web_identity", "access_key", "secret_key", "token", "endpoint", "endpoints", "skip_credentials_validation"])
    assert.ok(!config[key], `Unexpected backend credential or endpoint: ${key}`);
}

export function assertPartialRefresh(plan) {
  const prior = plan.prior_state?.values?.root_module?.resources || [];
  const owned = prior.filter(resource => resource.mode === "managed");
  assert.equal(owned.length, partialIds.size, "Partial refresh is not bound to the recorded apply");
  assert.deepEqual(new Set(owned.map(resource => resource.address)), new Set(partialIds.keys()));
  const drifts = plan.resource_drift || [];
  assert.equal(drifts.length, 5, "Unexpected ECR partial-state drift");
  const expected = new Set(["aws_iam_role.ecr_monitor", ...[...alarmNames].map(name => `aws_cloudwatch_metric_alarm.ecr_protection["${name}"]`)]);
  assert.deepEqual(new Set(drifts.map(drift => drift.address)), expected);
  for (const drift of drifts) {
    assert.deepEqual(drift.change.actions, ["update"]);
    const before = drift.change.before;
    const after = drift.change.after;
    if (drift.address === "aws_iam_role.ecr_monitor") {
      const policy = owned.find(resource => resource.address === "aws_iam_role_policy.ecr_monitor").values.policy;
      assert.deepEqual(before.inline_policy, []);
      assert.deepEqual(after.inline_policy?.map(item => item.name), ["mscqr-production-ecr-monitor"]);
      assert.equal(canonical(JSON.parse(after.inline_policy[0].policy)), canonical(JSON.parse(policy)));
      assert.deepEqual(after, { ...before, inline_policy: after.inline_policy }, "Unexpected monitor role drift");
    } else {
      assert.equal(before.dimensions, null);
      assert.equal(before.insufficient_data_actions, null);
      assert.deepEqual(after, { ...before, dimensions: {}, insufficient_data_actions: [] }, "Unexpected alarm drift");
    }
  }
  const changes = (plan.resource_changes || []).filter(change => change.mode === "managed" && change.change.actions.join(",") !== "no-op");
  assert.deepEqual(new Set(changes.map(change => change.address)), new Set([
    "aws_ecr_repository_policy.backend_delete_guard", "aws_ecr_repository_policy.web_delete_guard", "aws_ecr_repository_policy.worker_delete_guard",
  ]), "Partial continuation would change already applied resources");
  assert.ok(changes.every(change => change.change.actions.join(",") === "create"), "Partial continuation would replace a resource");
}

export function assertPlan(plan) {
  assert.equal(plan.errored, false);
  assert.equal(plan.applyable, true);
  if ((plan.resource_drift || []).length) assertPartialRefresh(plan);
  const providers = plan.configuration?.provider_config;
  assert.deepEqual(Object.keys(providers || {}), ["aws"]);
  assert.equal(providers.aws.full_name, "registry.terraform.io/hashicorp/aws");
  assert.deepEqual(providers.aws.expressions.allowed_account_ids.constant_value, [STATE.account]);
  assert.equal(providers.aws.expressions.region.constant_value, STATE.region);
  const root = plan.configuration.root_module;
  assert.equal(Object.keys(root.module_calls || {}).length, 0, "Nested Terraform modules are outside ECR scope");
  const configured = (root.resources || []).filter(resource => resource.mode === "managed");
  assert.deepEqual(new Set(configured.map(resource => resource.address)), managed, "Managed ECR resource scope changed");
  assert.deepEqual(new Set((root.resources || []).filter(resource => resource.mode === "data").map(resource => resource.address)), dataSources, "ECR data-source scope changed");
  assert.ok(configured.every(resource => !resource.provisioners?.length), "Provisioners are forbidden");
  for (const change of plan.resource_changes || []) {
    assert.equal(change.provider_name, "registry.terraform.io/hashicorp/aws");
    if (change.mode !== "managed") continue;
    const address = change.address.replace(/\["(?:critical|high|warning|unknown)"\]$/, "");
    assert.ok(managed.has(address), `Unrelated Terraform resource: ${change.address}`);
    if (address === "aws_cloudwatch_metric_alarm.ecr_protection") assert.ok(alarmNames.has(change.index), "Unexpected alarm");
    assert.ok(["create", "update", "no-op"].includes(change.change.actions?.join(",")), `Destructive ECR plan action: ${change.address}`);
    if (change.change.importing) assert.equal(change.address, "aws_sns_topic_policy.ecr_alerts", "Only existing SNS policy may be imported");
    if (address === "aws_sns_topic_policy.ecr_alerts") {
      const after = JSON.parse(change.change.after?.policy || "null");
      assert.equal(change.change.after?.arn, "arn:aws:sns:eu-west-2:368992683803:mscqr-prod-alerts");
      assert.ok(Array.isArray(after?.Statement), "SNS policy successor is not authenticated");
      if (change.change.importing) assert.equal(change.change.importing.id, "arn:aws:sns:eu-west-2:368992683803:mscqr-prod-alerts");
      else {
        const before = JSON.parse(change.change.before?.policy || "null");
        assert.ok(Array.isArray(before?.Statement), "SNS policy predecessor is not authenticated");
        for (const statement of before.Statement)
          assert.deepEqual(after.Statement.find(item => item.Sid === statement.Sid), statement, "Existing SNS authorization must be preserved");
      }
      assert.ok(after.Statement.some(item => item.Sid === "__default_statement_ID"), "Existing SNS default permission is missing");
      assert.equal(digest(canonical(after.Statement.find(item => item.Sid === "__default_statement_ID"))), SNS_DEFAULT_STATEMENT_SHA256,
        "SNS default permission changed in the plan");
      const grant = after.Statement.find(item => item.Sid === "AllowExactEcrProtectionRules");
      assert.equal(grant?.Principal?.Service, "events.amazonaws.com");
      assert.equal(grant?.Action, "sns:Publish");
      assert.deepEqual(grant?.Condition?.ArnEquals?.["aws:SourceArn"], [
        "arn:aws:events:eu-west-2:368992683803:rule/mscqr-production-ecr-protection-change",
        "arn:aws:events:eu-west-2:368992683803:rule/mscqr-production-ecr-image-action",
      ]);
      assert.equal(grant?.Condition?.StringEquals?.["aws:SourceAccount"], STATE.account);
    }
    if (address.startsWith("aws_ecr_repository_policy.")) {
      const expected = address.split(".").at(-1).replace("_delete_guard", "");
      assert.equal(change.change.after?.repository, expected === "web" ? "mscqr-web" : `mscqr-${expected}`);
      const policy = JSON.parse(change.change.after?.policy || "null");
      assert.equal(policy?.Statement?.length, 2, "Repository policy adds unrelated permissions");
      const guard = policy.Statement[0];
      assert.equal(guard.Effect, "Deny");
      assert.equal(guard.Principal, "*");
      assert.equal(guard.Resource, "*");
      assert.deepEqual(guard.Action, ["ecr:BatchDeleteImage", "ecr:DeleteRepository", "ecr:PutLifecyclePolicy"]);
      assert.ok(!guard.Condition && !guard.NotAction && !guard.NotResource && !guard.NotPrincipal, "Conditional deletion guard is unsafe");
      assert.deepEqual(policy.Statement[1], {
        Sid: "AllowLegacyPublisherProtectionRead", Effect: "Allow",
        Principal: { AWS: "arn:aws:iam::368992683803:role/github-actions-mscqr-deploy" },
        Resource: "*", Action: "ecr:GetRepositoryPolicy",
      }, "Publisher repository-policy read is not exact");
    }
    if (address === "aws_iam_role.ecr_monitor") {
      assert.equal(change.change.after?.name, "mscqr-production-ecr-monitor");
      assert.equal(change.change.after?.permissions_boundary, MONITOR_BOUNDARY_ARN);
      const trust = JSON.parse(change.change.after?.assume_role_policy || "null");
      assert.equal(trust?.Statement?.length, 1);
      const statement = trust.Statement[0];
      assert.equal(statement.Principal?.Federated, "arn:aws:iam::368992683803:oidc-provider/token.actions.githubusercontent.com");
      assert.equal(statement.Action, "sts:AssumeRoleWithWebIdentity");
      assert.deepEqual(statement.Condition?.StringEquals, {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": "repo:T-ej2003/genuine-scan-main:environment:production-ecr-monitor",
        "token.actions.githubusercontent.com:repository_id": "1145608538",
        "token.actions.githubusercontent.com:repository_owner_id": "183396573",
        "token.actions.githubusercontent.com:ref": "refs/heads/main",
        "token.actions.githubusercontent.com:workflow": "Production ECR Image Monitor",
      });
    }
    if (address === "aws_iam_role_policy.ecr_monitor") {
      assert.equal(change.change.after?.role, "mscqr-production-ecr-monitor");
      const policy = JSON.parse(change.change.after?.policy || "null");
      const allowed = new Set(["ecr:DescribeRepositories", "ecr:DescribeImages", "ecr:BatchGetImage", "ecr:GetLifecyclePolicy", "ecr:GetRepositoryPolicy",
        "ecs:DescribeServices", "ecs:ListTasks", "ecs:DescribeTaskDefinition", "ecs:DescribeTasks", "dynamodb:GetItem", "s3:ListBucket", "s3:GetObject", "cloudwatch:PutMetricData"]);
      assert.ok(policy?.Statement?.every(item => item.Effect === "Allow" && [item.Action].flat().every(action => allowed.has(action))), "Monitor IAM gained an unreviewed operation");
      assert.ok(policy.Statement.some(item => item.Action === "cloudwatch:PutMetricData" && item.Condition?.StringEquals?.["cloudwatch:namespace"] === "MSCQR/ProductionEcrProtection"));
    }
    if (address.startsWith("aws_cloudwatch_event_target.")) {
      assert.equal(change.change.after?.arn, "arn:aws:sns:eu-west-2:368992683803:mscqr-prod-alerts");
      assert.ok(!change.change.after?.role_arn, "SNS EventBridge target must not assume an IAM role");
    }
    if (address === "aws_cloudwatch_metric_alarm.ecr_protection") {
      assert.deepEqual(change.change.after?.alarm_actions, ["arn:aws:sns:eu-west-2:368992683803:mscqr-prod-alerts"]);
      assert.deepEqual(change.change.after?.ok_actions, ["arn:aws:sns:eu-west-2:368992683803:mscqr-prod-alerts"]);
    }
  }
  for (const resource of plan.prior_state?.values?.root_module?.resources || [])
    if (resource.mode === "managed") assert.ok(managed.has(resource.address.replace(/\["(?:critical|high|warning|unknown)"\]$/, "")), "Unrelated prior state owner");
  assert.equal((plan.prior_state?.values?.root_module?.child_modules || []).length, 0);
  return true;
}

export function assertInventoryReady(inventory, findings) {
  assert.ok(inventory.length > 0, "Protected-image inventory is empty");
  for (const repository of ["mscqr-backend", "mscqr-web", "mscqr-worker"])
    assert.ok(inventory.some(image => image.repository === repository), `Missing ${repository} protection dependency`);
  assert.deepEqual(findings, [], "Protected digest is absent, unauthenticated, or unreadable");
}

export function checkInventory(role, run = createAwsRunner()) {
  const inventory = collectProtectedInventory(run, new Date().toISOString(), role);
  const findings = inspectProtectedImages(inventory, (repository, imageDigest) => {
    const response = JSON.parse(run(["ecr", "describe-images", "--repository-name", repository, "--image-ids", `imageDigest=${imageDigest}`]));
    const detail = response.imageDetails?.[0];
    if (detail) verifyEcrManifestChildren(run, repository, detail);
    return detail;
  });
  assertInventoryReady(inventory, findings);
  return { count: inventory.length, inventorySha256: digest(JSON.stringify(inventory)) };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [mode, file, role] = process.argv.slice(2);
  if (mode === "inventory") {
    assert.ok(["mscqr-production-ecr-infrastructure-plan", "mscqr-production-ecr-infrastructure-apply"].includes(file));
    assert.equal(role, undefined);
    process.stdout.write(`${JSON.stringify(checkInventory(file))}\n`);
  } else if (mode === "sns") {
    assert.equal(role, undefined);
    checkSnsPolicy(file);
    process.stdout.write(`${JSON.stringify({ snsPolicy: "AUTHENTICATED" })}\n`);
  } else if (mode === "boundary") {
    assert.equal(file, undefined);
    assert.equal(role, undefined);
    checkMonitorBoundary();
    process.stdout.write(`${JSON.stringify({ monitorBoundaryArn: MONITOR_BOUNDARY_ARN })}\n`);
  } else if (mode === "ownership") {
    assert.equal(file, undefined);
    assert.equal(role, undefined);
    process.stdout.write(`${JSON.stringify({ stateOwnership: checkStateOwnership() })}\n`);
  } else {
    assert.equal(mode, "plan");
    assert.equal(role, undefined);
    assertBackendMetadata(JSON.parse(fs.readFileSync(`${STACK}/.terraform/terraform.tfstate`, "utf8")));
    const bytes = fs.readFileSync(file);
    assertPlan(JSON.parse(bytes));
    process.stdout.write(`${JSON.stringify({ planJsonSha256: digest(bytes) })}\n`);
  }
}

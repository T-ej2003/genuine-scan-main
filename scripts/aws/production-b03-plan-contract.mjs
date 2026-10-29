import assert from "node:assert/strict";
import { gunzipSync } from "node:zlib";
import { canonicalJson, canonicalSha256 } from "./production-green-stage-b-contract.mjs";
import { buildB03ExecutorDefinition } from "../../infra/aws/terraform/lambda/production-rls-approval-broker/b03-approval.mjs";

export const B03_TASK_ADDRESS = "aws_ecs_task_definition.b03[0]";
const arn = /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-production-b03-incremental:[1-9][0-9]*$/;
const equal = (a, b) => assert.equal(canonicalJson(a), canonicalJson(b), "B03 executable plan differs from its fixed definition");
const metadata = new Set(["arn", "arn_without_revision", "id", "revision"]);
const optional = { task_role_arn: null, ipc_mode: null, pid_mode: null, enable_fault_injection: false, track_latest: false,
  ephemeral_storage: [], placement_constraints: [], proxy_configuration: [], inference_accelerator: [] };

export function b03DefinitionFromContainer(container) {
  const entry = container?.entryPoint;
  assert.equal(entry?.length, 12);
  const bytes = gunzipSync(Buffer.from(entry[9], "base64"), { maxOutputLength: 96 * 1024 });
  const pkg = JSON.parse(bytes);
  assert.equal(canonicalSha256(pkg), entry[10]);
  const { packageSha256, ...body } = pkg;
  assert.equal(packageSha256, canonicalSha256(body));
  assert.equal(pkg.kind, "PRODUCTION_B03_INCREMENTAL_PACKAGE"); assert.equal(pkg.schemaVersion, 1);
  assert.equal(pkg.predecessorSourceSha, "d785aa7f1e154f37c0dc621082e3f6c46d5d5aec");
  assert.equal(pkg.mutations?.length, 44);
  return buildB03ExecutorDefinition({ sourceSha: pkg.sourceSha, backendImage: container.image,
    package: pkg, databaseHostname: entry[11] });
}

export function assertB03TaskPlan(change, plan) {
  assert.equal(change.address, B03_TASK_ADDRESS); assert.equal(change.type, "aws_ecs_task_definition");
  assert.ok(change.mode === undefined || change.mode === "managed");
  assert.ok(!change.module_address && !change.module && change.deposed === undefined);
  if (change.provider_name !== undefined) assert.equal(change.provider_name, "registry.terraform.io/hashicorp/aws");
  assert.ok(["[\"create\"]", "[\"no-op\"]"].includes(JSON.stringify(change.change?.actions)), "B03 permits create or retained no-op only");
  assert.ok(!change.change.replace_paths?.length);
  const variables = plan.variables || {};
  assert.equal(variables.account_id?.value, "368992683803");
  assert.equal(variables.aws_region?.value, "eu-west-2");
  assert.equal(variables.deployment_environment?.value, "production");
  assert.match(variables.tooling_sha?.value || "", /^[a-f0-9]{40}$/);
  if (change.change.actions[0] === "create") assert.equal(variables.image_release_sha?.value, variables.tooling_sha.value, "B03 requires exact-source images");
  const definition = JSON.parse(variables.b03_executor_definition_json?.value || "null");
  assert.ok(definition, "B03 fixed definition is missing");
  const expected = b03DefinitionFromContainer(definition.containerDefinitions?.[0]);
  if (change.change.actions[0] === "create") {
    assert.equal(expected.containerDefinitions[0].image, variables.backend_image?.value);
    assert.equal(expected.containerDefinitions[0].environment.find(({ name }) => name === "RELEASE_GIT_SHA")?.value, variables.tooling_sha.value);
  }
  equal(definition, expected);
  const tags = { Environment: "production", ManagedBy: "Terraform", Component: "b03-incremental-release" };
  const required = { family: expected.family, network_mode: expected.networkMode, requires_compatibilities: expected.requiresCompatibilities,
    cpu: expected.cpu, memory: expected.memory, execution_role_arn: expected.executionRoleArn, skip_destroy: true,
    runtime_platform: [{ operating_system_family: "LINUX", cpu_architecture: "X86_64" }], tags, tags_all: tags };
  const check = value => {
    assert.ok(value && typeof value === "object");
    for (const [key, expectedValue] of Object.entries(required)) equal(value[key], expectedValue);
    equal(JSON.parse(value.container_definitions), expected.containerDefinitions);
    assert.equal(value.volume?.length, 1); assert.equal(value.volume[0].name, "executor-tmp");
    for (const [key, item] of Object.entries(value.volume[0])) {
      assert.ok(["name", "host_path", "configure_at_launch", "docker_volume_configuration", "efs_volume_configuration", "fsx_windows_file_server_volume_configuration"].includes(key), "B03 unclassified volume field");
      if (key !== "name") assert.ok(item === null || item === "" || key === "configure_at_launch" && item === false || Array.isArray(item) && item.length === 0, "B03 unexpected volume configuration");
    }
    for (const [key, item] of Object.entries(value)) {
      if (metadata.has(key)) {
        if (item !== null && item !== undefined) {
          if (key === "arn") assert.match(item, arn);
          else if (key === "arn_without_revision") assert.equal(item, "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-b03-incremental");
          else if (key === "revision") assert.ok(Number.isInteger(item) && item > 0);
          else assert.equal(item, expected.family);
        }
      } else if (key in optional) assert.ok(item === null || item === "" && ["task_role_arn", "ipc_mode", "pid_mode"].includes(key) || canonicalJson(item) === canonicalJson(optional[key]), `B03 unsupported ${key}`);
      else assert.ok(key in required || ["container_definitions", "volume"].includes(key), `B03 unclassified field ${key}`);
    }
  };
  check(change.change.after);
  if (change.change.after.arn && change.change.after.revision) assert.equal(Number(change.change.after.arn.split(":").at(-1)), change.change.after.revision);
  if (change.change.actions[0] === "no-op") { assert.match(change.change.after.arn || "", arn); check(change.change.before); equal(change.change.before, change.change.after); }
  else assert.equal(change.change.before, null);
  const markers = (marker, known, allowMetadata, path = []) => {
    if (marker === false) return;
    if (marker === true) {
      assert.ok(allowMetadata && path.length === 1 && metadata.has(path[0]) && known == null, "B03 unknown executable or sensitive field");
      return;
    }
    assert.ok(marker && typeof marker === "object", "B03 malformed provider marker");
    if (Array.isArray(marker)) {
      assert.ok(Array.isArray(known) && marker.length === known.length);
      marker.forEach((item, i) => markers(item, known[i], allowMetadata, [...path, i]));
    } else for (const [key, item] of Object.entries(marker)) {
      assert.ok(known && Object.hasOwn(known, key) || allowMetadata && path.length === 0 && metadata.has(key), "B03 unclassified provider marker");
      markers(item, known?.[key], allowMetadata, [...path, key]);
    }
  };
  markers(change.change.after_unknown || {}, change.change.after, true);
  markers(change.change.before_sensitive || {}, change.change.before, false);
  markers(change.change.after_sensitive || {}, change.change.after, false);
  return { address: change.address, type: change.type, actions: change.change.actions, classification: "b03-fixed-executor" };
}

export function b03TaskArnFromPlan(plan) {
  const changes = (plan?.resource_changes || []).filter(c => c.address === B03_TASK_ADDRESS);
  assert.ok(changes.length <= 1, "B03 duplicate task definition");
  if (!changes.length) return null;
  assertB03TaskPlan(changes[0], plan);
  const value = changes[0].change.after.arn;
  if (value) return value;
  assert.equal(changes[0].change.after_unknown?.arn, true);
  return null;
}

export function assertB03PlanConfiguration(plan) {
  if (plan.variables?.b03_executor_definition_json?.value != null) assert.equal((plan.resource_changes || []).filter(c => c.address === B03_TASK_ADDRESS).length, 1, "B03 fixed definition requires exactly one executor");
  const resources = plan.configuration?.root_module?.resources || [];
  const matches = resources.filter(r => r.address === "aws_ecs_task_definition.b03");
  assert.ok(matches.length <= 1, "B03 duplicate configuration");
  if (!matches.length) {
    assert.ok(!(plan.resource_changes || []).some(c => c.address === B03_TASK_ADDRESS), "B03 configuration is missing");
    return;
  }
  const resource = matches[0];
  assert.equal(resource.type, "aws_ecs_task_definition"); assert.equal(resource.mode, "managed");
  const constants = { network_mode: "awsvpc", requires_compatibilities: ["FARGATE"], cpu: "1024", memory: "2048", skip_destroy: true,
    runtime_platform: [{ operating_system_family: "LINUX", cpu_architecture: "X86_64" }], volume: [{ name: "executor-tmp" }],
    tags: { Environment: "production", ManagedBy: "Terraform", Component: "b03-incremental-release" } };
  const refs = { family: "local.b03_definition.family", container_definitions: "local.b03_definition.containerDefinitions",
    execution_role_arn: 'aws_iam_role.execution["executor"].arn' };
  equal(Object.keys(resource.expressions || {}).sort(), [...Object.keys(constants), ...Object.keys(refs)].sort());
  for (const [key, value] of Object.entries(constants)) equal(resource.expressions[key], { constant_value: value });
  const checkRefs = (expression, expected) => {
    equal(Object.keys(expression || {}), ["references"]);
    assert.ok(expression.references.includes(expected));
    assert.ok(expression.references.every(ref => ref === expected || expected.startsWith(`${ref}.`) || expected.startsWith(`${ref}[`)), "B03 unexpected configuration reference");
  };
  for (const [key, value] of Object.entries(refs)) checkRefs(resource.expressions[key], value);
  checkRefs(resource.count_expression, "var.b03_executor_definition_json");
  for (const key of Object.keys(resource)) assert.ok(["address", "mode", "type", "name", "provider_config_key", "schema_version", "expressions", "count_expression"].includes(key), `B03 unclassified configuration ${key}`);
}

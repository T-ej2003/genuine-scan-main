import { buildB03ExecutorDefinition } from "../../aws/production-b03-release-contract.mjs";
import { canonicalSha256 } from "../../aws/production-green-stage-b-contract.mjs";
import { B03_TASK_ADDRESS } from "../../aws/production-b03-plan-contract.mjs";
export const source = "4".repeat(40), image = `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:${"a".repeat(64)}`;
export function fixture() {
  const body = { schemaVersion: 1, kind: "PRODUCTION_B03_INCREMENTAL_PACKAGE", sourceSha: source,
    predecessorSourceSha: "d785aa7f1e154f37c0dc621082e3f6c46d5d5aec", mutations: Array.from({ length: 44 }, () => ({ owner: "auth", sql: "SELECT 1" })) };
  const pkg = { ...body, packageSha256: canonicalSha256(body) };
  const definition = buildB03ExecutorDefinition({ sourceSha: source, backendImage: image, package: pkg, databaseHostname: "db.example.internal" });
  const tags = { Environment: "production", ManagedBy: "Terraform", Component: "b03-incremental-release" };
  const after = { family: definition.family, network_mode: "awsvpc", requires_compatibilities: ["FARGATE"], cpu: "1024", memory: "2048",
    execution_role_arn: definition.executionRoleArn, task_role_arn: "", container_definitions: JSON.stringify(definition.containerDefinitions),
    volume: [{ name: "executor-tmp", host_path: null, efs_volume_configuration: [], docker_volume_configuration: [] }],
    runtime_platform: [{ operating_system_family: "LINUX", cpu_architecture: "X86_64" }], tags, tags_all: tags, skip_destroy: true };
  return { variables: { account_id: { value: "368992683803" }, aws_region: { value: "eu-west-2" }, deployment_environment: { value: "production" },
    tooling_sha: { value: source }, image_release_sha: { value: source }, backend_image: { value: image },
    b03_executor_definition_json: { value: JSON.stringify(definition) } },
  resource_changes: [{ address: B03_TASK_ADDRESS, mode: "managed", type: "aws_ecs_task_definition",
    change: { actions: ["create"], before: null, after, after_unknown: { arn: true, id: true, revision: true, arn_without_revision: true } } }] };
}

export function b03Configuration() {
  return { address: "aws_ecs_task_definition.b03", mode: "managed", type: "aws_ecs_task_definition", name: "b03",
    count_expression: { references: ["var.b03_executor_definition_json"] }, expressions: {
      family: { references: ["local.b03_definition.family", "local.b03_definition"] },
      container_definitions: { references: ["local.b03_definition.containerDefinitions", "local.b03_definition"] },
      execution_role_arn: { references: ['aws_iam_role.execution["executor"].arn', 'aws_iam_role.execution["executor"]', "aws_iam_role.execution"] },
      network_mode: { constant_value: "awsvpc" }, requires_compatibilities: { constant_value: ["FARGATE"] }, cpu: { constant_value: "1024" },
      memory: { constant_value: "2048" }, skip_destroy: { constant_value: true }, volume: { constant_value: [{ name: "executor-tmp" }] },
      runtime_platform: { constant_value: [{ operating_system_family: "LINUX", cpu_architecture: "X86_64" }] },
      tags: { constant_value: { Environment: "production", ManagedBy: "Terraform", Component: "b03-incremental-release" } },
    } };
}

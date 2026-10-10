const ref = references => ({ references });
const runtimePlatformExpression = () => [{
 cpu_architecture: ref(['local.task_runtime_platform.cpu_architecture', 'local.task_runtime_platform']),
 operating_system_family: ref(['local.task_runtime_platform.operating_system_family', 'local.task_runtime_platform']),
}];
export function stageBStaticConfiguration() {
  const candidate = {
    address: "aws_ecs_task_definition.candidate",
    type: "aws_ecs_task_definition",
    for_each_expression: ref(["local.candidate_definitions_for_resources"]),
    expressions: {
      container_definitions: ref(["each.value.containerDefinitions", "each.value"]),
      cpu: ref(["each.value.cpu", "each.value"]),
      execution_role_arn: ref(["aws_iam_role.execution", "each.key"]),
      family: ref(["each.value.family", "each.value"]),
      memory: ref(["each.value.memory", "each.value"]),
      network_mode: ref(["each.value.networkMode", "each.value"]),
      requires_compatibilities: ref(["each.value.requiresCompatibilities", "each.value"]),
      runtime_platform: runtimePlatformExpression(),
      skip_destroy: { constant_value: true },
      tags: ref(["each.key", "local.backend_exec_tags", "local.tags"]),
      task_role_arn: ref(["aws_iam_role.task", "each.key"]),
    },
  };
  const executor = structuredClone(candidate);
  executor.address = "aws_ecs_task_definition.executor";
  executor.for_each_expression = ref(["local.executor_definitions_for_resources"]);
  executor.expressions.tags = ref(["local.tags"]);
  executor.expressions.execution_role_arn = ref(["aws_iam_role.execution[\"executor\"].arn", "aws_iam_role.execution[\"executor\"]", "aws_iam_role.execution"]);
  executor.expressions.task_role_arn = ref(["var.stage_a_executor_task_role_arn"]);
  return {
    root_module: { resources: [
      candidate,
      executor,
      { address: "aws_iam_policy.broker", type: "aws_iam_policy", expressions: { name: { constant_value: "mscqr-production-rls-approval-broker-runtime" }, path: { constant_value: "/" }, policy: ref(["local.broker_runtime_policy"]), tags: ref(["local.tags"]) } },
      { address: "aws_lambda_function.broker", type: "aws_lambda_function", expressions: {
        environment: [{ variables: ref([
          "local.broker_environment",
        ]) }],
        filename: ref(["var.broker_package_path"]), function_name: { constant_value: "mscqr-production-rls-approval-broker" }, handler: { constant_value: "index.handler" }, role: ref(["var.stage_a_broker_role_arn"]), publish: { constant_value: true }, runtime: { constant_value: "nodejs24.x" }, source_code_hash: ref(["var.broker_package_bytes_path", "var.broker_package_path"]), tags: ref(["local.tags"]), timeout: { constant_value: 180 },
      } },
      { address: "aws_lambda_alias.reviewed", type: "aws_lambda_alias", expressions: {
        name: { constant_value: "reviewed" },
        function_name: ref(["aws_lambda_function.broker.function_name", "aws_lambda_function.broker"]),
        function_version: ref([
          "aws_lambda_function.broker",
          "aws_lambda_function.broker.version",
          "var.stage_b_recovery_alias_target_version",
          "var.stage_b_recovery_only",
        ]),
      } },
      { address: "aws_cloudwatch_log_group.stage_b", type: "aws_cloudwatch_log_group", for_each_expression: ref(["local.stage_b_logs"]), expressions: { name: ref(["each.value"]), retention_in_days: ref(["var.log_retention_days"]), tags: ref(["local.tags"]) } },
      { address: "aws_dynamodb_table.replay", type: "aws_dynamodb_table", expressions: { attribute: [{ name: { constant_value: "approvalMode" }, type: { constant_value: "S" } }], billing_mode: { constant_value: "PAY_PER_REQUEST" }, hash_key: { constant_value: "approvalMode" }, name: { constant_value: "mscqr-production-rls-stage-b-replay" }, tags: ref(["local.tags"]), ttl: [{ attribute_name: { constant_value: "expiresAt" }, enabled: { constant_value: true } }] } },
      { address: "aws_ecs_task_definition.candidate_retained", type: "aws_ecs_task_definition", for_each_expression: ref(["local.retained_candidate_definitions"]), expressions: { container_definitions: ref(["each.value.definition.containerDefinitions", "each.value.definition", "each.value"]), cpu: ref(["each.value.definition.cpu", "each.value.definition", "each.value"]), execution_role_arn: ref(["aws_iam_role.execution", "each.value.kind", "each.value"]), family: ref(["each.value.definition.family", "each.value.definition", "each.value"]), memory: ref(["each.value.definition.memory", "each.value.definition", "each.value"]), network_mode: ref(["each.value.definition.networkMode", "each.value.definition", "each.value"]), requires_compatibilities: ref(["each.value.definition.requiresCompatibilities", "each.value.definition", "each.value"]), runtime_platform: runtimePlatformExpression(), skip_destroy: { constant_value: true }, tags: ref(["local.tags"]), task_role_arn: ref(["aws_iam_role.task", "each.value.kind", "each.value"]) } },
      { address: "aws_ecs_task_definition.executor_retained", type: "aws_ecs_task_definition", for_each_expression: ref(["local.retained_executor_definitions"]), expressions: { container_definitions: ref(["each.value.definition.containerDefinitions", "each.value.definition", "each.value"]), cpu: ref(["each.value.definition.cpu", "each.value.definition", "each.value"]), execution_role_arn: ref(["aws_iam_role.execution[\"executor\"].arn", "aws_iam_role.execution[\"executor\"]", "aws_iam_role.execution"]), family: ref(["each.value.definition.family", "each.value.definition", "each.value"]), memory: ref(["each.value.definition.memory", "each.value.definition", "each.value"]), network_mode: ref(["each.value.definition.networkMode", "each.value.definition", "each.value"]), requires_compatibilities: ref(["each.value.definition.requiresCompatibilities", "each.value.definition", "each.value"]), runtime_platform: runtimePlatformExpression(), skip_destroy: { constant_value: true }, tags: ref(["local.tags"]), task_role_arn: ref(["var.stage_a_executor_task_role_arn"]) } },
      { address: "aws_iam_role.execution", type: "aws_iam_role", for_each_expression: ref(["local.execution_role_names"]), expressions: { assume_role_policy: {}, name: ref(["each.value"]), tags: ref(["local.tags"]) } },
      { address: "aws_iam_role.task", type: "aws_iam_role", for_each_expression: ref(["local.task_role_names"]), expressions: { assume_role_policy: {}, name: ref(["each.value"]), tags: ref(["local.tags"]) } },
      { address: "aws_iam_role_policy.backend_ecs_exec", type: "aws_iam_role_policy", expressions: { name: { constant_value: "stage-b-backend-ecs-exec-ssm-channels" }, policy: {}, role: ref(["aws_iam_role.task[\"backend\"].id", "aws_iam_role.task[\"backend\"]", "aws_iam_role.task"]) } },
      { address: "aws_iam_role_policy.candidate_object_storage", type: "aws_iam_role_policy", for_each_expression: ref(["aws_iam_role.task"]), expressions: { name: { constant_value: "stage-b-object-storage" }, policy: ref(["each.key", "var.receipt_bucket_arn"]), role: ref(["each.value.id", "each.value"]) } },
      { address: "aws_iam_role_policy.execution", type: "aws_iam_role_policy", for_each_expression: ref(["aws_iam_role.execution"]), expressions: { name: { constant_value: "stage-b-exact-image-logs-and-secrets" }, policy: ref(["local.ecr_repository_arns", "each.key", "local.execution_log_group_arns", "each.key", "local.execution_policy_secret_arns", "each.key"]), role: ref(["each.value.id", "each.value"]) } },
      { address: "aws_iam_role_policy.executor_runtime", type: "aws_iam_role_policy", expressions: { name: { constant_value: "stage-b-executor-runtime" }, policy: ref(["var.stage_a_runtime_secret_arns", "var.approval_kms_key_arn", "var.receipt_bucket_arn"]), role: ref(["var.stage_a_executor_task_role_arn"]) } },
      { address: "aws_iam_role_policy_attachment.broker", type: "aws_iam_role_policy_attachment", expressions: { policy_arn: ref(["aws_iam_policy.broker.arn", "aws_iam_policy.broker"]), role: ref(["var.stage_a_broker_role_arn"]) } },
      { address: "aws_lambda_permission.release_deployer", type: "aws_lambda_permission", expressions: { action: { constant_value: "lambda:InvokeFunction" }, function_name: ref(["aws_lambda_function.broker.function_name", "aws_lambda_function.broker"]), principal: { constant_value: "arn:aws:iam::368992683803:role/mscqr-production-release-deployer" }, qualifier: ref(["aws_lambda_alias.reviewed.name", "aws_lambda_alias.reviewed"]), statement_id: { constant_value: "OnlyProtectedReleaseRoleMayInvokeReviewedAlias" } } },
    ] },
  };
}


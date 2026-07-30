locals {
  tags = {
    Environment = "production"
    ManagedBy   = "Terraform"
    Component   = "full-rls-green-stage-b"
  }
  confirmations = {
    full-rls-capability-preflight = ""
    full-rls-admin-bootstrap      = "MSCQR_PRODUCTION_GREEN_CREATE_AND_BOOTSTRAP_DATABASE"
    full-rls-role-provision       = "MSCQR_PRODUCTION_GREEN_PROVISION_RUNTIME_ROLES"
    full-rls-role-verify          = ""
    full-rls-admin-ownership      = "MSCQR_PRODUCTION_GREEN_INSTALL_OWNERSHIP_GRANTS"
    full-rls-runtime-policy       = "MSCQR_PRODUCTION_GREEN_INSTALL_RUNTIME_POLICIES"
    full-rls-verification         = ""
    full-rls-rollback             = "MSCQR_PRODUCTION_GREEN_ROLLBACK_EXACT_PACKAGE"
  }
  modes = toset(keys(local.confirmations))
  stage_b_logs = {
    backend          = "/ecs/mscqr-production/rls-green-backend"
    worker           = "/ecs/mscqr-production/rls-green-worker"
    canary           = "/ecs/mscqr-production/rls-green-canary"
    read_only_canary = "/ecs/mscqr-production/rls-green-read-only-canary"
  }
  logs = merge(local.stage_b_logs, {
    executor = var.stage_a_executor_log_group_name
    broker   = var.stage_a_broker_log_group_name
  })
  image_by_kind = {
    backend          = var.backend_image
    worker           = var.worker_image
    executor         = var.executor_image
    canary           = var.canary_image
    read_only_canary = var.read_only_canary_image
  }
  rendered_candidates = {
    backend          = replace(replace(replace(file("${path.module}/task-definitions/green-backend-candidate.json"), "{{BACKEND_IMAGE}}", var.backend_image), "{{RELEASE_SHA}}", var.release_sha), "{{BACKEND_LOG_GROUP}}", local.logs.backend)
    worker           = replace(replace(replace(file("${path.module}/task-definitions/green-worker-candidate.json"), "{{WORKER_IMAGE}}", var.worker_image), "{{RELEASE_SHA}}", var.release_sha), "{{WORKER_LOG_GROUP}}", local.logs.worker)
    canary           = replace(replace(replace(replace(replace(file("${path.module}/task-definitions/green-application-canary.json"), "{{CANARY_IMAGE}}", var.canary_image), "{{RELEASE_SHA}}", var.release_sha), "{{SOURCE_CONTRACT_SHA256}}", var.source_contract_sha256), "{{MIGRATION_SET_DIGEST}}", var.migration_set_digest), "{{CANARY_LOG_GROUP}}", local.logs.canary)
    read_only_canary = replace(replace(replace(file("${path.module}/task-definitions/green-read-only-rls-canary.json"), "{{READ_ONLY_CANARY_IMAGE}}", var.read_only_canary_image), "{{READ_ONLY_CANARY_DATABASE_SECRET_ARN}}", var.stage_a_read_only_canary_database_secret_arn), "{{READ_ONLY_CANARY_LOG_GROUP}}", local.logs.read_only_canary)
  }
  candidate_definitions = {
    for kind, rendered in local.rendered_candidates : kind => jsondecode(rendered)
  }
  executor_template = replace(replace(replace(replace(replace(replace(file("${path.module}/task-definitions/green-activation-executor.json"), "{{EXECUTOR_IMAGE}}", var.executor_image), "{{RELEASE_SHA}}", var.release_sha), "{{SOURCE_CONTRACT_SHA256}}", var.source_contract_sha256), "{{MIGRATION_SET_DIGEST}}", var.migration_set_digest), "{{PACKAGE_CHECKSUM_SHA256}}", var.package_checksum_sha256), "{{RECEIPT_BUCKET}}", trimprefix(var.receipt_bucket_arn, "arn:aws:s3:::"))
  executor_definitions = {
    for mode, confirmation in local.confirmations : mode => jsondecode(
      replace(
        replace(
          replace(local.executor_template, "{{MODE}}", mode),
          "{{CONFIRMATION}}",
          confirmation
        ),
        "{{EXECUTOR_LOG_GROUP}}",
        local.logs.executor
      )
    )
  }
  execution_secret_arns = {
    for kind, definition in merge(local.candidate_definitions, { executor = local.executor_definitions["full-rls-verification"] }) :
    kind => distinct([
      for secret in definition.containerDefinitions[0].secrets :
      regex("^arn:aws:secretsmanager:[^:]+:[^:]+:secret:[^:]+", secret.valueFrom)
    ])
  }
  execution_log_group_arns = merge(
    { for kind, log_group in aws_cloudwatch_log_group.stage_b : kind => log_group.arn },
    { executor = var.stage_a_executor_log_group_arn }
  )
  ecr_repository_arns = {
    backend          = "arn:aws:ecr:eu-west-2:368992683803:repository/mscqr-backend"
    worker           = "arn:aws:ecr:eu-west-2:368992683803:repository/mscqr-worker"
    executor         = "arn:aws:ecr:eu-west-2:368992683803:repository/mscqr-backend"
    canary           = "arn:aws:ecr:eu-west-2:368992683803:repository/mscqr-backend"
    read_only_canary = "arn:aws:ecr:eu-west-2:368992683803:repository/mscqr-backend"
  }
  task_role_names = {
    backend          = "mscqr-production-rls-green-backend-task"
    worker           = "mscqr-production-rls-green-worker-task"
    canary           = "mscqr-production-rls-green-canary-task"
    read_only_canary = "mscqr-production-full-rls-green-read-only-canary-task"
  }
  execution_role_names = {
    backend          = "mscqr-production-rls-green-backend-execution"
    worker           = "mscqr-production-rls-green-worker-execution"
    executor         = "mscqr-production-full-rls-green-executor-execution"
    canary           = "mscqr-production-rls-green-canary-execution"
    read_only_canary = "mscqr-production-full-rls-green-read-only-canary-execution"
  }
  broker_task_definition_arns = merge(
    { for mode, task in aws_ecs_task_definition.executor : mode => task.arn },
    { full-rls-application-canary = aws_ecs_task_definition.candidate["canary"].arn }
  )
  broker_template_hashes = {
    backend  = sha256(jsonencode(jsondecode(file("${path.module}/task-definitions/green-backend-candidate.json"))))
    worker   = sha256(jsonencode(jsondecode(file("${path.module}/task-definitions/green-worker-candidate.json"))))
    executor = sha256(jsonencode(jsondecode(file("${path.module}/task-definitions/green-activation-executor.json"))))
    canary   = sha256(jsonencode(jsondecode(file("${path.module}/task-definitions/green-application-canary.json"))))
  }
  broker_images = {
    backendImageDigest  = var.backend_image
    workerImageDigest   = var.worker_image
    executorImageDigest = var.executor_image
    canaryImageDigest   = var.canary_image
  }
  broker_approval_expected = {
    releaseSha              = var.release_sha
    sourceContractSha256    = var.source_contract_sha256
    migrationSetDigest      = var.migration_set_digest
    packageChecksumSha256   = var.package_checksum_sha256
    deploymentId            = "phase2"
    greenDatabaseName       = "mscqr_production_rls_green_phase2"
    administratorIdentity   = "mscqr_prod_admin"
    databaseSecurityGroupId = var.stage_a_database_security_group_id
    executorSecurityGroupId = var.stage_a_executor_security_group_id
  }
}

resource "aws_cloudwatch_log_group" "stage_b" {
  for_each          = local.stage_b_logs
  name              = each.value
  retention_in_days = var.log_retention_days
  tags              = local.tags
}

resource "aws_iam_role" "execution" {
  for_each           = local.execution_role_names
  name               = each.value
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Principal = { Service = "ecs-tasks.amazonaws.com" }, Action = "sts:AssumeRole" }] })
  tags               = local.tags
}

resource "aws_iam_role_policy" "execution" {
  for_each = aws_iam_role.execution
  name     = "stage-b-exact-image-logs-and-secrets"
  role     = each.value.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "EcrAuthorizationRequiredByEcs"
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken"]
        Resource = "*"
      },
      {
        Sid      = "PullOnlyApprovedRepository"
        Effect   = "Allow"
        Action   = ["ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"]
        Resource = local.ecr_repository_arns[each.key]
      },
      {
        Sid      = "WriteOnlyExactTaskLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${trimsuffix(local.execution_log_group_arns[each.key], ":*")}:log-stream:*"
      },
      {
        Sid      = "ReadOnlyExactInjectedSecrets"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = local.execution_secret_arns[each.key]
      }
    ]
  })
}

resource "aws_iam_role" "task" {
  for_each           = local.task_role_names
  name               = each.value
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Principal = { Service = "ecs-tasks.amazonaws.com" }, Action = "sts:AssumeRole" }] })
  tags               = local.tags
}

resource "aws_iam_role_policy" "candidate_object_storage" {
  for_each = { for key, role in aws_iam_role.task : key => role if key != "read_only_canary" }
  name     = "stage-b-object-storage"
  role     = each.value.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "ReadWriteOnlyProductionArtifactObjects"
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:PutObject"]
      Resource = "${var.receipt_bucket_arn}/*"
    }]
  })
}

resource "aws_iam_role_policy" "executor_runtime" {
  name = "stage-b-executor-runtime"
  role = split("/", var.stage_a_executor_task_role_arn)[1]
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ManageOnlyStageARuntimeRoleSecrets"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue"]
        Resource = values(var.stage_a_runtime_secret_arns)
      },
      {
        Sid      = "VerifyOnlyStageAApprovalKey"
        Effect   = "Allow"
        Action   = ["kms:Verify"]
        Resource = var.approval_kms_key_arn
      },
      {
        Sid      = "WriteOnlyExecutorReceipts"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${var.receipt_bucket_arn}/rls-receipts/*"
      }
    ]
  })
}

resource "aws_ecs_task_definition" "candidate" {
  for_each                 = local.candidate_definitions
  family                   = each.value.family
  network_mode             = each.value.networkMode
  requires_compatibilities = each.value.requiresCompatibilities
  cpu                      = each.value.cpu
  memory                   = each.value.memory
  execution_role_arn       = aws_iam_role.execution[each.key].arn
  task_role_arn            = aws_iam_role.task[each.key].arn
  container_definitions    = jsonencode(each.value.containerDefinitions)

  dynamic "volume" {
    for_each = try(each.value.volumes, [])
    content {
      name = volume.value.name
    }
  }

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }
  tags = local.tags
}

resource "aws_ecs_task_definition" "executor" {
  for_each                 = local.executor_definitions
  family                   = each.value.family
  network_mode             = each.value.networkMode
  requires_compatibilities = each.value.requiresCompatibilities
  cpu                      = each.value.cpu
  memory                   = each.value.memory
  execution_role_arn       = aws_iam_role.execution["executor"].arn
  task_role_arn            = var.stage_a_executor_task_role_arn
  container_definitions    = jsonencode(each.value.containerDefinitions)

  dynamic "volume" {
    for_each = each.value.volumes
    content {
      name = volume.value.name
    }
  }

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }
  tags = local.tags
}

resource "aws_dynamodb_table" "replay" {
  name         = "mscqr-production-rls-stage-b-replay"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "approvalMode"
  attribute {
    name = "approvalMode"
    type = "S"
  }
  ttl {
    attribute_name = "expiresAt"
    enabled        = true
  }
  tags = local.tags
}

resource "aws_iam_role_policy" "broker" {
  name = "stage-b-broker"
  role = split("/", var.stage_a_broker_role_arn)[1]
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "RunOnlyApprovedExecutorAndCanaryRevisions"
        Effect   = "Allow"
        Action   = ["ecs:RunTask"]
        Resource = values(local.broker_task_definition_arns)
      },
      {
        Sid      = "PassOnlyApprovedTaskRoles"
        Effect   = "Allow"
        Action   = ["iam:PassRole"]
        Resource = [var.stage_a_executor_task_role_arn, aws_iam_role.execution["executor"].arn, aws_iam_role.task["canary"].arn, aws_iam_role.execution["canary"].arn]
        Condition = {
          StringEquals = { "iam:PassedToService" = "ecs-tasks.amazonaws.com" }
        }
      },
      {
        Sid      = "ClaimOnlyStageBReplayRows"
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem", "dynamodb:DeleteItem", "dynamodb:UpdateItem"]
        Resource = aws_dynamodb_table.replay.arn
      },
      {
        Sid      = "ReadOnlyStageAApproval"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = var.approval_secret_arn
      },
      {
        Sid      = "VerifyOnlyStageAApprovalKey"
        Effect   = "Allow"
        Action   = ["kms:Verify"]
        Resource = var.approval_kms_key_arn
      },
      {
        Sid      = "WriteOnlyBrokerReceipts"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${var.receipt_bucket_arn}/rls-broker-receipts/*"
      },
      {
        Sid      = "WriteOnlyStageABrokerLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${trimsuffix(var.stage_a_broker_log_group_arn, ":*")}:log-stream:*"
      }
    ]
  })
}

resource "aws_lambda_function" "broker" {
  function_name    = "mscqr-production-rls-approval-broker"
  role             = var.stage_a_broker_role_arn
  handler          = "index.handler"
  runtime          = "nodejs24.x"
  filename         = var.broker_package_path
  source_code_hash = filebase64sha256(var.broker_package_path)
  timeout          = 30
  publish          = true
  environment {
    variables = {
      BROKER_REPLAY_TABLE               = aws_dynamodb_table.replay.name
      BROKER_RECEIPT_BUCKET             = trimprefix(var.receipt_bucket_arn, "arn:aws:s3:::")
      BROKER_CLUSTER_ARN                = var.ecs_cluster_arn
      BROKER_APPROVAL_SECRET_ARN        = var.approval_secret_arn
      BROKER_EXECUTOR_SECURITY_GROUP_ID = var.stage_a_executor_security_group_id
      BROKER_PRIVATE_SUBNETS_JSON       = jsonencode(var.private_subnet_ids)
      BROKER_TASK_DEFINITIONS_JSON      = jsonencode(local.broker_task_definition_arns)
      BROKER_TASK_TEMPLATE_HASHES_JSON  = jsonencode(local.broker_template_hashes)
      BROKER_APPROVAL_EXPECTED_JSON     = jsonencode(local.broker_approval_expected)
      BROKER_IMAGES_JSON                = jsonencode(local.broker_images)
    }
  }
  tags = local.tags
}

resource "aws_lambda_alias" "reviewed" {
  name             = "reviewed"
  function_name    = aws_lambda_function.broker.function_name
  function_version = aws_lambda_function.broker.version
}

resource "aws_lambda_permission" "release_deployer" {
  statement_id  = "OnlyProtectedReleaseRoleMayInvokeReviewedAlias"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.broker.function_name
  qualifier     = aws_lambda_alias.reviewed.name
  principal     = "arn:aws:iam::368992683803:role/mscqr-production-release-deployer"
}

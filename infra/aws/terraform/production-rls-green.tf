locals {
  full_rls_green_db_subnets = length(var.full_rls_green_db_subnet_ids) > 0 ? var.full_rls_green_db_subnet_ids : var.private_subnet_ids
  full_rls_green_modes = {
    full-rls-capability-preflight = null
    full-rls-admin-bootstrap      = "MSCQR_PRODUCTION_GREEN_CREATE_AND_BOOTSTRAP_DATABASE"
    full-rls-role-provision       = "MSCQR_PRODUCTION_GREEN_PROVISION_RUNTIME_ROLES"
    full-rls-role-verify          = null
    full-rls-admin-ownership      = "MSCQR_PRODUCTION_GREEN_INSTALL_OWNERSHIP_GRANTS"
    full-rls-runtime-policy       = "MSCQR_PRODUCTION_GREEN_INSTALL_RUNTIME_POLICIES"
    full-rls-verification         = null
    full-rls-rollback             = "MSCQR_PRODUCTION_GREEN_ROLLBACK_EXACT_PACKAGE"
  }
  full_rls_green_runtime_secret_arns = {
    for key, secret in aws_secretsmanager_secret.full_rls_green_runtime : key => secret.arn
  }
  full_rls_green_backend_secrets = {
    DATABASE_URL                   = lookup(local.full_rls_green_runtime_secret_arns, "app", null)
    AUTHENTICATED_APP_DATABASE_URL = lookup(local.full_rls_green_runtime_secret_arns, "app", null)
    PREAUTH_DATABASE_URL           = lookup(local.full_rls_green_runtime_secret_arns, "preauth", null)
    MSCQR_C03_PREAUTH_DATABASE_URL = lookup(local.full_rls_green_runtime_secret_arns, "preauth", null)
  }
  backend_database_secret_names = toset(keys(local.full_rls_green_backend_secrets))
  backend_container_definitions = var.activate_full_rls_green_runtime ? jsonencode([
    for container in jsondecode(var.backend_container_definitions_json) : merge(container, {
      secrets = concat(
        [for secret in try(container.secrets, []) : secret if !contains(local.backend_database_secret_names, secret.name)],
        [for name, arn in local.full_rls_green_backend_secrets : { name = name, valueFrom = arn }]
      )
    })
  ]) : var.backend_container_definitions_json
  worker_container_definitions = var.activate_full_rls_green_runtime ? jsonencode([
    for container in jsondecode(var.worker_container_definitions_json) : merge(container, {
      secrets = concat(
        [for secret in try(container.secrets, []) : secret if secret.name != "DATABASE_URL"],
        [{ name = "DATABASE_URL", valueFrom = lookup(local.full_rls_green_runtime_secret_arns, "worker", null) }]
      )
    })
  ]) : var.worker_container_definitions_json
  full_rls_green_canary_secret_arns = {
    for key, secret in aws_secretsmanager_secret.full_rls_green_canary : key => secret.arn
  }
  full_rls_green_backend_container = one([
    for container in jsondecode(var.backend_container_definitions_json) : container
    if container.name == var.backend_container_name
  ])
  full_rls_green_canary_container = merge(local.full_rls_green_backend_container, {
    image   = var.full_rls_green_backend_image
    command = ["node", "scripts/production-green-application-canary.mjs"]
    secrets = concat(
      [for secret in try(local.full_rls_green_backend_container.secrets, []) :
        secret if !contains(local.backend_database_secret_names, secret.name)
      ],
      [for name, arn in local.full_rls_green_backend_secrets : { name = name, valueFrom = arn }],
      [
        { name = "MSCQR_CANARY_ORDINARY_EMAIL", valueFrom = lookup(local.full_rls_green_canary_secret_arns, "ordinary_email", null) },
        { name = "MSCQR_CANARY_ORDINARY_PASSWORD", valueFrom = lookup(local.full_rls_green_canary_secret_arns, "ordinary_password", null) },
        { name = "MSCQR_CANARY_ORDINARY_MFA_SECRET", valueFrom = lookup(local.full_rls_green_canary_secret_arns, "ordinary_mfa_secret", null) },
        { name = "MSCQR_CANARY_ADMIN_EMAIL", valueFrom = lookup(local.full_rls_green_canary_secret_arns, "admin_email", null) },
        { name = "MSCQR_CANARY_ADMIN_PASSWORD", valueFrom = lookup(local.full_rls_green_canary_secret_arns, "admin_password", null) },
        { name = "MSCQR_CANARY_ADMIN_MFA_SECRET", valueFrom = lookup(local.full_rls_green_canary_secret_arns, "admin_mfa_secret", null) },
      ]
    )
  })
}

check "full_rls_green_runtime_is_all_or_nothing" {
  assert {
    condition = !var.activate_full_rls_green_runtime || (
      var.enable_full_rls_green_executor
      && length(local.full_rls_green_runtime_secret_arns) == 7
      && alltrue([for name in ["DATABASE_URL", "AUTHENTICATED_APP_DATABASE_URL", "PREAUTH_DATABASE_URL"] :
        contains(keys(local.full_rls_green_backend_secrets), name)
      ])
    )
    error_message = "Production green runtime activation requires the complete app/preauth/worker secret set."
  }
}

check "full_rls_green_executor_requires_infrastructure" {
  assert {
    condition     = !var.enable_full_rls_green_executor || var.enable_full_rls_green_infrastructure
    error_message = "Release-bound production green execution requires the isolated green infrastructure first."
  }
}

resource "aws_kms_key" "full_rls_green_storage" {
  count                   = var.enable_full_rls_green_infrastructure ? 1 : 0
  description             = "MSCQR isolated production green PostgreSQL storage"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  tags                    = merge(local.common_tags, { Component = "full-rls-green-storage" })
}

resource "aws_kms_alias" "full_rls_green_storage" {
  count         = var.enable_full_rls_green_infrastructure ? 1 : 0
  name          = "alias/mscqr-production-rls-green-storage"
  target_key_id = aws_kms_key.full_rls_green_storage[0].key_id
}

resource "aws_db_subnet_group" "full_rls_green" {
  count      = var.enable_full_rls_green_infrastructure ? 1 : 0
  name       = "mscqr-production-rls-green-phase2"
  subnet_ids = local.full_rls_green_db_subnets
  tags       = merge(local.common_tags, { Component = "full-rls-green-database" })
}

resource "aws_db_parameter_group" "full_rls_green" {
  count  = var.enable_full_rls_green_infrastructure ? 1 : 0
  name   = "mscqr-production-rls-green-pg18"
  family = "postgres18"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }

  tags = merge(local.common_tags, { Component = "full-rls-green-database" })
}

resource "aws_security_group" "full_rls_green_executor" {
  count       = var.enable_full_rls_green_infrastructure ? 1 : 0
  name        = "mscqr-production-rls-green-executor"
  description = "No-ingress executor for isolated production green PostgreSQL"
  vpc_id      = var.vpc_id
  tags        = merge(local.common_tags, { Component = "full-rls-green-executor" })
}

resource "aws_vpc_security_group_egress_rule" "full_rls_green_executor" {
  count             = var.enable_full_rls_green_infrastructure ? 1 : 0
  security_group_id = aws_security_group.full_rls_green_executor[0].id
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
  description       = "TLS database and AWS VPC endpoint access"
}

resource "aws_security_group" "full_rls_green_database" {
  count       = var.enable_full_rls_green_infrastructure ? 1 : 0
  name        = "mscqr-production-rls-green-database"
  description = "PostgreSQL ingress only from reviewed ECS security groups"
  vpc_id      = var.vpc_id
  tags        = merge(local.common_tags, { Component = "full-rls-green-database" })
}

resource "aws_vpc_security_group_ingress_rule" "full_rls_green_executor_database" {
  count                        = var.enable_full_rls_green_infrastructure ? 1 : 0
  security_group_id            = aws_security_group.full_rls_green_database[0].id
  referenced_security_group_id = aws_security_group.full_rls_green_executor[0].id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
  description                  = "Brokered RLS executor"
}

resource "aws_vpc_security_group_ingress_rule" "full_rls_green_runtime_database" {
  for_each                     = var.enable_full_rls_green_infrastructure ? toset(var.service_security_group_ids) : toset([])
  security_group_id            = aws_security_group.full_rls_green_database[0].id
  referenced_security_group_id = each.value
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
  description                  = "Controlled production ECS runtime"
}

resource "aws_db_instance" "full_rls_green" {
  count                        = var.enable_full_rls_green_infrastructure ? 1 : 0
  identifier                   = "mscqr-production-rls-green-phase2"
  engine                       = "postgres"
  engine_version               = "18.4"
  instance_class               = var.full_rls_green_db_instance_class
  allocated_storage            = 100
  max_allocated_storage        = 500
  storage_type                 = "gp3"
  storage_encrypted            = true
  kms_key_id                   = aws_kms_key.full_rls_green_storage[0].arn
  db_name                      = "mscqr_production"
  username                     = "mscqr_prod_admin"
  manage_master_user_password  = true
  port                         = 5432
  publicly_accessible          = false
  multi_az                     = true
  backup_retention_period      = 14
  backup_window                = "02:00-03:00"
  maintenance_window           = "sun:03:30-sun:04:30"
  auto_minor_version_upgrade   = true
  deletion_protection          = true
  skip_final_snapshot          = false
  final_snapshot_identifier    = "mscqr-production-rls-green-phase2-final"
  copy_tags_to_snapshot        = true
  performance_insights_enabled = true
  db_subnet_group_name         = aws_db_subnet_group.full_rls_green[0].name
  parameter_group_name         = aws_db_parameter_group.full_rls_green[0].name
  vpc_security_group_ids       = [aws_security_group.full_rls_green_database[0].id]
  tags                         = merge(local.common_tags, { Component = "full-rls-green-database", Colour = "green" })
}

resource "aws_iam_role" "full_rls_green_checker" {
  count = var.enable_full_rls_green_infrastructure ? 1 : 0
  name  = "mscqr-production-rls-independent-checker"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = var.full_rls_green_checker_principal_arns }
      Action    = "sts:AssumeRole"
      Condition = { Bool = { "aws:MultiFactorAuthPresent" = "true" } }
    }]
  })
  tags = merge(local.common_tags, { Component = "full-rls-green-approval" })
}

resource "aws_kms_key" "full_rls_green_approval" {
  count                    = var.enable_full_rls_green_infrastructure ? 1 : 0
  description              = "Independent production RLS approval signing key"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "RSA_3072"
  deletion_window_in_days  = 30
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountAdministration"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::368992683803:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "IndependentCheckerSigns"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.full_rls_green_checker[0].arn }
        Action    = ["kms:GetPublicKey", "kms:Sign", "kms:Verify"]
        Resource  = "*"
      },
    ]
  })
  tags = merge(local.common_tags, { Component = "full-rls-green-approval" })
}

resource "aws_kms_alias" "full_rls_green_approval" {
  count         = var.enable_full_rls_green_infrastructure ? 1 : 0
  name          = "alias/mscqr-production-rls-approval"
  target_key_id = aws_kms_key.full_rls_green_approval[0].key_id
}

resource "aws_secretsmanager_secret" "full_rls_green_approval" {
  count                   = var.enable_full_rls_green_infrastructure ? 1 : 0
  name                    = "mscqr/production/rls-green/phase2/approval"
  description             = "Short-lived independently signed production RLS approval artifact"
  recovery_window_in_days = 30
  tags                    = merge(local.common_tags, { Component = "full-rls-green-approval" })
}

resource "aws_secretsmanager_secret" "full_rls_green_canary" {
  for_each = var.enable_full_rls_green_infrastructure ? toset([
    "ordinary_email",
    "ordinary_password",
    "ordinary_mfa_secret",
    "admin_email",
    "admin_password",
    "admin_mfa_secret",
  ]) : toset([])
  name                    = "mscqr/production/rls-green/phase2/canary/${replace(each.key, "_", "-")}"
  description             = "Existing approved production canary ${replace(each.key, "_", " ")}"
  recovery_window_in_days = 30
  tags                    = merge(local.common_tags, { Component = "full-rls-green-canary" })
}

resource "aws_iam_role_policy" "full_rls_green_checker" {
  count = var.enable_full_rls_green_infrastructure ? 1 : 0
  name  = "mscqr-production-rls-independent-checker"
  role  = aws_iam_role.full_rls_green_checker[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["kms:GetPublicKey", "kms:Sign", "kms:Verify"]
        Resource = aws_kms_key.full_rls_green_approval[0].arn
      },
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:DescribeSecret", "secretsmanager:PutSecretValue"]
        Resource = aws_secretsmanager_secret.full_rls_green_approval[0].arn
      }
    ]
  })
}

resource "aws_ecs_task_definition" "full_rls_green" {
  for_each                 = var.enable_full_rls_green_executor ? local.full_rls_green_modes : {}
  family                   = "mscqr-production-full-rls-green-${replace(each.key, "full-rls-", "")}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "512"
  memory                   = "1024"
  execution_role_arn       = var.backend_execution_role_arn
  task_role_arn            = aws_iam_role.full_rls_green_executor[0].arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  container_definitions = jsonencode([{
    name      = "full-rls-green"
    image     = var.full_rls_green_executor_image
    essential = true
    command   = ["node", "scripts/production-full-rls-green-executor.mjs"]
    environment = concat([
      { name = "MSCQR_FULL_RLS_MODE", value = each.key },
      { name = "MSCQR_FULL_RLS_SOURCE_CONTRACT_SHA256", value = var.full_rls_green_source_contract_sha256 },
      { name = "MSCQR_FULL_RLS_MIGRATION_SET_DIGEST", value = var.full_rls_green_migration_set_digest },
      { name = "MSCQR_FULL_RLS_PACKAGE_CHECKSUM_SHA256", value = var.full_rls_green_package_checksum_sha256 },
      { name = "MSCQR_FULL_RLS_RECEIPT_BUCKET", value = trimprefix(var.full_rls_receipt_bucket_arn, "arn:aws:s3:::") },
      { name = "MSCQR_PRODUCTION_RLS_APPROVAL_KMS_KEY_ARN", value = aws_kms_key.full_rls_green_approval[0].arn },
      { name = "MSCQR_RLS_GREEN_ENDPOINT", value = aws_db_instance.full_rls_green[0].address },
      { name = "MSCQR_RLS_GREEN_PORT", value = tostring(aws_db_instance.full_rls_green[0].port) },
      { name = "RELEASE_GIT_SHA", value = var.full_rls_green_release_sha },
      ], each.value == null ? [] : [
      { name = "MSCQR_FULL_RLS_CONFIRMATION", value = each.value }
    ])
    secrets = concat([
      { name = "MSCQR_RLS_ADMIN_USERNAME", valueFrom = "${aws_db_instance.full_rls_green[0].master_user_secret[0].secret_arn}:username::" },
      { name = "MSCQR_RLS_ADMIN_PASSWORD", valueFrom = "${aws_db_instance.full_rls_green[0].master_user_secret[0].secret_arn}:password::" },
      { name = "MSCQR_PRODUCTION_RLS_APPROVAL_ARTIFACT", valueFrom = aws_secretsmanager_secret.full_rls_green_approval[0].arn },
      ], each.key == "full-rls-admin-ownership" ? concat(
      [for key, arn in local.full_rls_green_canary_secret_arns : {
        name      = "MSCQR_CANARY_${upper(key)}"
        valueFrom = arn
      }],
      [for secret in try(local.full_rls_green_backend_container.secrets, []) :
        secret if secret.name == "AUTH_MFA_ENCRYPTION_KEY"
      ]
      ) : []
    )
    user                   = "node"
    privileged             = false
    readonlyRootFilesystem = true
    linuxParameters = {
      initProcessEnabled = true
      capabilities       = { add = [], drop = ["ALL"] }
      devices            = []
      tmpfs              = []
    }
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.full_rls_green[0].name
        awslogs-region        = var.aws_region
        awslogs-stream-prefix = each.key
      }
    }
  }])

  tags = merge(local.common_tags, {
    Component = "full-rls-green-executor"
    Mode      = each.key
  })
}

resource "aws_ecs_task_definition" "full_rls_green_canary" {
  count                    = var.enable_full_rls_green_executor ? 1 : 0
  family                   = "mscqr-production-full-rls-green-application-canary"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.backend_cpu
  memory                   = var.backend_memory
  execution_role_arn       = var.backend_execution_role_arn
  task_role_arn            = var.backend_task_role_arn
  container_definitions    = jsonencode([local.full_rls_green_canary_container])

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  tags = merge(local.common_tags, { Component = "full-rls-green-canary" })
}

resource "aws_cloudwatch_log_group" "full_rls_green_broker" {
  count             = var.enable_full_rls_green_executor ? 1 : 0
  name              = "/aws/lambda/mscqr-production-rls-approval-broker"
  retention_in_days = var.log_retention_days
  tags              = merge(local.common_tags, { Component = "full-rls-green-approval" })
}

resource "aws_iam_role" "full_rls_green_broker" {
  count = var.enable_full_rls_green_executor ? 1 : 0
  name  = "mscqr-production-rls-approval-broker"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = merge(local.common_tags, { Component = "full-rls-green-approval" })
}

resource "aws_iam_role_policy" "full_rls_green_broker" {
  count = var.enable_full_rls_green_executor ? 1 : 0
  name  = "mscqr-production-rls-approval-broker"
  role  = aws_iam_role.full_rls_green_broker[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.full_rls_green_broker[0].arn}:*"
      },
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = aws_secretsmanager_secret.full_rls_green_approval[0].arn
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Verify"]
        Resource = aws_kms_key.full_rls_green_approval[0].arn
      },
      {
        Effect = "Allow"
        Action = ["ecs:RunTask"]
        Resource = concat(
          [for task in aws_ecs_task_definition.full_rls_green : task.arn],
          [aws_ecs_task_definition.full_rls_green_canary[0].arn],
        )
      },
      {
        Effect   = "Allow"
        Action   = ["iam:PassRole"]
        Resource = [aws_iam_role.full_rls_green_executor[0].arn, var.backend_execution_role_arn, var.backend_task_role_arn]
        Condition = {
          StringEquals = { "iam:PassedToService" = "ecs-tasks.amazonaws.com" }
        }
      }
    ]
  })
}

data "archive_file" "full_rls_green_broker" {
  count       = var.enable_full_rls_green_executor ? 1 : 0
  type        = "zip"
  output_path = "${path.module}/.terraform/production-rls-approval-broker.zip"

  source {
    content  = file("${path.module}/lambda/production-rls-approval-broker/index.mjs")
    filename = "index.mjs"
  }
  source {
    content  = file("${path.module}/../../../backend/scripts/production-rls-approval.mjs")
    filename = "production-rls-approval.mjs"
  }
}

resource "aws_lambda_function" "full_rls_green_broker" {
  count            = var.enable_full_rls_green_executor ? 1 : 0
  function_name    = "mscqr-production-rls-approval-broker"
  role             = aws_iam_role.full_rls_green_broker[0].arn
  runtime          = "nodejs22.x"
  handler          = "index.handler"
  filename         = data.archive_file.full_rls_green_broker[0].output_path
  source_code_hash = data.archive_file.full_rls_green_broker[0].output_base64sha256
  timeout          = 30
  memory_size      = 256
  publish          = true

  environment {
    variables = {
      BROKER_CLUSTER_ARN = aws_ecs_cluster.this.arn
      BROKER_TASK_DEFINITIONS_JSON = jsonencode(merge(
        { for mode, task in aws_ecs_task_definition.full_rls_green : mode => task.arn },
        { full-rls-application-canary = aws_ecs_task_definition.full_rls_green_canary[0].arn },
      ))
      BROKER_APPROVAL_SECRET_ARN            = aws_secretsmanager_secret.full_rls_green_approval[0].arn
      BROKER_APPROVAL_KMS_KEY_ARN           = aws_kms_key.full_rls_green_approval[0].arn
      BROKER_PRIVATE_SUBNETS_JSON           = jsonencode(var.private_subnet_ids)
      BROKER_SECURITY_GROUPS_JSON           = jsonencode([aws_security_group.full_rls_green_executor[0].id])
      RELEASE_GIT_SHA                       = var.full_rls_green_release_sha
      MSCQR_FULL_RLS_SOURCE_CONTRACT_SHA256 = var.full_rls_green_source_contract_sha256
      MSCQR_FULL_RLS_MIGRATION_SET_DIGEST   = var.full_rls_green_migration_set_digest
    }
  }

  depends_on = [aws_cloudwatch_log_group.full_rls_green_broker]
  tags       = merge(local.common_tags, { Component = "full-rls-green-approval" })
}

resource "aws_lambda_alias" "full_rls_green_broker_reviewed" {
  count            = var.enable_full_rls_green_executor ? 1 : 0
  name             = "reviewed"
  description      = "Immutable reviewed production RLS approval broker"
  function_name    = aws_lambda_function.full_rls_green_broker[0].function_name
  function_version = aws_lambda_function.full_rls_green_broker[0].version
}

resource "aws_iam_role_policy" "full_rls_green_release_broker" {
  count = var.enable_full_rls_green_executor ? 1 : 0
  name  = "mscqr-production-rls-reviewed-broker-only"
  role  = element(reverse(split("/", var.full_rls_green_release_role_arn)), 0)
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadAndVerifyExactProductionApproval"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
        Resource = aws_secretsmanager_secret.full_rls_green_approval[0].arn
      },
      {
        Sid      = "VerifyProductionApprovalSignature"
        Effect   = "Allow"
        Action   = ["kms:Verify"]
        Resource = aws_kms_key.full_rls_green_approval[0].arn
      },
      {
        Sid      = "InvokeOnlyReviewedProductionRlsBroker"
        Effect   = "Allow"
        Action   = ["lambda:InvokeFunction"]
        Resource = aws_lambda_alias.full_rls_green_broker_reviewed[0].arn
      },
      {
        Sid      = "ObserveBrokeredTasks"
        Effect   = "Allow"
        Action   = ["ecs:DescribeTasks"]
        Resource = "*"
        Condition = {
          ArnEquals = { "ecs:cluster" = aws_ecs_cluster.this.arn }
        }
      },
      {
        Sid      = "ListProductionRlsReceipts"
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = var.full_rls_receipt_bucket_arn
        Condition = {
          StringLike = { "s3:prefix" = ["rls-receipts/${var.full_rls_green_release_sha}/*"] }
        }
      },
      {
        Sid      = "ReadProductionRlsReceipts"
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "${var.full_rls_receipt_bucket_arn}/rls-receipts/${var.full_rls_green_release_sha}/*"
      }
    ]
  })
}

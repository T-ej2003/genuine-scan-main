locals {
  # Production names are forbidden in this root module. Keep all names staging/stg-prefixed.
  name_prefix       = "mscqr-staging"
  short_name_prefix = "mscqr-stg"

  cluster_name                        = "mscqr-staging-euw2-main"
  service_name                        = "mscqr-staging-backend-service-euw2"
  task_family                         = "mscqr-staging-backend"
  alb_name                            = "mscqr-stg-alb-euw2"
  target_group_name                   = "mscqr-stg-backend-tg-euw2"
  log_group_name                      = "/ecs/mscqr-staging-backend"
  exec_log_group_name                 = "/aws/ecs/mscqr-staging/exec"
  database_role_broker_log_group_name = "/aws/lambda/mscqr-staging-database-role-executor-broker"
  db_identifier                       = "mscqr-staging-db"
  redis_group_id                      = "mscqr-staging-redis-euw2"
  artifacts_bucket                    = "mscqr-staging-euw2-artifacts-${var.account_id}"

  common_tags = merge(
    {
      ManagedBy   = "Terraform"
      Project     = "mscqr"
      Environment = var.environment
      Scope       = "staging-api"
    },
    var.tags
  )

  backend_environment = [
    { name = "NODE_ENV", value = "staging" },
    { name = "PORT", value = "4000" },
    { name = "SENTRY_ENVIRONMENT", value = "staging" },
    { name = "RUN_DB_MIGRATIONS_ON_START", value = "false" },
    { name = "RUN_BACKGROUND_WORKERS", value = "false" },
    { name = "OBJECT_STORAGE_REGION", value = var.aws_region },
    { name = "OBJECT_STORAGE_BUCKET", value = local.artifacts_bucket },
  ]

  backend_secrets = merge({
    DATABASE_URL                    = var.staging_secret_arns.database_url
    REDIS_URL                       = var.staging_secret_arns.redis_url
    JWT_SECRET_CURRENT              = var.staging_secret_arns.jwt_secret_current
    QR_SIGN_PRIVATE_KEY             = var.staging_secret_arns.qr_sign_private_key
    QR_SIGN_PUBLIC_KEY              = var.staging_secret_arns.qr_sign_public_key
    IP_HASH_SALT_CURRENT            = var.staging_secret_arns.ip_hash_salt_current
    TOKEN_HASH_SECRET_CURRENT       = var.staging_secret_arns.token_hash_secret_current
    SCAN_FINGERPRINT_SECRET         = var.staging_secret_arns.scan_fingerprint_secret
    PRINTER_SSE_SIGN_SECRET_CURRENT = var.staging_secret_arns.printer_sse_sign_secret_current
    CUSTOMER_VERIFY_OTP_SECRET      = var.staging_secret_arns.customer_verify_otp_secret
    CUSTOMER_VERIFY_TOKEN_SECRET    = var.staging_secret_arns.customer_verify_token_secret
    INCIDENT_HASH_SALT_CURRENT      = var.staging_secret_arns.incident_hash_salt_current
    AUTH_MFA_ENCRYPTION_KEY         = var.staging_secret_arns.auth_mfa_encryption_key
  }, local.full_rls_green_backend_secrets)

  app_database_secret_arn_pattern        = "arn:aws:secretsmanager:${var.aws_region}:${var.account_id}:secret:mscqr/staging/database-url/app-*"
  database_role_executor_contract_sha256 = filesha256("${path.module}/../../../documents/security/rls-program/staging-full-rls-executor-contract.json")
  database_role_broker_source_sha256     = filesha256("${path.module}/lambda/database-role-executor-broker/index.mjs")
  full_rls_green_modes = {
    full-rls-capability-preflight = null
    full-rls-role-provision       = "MSCQR_STAGING_GREEN_PROVISION_RUNTIME_ROLES"
    full-rls-role-verify          = null
    full-rls-admin-bootstrap      = "MSCQR_STAGING_GREEN_CREATE_AND_BOOTSTRAP_DATABASE"
    full-rls-admin-ownership      = "MSCQR_STAGING_GREEN_INSTALL_OWNERSHIP_GRANTS"
    full-rls-runtime-policy       = "MSCQR_STAGING_GREEN_INSTALL_RUNTIME_POLICIES"
    full-rls-verification         = null
    full-rls-rollback             = "MSCQR_STAGING_GREEN_ROLLBACK_EXACT_PACKAGE"
  }
  full_rls_green_runtime_secrets = {
    for key in ["app", "read", "preauth", "worker", "scheduled", "operator", "migration"] :
    key => "mscqr/staging/rls-green/phase2/database-url/${key}"
  }
  full_rls_green_backend_secrets = var.activate_full_rls_green_runtime ? {
    DATABASE_URL                   = aws_secretsmanager_secret.full_rls_green_runtime["app"].arn
    AUTHENTICATED_APP_DATABASE_URL = aws_secretsmanager_secret.full_rls_green_runtime["app"].arn
    PREAUTH_DATABASE_URL           = aws_secretsmanager_secret.full_rls_green_runtime["preauth"].arn
    MSCQR_C03_PREAUTH_DATABASE_URL = aws_secretsmanager_secret.full_rls_green_runtime["preauth"].arn
  } : {}
}

check "staging_name_guard" {
  assert {
    condition = alltrue([
      for name in [
        local.cluster_name,
        local.service_name,
        local.task_family,
        local.alb_name,
        local.target_group_name,
        local.log_group_name,
        local.exec_log_group_name,
        local.db_identifier,
        local.redis_group_id,
        local.artifacts_bucket,
      ] : can(regex("(?i)staging|stg", name)) && !can(regex("(?i)prod|production", name))
    ])
    error_message = "Every managed resource name must include staging/stg and must not include prod/production."
  }
}

data "aws_iam_policy_document" "ecs_exec_logs_kms" {
  statement {
    sid    = "EnableAccountIamPermissionsForStagingKey"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account_id}:root"]
    }

    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid    = "AllowCloudWatchLogsEncryptionForReviewedStagingLogGroups"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["logs.${var.aws_region}.amazonaws.com"]
    }

    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:GenerateDataKey*",
      "kms:ReEncrypt*",
    ]
    resources = ["*"]

    condition {
      test     = "ArnEquals"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values = [
        "arn:aws:logs:${var.aws_region}:${var.account_id}:log-group:${local.exec_log_group_name}",
        "arn:aws:logs:${var.aws_region}:${var.account_id}:log-group:${local.database_role_broker_log_group_name}",
      ]
    }
  }
}

resource "aws_kms_key" "ecs_exec_logs" {
  description             = "MSCQR staging ECS Exec session log encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.ecs_exec_logs_kms.json
}

resource "aws_kms_alias" "ecs_exec_logs" {
  name          = "alias/mscqr-staging-ecs-exec-logs"
  target_key_id = aws_kms_key.ecs_exec_logs.key_id
}

resource "aws_cloudwatch_log_group" "backend" {
  name              = local.log_group_name
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_log_group" "ecs_exec" {
  name              = local.exec_log_group_name
  retention_in_days = var.exec_log_retention_days
  kms_key_id        = aws_kms_key.ecs_exec_logs.arn
}

resource "aws_iam_role" "ecs_execution" {
  name = "mscqr-staging-ecs-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_execution_managed" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "ecs_execution_staging_secrets" {
  name = "mscqr-staging-ecs-execution-secrets"
  role = aws_iam_role.ecs_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue"]
        Resource = concat(
          values(local.backend_secrets),
          [local.app_database_secret_arn_pattern, var.staging_secret_arns.rls_green_admin_database_url]
        )
      }
    ]
  })
}

resource "aws_iam_role" "ecs_task" {
  name = "mscqr-staging-ecs-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role" "database_role_admin_task" {
  name = "mscqr-staging-database-role-admin-task"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role" "full_rls_green_executor_task" {
  name = "mscqr-staging-full-rls-green-executor-task"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = merge(local.common_tags, { Component = "full-rls-green-executor" })
}

resource "aws_iam_role" "database_role_cutover" {
  name = "mscqr-staging-database-role-cutover"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "TrustDedicatedStagingDatabaseRoleCutoverUserWithMfa"
      Effect    = "Allow"
      Principal = { AWS = var.database_role_cutover_operator_principal_arn }
      Action    = "sts:AssumeRole"
      Condition = {
        Bool = { "aws:MultiFactorAuthPresent" = "true" }
      }
    }]
  })

  tags = merge(local.common_tags, { Component = "database-role-cutover" })
}

resource "aws_iam_role_policy" "database_role_cutover" {
  name = "mscqr-staging-database-role-cutover"
  role = aws_iam_role.database_role_cutover.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "IdentifyExactStagingAccount"
        Effect   = "Allow"
        Action   = ["sts:GetCallerIdentity"]
        Resource = "*"
      },
      {
        Sid      = "DescribeExactStagingBackendService"
        Effect   = "Allow"
        Action   = ["ecs:DescribeServices"]
        Resource = "arn:aws:ecs:${var.aws_region}:${var.account_id}:service/${local.cluster_name}/${local.service_name}"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = var.aws_region
            "ecs:cluster"         = aws_ecs_cluster.staging.arn
          }
        }
      },
      {
        Sid      = "DescribeOnlyReviewedStagingTasks"
        Effect   = "Allow"
        Action   = ["ecs:DescribeTasks"]
        Resource = "arn:aws:ecs:${var.aws_region}:${var.account_id}:task/${local.cluster_name}/*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = var.aws_region
            "ecs:cluster"         = aws_ecs_cluster.staging.arn
          }
        }
      },
      {
        Sid      = "DescribeTaskDefinitionsRequiredByEcsApi"
        Effect   = "Allow"
        Action   = ["ecs:DescribeTaskDefinition"]
        Resource = "*"
        Condition = {
          StringEquals = { "aws:RequestedRegion" = var.aws_region }
        }
      },
      {
        Sid      = "ListExactStagingClusterServices"
        Effect   = "Allow"
        Action   = ["ecs:ListServices"]
        Resource = "*"
        Condition = {
          StringEquals = { "aws:RequestedRegion" = var.aws_region }
          ArnEquals    = { "ecs:cluster" = aws_ecs_cluster.staging.arn }
        }
      },
      {
        Sid      = "ListTaskDefinitionsRequiredByEcsApi"
        Effect   = "Allow"
        Action   = ["ecs:ListTaskDefinitions"]
        Resource = "*"
        Condition = {
          StringEquals = { "aws:RequestedRegion" = var.aws_region }
        }
      },
      {
        Sid      = "ListExactStagingBackendTasks"
        Effect   = "Allow"
        Action   = ["ecs:ListTasks"]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = var.aws_region
            "ecs:cluster"         = aws_ecs_cluster.staging.arn
          }
        }
      },
      {
        Sid      = "ListStagingEventBridgeRulesRequiredForConsumerInventory"
        Effect   = "Allow"
        Action   = ["events:ListRules"]
        Resource = "*"
        Condition = {
          StringEquals = { "aws:RequestedRegion" = var.aws_region }
        }
      },
      {
        Sid      = "ListOnlyStagingEventBridgeRuleTargets"
        Effect   = "Allow"
        Action   = ["events:ListTargetsByRule"]
        Resource = "arn:aws:events:${var.aws_region}:${var.account_id}:rule/mscqr-staging*"
        Condition = {
          StringEquals = { "aws:RequestedRegion" = var.aws_region }
        }
      },
      {
        Sid      = "DescribeOnlyStagingAppDatabaseSecretMetadata"
        Effect   = "Allow"
        Action   = ["secretsmanager:DescribeSecret"]
        Resource = local.app_database_secret_arn_pattern
        Condition = {
          StringEquals = { "aws:RequestedRegion" = var.aws_region }
        }
      },
      {
        Sid      = "RegisterOnlyReviewedStagingBackendTaskDefinitionFamily"
        Effect   = "Allow"
        Action   = ["ecs:RegisterTaskDefinition"]
        Resource = "arn:aws:ecs:${var.aws_region}:${var.account_id}:task-definition/${local.task_family}:*"
        Condition = {
          StringEquals = { "aws:RequestedRegion" = var.aws_region }
        }
      },
      {
        Sid      = "TagOnlyReviewedStagingBackendTaskDefinitionOnRegistration"
        Effect   = "Allow"
        Action   = ["ecs:TagResource"]
        Resource = "arn:aws:ecs:${var.aws_region}:${var.account_id}:task-definition/${local.task_family}:*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = var.aws_region
            "ecs:CreateAction"    = "RegisterTaskDefinition"
          }
        }
      },
      {
        Sid      = "UpdateOnlyExactStagingBackendService"
        Effect   = "Allow"
        Action   = ["ecs:UpdateService"]
        Resource = "arn:aws:ecs:${var.aws_region}:${var.account_id}:service/${local.cluster_name}/${local.service_name}"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = var.aws_region
            "ecs:cluster"         = aws_ecs_cluster.staging.arn
          }
          ArnLike = {
            "ecs:task-definition" = "arn:aws:ecs:${var.aws_region}:${var.account_id}:task-definition/${local.task_family}:*"
          }
        }
      },
      {
        Sid    = "ExecuteIdentityProofOnlyInReviewedBackendContainer"
        Effect = "Allow"
        Action = ["ecs:ExecuteCommand"]
        Resource = [
          aws_ecs_cluster.staging.arn,
          "arn:aws:ecs:${var.aws_region}:${var.account_id}:task/${local.cluster_name}/*",
        ]
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = var.aws_region
            "ecs:cluster"         = aws_ecs_cluster.staging.arn
            "ecs:container-name"  = "backend"
          }
          ArnLike = {
            "ecs:task" = "arn:aws:ecs:${var.aws_region}:${var.account_id}:task/${local.cluster_name}/*"
          }
        }
      },
      {
        Sid      = "GenerateOnlyStagingExecSessionDataKey"
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey"]
        Resource = aws_kms_key.ecs_exec_logs.arn
        Condition = {
          StringEquals = { "aws:RequestedRegion" = var.aws_region }
        }
      },
      {
        Sid      = "PassOnlyReviewedStagingBackendTaskRolesToEcs"
        Effect   = "Allow"
        Action   = ["iam:PassRole"]
        Resource = [aws_iam_role.ecs_execution.arn, aws_iam_role.ecs_task.arn]
        Condition = {
          StringEquals = { "iam:PassedToService" = "ecs-tasks.amazonaws.com" }
        }
      },
    ]
  })
}

resource "aws_iam_role_policy" "database_role_admin_task_secrets" {
  name = "mscqr-staging-database-role-admin-secrets"
  role = aws_iam_role.database_role_admin_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        for role, secret_name in {
          app      = "mscqr/staging/database-url/app"
          migrator = "mscqr/staging/database-url/migrator"
          } : {
          Sid      = "Create${replace(title(role), "-", "")}DatabaseRoleSecret"
          Effect   = "Allow"
          Action   = ["secretsmanager:CreateSecret"]
          Resource = "*"
          Condition = {
            StringEquals = {
              "secretsmanager:Name"        = secret_name
              "aws:RequestedRegion"        = var.aws_region
              "aws:RequestTag/Environment" = "staging"
              "aws:RequestTag/Application" = "mscqr"
              "aws:RequestTag/Purpose"     = "database-role-credential"
              "aws:RequestTag/ManagedBy"   = "manual-reviewed-script"
              "aws:RequestTag/Role"        = role
            }
          }
        }
      ],
      [{
        Sid    = "ManageExactStagingDatabaseRoleSecrets"
        Effect = "Allow"
        Action = [
          "secretsmanager:DescribeSecret",
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue",
          "secretsmanager:TagResource",
          "secretsmanager:UpdateSecretVersionStage",
        ]
        Resource = [
          "arn:aws:secretsmanager:${var.aws_region}:${var.account_id}:secret:mscqr/staging/database-url/app-*",
          "arn:aws:secretsmanager:${var.aws_region}:${var.account_id}:secret:mscqr/staging/database-url/migrator-*",
        ]
        Condition = {
          StringEquals = { "aws:RequestedRegion" = var.aws_region }
        }
      }]
    )
  })
}

resource "aws_secretsmanager_secret" "full_rls_green_runtime" {
  for_each                = local.full_rls_green_runtime_secrets
  name                    = each.value
  description             = "MSCQR staging full-RLS green ${each.key} database URL"
  recovery_window_in_days = 30
  tags = merge(local.common_tags, {
    Component = "full-rls-green-runtime"
    Role      = each.key
  })
}

resource "aws_iam_role_policy" "full_rls_green_executor" {
  name = "mscqr-staging-full-rls-green-executor"
  role = aws_iam_role.full_rls_green_executor_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadOnlyGreenAdministratorCredential"
        Effect   = "Allow"
        Action   = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"]
        Resource = var.staging_secret_arns.rls_green_admin_database_url
      },
      {
        Sid      = "ProvisionOnlyExactGreenRuntimeCredentials"
        Effect   = "Allow"
        Action   = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue"]
        Resource = [for secret in aws_secretsmanager_secret.full_rls_green_runtime : secret.arn]
      },
      {
        Sid      = "AppendOnlyGreenReceipts"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${aws_s3_bucket.artifacts.arn}/rls-receipts/*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "ecs_task_artifacts" {
  name = "mscqr-staging-artifacts-access"
  role = aws_iam_role.ecs_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowBucketReadinessChecks"
        Effect   = "Allow"
        Action   = ["s3:ListBucket", "s3:GetBucketLocation"]
        Resource = aws_s3_bucket.artifacts.arn
      },
      {
        Sid      = "AllowRlsValidationPrefixList"
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = aws_s3_bucket.artifacts.arn
        Condition = {
          StringLike = {
            "s3:prefix" = ["rls-validation/*"]
          }
        }
      },
      {
        Sid      = "AllowRlsValidationPrefixObjects"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
        Resource = "${aws_s3_bucket.artifacts.arn}/rls-validation/*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "ecs_task_execute_command_channels" {
  name = "mscqr-staging-ecs-exec-channels"
  role = aws_iam_role.ecs_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowEcsExecSsmMessagesChannelsInStagingRegion"
        Effect = "Allow"
        Action = [
          "ssmmessages:CreateControlChannel",
          "ssmmessages:CreateDataChannel",
          "ssmmessages:OpenControlChannel",
          "ssmmessages:OpenDataChannel",
        ]
        # AWS SSM Messages channel actions used by ECS Exec do not expose a
        # resource ARN, so IAM requires Resource="*"; scope is constrained to
        # the exact channel actions and the reviewed staging region.
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = var.aws_region
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "ecs_task_execute_command_kms" {
  name = "mscqr-staging-ecs-exec-kms"
  role = aws_iam_role.ecs_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowTaskAgentToDecryptStagingExecSessionKey"
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = aws_kms_key.ecs_exec_logs.arn
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = var.aws_region
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "ecs_task_execute_command_logs" {
  name = "mscqr-staging-ecs-exec-logs"
  role = aws_iam_role.ecs_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowExecAgentToDiscoverStagingExecLogGroups"
        Effect   = "Allow"
        Action   = ["logs:DescribeLogGroups"]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = var.aws_region
          }
        }
      },
      {
        Sid    = "AllowExecAgentToWriteStagingExecSessionLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:DescribeLogStreams",
          "logs:PutLogEvents",
        ]
        Resource = "arn:aws:logs:${var.aws_region}:${var.account_id}:log-group:${local.exec_log_group_name}:*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = var.aws_region
          }
        }
      }
    ]
  })
}

resource "aws_security_group" "alb" {
  name        = "mscqr-stg-alb-sg-euw2"
  description = "Staging ALB ingress from approved operator or CI CIDRs only"
  vpc_id      = var.vpc_id
}

resource "aws_security_group" "ecs" {
  name        = "mscqr-stg-ecs-sg-euw2"
  description = "Staging ECS backend accepts traffic only from staging ALB"
  vpc_id      = var.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "alb_operator_http" {
  for_each = toset(var.allowed_operator_cidrs)

  security_group_id = aws_security_group.alb.id
  description       = "Temporary staging HTTP ingress"
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
  cidr_ipv4         = can(regex(":", each.value)) ? null : each.value
  cidr_ipv6         = can(regex(":", each.value)) ? each.value : null
}

resource "aws_vpc_security_group_egress_rule" "alb_to_ecs_backend" {
  security_group_id            = aws_security_group.alb.id
  description                  = "ALB to staging ECS targets"
  from_port                    = 4000
  to_port                      = 4000
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.ecs.id
}

resource "aws_vpc_security_group_ingress_rule" "ecs_from_alb_backend" {
  security_group_id            = aws_security_group.ecs.id
  description                  = "Backend port from staging ALB"
  from_port                    = 4000
  to_port                      = 4000
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.alb.id
}

resource "aws_vpc_security_group_egress_rule" "ecs_temporary_outbound" {
  security_group_id = aws_security_group.ecs.id
  description       = "Temporary staging ECS outbound for AWS APIs, package endpoints, DB, and cache"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_security_group" "db" {
  name        = "mscqr-stg-db-sg-euw2"
  description = "Staging Postgres accepts traffic only from staging ECS"
  vpc_id      = var.vpc_id
}

resource "aws_security_group" "redis" {
  name        = "mscqr-stg-redis-sg-euw2"
  description = "Staging Valkey accepts traffic only from staging ECS"
  vpc_id      = var.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "db_from_ecs_postgres" {
  security_group_id            = aws_security_group.db.id
  description                  = "Postgres from staging ECS"
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.ecs.id
}

resource "aws_vpc_security_group_ingress_rule" "redis_from_ecs_valkey" {
  security_group_id            = aws_security_group.redis.id
  description                  = "Valkey from staging ECS"
  from_port                    = 6379
  to_port                      = 6379
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.ecs.id
}

resource "aws_lb" "staging" {
  name               = local.alb_name
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.public_subnet_ids
}

resource "aws_lb_target_group" "backend" {
  name        = local.target_group_name
  port        = 4000
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = var.vpc_id

  health_check {
    enabled             = true
    path                = "/health/live"
    protocol            = "HTTP"
    matcher             = "200-399"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.staging.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.backend.arn
  }
}

resource "aws_ecs_cluster" "staging" {
  name = local.cluster_name

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  configuration {
    execute_command_configuration {
      kms_key_id = aws_kms_key.ecs_exec_logs.arn
      logging    = "OVERRIDE"

      log_configuration {
        cloud_watch_encryption_enabled = true
        cloud_watch_log_group_name     = aws_cloudwatch_log_group.ecs_exec.name
      }
    }
  }
}

resource "aws_ecs_task_definition" "backend" {
  family                   = local.task_family
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = tostring(var.task_cpu)
  memory                   = tostring(var.task_memory)
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  container_definitions = jsonencode([
    {
      name      = "backend"
      image     = var.backend_image_uri
      essential = true
      portMappings = [
        {
          containerPort = 4000
          hostPort      = 4000
          protocol      = "tcp"
        }
      ]
      environment = local.backend_environment
      secrets = [
        for name, arn in local.backend_secrets : {
          name      = name
          valueFrom = arn
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.backend.name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "ecs"
        }
      }
    }
  ])
}

resource "aws_ecs_task_definition" "database_role_admin" {
  family                   = "mscqr-staging-database-role-admin"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.database_role_admin_task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  container_definitions = jsonencode([{
    name                   = "db-admin"
    image                  = var.backend_image_uri
    essential              = true
    command                = ["node", "scripts/staging-database-role-vpc-executor.mjs"]
    environment            = [{ name = "MSCQR_VPC_EXECUTOR_MODE", value = "probe" }]
    secrets                = [{ name = "DATABASE_URL", valueFrom = var.staging_secret_arns.database_url }]
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
        awslogs-group         = aws_cloudwatch_log_group.backend.name
        awslogs-region        = var.aws_region
        awslogs-stream-prefix = "database-role-admin"
      }
    }
  }])

  tags = merge(local.common_tags, { Component = "database-role-admin" })
}

resource "aws_ecs_task_definition" "full_rls_green" {
  for_each                 = local.full_rls_green_modes
  family                   = "mscqr-staging-full-rls-green-${replace(each.key, "full-rls-", "")}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.full_rls_green_executor_task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  container_definitions = jsonencode([{
    name      = "full-rls-green"
    image     = var.full_rls_green_executor_image_uri
    essential = true
    command   = ["node", "scripts/staging-full-rls-green-executor.mjs"]
    environment = concat([
      { name = "MSCQR_FULL_RLS_MODE", value = each.key },
      { name = "MSCQR_FULL_RLS_SOURCE_CONTRACT_SHA256", value = var.full_rls_green_source_contract_sha256 },
      { name = "MSCQR_FULL_RLS_PACKAGE_CHECKSUM_SHA256", value = var.full_rls_green_package_checksum_sha256 },
      { name = "MSCQR_FULL_RLS_RECEIPT_BUCKET", value = aws_s3_bucket.artifacts.id },
      { name = "RELEASE_GIT_SHA", value = var.full_rls_green_release_sha },
      ], each.value == null ? [] : [
      { name = "MSCQR_FULL_RLS_CONFIRMATION", value = each.value }
    ])
    secrets = [{
      name      = "DATABASE_URL"
      valueFrom = var.staging_secret_arns.rls_green_admin_database_url
    }]
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
        awslogs-group         = aws_cloudwatch_log_group.backend.name
        awslogs-region        = var.aws_region
        awslogs-stream-prefix = "full-rls-green"
      }
    }
  }])

  tags = merge(local.common_tags, {
    Component = "full-rls-green-executor"
    Mode      = each.key
  })
}

data "archive_file" "database_role_executor_broker" {
  type        = "zip"
  source_dir  = "${path.module}/lambda/database-role-executor-broker"
  output_path = "${path.module}/.terraform/database-role-executor-broker.zip"
}

resource "aws_iam_role" "database_role_executor_broker" {
  name = "mscqr-staging-database-role-executor-broker-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "database_role_executor_broker" {
  name = "mscqr-staging-database-role-executor-broker"
  role = aws_iam_role.database_role_executor_broker.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "RunReviewedDisposableDatabaseRoleTask"
        Effect = "Allow"
        Action = ["ecs:RunTask"]
        Resource = concat(
          ["arn:aws:ecs:${var.aws_region}:${var.account_id}:task-definition/mscqr-staging-database-role-admin:*"],
          [for task in aws_ecs_task_definition.full_rls_green : task.arn]
        )
        Condition = {
          ArnEquals = { "ecs:cluster" = aws_ecs_cluster.staging.arn }
        }
      },
      {
        Sid    = "PassOnlyReviewedDatabaseRoleTaskRoles"
        Effect = "Allow"
        Action = ["iam:PassRole"]
        Resource = [
          aws_iam_role.database_role_admin_task.arn,
          aws_iam_role.full_rls_green_executor_task.arn,
          aws_iam_role.ecs_execution.arn
        ]
        Condition = {
          StringEquals = { "iam:PassedToService" = "ecs-tasks.amazonaws.com" }
        }
      },
      {
        Sid      = "WriteOnlyReviewedBrokerLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.database_role_executor_broker.arn}:*"
      },
    ]
  })
}

resource "aws_cloudwatch_log_group" "database_role_executor_broker" {
  name              = local.database_role_broker_log_group_name
  retention_in_days = 30
  kms_key_id        = aws_kms_key.ecs_exec_logs.arn
  tags              = merge(local.common_tags, { Component = "database-role-executor-broker" })
}

resource "aws_lambda_function" "database_role_executor_broker" {
  function_name                  = "mscqr-staging-database-role-executor-broker"
  role                           = aws_iam_role.database_role_executor_broker.arn
  runtime                        = "nodejs22.x"
  handler                        = "index.handler"
  filename                       = data.archive_file.database_role_executor_broker.output_path
  source_code_hash               = data.archive_file.database_role_executor_broker.output_base64sha256
  memory_size                    = 128
  timeout                        = 30
  reserved_concurrent_executions = 1
  publish                        = true

  environment {
    variables = {
      BROKER_CLUSTER_ARN         = aws_ecs_cluster.staging.arn
      BROKER_TASK_DEFINITION_ARN = aws_ecs_task_definition.database_role_admin.arn
      BROKER_GREEN_TASK_DEFINITIONS_JSON = jsonencode({
        for mode, task in aws_ecs_task_definition.full_rls_green : mode => task.arn
      })
      BROKER_PRIVATE_SUBNETS_JSON     = jsonencode(var.app_private_subnet_ids)
      BROKER_SECURITY_GROUPS_JSON     = jsonencode([aws_security_group.ecs.id])
      BROKER_EXECUTOR_CONTRACT_SHA256 = local.database_role_executor_contract_sha256
      BROKER_SOURCE_SHA256            = local.database_role_broker_source_sha256
    }
  }

  tags = merge(local.common_tags, { Component = "database-role-executor-broker" })

  depends_on = [aws_cloudwatch_log_group.database_role_executor_broker]
}

resource "aws_lambda_alias" "database_role_executor_broker_reviewed" {
  name             = "reviewed"
  description      = "Immutable reviewed staging database-role executor broker"
  function_name    = aws_lambda_function.database_role_executor_broker.function_name
  function_version = aws_lambda_function.database_role_executor_broker.version
}

resource "aws_ecs_service" "backend" {
  name                   = local.service_name
  cluster                = aws_ecs_cluster.staging.id
  task_definition        = aws_ecs_task_definition.backend.arn
  desired_count          = var.desired_count
  launch_type            = "FARGATE"
  enable_execute_command = true

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200
  health_check_grace_period_seconds  = 120

  network_configuration {
    assign_public_ip = false
    security_groups  = [aws_security_group.ecs.id]
    subnets          = var.app_private_subnet_ids
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.backend.arn
    container_name   = "backend"
    container_port   = 4000
  }

  depends_on = [aws_lb_listener.http]
}

resource "aws_db_subnet_group" "staging" {
  name       = "mscqr-staging-db-subnet-euw2"
  subnet_ids = var.db_private_subnet_ids
}

resource "aws_db_instance" "staging" {
  identifier                  = local.db_identifier
  engine                      = "postgres"
  engine_version              = var.db_engine_version
  instance_class              = var.db_instance_class
  allocated_storage           = var.db_allocated_storage_gb
  storage_type                = "gp3"
  db_name                     = "mscqr_staging"
  username                    = "mscqr_staging_admin"
  manage_master_user_password = true
  publicly_accessible         = false
  multi_az                    = false
  backup_retention_period     = 7
  deletion_protection         = true
  skip_final_snapshot         = false
  db_subnet_group_name        = aws_db_subnet_group.staging.name
  vpc_security_group_ids      = [aws_security_group.db.id]
}

resource "aws_elasticache_subnet_group" "staging" {
  name       = "mscqr-staging-redis-subnet-euw2"
  subnet_ids = var.app_private_subnet_ids
}

resource "aws_elasticache_replication_group" "staging" {
  replication_group_id       = local.redis_group_id
  description                = "MSCQR staging Valkey for API/RLS validation"
  engine                     = "valkey"
  node_type                  = var.redis_node_type
  num_cache_clusters         = 1
  automatic_failover_enabled = false
  port                       = 6379
  subnet_group_name          = aws_elasticache_subnet_group.staging.name
  security_group_ids         = [aws_security_group.redis.id]
}

resource "aws_s3_bucket" "artifacts" {
  bucket = local.artifacts_bucket
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    id     = "expire-rls-validation-evidence"
    status = "Enabled"

    filter {
      prefix = "rls-validation/"
    }

    expiration {
      days = 30
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

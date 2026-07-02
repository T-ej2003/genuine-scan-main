locals {
  # Production names are forbidden in this root module. Keep all names staging/stg-prefixed.
  name_prefix       = "mscqr-staging"
  short_name_prefix = "mscqr-stg"

  cluster_name        = "mscqr-staging-euw2-main"
  service_name        = "mscqr-staging-backend-service-euw2"
  task_family         = "mscqr-staging-backend"
  alb_name            = "mscqr-stg-alb-euw2"
  target_group_name   = "mscqr-stg-backend-tg-euw2"
  log_group_name      = "/ecs/mscqr-staging-backend"
  exec_log_group_name = "/aws/ecs/mscqr-staging/exec"
  db_identifier       = "mscqr-staging-db"
  redis_group_id      = "mscqr-staging-redis-euw2"
  artifacts_bucket    = "mscqr-staging-euw2-artifacts-${var.account_id}"

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
    { name = "MSCQR_STAGING_RLS_BATCHES_READ_ENABLED", value = "false" },
    { name = "MSCQR_STAGING_RLS_BATCH_ALLOCATION_MAP_ENABLED", value = "false" },
    { name = "MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED", value = "false" },
  ]

  backend_secrets = {
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
  }
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
    sid    = "AllowCloudWatchLogsEncryptionForStagingExecLogGroup"
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
      values   = ["arn:aws:logs:${var.aws_region}:${var.account_id}:log-group:${local.exec_log_group_name}"]
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
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = values(local.backend_secrets)
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

resource "aws_iam_role_policy" "ecs_task_artifacts" {
  name = "mscqr-staging-artifacts-access"
  role = aws_iam_role.ecs_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
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

  ingress {
    description = "Temporary staging HTTP ingress"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.allowed_operator_cidrs
  }

  egress {
    description = "ALB to staging ECS targets"
    from_port   = 4000
    to_port     = 4000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "ecs" {
  name        = "mscqr-stg-ecs-sg-euw2"
  description = "Staging ECS backend accepts traffic only from staging ALB"
  vpc_id      = var.vpc_id

  ingress {
    description     = "Backend port from staging ALB"
    from_port       = 4000
    to_port         = 4000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    description = "Staging ECS controlled egress for AWS APIs, package endpoints, DB, and cache"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "db" {
  name        = "mscqr-stg-db-sg-euw2"
  description = "Staging Postgres accepts traffic only from staging ECS"
  vpc_id      = var.vpc_id

  ingress {
    description     = "Postgres from staging ECS"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs.id]
  }
}

resource "aws_security_group" "redis" {
  name        = "mscqr-stg-redis-sg-euw2"
  description = "Staging Valkey accepts traffic only from staging ECS"
  vpc_id      = var.vpc_id

  ingress {
    description     = "Valkey from staging ECS"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs.id]
  }
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

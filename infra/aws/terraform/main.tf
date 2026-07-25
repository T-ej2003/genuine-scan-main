locals {
  common_tags = merge(
    {
      ManagedBy = "Terraform"
      Project   = var.name_prefix
      Service   = "mscqr"
    },
    var.tags
  )

  ecr_lifecycle_policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Expire untagged images older than configured threshold"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = var.ecr_untagged_expiry_days
        }
        action = {
          type = "expire"
        }
      },
      {
        rulePriority = 2
        description  = "Keep only the newest release images"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = var.ecr_keep_release_images
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}

resource "aws_ecr_repository" "backend" {
  name                 = "${var.name_prefix}-backend"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = merge(local.common_tags, { Component = "backend" })
}

resource "aws_ecr_lifecycle_policy" "backend" {
  repository = aws_ecr_repository.backend.name
  policy     = local.ecr_lifecycle_policy
}

resource "aws_ecr_repository" "worker" {
  name                 = "${var.name_prefix}-worker"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = merge(local.common_tags, { Component = "worker" })
}

resource "aws_ecr_lifecycle_policy" "worker" {
  repository = aws_ecr_repository.worker.name
  policy     = local.ecr_lifecycle_policy
}

resource "aws_cloudwatch_log_group" "backend" {
  name              = "/ecs/${var.name_prefix}/backend"
  retention_in_days = var.log_retention_days
  tags              = merge(local.common_tags, { Component = "backend" })
}

resource "aws_cloudwatch_log_group" "worker" {
  name              = "/ecs/${var.name_prefix}/worker"
  retention_in_days = var.log_retention_days
  tags              = merge(local.common_tags, { Component = "worker" })
}

resource "aws_cloudwatch_log_group" "full_rls_green" {
  count             = var.enable_full_rls_green_executor ? 1 : 0
  name              = "/ecs/mscqr-production/full-rls-green"
  retention_in_days = var.log_retention_days
  tags              = merge(local.common_tags, { Component = "full-rls-green-executor" })
}

resource "aws_iam_role" "full_rls_green_executor" {
  count = var.enable_full_rls_green_executor ? 1 : 0
  name  = "mscqr-production-full-rls-green-executor-task"

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

resource "aws_secretsmanager_secret" "full_rls_green_runtime" {
  for_each                = var.enable_full_rls_green_executor ? toset(["app", "read", "preauth", "worker", "scheduled", "operator", "migration"]) : toset([])
  name                    = "mscqr/production/rls-green/phase2/database-url/${each.key}"
  description             = "MSCQR production full-RLS green ${each.key} database URL"
  recovery_window_in_days = 30
  tags                    = merge(local.common_tags, { Component = "full-rls-green-runtime", Role = each.key })
}

resource "aws_iam_role_policy" "full_rls_green_executor" {
  count = var.enable_full_rls_green_executor ? 1 : 0
  name  = "mscqr-production-full-rls-green-executor"
  role  = aws_iam_role.full_rls_green_executor[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadOnlyProductionGreenAdministratorCredential"
        Effect   = "Allow"
        Action   = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"]
        Resource = var.full_rls_green_admin_secret_arn
      },
      {
        Sid      = "ProvisionOnlyExactProductionGreenRuntimeCredentials"
        Effect   = "Allow"
        Action   = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue"]
        Resource = [for secret in aws_secretsmanager_secret.full_rls_green_runtime : secret.arn]
      },
      {
        Sid      = "AppendOnlyProductionGreenReceipts"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${var.full_rls_receipt_bucket_arn}/rls-receipts/*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "full_rls_green_execution_secret" {
  count = var.enable_full_rls_green_executor ? 1 : 0
  name  = "mscqr-production-full-rls-green-execution-secret"
  role  = element(reverse(split("/", var.backend_execution_role_arn)), 0)

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "ReadOnlyProductionGreenAdministratorCredentialAtTaskStart"
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = var.full_rls_green_admin_secret_arn
    }]
  })
}

check "full_rls_green_execution_role_guard" {
  assert {
    condition = !var.enable_full_rls_green_executor || can(regex(
      "^arn:aws:iam::[0-9]{12}:role/mscqr-production-ecs-execution-role$",
      var.backend_execution_role_arn
    ))
    error_message = "The production green executor must use the reviewed ECS execution role."
  }
}

resource "aws_ecs_cluster" "this" {
  name = var.cluster_name

  setting {
    name  = "containerInsights"
    value = var.enable_container_insights ? "enabled" : "disabled"
  }

  tags = local.common_tags
}

resource "aws_ecs_task_definition" "backend" {
  family                   = "${var.name_prefix}-backend"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.backend_cpu
  memory                   = var.backend_memory
  execution_role_arn       = var.backend_execution_role_arn
  task_role_arn            = var.backend_task_role_arn
  container_definitions    = var.backend_container_definitions_json

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  tags = merge(local.common_tags, { Component = "backend" })
}

resource "aws_ecs_task_definition" "worker" {
  family                   = "${var.name_prefix}-worker"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.worker_cpu
  memory                   = var.worker_memory
  execution_role_arn       = var.worker_execution_role_arn
  task_role_arn            = var.worker_task_role_arn
  container_definitions    = var.worker_container_definitions_json

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  tags = merge(local.common_tags, { Component = "worker" })
}

resource "aws_ecs_service" "backend" {
  name            = "${var.name_prefix}-backend"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.backend.arn
  desired_count   = var.backend_desired_count
  launch_type     = "FARGATE"

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200
  health_check_grace_period_seconds  = var.backend_target_group_arn != null ? var.backend_health_check_grace_period_seconds : null
  wait_for_steady_state              = true

  network_configuration {
    assign_public_ip = false
    security_groups  = var.service_security_group_ids
    subnets          = var.private_subnet_ids
  }

  dynamic "load_balancer" {
    for_each = var.backend_target_group_arn != null ? [1] : []
    content {
      target_group_arn = var.backend_target_group_arn
      container_name   = var.backend_container_name
      container_port   = var.backend_container_port
    }
  }

  tags = merge(local.common_tags, { Component = "backend" })
}

resource "aws_ecs_service" "worker" {
  name            = "${var.name_prefix}-worker"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.worker.arn
  desired_count   = var.worker_desired_count
  launch_type     = "FARGATE"

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200
  wait_for_steady_state              = true

  network_configuration {
    assign_public_ip = false
    security_groups  = var.service_security_group_ids
    subnets          = var.private_subnet_ids
  }

  tags = merge(local.common_tags, { Component = "worker" })
}

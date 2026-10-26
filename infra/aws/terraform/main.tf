locals {
  common_tags = merge(
    {
      ManagedBy = "Terraform"
      Project   = var.name_prefix
      Service   = "mscqr"
    },
    var.tags
  )

  # Retirement is disabled until a source-bound inventory and one-use deletion
  # authorization exist. A count-based ECR rule can expire a live digest.
  ecr_delete_guard = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyUnreviewedProductionImageRetirement"
      Effect    = "Deny"
      Principal = "*"
      Resource  = "*"
      Action = [
        "ecr:BatchDeleteImage",
        "ecr:DeleteRepository",
        "ecr:PutLifecyclePolicy",
        "ecr:UpdateImageStorageClass"
      ]
    }]
  })
  backend_container_definitions = var.backend_container_definitions_json
  worker_container_definitions  = var.worker_container_definitions_json
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

resource "aws_ecr_repository_policy" "backend_delete_guard" {
  repository = aws_ecr_repository.backend.name
  policy     = local.ecr_delete_guard
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

resource "aws_ecr_repository_policy" "worker_delete_guard" {
  repository = aws_ecr_repository.worker.name
  policy     = local.ecr_delete_guard
}

resource "aws_ecr_repository_policy" "web_delete_guard" {
  repository = "mscqr-web"
  policy     = local.ecr_delete_guard
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
  container_definitions    = local.backend_container_definitions

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
  container_definitions    = local.worker_container_definitions

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

variable "source_sha" {
  type = string
  validation {
    condition     = can(regex("^[a-f0-9]{40}$", var.source_sha))
    error_message = "Use the exact protected-main SHA."
  }
}

variable "worker_image" {
  type = string
  validation {
    condition     = can(regex("^368992683803\\.dkr\\.ecr\\.eu-west-2\\.amazonaws\\.com/mscqr-worker@sha256:[a-f0-9]{64}$", var.worker_image))
    error_message = "Use an immutable production worker image digest."
  }
}

variable "desired_count" {
  type    = number
  default = 0
  validation {
    condition     = contains([0, 1], var.desired_count)
    error_message = "Worker desired count must be zero for preparation or one for activation."
  }
}

data "aws_ecr_image" "worker" {
  repository_name = "mscqr-worker"
  image_tag       = var.source_sha
}

data "aws_ecs_cluster" "production" {
  cluster_name = "mscqr-prod-euw2-main"
}

data "aws_iam_role" "execution" {
  name = "mscqr-production-rls-green-worker-execution"
}

data "aws_iam_role" "task" {
  name = "mscqr-production-rls-green-worker-task"
}

data "aws_secretsmanager_secret" "smtp" {
  arn = "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/smtp-pass-arDHq6"
}

data "aws_cloudwatch_log_group" "worker" {
  name = "/ecs/mscqr-production/rls-green-worker"
}

locals {
  template = jsondecode(file("${path.module}/../production-green-stage-b/task-definitions/green-worker-candidate.json"))
  worker = merge(local.template.containerDefinitions[0], {
    image = var.worker_image
    environment = concat([
      for item in local.template.containerDefinitions[0].environment :
      item.name == "RELEASE_GIT_SHA" ? merge(item, { value = var.source_sha }) : item
    ], [{ name = "MSCQR_WORKER_MODE", value = "support-response-email" }])
    logConfiguration = merge(local.template.containerDefinitions[0].logConfiguration, {
      options = merge(local.template.containerDefinitions[0].logConfiguration.options, {
        "awslogs-group"         = data.aws_cloudwatch_log_group.worker.name
        "awslogs-stream-prefix" = "support-email"
      })
    })
  })
}

resource "aws_iam_role_policy" "smtp_secret_read" {
  name = "mscqr-support-email-smtp-secret-read"
  role = data.aws_iam_role.execution.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = data.aws_secretsmanager_secret.smtp.arn
    }]
  })
}

resource "aws_ecs_task_definition" "support_email" {
  family                   = "mscqr-production-support-email-worker"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = local.template.cpu
  memory                   = local.template.memory
  execution_role_arn       = data.aws_iam_role.execution.arn
  task_role_arn            = data.aws_iam_role.task.arn
  container_definitions    = jsonencode([local.worker])

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  lifecycle {
    precondition {
      condition     = data.aws_ecr_image.worker.image_digest == split("@", var.worker_image)[1]
      error_message = "Worker digest does not match the exact protected-source ECR tag."
    }
    precondition {
      condition     = local.template.executionRoleArn == data.aws_iam_role.execution.arn && local.template.taskRoleArn == data.aws_iam_role.task.arn
      error_message = "Worker task roles differ from the governed Stage B template."
    }
  }
}

resource "aws_ecs_service" "support_email" {
  name            = "mscqr-support-email-worker"
  cluster         = data.aws_ecs_cluster.production.arn
  task_definition = aws_ecs_task_definition.support_email.arn
  desired_count   = var.desired_count
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
    security_groups  = ["sg-0db971332ae625441"]
    subnets          = ["subnet-068d949017bd2ce45", "subnet-07e0a76e3a5241138"]
  }

  depends_on = [aws_iam_role_policy.smtp_secret_read]
}

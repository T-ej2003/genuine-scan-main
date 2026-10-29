variable "b03_executor_definition_json" {
  description = "Canonical fixed B03 definition generated from authenticated requirements and exact-source image evidence; the governed tfvars generator retains any installed revision."
  type        = string
  nullable    = true
  validation {
    condition = var.b03_executor_definition_json == null ? true : try(
      jsondecode(var.b03_executor_definition_json).family == "mscqr-production-b03-incremental" &&
      jsondecode(var.b03_executor_definition_json).executionRoleArn == "arn:aws:iam::368992683803:role/mscqr-production-full-rls-green-executor-execution" &&
      !contains(keys(jsondecode(var.b03_executor_definition_json)), "taskRoleArn") &&
      length(jsondecode(var.b03_executor_definition_json).containerDefinitions) == 1 &&
      jsondecode(var.b03_executor_definition_json).containerDefinitions[0].name == "production-b03-incremental" &&
    can(regex("^368992683803\\.dkr\\.ecr\\.eu-west-2\\.amazonaws\\.com/mscqr-backend@sha256:[a-f0-9]{64}$", jsondecode(var.b03_executor_definition_json).containerDefinitions[0].image)), false)
    error_message = "B03 requires its dedicated family, existing execution role, no task role, and an immutable backend image."
  }
}

locals {
  b03_definition = var.b03_executor_definition_json == null ? null : jsondecode(var.b03_executor_definition_json)
}

resource "aws_ecs_task_definition" "b03" {
  count                    = var.b03_executor_definition_json == null ? 0 : 1
  skip_destroy             = true
  family                   = local.b03_definition.family
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "1024"
  memory                   = "2048"
  execution_role_arn       = aws_iam_role.execution["executor"].arn
  container_definitions    = jsonencode(local.b03_definition.containerDefinitions)
  volume { name = "executor-tmp" }
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }
  tags = { Environment = "production", ManagedBy = "Terraform", Component = "b03-incremental-release" }
  lifecycle {
    precondition {
      condition     = !var.stage_b_recovery_only
      error_message = "B03 registration cannot be mixed with historical Stage B recovery."
    }
  }
}

output "b03_executor_task_definition_arn" {
  value = one(aws_ecs_task_definition.b03[*].arn)
}

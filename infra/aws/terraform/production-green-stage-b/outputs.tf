output "task_definition_arns" {
  value = merge(
    {
      for kind, arn in local.current_candidate_task_definition_arns : kind => arn
      if contains(["backend", "worker"], kind)
    },
    local.broker_task_definition_arns
  )
}

output "task_roles" {
  value = {
    executor = var.stage_a_executor_task_role_arn
    broker   = var.stage_a_broker_role_arn
    candidates = {
      for key, value in aws_iam_role.task : key => value.arn
    }
    execution = {
      for key, value in aws_iam_role.execution : key => value.arn
    }
  }
}

output "log_groups" {
  value = merge(
    { for key, value in aws_cloudwatch_log_group.stage_b : key => value.name },
    {
      executor = var.stage_a_executor_log_group_name
      broker   = var.stage_a_broker_log_group_name
    }
  )
}

output "security_group_id" {
  description = "Stage A-owned executor security group used by every broker-launched task."
  value       = var.stage_a_executor_security_group_id
}

output "bound_images" { value = local.image_by_kind }
output "broker_alias_arn" { value = aws_lambda_alias.reviewed.arn }

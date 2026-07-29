output "task_definition_arns" { value = merge({ for key, value in aws_ecs_task_definition.candidate : key => value.arn }, { for key, value in aws_ecs_task_definition.executor : key => value.arn }) }
output "task_roles" { value = { executor = var.stage_a_executor_task_role_arn, broker = var.stage_a_broker_role_arn, candidates = { for key, value in aws_iam_role.task : key => value.arn }, execution = { for key, value in aws_iam_role.execution : key => value.arn } } }
output "log_groups" { value = { for key, value in aws_cloudwatch_log_group.this : key => value.name } }
output "security_group_id" { value = aws_security_group.tasks.id }
output "bound_images" { value = local.image_by_kind }
output "broker_alias_arn" { value = aws_lambda_alias.reviewed.arn }

output "cluster_name" {
  value = aws_ecs_cluster.this.name
}

output "backend_ecr_repository_url" {
  value = aws_ecr_repository.backend.repository_url
}

output "worker_ecr_repository_url" {
  value = aws_ecr_repository.worker.repository_url
}

output "backend_service_name" {
  value = aws_ecs_service.backend.name
}

output "worker_service_name" {
  value = aws_ecs_service.worker.name
}

output "backend_task_definition_arn" {
  value = aws_ecs_task_definition.backend.arn
}

output "worker_task_definition_arn" {
  value = aws_ecs_task_definition.worker.arn
}
output "full_rls_green_executor_task_role_arn" {
  description = "Task role ARN for the isolated production full-RLS executor, when enabled."
  value       = var.enable_full_rls_green_infrastructure ? aws_iam_role.full_rls_green_executor[0].arn : null
}

output "full_rls_green_runtime_secret_arns" {
  description = "Exact runtime database secret ARNs provisioned for the production green boundary."
  value       = { for key, secret in aws_secretsmanager_secret.full_rls_green_runtime : key => secret.arn }
}

output "full_rls_green_database" {
  description = "Isolated green PostgreSQL metadata; contains no credential values."
  value = var.enable_full_rls_green_infrastructure ? {
    identifier        = aws_db_instance.full_rls_green[0].identifier
    endpoint          = aws_db_instance.full_rls_green[0].address
    maintenance_db    = aws_db_instance.full_rls_green[0].db_name
    administrator_arn = aws_db_instance.full_rls_green[0].master_user_secret[0].secret_arn
  } : null
}

output "full_rls_green_approval" {
  description = "Approval broker handles; contains no approval artifact or signature."
  value = var.enable_full_rls_green_infrastructure ? {
    checker_role_arn = aws_iam_role.full_rls_green_checker[0].arn
    kms_key_arn      = aws_kms_key.full_rls_green_approval[0].arn
    approval_secret  = aws_secretsmanager_secret.full_rls_green_approval[0].arn
    broker_function  = var.enable_full_rls_green_executor ? aws_lambda_function.full_rls_green_broker[0].arn : null
  } : null
}

output "full_rls_green_task_definition_arns" {
  description = "Fixed approval-broker task definitions by reviewed activation mode."
  value       = { for mode, task in aws_ecs_task_definition.full_rls_green : mode => task.arn }
}

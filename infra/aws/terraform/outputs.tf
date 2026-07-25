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
  value       = var.enable_full_rls_green_executor ? aws_iam_role.full_rls_green_executor[0].arn : null
}

output "full_rls_green_runtime_secret_arns" {
  description = "Exact runtime database secret ARNs provisioned for the production green boundary."
  value       = { for key, secret in aws_secretsmanager_secret.full_rls_green_runtime : key => secret.arn }
}

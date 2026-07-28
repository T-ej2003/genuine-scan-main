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

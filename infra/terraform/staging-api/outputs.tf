output "staging_alb_dns_name" {
  description = "AWS-generated staging ALB DNS name. Use this for collector STAGING_BASE_URL after apply approval."
  value       = aws_lb.staging.dns_name
}

output "ecs_cluster_name" {
  description = "Staging ECS cluster name."
  value       = aws_ecs_cluster.staging.name
}

output "staging_cluster_name" {
  description = "Staging ECS cluster name for approval evidence."
  value       = aws_ecs_cluster.staging.name
}

output "ecs_service_name" {
  description = "Staging backend ECS service name."
  value       = aws_ecs_service.backend.name
}

output "staging_backend_service_name" {
  description = "Staging backend ECS service name for approval evidence."
  value       = aws_ecs_service.backend.name
}

output "exec_log_group_name" {
  description = "CloudWatch log group for staging ECS Exec session logs."
  value       = aws_cloudwatch_log_group.ecs_exec.name
}

output "task_family" {
  description = "Staging backend ECS task family."
  value       = aws_ecs_task_definition.backend.family
}

output "rds_identifier" {
  description = "Staging RDS identifier."
  value       = aws_db_instance.staging.identifier
}

output "redis_replication_group_id" {
  description = "Staging Valkey replication group ID."
  value       = aws_elasticache_replication_group.staging.replication_group_id
}

output "artifacts_bucket" {
  description = "Staging artifacts bucket."
  value       = aws_s3_bucket.artifacts.bucket
}

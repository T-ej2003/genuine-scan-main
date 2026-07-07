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

output "staging_rds_address" {
  description = "Staging RDS hostname only. Does not include username, password, database name, or URL query parameters."
  value       = aws_db_instance.staging.address
}

output "staging_rds_endpoint" {
  description = "Staging RDS endpoint in host:port form. Does not include username, password, database name, or URL query parameters."
  value       = aws_db_instance.staging.endpoint
}

output "staging_rds_port" {
  description = "Staging RDS port only."
  value       = aws_db_instance.staging.port
}

output "staging_rds_database_name" {
  description = "Staging database name only. Does not include credentials or a full connection URL."
  value       = aws_db_instance.staging.db_name
}

output "staging_rds_username" {
  description = "Staging database username only. Does not include the database password or a full connection URL."
  value       = aws_db_instance.staging.username
}

output "redis_replication_group_id" {
  description = "Staging Valkey replication group ID."
  value       = aws_elasticache_replication_group.staging.replication_group_id
}

output "staging_redis_primary_endpoint_address" {
  description = "Staging Valkey primary endpoint hostname only. Does not include credentials or a full Redis URL."
  value       = aws_elasticache_replication_group.staging.primary_endpoint_address
}

output "staging_redis_port" {
  description = "Staging Valkey port only."
  value       = aws_elasticache_replication_group.staging.port
}

output "artifacts_bucket" {
  description = "Staging artifacts bucket."
  value       = aws_s3_bucket.artifacts.bucket
}

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

output "database_role_admin_task_definition_arn" {
  description = "Reviewed disposable staging-VPC database role executor task definition ARN. Contains no credential value."
  value       = aws_ecs_task_definition.database_role_admin.arn
}

output "database_role_executor_broker_function_name" {
  description = "Exact staging broker Lambda used to launch the reviewed disposable database-role task."
  value       = aws_lambda_function.database_role_executor_broker.function_name
}

output "database_role_executor_broker_reviewed_alias_arn" {
  description = "Immutable reviewed alias used for every staging database-role broker invocation."
  value       = aws_lambda_alias.database_role_executor_broker_reviewed.arn
}

output "database_role_cutover_role_arn" {
  description = "Dedicated MFA-gated role for the reviewed staging ECS database-role cutover only."
  value       = aws_iam_role.database_role_cutover.arn
}

output "staging_base_url" {
  description = "HTTP base URL for the Terraform-managed staging ALB. No custom DNS record exists in this module."
  value       = "http://${aws_lb.staging.dns_name}"
}

output "staging_health_url" {
  description = "Credential-free live-health URL for the Terraform-managed staging ALB."
  value       = "http://${aws_lb.staging.dns_name}/health/live"
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

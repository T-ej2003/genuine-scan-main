output "green_database" {
  value = { identifier = aws_db_instance.green.identifier, endpoint = aws_db_instance.green.address, port = aws_db_instance.green.port }
}

output "rds_managed_administrator_secret" {
  description = "RDS-managed master-user secret ARN only; Terraform never receives its value."
  value       = one(aws_db_instance.green.master_user_secret).secret_arn
}

output "stage_b_prerequisites" {
  value = {
    approval_kms_key_arn                 = aws_kms_key.approval.arn
    approval_secret_arn                  = aws_secretsmanager_secret.approval.arn
    executor_role_arn                    = aws_iam_role.executor.arn
    broker_role_arn                      = aws_iam_role.broker.arn
    database_security_group_id           = aws_security_group.database.id
    executor_security_group_id           = aws_security_group.executor.id
    executor_log_group_name              = aws_cloudwatch_log_group.executor.name
    executor_log_group_arn               = aws_cloudwatch_log_group.executor.arn
    broker_log_group_name                = aws_cloudwatch_log_group.broker.name
    broker_log_group_arn                 = aws_cloudwatch_log_group.broker.arn
    runtime_secret_arns                  = { for role, secret in aws_secretsmanager_secret.runtime : role => secret.arn }
    read_only_canary_database_secret_arn = aws_secretsmanager_secret.read_only_canary.arn
  }
}

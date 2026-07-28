output "green_database" {
  value = { identifier = aws_db_instance.green.identifier, endpoint = aws_db_instance.green.address, port = aws_db_instance.green.port }
}
output "stage_b_prerequisites" {
  value = {
    approval_kms_key_arn       = aws_kms_key.approval.arn
    approval_secret_arn        = aws_secretsmanager_secret.approval.arn
    executor_role_arn          = aws_iam_role.executor.arn
    broker_role_arn            = aws_iam_role.broker.arn
    executor_security_group_id = aws_security_group.executor.id
  }
}

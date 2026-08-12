locals {
  tags                      = merge({ Environment = "production", ManagedBy = "Terraform", Component = "full-rls-green-stage-a" }, var.tags)
  checker_assumer_role_name = "mscqr-production-independent-checker"
  executor_interface_endpoint_services = toset([
    "ecr.api",
    "ecr.dkr",
    "logs",
    "secretsmanager",
    "kms",
  ])
  runtime_secret_roles = toset(["app", "read", "preauth", "worker", "scheduled", "operator", "migration"])
  canary_secret_names  = toset(["ordinary_email", "ordinary_password", "ordinary_mfa_secret", "admin_email", "admin_password", "admin_mfa_secret"])
}

# Stage A owns only new, isolated green resources. Blue ECS, ALB, DNS, RDS,
# ECR and existing Secrets Manager handles are intentionally absent.
resource "aws_kms_key" "storage" {
  description             = "MSCQR isolated production green PostgreSQL storage"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  tags                    = local.tags
}

resource "aws_kms_alias" "storage" {
  name          = "alias/mscqr-production-rls-green-storage"
  target_key_id = aws_kms_key.storage.key_id
}

resource "aws_db_subnet_group" "green" {
  name       = "mscqr-production-rls-green-phase2"
  subnet_ids = var.private_subnet_ids
  tags       = local.tags
}

resource "aws_db_parameter_group" "green" {
  name   = "mscqr-production-rls-green-pg18"
  family = "postgres18"
  parameter {
    name         = "rds.force_ssl"
    value        = "1"
    apply_method = "pending-reboot"
  }
  tags = local.tags
}

resource "aws_security_group" "executor" {
  name        = "mscqr-production-rls-green-executor"
  description = "No-ingress or egress executor security group until reviewed Stage B networking"
  vpc_id      = var.vpc_id
  tags        = local.tags
}

resource "aws_security_group" "database" {
  name        = "mscqr-production-rls-green-database"
  description = "PostgreSQL ingress only from approved production security groups"
  vpc_id      = var.vpc_id
  tags        = local.tags
}

resource "aws_security_group" "executor_endpoints" {
  name        = "mscqr-production-rls-green-executor-endpoints"
  description = "HTTPS only from the production green executor"
  vpc_id      = var.vpc_id
  tags        = local.tags
}

resource "aws_vpc_security_group_ingress_rule" "executor_endpoints_https" {
  security_group_id            = aws_security_group.executor_endpoints.id
  referenced_security_group_id = aws_security_group.executor.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Production green executor to reviewed AWS interface endpoints"
}

resource "aws_vpc_security_group_ingress_rule" "runtime_endpoints_https" {
  for_each                     = var.runtime_security_group_ids
  security_group_id            = aws_security_group.executor_endpoints.id
  referenced_security_group_id = each.value
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Approved production runtime to reviewed AWS interface endpoints"
}

resource "aws_vpc_endpoint" "executor" {
  for_each            = local.executor_interface_endpoint_services
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${var.aws_region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = var.private_subnet_ids
  security_group_ids  = [aws_security_group.executor_endpoints.id]
  tags                = merge(local.tags, { Service = each.value })
}

resource "aws_vpc_security_group_ingress_rule" "executor_database" {
  security_group_id            = aws_security_group.database.id
  referenced_security_group_id = aws_security_group.executor.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
  description                  = "Brokered production RLS executor"
}

resource "aws_vpc_security_group_egress_rule" "executor_database" {
  security_group_id            = aws_security_group.executor.id
  referenced_security_group_id = aws_security_group.database.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
  description                  = "Green PostgreSQL only"
}

resource "aws_vpc_security_group_egress_rule" "executor_interface_endpoints" {
  security_group_id            = aws_security_group.executor.id
  referenced_security_group_id = aws_security_group.executor_endpoints.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Reviewed AWS interface endpoints only"
}

resource "aws_vpc_security_group_egress_rule" "executor_s3" {
  security_group_id = aws_security_group.executor.id
  prefix_list_id    = var.s3_prefix_list_id
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  description       = "Regional S3 gateway endpoint only"
}

resource "aws_vpc_security_group_egress_rule" "executor_dns_udp" {
  security_group_id = aws_security_group.executor.id
  cidr_ipv4         = var.vpc_dns_resolver_cidr
  from_port         = 53
  to_port           = 53
  ip_protocol       = "udp"
  description       = "VPC resolver DNS only"
}

resource "aws_vpc_security_group_egress_rule" "executor_dns_tcp" {
  security_group_id = aws_security_group.executor.id
  cidr_ipv4         = var.vpc_dns_resolver_cidr
  from_port         = 53
  to_port           = 53
  ip_protocol       = "tcp"
  description       = "VPC resolver DNS fallback only"
}

resource "aws_vpc_security_group_ingress_rule" "runtime_database" {
  for_each                     = var.runtime_security_group_ids
  security_group_id            = aws_security_group.database.id
  referenced_security_group_id = each.value
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
  description                  = "Approved production runtime"
}

resource "aws_db_instance" "green" {
  identifier                   = "mscqr-production-rls-green-phase2"
  engine                       = "postgres"
  engine_version               = "18.4"
  instance_class               = var.db_instance_class
  allocated_storage            = 100
  max_allocated_storage        = 500
  storage_type                 = "gp3"
  storage_encrypted            = true
  kms_key_id                   = aws_kms_key.storage.arn
  db_name                      = "mscqr_production"
  username                     = "mscqr_prod_admin"
  manage_master_user_password  = true
  port                         = 5432
  publicly_accessible          = false
  multi_az                     = true
  backup_retention_period      = 14
  backup_window                = "02:00-03:00"
  maintenance_window           = "sun:03:30-sun:04:30"
  auto_minor_version_upgrade   = true
  deletion_protection          = true
  skip_final_snapshot          = false
  final_snapshot_identifier    = "mscqr-production-rls-green-phase2-final"
  copy_tags_to_snapshot        = true
  performance_insights_enabled = true
  db_subnet_group_name         = aws_db_subnet_group.green.name
  parameter_group_name         = aws_db_parameter_group.green.name
  vpc_security_group_ids       = [aws_security_group.database.id]
  tags                         = merge(local.tags, { Colour = "green" })
}

resource "aws_iam_role" "checker" {
  name = "mscqr-production-rls-independent-checker"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect    = "Allow", Principal = { AWS = var.checker_principal_arns }, Action = "sts:AssumeRole",
    Condition = { Bool = { "aws:MultiFactorAuthPresent" = "true" } }
  }] })
  tags = local.tags
}

resource "aws_kms_key" "approval" {
  description              = "Independent production RLS approval signing key"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "RSA_3072"
  deletion_window_in_days  = 30
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Sid = "AccountAdministration", Effect = "Allow", Principal = { AWS = "arn:aws:iam::368992683803:root" }, Action = "kms:*", Resource = "*" },
    { Sid = "IndependentCheckerSigns", Effect = "Allow", Principal = { AWS = aws_iam_role.checker.arn }, Action = ["kms:GetPublicKey", "kms:Sign", "kms:Verify"], Resource = "*" }
  ] })
  tags = local.tags
}

resource "aws_kms_alias" "approval" {
  name          = "alias/mscqr-production-rls-approval"
  target_key_id = aws_kms_key.approval.key_id
}

resource "aws_iam_role_policy" "checker" {
  name = "mscqr-production-rls-independent-checker"
  role = aws_iam_role.checker.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect = "Allow", Action = ["kms:GetPublicKey", "kms:Sign", "kms:Verify"], Resource = aws_kms_key.approval.arn
  }] })
}

resource "aws_iam_role_policy" "checker_assume_target" {
  name = "mscqr-production-independent-checker-role-chain"
  role = local.checker_assumer_role_name
  policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Sid      = "AssumeExactRlsIndependentChecker"
    Effect   = "Allow"
    Action   = "sts:AssumeRole"
    Resource = aws_iam_role.checker.arn
  }] })
}

resource "aws_iam_role" "executor" {
  name = "mscqr-production-full-rls-green-executor-task"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect = "Allow", Principal = { Service = "ecs-tasks.amazonaws.com" }, Action = "sts:AssumeRole"
  }] })
  tags = local.tags
}

resource "aws_iam_role" "broker" {
  name = "mscqr-production-rls-approval-broker"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole"
  }] })
  tags = local.tags
}

resource "aws_cloudwatch_log_group" "executor" {
  name              = "/ecs/mscqr-production/full-rls-green"
  retention_in_days = var.log_retention_days
  tags              = local.tags
}

resource "aws_cloudwatch_log_group" "broker" {
  name              = "/aws/lambda/mscqr-production-rls-approval-broker"
  retention_in_days = var.log_retention_days
  tags              = local.tags
}

resource "aws_secretsmanager_secret" "approval" {
  name                    = "mscqr/production/rls-green/phase2/approval"
  description             = "Short-lived independently signed production RLS approval artifact"
  recovery_window_in_days = 30
  tags                    = local.tags
}

resource "aws_secretsmanager_secret" "runtime" {
  for_each                = local.runtime_secret_roles
  name                    = "mscqr/production/rls-green/phase2/database-url/${each.value}"
  description             = "MSCQR production full-RLS green ${each.value} database URL"
  recovery_window_in_days = 30
  tags                    = merge(local.tags, { Role = each.value })
}

resource "aws_secretsmanager_secret" "read_only_canary" {
  name                    = "mscqr/production/rls-green/phase4/read-only-canary-database-url"
  description             = "Dedicated production Phase 4 read-only RLS canary database URL handle"
  recovery_window_in_days = 30
  tags                    = merge(local.tags, { Role = "read_only_canary" })
}

resource "aws_secretsmanager_secret" "canary" {
  for_each                = local.canary_secret_names
  name                    = "mscqr/production/rls-green/phase2/canary/${replace(each.value, "_", "-")}"
  description             = "Approved production green canary ${replace(each.value, "_", " ")}"
  recovery_window_in_days = 30
  tags                    = local.tags
}

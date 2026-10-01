locals {
  account       = "368992683803"
  region        = "eu-west-2"
  repository    = "mscqr-victoria-recovery"
  family        = "mscqr-production-victoria-recovery"
  cluster_arn   = "arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main"
  task_role     = "mscqr-production-victoria-recovery-task"
  exec_role     = "mscqr-production-victoria-recovery-execution"
  broker_role   = "mscqr-production-victoria-recovery-broker"
  operator_role = "mscqr-production-victoria-recovery-operator"
  task_arn      = "arn:aws:ecs:eu-west-2:368992683803:task-definition/${local.family}:*"
  repo_arn      = "arn:aws:ecr:eu-west-2:368992683803:repository/${local.repository}"
  log_group     = "/ecs/mscqr-production/victoria-recovery"
  common_tags   = { Operation = "VICTORIA_FAILED_ONBOARDING_RECOVERY_V1", Target = "victoria@mscqr.com" }
}

resource "aws_ecr_repository" "recovery" {
  name                 = local.repository
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration { scan_on_push = true }
  encryption_configuration { encryption_type = "AES256" }
  tags = local.common_tags
}
resource "aws_ecr_lifecycle_policy" "recovery" {
  repository = aws_ecr_repository.recovery.name
  policy = jsonencode({ rules = [{ rulePriority = 1, description = "Retain three fixed-operation images", selection = {
    tagStatus = "any", countType = "imageCountMoreThan", countNumber = 3
  }, action = { type = "expire" } }] })
}

resource "aws_cloudwatch_log_group" "recovery" {
  name              = local.log_group
  retention_in_days = 365
  tags              = local.common_tags
}

resource "aws_s3_bucket" "evidence" {
  bucket        = var.evidence_bucket_name
  force_destroy = false
  tags          = local.common_tags
}
resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.evidence.arn
    }
  }
}
resource "aws_kms_key" "evidence" {
  description             = "Encrypted evidence for the fixed Victoria onboarding recovery operation"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  tags                    = local.common_tags
}
resource "aws_kms_alias" "evidence" {
  name          = "alias/mscqr-production-victoria-recovery-evidence"
  target_key_id = aws_kms_key.evidence.key_id
}
resource "aws_kms_key" "authorization" {
  description              = "Asymmetric solo-operator authorization for the fixed Victoria recovery"
  customer_master_key_spec = "RSA_2048"
  key_usage                = "SIGN_VERIFY"
  deletion_window_in_days  = 30
  tags                     = local.common_tags
}
resource "aws_kms_alias" "authorization" {
  name          = "alias/mscqr-production-victoria-recovery-authorization"
  target_key_id = aws_kms_key.authorization.key_id
}

resource "aws_security_group" "recovery" {
  name        = "mscqr-production-victoria-recovery"
  description = "Isolated egress for the one-shot Victoria recovery task"
  vpc_id      = var.vpc_id
  ingress     = []
  egress      = []
  tags        = local.common_tags
}
resource "aws_vpc_security_group_egress_rule" "database" {
  security_group_id            = aws_security_group.recovery.id
  referenced_security_group_id = var.active_database_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  description                  = "Only the active production PostgreSQL endpoint"
}
resource "aws_vpc_security_group_egress_rule" "dns_udp" {
  security_group_id = aws_security_group.recovery.id
  cidr_ipv4         = "${cidrhost(var.vpc_cidr_block, 2)}/32"
  ip_protocol       = "udp"
  from_port         = 53
  to_port           = 53
  description       = "VPC DNS resolver for fixed private endpoints"
}
resource "aws_vpc_security_group_egress_rule" "dns_tcp" {
  security_group_id = aws_security_group.recovery.id
  cidr_ipv4         = "${cidrhost(var.vpc_cidr_block, 2)}/32"
  ip_protocol       = "tcp"
  from_port         = 53
  to_port           = 53
  description       = "VPC DNS resolver for fixed private endpoints"
}
resource "aws_vpc_security_group_egress_rule" "aws_endpoints" {
  for_each                     = toset(var.service_endpoint_security_group_ids)
  security_group_id            = aws_security_group.recovery.id
  referenced_security_group_id = each.value
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  description                  = "Private AWS service endpoints"
}
resource "aws_iam_role" "task" {
  name                 = local.task_role
  assume_role_policy   = data.aws_iam_policy_document.ecs_trust.json
  max_session_duration = 3600
  tags                 = local.common_tags
}
resource "aws_iam_role" "execution" {
  name               = local.exec_role
  assume_role_policy = data.aws_iam_policy_document.ecs_trust.json
  tags               = local.common_tags
}
resource "aws_iam_role_policy" "execution" {
  role = aws_iam_role.execution.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = "ecr:GetAuthorizationToken", Resource = "*" },
    { Effect = "Allow", Action = ["ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"], Resource = local.repo_arn },
    { Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = "${aws_cloudwatch_log_group.recovery.arn}:*" },
  ] })
}
resource "aws_iam_role_policy" "task" {
  role = aws_iam_role.task.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = "rds-db:connect", Resource = "arn:aws:rds-db:eu-west-2:368992683803:dbuser/${var.active_database_resource_id}/mscqr_prod_victoria_recovery" },
    { Effect = "Allow", Action = "kms:Verify", Resource = aws_kms_key.authorization.arn },
    { Effect = "Allow", Action = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"], Resource = aws_kms_key.evidence.arn },
    { Effect = "Allow", Action = "s3:GetObject", Resource = "${aws_s3_bucket.evidence.arn}/authorizations/*" },
    { Effect = "Allow", Action = "s3:PutObject", Resource = ["${aws_s3_bucket.evidence.arn}/nonces/*", "${aws_s3_bucket.evidence.arn}/results/*"] },
  ] })
}

data "aws_iam_policy_document" "ecs_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "broker" {
  name               = local.broker_role
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
  tags               = local.common_tags
}
data "aws_iam_policy_document" "lambda_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}
resource "aws_iam_role_policy" "broker" {
  role = aws_iam_role.broker.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = "ecs:DescribeTaskDefinition", Resource = local.task_arn },
    { Effect = "Allow", Action = "ecs:StopTask", Resource = "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/*", Condition = { ArnEquals = { "ecs:cluster" = local.cluster_arn } } },
    { Effect = "Allow", Action = "ecs:RunTask", Resource = local.task_arn, Condition = { StringEquals = { "aws:RequestedRegion" = local.region, "ecs:enable-execute-command" = "false" }, ArnEquals = { "ecs:cluster" = local.cluster_arn } } },
    { Effect = "Allow", Action = "iam:PassRole", Resource = [aws_iam_role.task.arn, aws_iam_role.execution.arn], Condition = { StringEquals = { "iam:PassedToService" = "ecs-tasks.amazonaws.com" } } },
    { Effect = "Allow", Action = "kms:Verify", Resource = aws_kms_key.authorization.arn },
    { Effect = "Allow", Action = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"], Resource = aws_kms_key.evidence.arn },
    { Effect = "Allow", Action = "s3:GetObject", Resource = "${aws_s3_bucket.evidence.arn}/authorizations/*" },
    { Effect = "Allow", Action = "s3:PutObject", Resource = ["${aws_s3_bucket.evidence.arn}/invocations/*", "${aws_s3_bucket.evidence.arn}/tasks/*", "${aws_s3_bucket.evidence.arn}/cleanups/*"] },
    { Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = "${aws_cloudwatch_log_group.broker.arn}:*" },
    { Effect = "Allow", Action = "ecs:ListTasks", Resource = "*", Condition = { ArnEquals = { "ecs:cluster" = local.cluster_arn } } },
    { Effect = "Allow", Action = "ecs:DescribeTasks", Resource = "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/*", Condition = { ArnEquals = { "ecs:cluster" = local.cluster_arn } } },
    { Effect = "Allow", Action = "ec2:DescribeSecurityGroupRules", Resource = "*" },
    { Effect = "Allow", Action = "ec2:AuthorizeSecurityGroupIngress", Resource = "arn:aws:ec2:eu-west-2:368992683803:security-group/${var.active_database_security_group_id}" },
    { Effect = "Allow", Action = "ec2:CreateTags", Resource = "arn:aws:ec2:eu-west-2:368992683803:security-group-rule/*", Condition = { StringEquals = { "ec2:CreateAction" = "AuthorizeSecurityGroupIngress", "aws:RequestTag/Operation" = local.common_tags.Operation, "aws:RequestTag/Target" = local.common_tags.Target }, "ForAllValues:StringEquals" = { "aws:TagKeys" = ["Operation", "Target", "AuthorizationNonce", "SourceSha"] } } },
    { Effect = "Allow", Action = "ec2:RevokeSecurityGroupIngress", Resource = "arn:aws:ec2:eu-west-2:368992683803:security-group/${var.active_database_security_group_id}" },
  ] })
}
resource "aws_cloudwatch_log_group" "broker" {
  name              = "/aws/lambda/mscqr-production-victoria-recovery-broker"
  retention_in_days = 365
  tags              = local.common_tags
}

data "archive_file" "broker" {
  type        = "zip"
  output_path = "${path.module}/.terraform/victoria-recovery-broker.zip"
  source {
    content  = file("${path.module}/../lambda/victoria-recovery-broker/index.mjs")
    filename = "infra/aws/terraform/lambda/victoria-recovery-broker/index.mjs"
  }
  source {
    content  = file("${path.module}/../../../../scripts/aws/victoria-recovery-authorization.mjs")
    filename = "scripts/aws/victoria-recovery-authorization.mjs"
  }
  source {
    content  = file("${path.module}/../../../../scripts/aws/publish-victoria-recovery-authorization.mjs")
    filename = "scripts/aws/publish-victoria-recovery-authorization.mjs"
  }
  source {
    content  = file("${path.module}/../../../../scripts/aws/register-victoria-recovery-task-definition.mjs")
    filename = "scripts/aws/register-victoria-recovery-task-definition.mjs"
  }
  source {
    content  = file("${path.module}/../../../../scripts/aws/production-github-environment-approval.mjs")
    filename = "scripts/aws/production-github-environment-approval.mjs"
  }
  source {
    content  = file("${path.module}/../../../../scripts/security/victoria-recovery-dependencies.json")
    filename = "scripts/security/victoria-recovery-dependencies.json"
  }
  source {
    content  = file("${path.module}/../../../../scripts/security/victoria-recovery-sql.mjs")
    filename = "scripts/security/victoria-recovery-sql.mjs"
  }
  source {
    content  = file("${path.module}/../../../../scripts/security/victoria-recovery-installation.mjs")
    filename = "scripts/security/victoria-recovery-installation.mjs"
  }
  source {
    content  = file("${path.module}/../../../../backend/src/rls-waves/session-c/c05/victoriaRecovery.template.sql")
    filename = "backend/src/rls-waves/session-c/c05/victoriaRecovery.template.sql"
  }
  source {
    content  = file("${path.module}/../../../../backend/src/rls-waves/session-c/c05/victoriaRecovery.sql")
    filename = "backend/src/rls-waves/session-c/c05/victoriaRecovery.sql"
  }
  source {
    content  = file("${path.module}/../../../../backend/scripts/victoria-failed-onboarding-recovery.mjs")
    filename = "backend/scripts/victoria-failed-onboarding-recovery.mjs"
  }
  source {
    content  = file("${path.module}/../../../../backend/scripts/victoria-rds-iam-token.mjs")
    filename = "backend/scripts/victoria-rds-iam-token.mjs"
  }
  source {
    content  = file("${path.module}/../../../../.github/workflows/execute-victoria-onboarding-recovery.yml")
    filename = ".github/workflows/execute-victoria-onboarding-recovery.yml"
  }
  source {
    content  = file("${path.module}/Dockerfile")
    filename = "infra/aws/terraform/production-victoria-recovery/Dockerfile"
  }
  source {
    content  = file("${path.module}/task-definition.json")
    filename = "infra/aws/terraform/production-victoria-recovery/task-definition.json"
  }
  source {
    content  = file("${path.module}/main.tf")
    filename = "infra/aws/terraform/production-victoria-recovery/main.tf"
  }
  source {
    content  = file("${path.module}/variables.tf")
    filename = "infra/aws/terraform/production-victoria-recovery/variables.tf"
  }
  source {
    content  = file("${path.module}/outputs.tf")
    filename = "infra/aws/terraform/production-victoria-recovery/outputs.tf"
  }
  source {
    content  = file("${path.module}/versions.tf")
    filename = "infra/aws/terraform/production-victoria-recovery/versions.tf"
  }
}
resource "aws_lambda_function" "broker" {
  function_name                  = "mscqr-production-victoria-recovery-broker"
  role                           = aws_iam_role.broker.arn
  runtime                        = "nodejs24.x"
  handler                        = "infra/aws/terraform/lambda/victoria-recovery-broker/index.handler"
  filename                       = data.archive_file.broker.output_path
  source_code_hash               = data.archive_file.broker.output_base64sha256
  timeout                        = 120
  memory_size                    = 256
  publish                        = true
  reserved_concurrent_executions = 1
  environment {
    variables = {
      EVIDENCE_BUCKET             = aws_s3_bucket.evidence.bucket
      SIGNING_KEY_ARN             = aws_kms_key.authorization.arn
      ACTIVE_DATABASE_HOST        = var.active_database_host
      DATABASE_SECURITY_GROUP_ID  = var.active_database_security_group_id
      RECOVERY_SECURITY_GROUP_ID  = aws_security_group.recovery.id
      TASK_ROLE_ARN               = aws_iam_role.task.arn
      EXECUTION_ROLE_ARN          = aws_iam_role.execution.arn
      ECS_CLUSTER_ARN             = local.cluster_arn
      PRIVATE_SUBNET_IDS          = jsonencode(var.private_subnet_ids)
      RECOVERY_SECURITY_GROUP_IDS = jsonencode([aws_security_group.recovery.id])
    }
  }
  tags = local.common_tags
}
resource "aws_lambda_alias" "broker" {
  name             = "production"
  function_name    = aws_lambda_function.broker.function_name
  function_version = aws_lambda_function.broker.version
}

data "aws_iam_policy_document" "operator_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = ["arn:aws:iam::368992683803:oidc-provider/token.actions.githubusercontent.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:T-ej2003/genuine-scan-main:environment:production-victoria-recovery"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:repository_id"
      values   = ["1145608538"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:repository_owner_id"
      values   = ["183396573"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:ref"
      values   = ["refs/heads/main"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:job_workflow_ref"
      values   = ["T-ej2003/genuine-scan-main/.github/workflows/execute-victoria-onboarding-recovery.yml@refs/heads/main"]
    }
  }
}
resource "aws_iam_role" "operator" {
  name               = local.operator_role
  assume_role_policy = data.aws_iam_policy_document.operator_trust.json
  tags               = local.common_tags
}
resource "aws_iam_role_policy" "operator" {
  role = aws_iam_role.operator.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = "kms:Sign", Resource = aws_kms_key.authorization.arn },
    { Effect = "Allow", Action = ["ecr:GetAuthorizationToken"], Resource = "*" },
    { Effect = "Allow", Action = ["ecr:BatchCheckLayerAvailability", "ecr:CompleteLayerUpload", "ecr:InitiateLayerUpload", "ecr:PutImage", "ecr:UploadLayerPart", "ecr:DescribeImages"], Resource = local.repo_arn },
    { Effect = "Allow", Action = "ecs:RegisterTaskDefinition", Resource = "*" },
    { Effect = "Allow", Action = "iam:PassRole", Resource = [aws_iam_role.task.arn, aws_iam_role.execution.arn], Condition = { StringEquals = { "iam:PassedToService" = "ecs-tasks.amazonaws.com" } } },
    { Effect = "Allow", Action = "lambda:InvokeFunction", Resource = aws_lambda_alias.broker.arn },
    { Effect = "Allow", Action = "s3:PutObject", Resource = "${aws_s3_bucket.evidence.arn}/authorizations/*" },
    { Effect = "Allow", Action = ["kms:Decrypt", "kms:GenerateDataKey"], Resource = aws_kms_key.evidence.arn },
    { Effect = "Allow", Action = "s3:GetObject", Resource = "${aws_s3_bucket.evidence.arn}/results/*" },
  ] })
}

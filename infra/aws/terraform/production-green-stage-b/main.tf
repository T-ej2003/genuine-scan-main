locals {
  tags                  = { Environment = "production", ManagedBy = "Terraform", Component = "full-rls-green-stage-b" }
  modes                 = toset(["full-rls-capability-preflight", "full-rls-admin-bootstrap", "full-rls-role-provision", "full-rls-role-verify", "full-rls-admin-ownership", "full-rls-runtime-policy", "full-rls-verification", "full-rls-rollback"])
  logs                  = { backend = "/ecs/mscqr-production/rls-green-backend", worker = "/ecs/mscqr-production/rls-green-worker", executor = "/ecs/mscqr-production/full-rls-green", canary = "/ecs/mscqr-production/rls-green-canary", broker = "/aws/lambda/mscqr-production-rls-approval-broker" }
  image_by_kind         = { backend = var.backend_image, worker = var.worker_image, executor = var.executor_image, canary = var.canary_image }
  backend               = replace(replace(replace(file("${path.module}/task-definitions/green-backend-candidate.json"), "{{BACKEND_IMAGE}}", var.backend_image), "{{RELEASE_SHA}}", var.release_sha), "{{BACKEND_LOG_GROUP}}", local.logs.backend)
  worker                = replace(replace(replace(file("${path.module}/task-definitions/green-worker-candidate.json"), "{{WORKER_IMAGE}}", var.worker_image), "{{RELEASE_SHA}}", var.release_sha), "{{WORKER_LOG_GROUP}}", local.logs.worker)
  canary                = replace(replace(replace(replace(replace(file("${path.module}/task-definitions/green-application-canary.json"), "{{CANARY_IMAGE}}", var.canary_image), "{{RELEASE_SHA}}", var.release_sha), "{{SOURCE_CONTRACT_SHA256}}", var.source_contract_sha256), "{{MIGRATION_SET_DIGEST}}", var.migration_set_digest), "{{CANARY_LOG_GROUP}}", local.logs.canary)
  executor              = replace(replace(replace(replace(replace(replace(replace(replace(file("${path.module}/task-definitions/green-activation-executor.json"), "{{EXECUTOR_IMAGE}}", var.executor_image), "{{MODE}}", "full-rls-verification"), "{{RELEASE_SHA}}", var.release_sha), "{{SOURCE_CONTRACT_SHA256}}", var.source_contract_sha256), "{{MIGRATION_SET_DIGEST}}", var.migration_set_digest), "{{PACKAGE_CHECKSUM_SHA256}}", var.package_checksum_sha256), "{{RECEIPT_BUCKET}}", trimprefix(var.receipt_bucket_arn, "arn:aws:s3:::")), "{{EXECUTOR_LOG_GROUP}}", local.logs.executor)
  execution_secret_arns = { for kind, rendered in { backend = local.backend, worker = local.worker, canary = local.canary, executor = local.executor } : kind => distinct([for secret in jsondecode(rendered).containerDefinitions[0].secrets : regex("^arn:aws:secretsmanager:[^:]+:[^:]+:secret:[^:]+", secret.valueFrom)]) }
}

resource "aws_security_group" "tasks" {
  name        = "mscqr-production-rls-green-stage-b"
  description = "Stage B task egress only to approved endpoints and green database"
  vpc_id      = var.vpc_id
  egress      = []
  tags        = local.tags
}
resource "aws_vpc_security_group_egress_rule" "database" {
  security_group_id            = aws_security_group.tasks.id
  referenced_security_group_id = var.stage_a_executor_security_group_id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
  description                  = "Green database only"
}
resource "aws_cloudwatch_log_group" "this" {
  for_each          = local.logs
  name              = each.value
  retention_in_days = var.log_retention_days
  tags              = local.tags
}
resource "aws_iam_role" "execution" {
  for_each           = toset(["backend", "worker", "executor", "canary"])
  name               = "mscqr-production-rls-green-${each.key}-execution"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Principal = { Service = "ecs-tasks.amazonaws.com" }, Action = "sts:AssumeRole" }] })
  tags               = local.tags
}
resource "aws_iam_role_policy_attachment" "execution" {
  for_each   = aws_iam_role.execution
  role       = each.value.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}
resource "aws_iam_role_policy" "execution_secrets" {
  for_each = aws_iam_role.execution
  name     = "stage-b-exact-secret-references"
  role     = each.value.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect = "Allow", Action = ["secretsmanager:GetSecretValue"], Resource = local.execution_secret_arns[each.key]
  }] })
}
resource "aws_iam_role" "task" {
  for_each           = toset(["backend", "worker", "canary"])
  name               = "mscqr-production-rls-green-${each.key}-task"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Principal = { Service = "ecs-tasks.amazonaws.com" }, Action = "sts:AssumeRole" }] })
  tags               = local.tags
}
resource "aws_ecs_task_definition" "candidate" {
  for_each                 = { backend = local.backend, worker = local.worker, canary = local.canary }
  family                   = jsondecode(each.value).family
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = jsondecode(each.value).cpu
  memory                   = jsondecode(each.value).memory
  execution_role_arn       = aws_iam_role.execution[each.key].arn
  task_role_arn            = aws_iam_role.task[each.key].arn
  container_definitions    = each.value
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }
  tags = local.tags
}
resource "aws_ecs_task_definition" "executor" {
  for_each                 = local.modes
  family                   = replace(jsondecode(local.executor).family, "full-rls-verification", each.key)
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = jsondecode(local.executor).cpu
  memory                   = jsondecode(local.executor).memory
  execution_role_arn       = aws_iam_role.execution["executor"].arn
  task_role_arn            = var.stage_a_executor_task_role_arn
  container_definitions    = replace(local.executor, "full-rls-verification", each.key)
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }
  tags = local.tags
}
resource "aws_dynamodb_table" "replay" {
  name         = "mscqr-production-rls-stage-b-replay"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "approvalMode"
  attribute {
    name = "approvalMode"
    type = "S"
  }
  ttl {
    attribute_name = "expiresAt"
    enabled        = true
  }
  tags = local.tags
}
resource "aws_iam_role_policy" "broker" {
  name = "stage-b-broker"
  role = split("/", var.stage_a_broker_role_arn)[1]
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["ecs:RunTask"], Resource = values(aws_ecs_task_definition.executor)[*].arn },
    { Effect = "Allow", Action = ["iam:PassRole"], Resource = [var.stage_a_executor_task_role_arn, aws_iam_role.execution["executor"].arn] },
    { Effect = "Allow", Action = ["dynamodb:PutItem", "dynamodb:DeleteItem", "dynamodb:UpdateItem"], Resource = aws_dynamodb_table.replay.arn },
    { Effect = "Allow", Action = ["secretsmanager:GetSecretValue", "kms:Verify"], Resource = [var.approval_secret_arn, var.approval_kms_key_arn] }
  ] })
}
resource "aws_lambda_function" "broker" {
  function_name    = "mscqr-production-rls-approval-broker"
  role             = var.stage_a_broker_role_arn
  handler          = "index.handler"
  runtime          = "nodejs24.x"
  filename         = var.broker_package_path
  source_code_hash = filebase64sha256(var.broker_package_path)
  timeout          = 30
  environment { variables = { STAGE_B_REPLAY_TABLE = aws_dynamodb_table.replay.name, STAGE_B_RECEIPT_BUCKET = trimprefix(var.receipt_bucket_arn, "arn:aws:s3:::") } }
  tags = local.tags
}
resource "aws_lambda_alias" "reviewed" {
  name             = "reviewed"
  function_name    = aws_lambda_function.broker.function_name
  function_version = aws_lambda_function.broker.version
}
resource "aws_lambda_permission" "release_deployer" {
  statement_id  = "OnlyProtectedReleaseRoleMayInvokeReviewedAlias"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.broker.function_name
  qualifier     = aws_lambda_alias.reviewed.name
  principal     = "arn:aws:iam::368992683803:role/mscqr-production-release-deployer"
}

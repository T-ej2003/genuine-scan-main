locals {
  normal_deployer_role = "mscqr-production-normal-deployer"
  bootstrap_role       = "mscqr-production-component-state-bootstrap"
  release_role         = "mscqr-production-release-deployer"
  tags                 = { ManagedBy = "Terraform", Environment = "production", Stack = "production-component-deployment-state" }
}

resource "aws_dynamodb_table" "component_deployment_state" {
  name         = "mscqr-production-component-deployment-state"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "stateKey"
  attribute {
    name = "stateKey"
    type = "S"
  }
  point_in_time_recovery {
    enabled = true
  }
  server_side_encryption {
    enabled = true
  }
  tags = local.tags
}

resource "aws_iam_role" "normal_deployer" {
  name                 = local.normal_deployer_role
  description          = "GitHub OIDC only: normal production backend/frontend deployment and component-state CAS."
  max_session_duration = 3600
  assume_role_policy   = file("${path.module}/normal-deployer-trust-policy.json")
  tags                 = local.tags
}

resource "aws_iam_role_policy" "normal_deployer" {
  name   = "MSCQRProductionNormalDeployment"
  role   = aws_iam_role.normal_deployer.id
  policy = file("${path.module}/normal-deployer-policy.json")
}

resource "aws_iam_role" "bootstrap" {
  name                 = local.bootstrap_role
  description          = "GitHub OIDC only: one-time authenticated production component-state bootstrap."
  max_session_duration = 3600
  assume_role_policy   = file("${path.module}/bootstrap-trust-policy.json")
  tags                 = local.tags
}

resource "aws_iam_role_policy" "bootstrap" {
  name   = "MSCQRProductionComponentStateBootstrap"
  role   = aws_iam_role.bootstrap.id
  policy = file("${path.module}/bootstrap-policy.json")
}

data "aws_iam_role" "release_deployer" {
  name = local.release_role
}

resource "aws_iam_role_policy" "release_terminal_state" {
  name   = "MSCQRProductionComponentStateTerminalWriter"
  role   = data.aws_iam_role.release_deployer.id
  policy = file("${path.module}/release-terminal-state-policy.json")
}

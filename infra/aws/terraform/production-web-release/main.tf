locals {
  publisher_role = "mscqr-production-web-image-publisher"
  release_role   = "mscqr-production-release-deployer"
  tags           = { ManagedBy = "Terraform", Environment = "production", Stack = "production-web-release" }
}

resource "aws_iam_role" "publisher" {
  name                 = local.publisher_role
  description          = "GitHub OIDC only: publish the reviewed production web image."
  max_session_duration = 3600
  assume_role_policy   = file("${path.module}/publisher-trust-policy.json")
  permissions_boundary = aws_iam_policy.publisher_boundary.arn
  tags                 = local.tags
}

resource "aws_iam_policy" "publisher_boundary" {
  name   = "MSCQRProductionWebImagePublisherBoundary"
  policy = file("${path.module}/publisher-permissions-policy.json")
}

resource "aws_iam_role_policy" "publisher" {
  name   = "MSCQRProductionWebImagePublisher"
  role   = aws_iam_role.publisher.id
  policy = file("${path.module}/publisher-permissions-policy.json")
}

data "aws_iam_role" "release_deployer" { name = local.release_role }

resource "aws_iam_role_policy" "frontend_activation" {
  name   = "MSCQRProductionFrontendActivation"
  role   = data.aws_iam_role.release_deployer.id
  policy = file("${path.module}/frontend-activation-policy.json")
}

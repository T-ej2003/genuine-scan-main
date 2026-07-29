locals {
  role_name = "mscqr-production-stage-b-publisher-bootstrap"
  tags = {
    ManagedBy   = "Terraform"
    Environment = "production"
    Stack       = "production-green-stage-b-publisher-bootstrap"
  }
}

resource "aws_iam_role" "publisher_bootstrap" {
  name        = local.role_name
  description = "MFA-only operator role for the isolated Stage B image-publisher Terraform root."
  # IAM's shortest supported role maximum is one hour.
  max_session_duration = 3600
  assume_role_policy   = file("${path.module}/trust-policy.json")
  tags                 = local.tags
}

resource "aws_iam_role_policy" "publisher_bootstrap" {
  name   = "MSCQRProductionStageBPublisherBootstrap"
  role   = aws_iam_role.publisher_bootstrap.id
  policy = file("${path.module}/permissions-policy.json")
}

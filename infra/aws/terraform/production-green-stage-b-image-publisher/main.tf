locals {
  role_name = "mscqr-production-stage-b-image-publisher"
  tags = {
    ManagedBy   = "Terraform"
    Environment = "production"
    Stack       = "production-green-stage-b-image-publisher"
  }
}

resource "aws_iam_role" "publisher" {
  name                 = local.role_name
  description          = "GitHub OIDC only: publish reviewed production-green Stage B images."
  max_session_duration = 3600
  assume_role_policy   = file("${path.module}/trust-policy.json")
  tags                 = local.tags
}

resource "aws_iam_policy" "publisher" {
  name        = "MSCQRProductionGreenStageBImagePublisher"
  description = "ECR-only policy for the reviewed production-green Stage B image publisher."
  policy      = file("${path.module}/permissions-policy.json")
}

resource "aws_iam_role_policy_attachment" "publisher" {
  role       = aws_iam_role.publisher.name
  policy_arn = aws_iam_policy.publisher.arn
}

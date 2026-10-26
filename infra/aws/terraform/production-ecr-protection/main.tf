locals {
  common_tags = {
    ManagedBy   = "Terraform"
    Environment = "production"
    Stack       = "production-ecr-protection"
  }

  # Retirement stays disabled until a separately governed transaction exists.
  ecr_delete_guard = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyUnreviewedProductionImageRetirement"
      Effect    = "Deny"
      Principal = "*"
      Resource  = "*"
      Action = [
        "ecr:BatchDeleteImage",
        "ecr:DeleteRepository",
        "ecr:PutLifecyclePolicy",
        "ecr:UpdateImageStorageClass"
      ]
      }, {
      Sid       = "AllowLegacyPublisherProtectionRead"
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::368992683803:role/github-actions-mscqr-deploy" }
      Resource  = "*"
      Action    = "ecr:GetRepositoryPolicy"
    }]
  })
}

data "aws_ecr_repository" "backend" { name = "mscqr-backend" }
data "aws_ecr_repository" "web" { name = "mscqr-web" }
data "aws_ecr_repository" "worker" { name = "mscqr-worker" }
data "aws_sns_topic" "alerts" { name = "mscqr-prod-alerts" }

resource "aws_ecr_repository_policy" "backend_delete_guard" {
  repository = data.aws_ecr_repository.backend.name
  policy     = local.ecr_delete_guard
}

resource "aws_ecr_repository_policy" "web_delete_guard" {
  repository = data.aws_ecr_repository.web.name
  policy     = local.ecr_delete_guard
}

resource "aws_ecr_repository_policy" "worker_delete_guard" {
  repository = data.aws_ecr_repository.worker.name
  policy     = local.ecr_delete_guard
}

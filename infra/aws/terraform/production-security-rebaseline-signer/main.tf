locals {
  account_id = "368992683803"
  region     = "eu-west-2"
  role_name  = "mscqr-production-security-rebaseline-image-signer"
  key_alias  = "alias/mscqr-production-security-rebaseline-image-evidence"
  tags = {
    ManagedBy   = "Terraform"
    Environment = "production"
    Stack       = "production-security-rebaseline-signer"
    Purpose     = "read-only-security-rebaseline-image-authorization"
  }
}

resource "aws_iam_role" "signer" {
  name                 = local.role_name
  description          = "Purpose-limited GitHub OIDC signer for read-only production security-rebaseline image authorizations."
  max_session_duration = 3600
  assume_role_policy   = file("${path.module}/trust-policy.json")
  tags                 = local.tags
}

resource "aws_kms_key" "image_authorization" {
  description              = "Purpose-specific production security-rebaseline image authorization signer"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "RSA_3072"
  deletion_window_in_days  = 30
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountBreakGlassAdministration"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "ProtectedWorkflowImageAuthorizationSigningOnly"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.signer.arn }
        Action    = ["kms:Sign"]
        Resource  = "*"
        Condition = {
          StringEquals = {
            "kms:SigningAlgorithm" = "RSASSA_PSS_SHA_256"
            "kms:MessageType"      = "DIGEST"
            "kms:RequestAlias"     = local.key_alias
          }
        }
      }
    ]
  })
  tags = local.tags
}

resource "aws_kms_alias" "image_authorization" {
  name          = local.key_alias
  target_key_id = aws_kms_key.image_authorization.key_id
}

resource "aws_iam_role_policy" "sign_only" {
  name = "ProductionSecurityRebaselineImageAuthorizationSignOnly"
  role = aws_iam_role.signer.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "SignPurposeSpecificAuthorizationDigestsOnly"
      Effect   = "Allow"
      Action   = ["kms:Sign"]
      Resource = aws_kms_key.image_authorization.arn
      Condition = {
        StringEquals = {
          "kms:SigningAlgorithm" = "RSASSA_PSS_SHA_256"
          "kms:MessageType"      = "DIGEST"
          "kms:RequestAlias"     = local.key_alias
        }
      }
    }]
  })
}

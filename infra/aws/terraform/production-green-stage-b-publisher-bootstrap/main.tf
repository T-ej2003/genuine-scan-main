locals {
  role_name = "mscqr-production-stage-b-publisher-bootstrap"
  tags = {
    ManagedBy   = "Terraform"
    Environment = "production"
    Stack       = "production-green-stage-b-publisher-bootstrap"
  }
}

resource "aws_kms_key" "root_attestation" {
  description              = "Root-only MSCQR production evidence attestation key"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "RSA_3072"
  deletion_window_in_days  = 30
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Sid = "AccountAdministration", Effect = "Allow", Principal = { AWS = "arn:aws:iam::368992683803:root" }, Action = "kms:*", Resource = "*" },
    { Sid = "DenyNonRootAttestationSigning", Effect = "Deny", Principal = "*", Action = "kms:Sign", Resource = "*", Condition = { StringNotEquals = { "aws:PrincipalArn" = "arn:aws:iam::368992683803:root" } } },
    { Sid = "ReleaseVerifiesRootAttestations", Effect = "Allow", Principal = { AWS = "arn:aws:iam::368992683803:role/mscqr-production-release-deployer" }, Action = ["kms:DescribeKey", "kms:GetKeyPolicy", "kms:GetPublicKey", "kms:ListResourceTags", "kms:Verify"], Resource = "*" },
  ] })
  tags = {
    ManagedBy   = "Terraform"
    Environment = "production"
    Stack       = "production-root-attestation"
  }
}

resource "aws_kms_alias" "root_attestation" {
  name          = "alias/mscqr-production-root-attestation"
  target_key_id = aws_kms_key.root_attestation.key_id
}

resource "aws_iam_policy" "publisher_permissions_boundary" {
  name        = "MSCQRProductionStageBImagePublisherBoundary"
  description = "Immutable maximum permissions for the production-green Stage B image publisher."
  policy      = file("${path.module}/publisher-permissions-boundary.json")
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

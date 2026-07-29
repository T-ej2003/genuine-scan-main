output "publisher_bootstrap_role_arn" {
  description = "MFA-only operator role that may apply only the Stage B image-publisher Terraform root."
  value       = aws_iam_role.publisher_bootstrap.arn
}

output "trust_policy_sha256" {
  value = filesha256("${path.module}/trust-policy.json")
}

output "permissions_policy_sha256" {
  value = filesha256("${path.module}/permissions-policy.json")
}

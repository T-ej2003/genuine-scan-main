output "publisher_role_arn" {
  description = "Set only this non-secret ARN as the protected GitHub production-environment variable PRODUCTION_STAGE_B_IMAGE_PUBLISH_ROLE after approved apply."
  value       = aws_iam_role.publisher.arn
}

output "trust_policy_sha256" {
  value = filesha256("${path.module}/trust-policy.json")
}

output "permissions_policy_sha256" {
  value = filesha256("${path.module}/permissions-policy.json")
}

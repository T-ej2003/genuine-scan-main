output "signer_role_arn" {
  description = "Configure only as the protected production-security-rebaseline-signing environment variable after approved apply."
  value       = aws_iam_role.signer.arn
}

output "key_arn" {
  value = aws_kms_key.image_authorization.arn
}

output "key_alias_arn" {
  value = aws_kms_alias.image_authorization.arn
}

output "trust_policy_sha256" {
  value = filesha256("${path.module}/trust-policy.json")
}

output "signing_policy_sha256" {
  value = sha256(jsonencode(aws_iam_role_policy.sign_only.policy))
}

output "github_environment_contract_sha256" {
  value = filesha256("${path.module}/github-environment-contract.json")
}

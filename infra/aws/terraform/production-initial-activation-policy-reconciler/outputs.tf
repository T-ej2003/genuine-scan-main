output "role_name" {
  value = aws_iam_role.reconciler.name
}

output "role_arn" {
  value = aws_iam_role.reconciler.arn
}

output "policy_name" {
  value = aws_iam_policy.reconciler.name
}

output "policy_arn" {
  value = aws_iam_policy.reconciler.arn
}

output "trust_policy_sha256" {
  value = filesha256("${path.module}/trust-policy.json")
}

output "permissions_policy_sha256" {
  value = filesha256("${path.module}/permissions-policy.json")
}

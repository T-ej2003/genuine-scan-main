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

output "mixed_recovery_role_arn" {
  value = aws_iam_role.mixed_recovery.arn
}

output "mixed_recovery_policy_arn" {
  value = aws_iam_policy.mixed_recovery.arn
}

output "mixed_recovery_permissions_policy_sha256" {
  value = filesha256("${path.module}/mixed-recovery-permissions-policy.json")
}

output "mixed_recovery_trust_policy_sha256" {
  value = filesha256("${path.module}/mixed-recovery-trust-policy.json")
}

output "broker_recovery_successor_evidence_reader_role_arn" {
  value = aws_iam_role.broker_recovery_successor_evidence_reader.arn
}

output "broker_recovery_successor_evidence_reader_policy_arn" {
  value = aws_iam_policy.broker_recovery_successor_evidence_reader.arn
}

output "broker_recovery_successor_evidence_reader_trust_policy_sha256" {
  value = filesha256("${path.module}/broker-recovery-successor-evidence-reader-trust-policy.json")
}

output "broker_recovery_successor_evidence_reader_permissions_policy_sha256" {
  value = filesha256("${path.module}/broker-recovery-successor-evidence-reader-permissions-policy.json")
}

output "mutation_role_arn" {
  value = aws_iam_role.mutation.arn
}

output "read_only_role_arn" {
  value = aws_iam_role.read_only.arn
}

output "mutation_policy_arns" {
  value = sort([for policy in data.aws_iam_policy.mutation : policy.arn])
}

output "read_only_policy_arns" {
  value = sort([for policy in data.aws_iam_policy.read_only : policy.arn])
}

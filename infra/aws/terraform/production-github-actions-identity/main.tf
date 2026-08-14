locals {
  account_id = "368992683803"
  policy_arns = {
    stage_a_release       = "arn:aws:iam::368992683803:policy/MSCQRProductionGreenStageARelease"
    provider_recovery     = "arn:aws:iam::368992683803:policy/MSCQRProductionGreenStageBProviderRecovery"
    provider_read_only    = "arn:aws:iam::368992683803:policy/MSCQRProductionGreenStageBProviderReadOnly"
    reference_audit       = "arn:aws:iam::368992683803:policy/MSCQRProductionGreenStageBReferenceAuditReadOnly"
    final_apply_write     = "arn:aws:iam::368992683803:policy/MSCQRProductionGreenStageBFinalApplyWrite"
    task_definition_reg   = "arn:aws:iam::368992683803:policy/MSCQRProductionGreenStageBTaskDefinitionRegistration"
    broker_code_sign_read = "arn:aws:iam::368992683803:policy/MSCQRProductionGreenStageBBrokerCodeSigningRead"
    workspace_state       = "arn:aws:iam::368992683803:policy/MSCQRProductionGreenStageBWorkspaceState"
  }
  read_only_policy_arns = {
    provider_read_only = local.policy_arns.provider_read_only
    reference_audit    = local.policy_arns.reference_audit
  }
  tags = {
    ManagedBy   = "Terraform"
    Environment = "production"
    Component   = "github-actions-production-identity"
  }
}

resource "aws_iam_role" "mutation" {
  name                 = "mscqr-production-github-actions-mutation"
  description          = "GitHub OIDC production mutation role; release-gate only."
  max_session_duration = 3600
  assume_role_policy   = file("${path.module}/mutation-trust-policy.json")
  tags                 = merge(local.tags, { Identity = "GITHUB_OIDC_APPROVED_MUTATION" })
}

resource "aws_iam_role" "read_only" {
  name                 = "mscqr-production-github-actions-readonly"
  description          = "GitHub OIDC production read-only preflight role."
  max_session_duration = 3600
  assume_role_policy   = file("${path.module}/read-only-trust-policy.json")
  tags                 = merge(local.tags, { Identity = "GITHUB_OIDC_READ_ONLY" })
}

data "aws_iam_policy" "mutation" {
  for_each = local.policy_arns
  arn      = each.value
}

data "aws_iam_policy" "read_only" {
  for_each = local.read_only_policy_arns
  arn      = each.value
}

resource "aws_iam_role_policy_attachment" "mutation" {
  for_each   = data.aws_iam_policy.mutation
  role       = aws_iam_role.mutation.name
  policy_arn = each.value.arn
}

resource "aws_iam_role_policy_attachment" "read_only" {
  for_each   = data.aws_iam_policy.read_only
  role       = aws_iam_role.read_only.name
  policy_arn = each.value.arn
}

locals {
  role_name                  = "mscqr-production-initial-activation-policy-reconciler"
  policy_name                = "MSCQRProductionInitialActivationPolicyReconciler"
  mixed_recovery_role_name   = "mscqr-production-mixed-dual-slot-recovery-executor"
  mixed_recovery_policy_name = "MSCQRProductionMixedDualSlotRecoveryExecutor"
  tags = {
    ManagedBy   = "Terraform"
    Environment = "production"
    Component   = "initial-activation-policy-reconciliation"
    Stack       = "production-initial-activation-policy-reconciler"
  }
}

resource "aws_iam_role" "mixed_recovery" {
  name                 = local.mixed_recovery_role_name
  description          = "GitHub production-environment executor for the exact mixed dual-slot topology recovery."
  max_session_duration = 3600
  assume_role_policy   = file("${path.module}/trust-policy.json")
  tags                 = merge(local.tags, { Component = "mixed-dual-slot-topology-recovery" })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_policy" "mixed_recovery" {
  name        = local.mixed_recovery_policy_name
  description = "Exact readback and AWSCURRENT-removal capability for mixed dual-slot topology recovery."
  policy      = file("${path.module}/mixed-recovery-permissions-policy.json")
  tags        = merge(local.tags, { Component = "mixed-dual-slot-topology-recovery" })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_role_policy_attachment" "mixed_recovery" {
  role       = aws_iam_role.mixed_recovery.name
  policy_arn = aws_iam_policy.mixed_recovery.arn
}

resource "aws_iam_role" "reconciler" {
  name                 = local.role_name
  description          = "GitHub OIDC-only writer for the exact InitialActivationLifecycle policy reconciliation."
  max_session_duration = 3600
  assume_role_policy   = file("${path.module}/trust-policy.json")
  tags                 = local.tags

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_policy" "reconciler" {
  name        = local.policy_name
  description = "Exact readback and CreatePolicyVersion capability for InitialActivationLifecycle reconciliation."
  policy      = file("${path.module}/permissions-policy.json")
  tags        = local.tags

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_role_policy_attachment" "reconciler" {
  role       = aws_iam_role.reconciler.name
  policy_arn = aws_iam_policy.reconciler.arn
}

locals {
  role_name                                             = "mscqr-production-initial-activation-policy-reconciler"
  policy_name                                           = "MSCQRProductionInitialActivationPolicyReconciler"
  mixed_recovery_role_name                              = "mscqr-production-mixed-dual-slot-recovery-executor"
  mixed_recovery_policy_name                            = "MSCQRProductionMixedDualSlotRecoveryExecutor"
  broker_recovery_successor_evidence_reader_role_name   = "mscqr-production-broker-recovery-successor-evidence-reader"
  broker_recovery_successor_evidence_reader_policy_name = "MSCQRProductionBrokerRecoverySuccessorEvidenceRead"
  tags = {
    ManagedBy   = "Terraform"
    Environment = "production"
    Component   = "initial-activation-policy-reconciliation"
    Stack       = "production-initial-activation-policy-reconciler"
  }
}

resource "aws_iam_role" "broker_recovery_successor_evidence_reader" {
  name                 = local.broker_recovery_successor_evidence_reader_role_name
  description          = "Temporary GitHub OIDC reader for exact broker successor lineage evidence."
  max_session_duration = 3600
  assume_role_policy   = file("${path.module}/broker-recovery-successor-evidence-reader-trust-policy.json")
  tags                 = merge(local.tags, { Component = "broker-recovery-successor-evidence" })

  lifecycle { prevent_destroy = true }
}

resource "aws_iam_policy" "broker_recovery_successor_evidence_reader" {
  name        = local.broker_recovery_successor_evidence_reader_policy_name
  description = "Read only the two immutable component broker successor lineage objects."
  policy      = file("${path.module}/broker-recovery-successor-evidence-reader-permissions-policy.json")
  tags        = merge(local.tags, { Component = "broker-recovery-successor-evidence" })

  lifecycle { prevent_destroy = true }
}

resource "aws_iam_role_policy_attachment" "broker_recovery_successor_evidence_reader" {
  role       = aws_iam_role.broker_recovery_successor_evidence_reader.name
  policy_arn = aws_iam_policy.broker_recovery_successor_evidence_reader.arn
}

resource "aws_iam_role" "mixed_recovery" {
  name                 = local.mixed_recovery_role_name
  description          = "GitHub workflow-dedicated environment executor for the exact mixed dual-slot topology recovery."
  max_session_duration = 3600
  assume_role_policy   = file("${path.module}/mixed-recovery-trust-policy.json")
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

resource "aws_iam_role" "bootstrap_operator_policy_authorizer" {
  name                 = "mscqr-production-bootstrap-operator-policy-authorizer"
  description          = "GitHub OIDC-only read-only authorizer for the exact bootstrap-operator legacy transition."
  max_session_duration = 3600
  assume_role_policy   = file("${path.module}/bootstrap-operator-policy-authorizer-trust-policy.json")
  tags                 = merge(local.tags, { Component = "bootstrap-operator-policy-authorization" })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_policy" "bootstrap_operator_policy_authorizer" {
  name        = "MSCQRProductionBootstrapOperatorPolicyAuthorizer"
  description = "Exact read-only binding verification for bootstrap-operator policy authorization."
  policy      = file("${path.module}/bootstrap-operator-policy-authorizer-permissions-policy.json")
  tags        = merge(local.tags, { Component = "bootstrap-operator-policy-authorization" })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_role_policy_attachment" "bootstrap_operator_policy_authorizer" {
  role       = aws_iam_role.bootstrap_operator_policy_authorizer.name
  policy_arn = aws_iam_policy.bootstrap_operator_policy_authorizer.arn
}

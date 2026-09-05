# MSCQR initial-activation policy reconciler

This is the source contract for the dedicated workflow-only principal required
by PR #448. It defines the role and exact runtime policy but does not claim that
the live role exists and does not migrate PR #448 execution.

`ROLE_DEFINED_IN_SOURCE=true` and `PR448_RUNTIME_MIGRATED=false` remain
deliberately separate states. Installation requires a fresh, independently
authorized administrator Terraform operation followed by authenticated
readback. The runtime role is never permitted to create, update, delete, attach,
or detach IAM resources, including itself.

The role trust is restricted to the existing GitHub Actions OIDC provider,
`aud=sts.amazonaws.com`, and
`sub=repo:T-ej2003/genuine-scan-main:environment:production`. The policy grants
only exact target-policy readback plus `iam:CreatePolicyVersion` on
`arn:aws:iam::368992683803:policy/MSCQRProductionInitialActivationLifecycle`.

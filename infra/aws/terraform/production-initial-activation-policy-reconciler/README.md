# Initial-activation policy reconciler IAM root

This isolated Terraform root owns only the purpose-bound
`mscqr-production-initial-activation-policy-reconciler` role, its exact managed
policy, and their attachment. The role trusts only GitHub Actions OIDC for the
protected `production` environment. It has no MFA, user, release-deployer,
Stage-A, Stage-B, image-publisher, self-installation, or policy-management
capability.

The runtime policy permits only the exact IAM reads required to authenticate the
reviewed InitialActivationLifecycle target and one
`iam:CreatePolicyVersion` action on that exact policy ARN. It does not grant
`SetDefaultPolicyVersion`, version deletion, attachment, trust, role, or policy
creation actions. PR #448 is migrated to this purpose-bound OIDC execution
path.

Installation is performed only by the protected production-environment workflow
using the exact OIDC bootstrap role documented in
`documents/ops/iam/MSCQR_PRODUCTION_INITIAL_ACTIVATION_RECONCILER_BOOTSTRAP.md`.
The workflow applies one saved, source-bound plan under the shared
`production-deploy` queue and then runs
`scripts/aws/verify-production-initial-activation-policy-reconciler.mjs`.
The bootstrap role itself is installed once by an independently authorized
local root transition; root never enters GitHub Actions.

The source contract intentionally does not own the external release-deployer,
Stage-A or Stage-B roots, the image-publisher roots, or any generic production
IAM namespace. Unexpected live role, trust, policy, or attachment topology must
fail closed during verification.

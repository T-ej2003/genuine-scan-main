# Initial-activation policy reconciler IAM root

This isolated Terraform root owns only the purpose-bound
`mscqr-production-initial-activation-policy-reconciler` role, its exact managed
policy, and their attachment. The role trusts only GitHub Actions OIDC for the
protected `production` environment. It has no MFA, user, release-deployer,
Stage-A, Stage-B, image-publisher, self-installation, or policy-management
capability.

The runtime policy permits only the exact IAM reads and
`iam:CreatePolicyVersion` actions required for two allowlisted targets:
InitialActivationLifecycle and ProviderReadOnly. ProviderReadOnly replay state
uses conditional writes under one exact artifact-bucket prefix. The role does
not grant `SetDefaultPolicyVersion`, version deletion, attachment, trust, role,
or policy creation actions, and neither entrypoint accepts an arbitrary policy
ARN or document.

An existing installation is upgraded only through the same protected
bootstrap and saved-plan workflow: the bootstrap inline policy gains
`iam:CreatePolicyVersion` solely on this reconciler policy, and the plan accepts
only the exact predecessor-to-source policy update. Five-version state blocks
before apply because no deletion rule exists.

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

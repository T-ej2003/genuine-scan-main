# Initial-activation policy reconciler IAM root

This isolated Terraform root owns only the purpose-bound
`mscqr-production-initial-activation-policy-reconciler` and
`mscqr-production-mixed-dual-slot-recovery-executor` roles, their exact managed
policies, and their attachments. The recovery role trust additionally requires
the OIDC subject of the workflow-dedicated protected
`production-mixed-dual-slot-recovery` environment. It has no MFA, user,
release-deployer,
Stage-A, Stage-B, image-publisher, self-installation, or policy-management
capability.

The runtime policy permits only the exact IAM reads and
`iam:CreatePolicyVersion` actions required for two allowlisted targets:
InitialActivationLifecycle and ProviderReadOnly. ProviderReadOnly replay state
uses conditional writes under one exact artifact-bucket prefix. The role does
not grant `SetDefaultPolicyVersion`, version deletion, attachment, trust, role,
or policy creation actions, and neither entrypoint accepts an arbitrary policy
ARN or document.

An existing installation is upgraded only through the same protected bootstrap
and saved-plan workflow. The plan accepts the exact policy predecessor or one
trust-only update from the reviewed shared-production-environment predecessor
to the workflow-dedicated `production-mixed-dual-slot-recovery` environment
subject. Five-version or any other state blocks before apply because no
deletion or generic trust-update rule exists.

Interrupted installation and executor-policy expansion are resumable from each
exact Terraform prefix. Every present reconciler or mixed-recovery role,
policy, and attachment must retain its canonical metadata and attachment
topology; substituted or unrelated IAM resources remain fail closed.

The dedicated environment is operator-configured from
`mixed-recovery-github-environment-contract.json`; only the execution workflow
uses it, so the supported OIDC `sub` claim isolates the mutation role without
relying on unsupported token claims.

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

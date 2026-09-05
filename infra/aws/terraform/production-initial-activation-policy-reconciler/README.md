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
creation actions. PR #448 is not migrated by this source package.

This PR defines source and verification contracts only. A separately approved
administrator must perform the future Terraform installation from a clean
protected-main checkout using the exact backend coordinates in
`state-backend-contract.json` and `installation-contract.json`, then run the read-only verifier
`scripts/aws/verify-production-initial-activation-policy-reconciler.mjs`.
No installation, role creation, policy creation, attachment, or production
reconciliation is performed by this package.

The source contract intentionally does not own the external release-deployer,
Stage-A or Stage-B roots, the image-publisher roots, or any generic production
IAM namespace. Unexpected live role, trust, policy, or attachment topology must
fail closed during verification.

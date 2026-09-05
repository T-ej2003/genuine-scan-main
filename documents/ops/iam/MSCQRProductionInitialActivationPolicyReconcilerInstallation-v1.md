# Initial-activation reconciler installation contract

`PRODUCTION_INITIAL_ACTIVATION_POLICY_RECONCILER_INSTALLATION` installs only
the three resources owned by
`infra/aws/terraform/production-initial-activation-policy-reconciler`.

Preparation remains a read-only local-root operation. It authenticates protected
main, the exact backend and workspace, Terraform state, live IAM predecessor,
and a saved plan whose complete configuration and create/no-op actions match the
reviewed role, policy, and attachment. The rendered plan is always derived from
the saved plan; temporary render copies are unique, private, and removed in
`finally`.

The saved plan and preparation bytes are submitted to the canonical GitHub
workflow. The `production` environment supplies independent human approval.
The same workflow run assumes only
`mscqr-production-initial-activation-policy-reconciler-bootstrap`, rechecks the
source, backend, default workspace, state/live predecessor, plan digest and
semantics, then applies the exact saved plan once under Terraform's native S3
lock. It shares the non-cancelling `production-deploy` concurrency group with
the release workflow. No local executor can perform the apply.

An exact complete topology plus compatible state and a real no-op plan finalizes
with zero apply. An ambiguous apply is never retried; exact post-state and the
canonical live verifier must both authenticate before completion evidence is
written. Unexpected or partial ambiguous outcomes fail closed.

The workflow bootstrap role has depth one. Its independently approved local-root
installer can create only that exact OIDC role and its fixed inline policy. The
root transition is convergent and is documented in
`MSCQR_PRODUCTION_INITIAL_ACTIVATION_RECONCILER_BOOTSTRAP.md`. Root credentials
never enter GitHub, and neither the release-deployer nor legacy GitHub role is
expanded.

This lifecycle does not mutate the InitialActivationLifecycle target policy,
reopen Stage A, change Stage B, publish images, or modify PR #448.

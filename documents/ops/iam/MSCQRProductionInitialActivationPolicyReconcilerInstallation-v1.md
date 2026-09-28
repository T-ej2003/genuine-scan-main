# Initial-activation reconciler installation contract

`PRODUCTION_INITIAL_ACTIVATION_POLICY_RECONCILER_INSTALLATION` installs only
the fourteen resources owned by
`infra/aws/terraform/production-initial-activation-policy-reconciler`: the
reconciler, mixed-recovery executor, bootstrap-operator policy authorizer, and
successor evidence-reader role/policy/attachment groups, plus the signer policy
installer role and inline policy.

Preparation remains a read-only local-root operation. It authenticates protected
main, the exact backend and workspace, Terraform state, live IAM predecessor,
and a saved plan whose complete configuration and create/no-op actions match the
reviewed roles, policies, and attachments. The rendered plan is always derived from
the saved plan; temporary render copies are unique, private, and removed in
`finally`.

The saved plan and preparation bytes are submitted to the canonical GitHub
workflow by `dispatch-production-initial-activation-reconciler-installation.mjs`.
The helper authenticates protected main and both local artifacts, transports only
the preparation through the repository's deterministic bounded gzip/Base64
contract, keeps the saved plan in canonical Base64, and rejects the complete
serialized inputs above the repository's 60,000-character budget before calling
GitHub. The workflow decompresses the preparation under the same ceiling and
authenticates its original uncompressed byte SHA-256 before authorization. The
dedicated `production-initial-activation-reconciler-bootstrap`
environment supplies authenticated human approval and the matching OIDC subject;
`production` remains the deployment tier, not the GitHub environment identity.
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

Predecessor discovery carries every observed canonical Terraform address into
preparation, including the signer policy-installer role and inline policy. A
role-only signer prefix is resumable; during the evidence-reader expansion,
already-created signer resources must be plan no-ops and only missing resources
may be created. Mixed evidence-reader attachment states remain fail-closed.

The deployed twelve-resource installation is an authenticated predecessor:
its evidence-reader policy has the retained two-object description and exact
two-object read document, the bootstrap authorizer has the recognized v2
document, and the signer installer is absent. The incremental successor keeps
the existing policy identity and description, updates only its document to the
canonical three-object read set, adds the two signer installer resources, and
updates the authorizer only with its canonical ECS read statements. The live
bootstrap inline policy is pinned as predecessor generation 9; its separately
governed upgrade grants policy-version access only to the exact evidence-reader
policy in addition to previously authorized policy ARNs. A saved plan that
replaces or deletes the evidence-reader policy is rejected.

For the reviewed exact legacy-to-dedicated-role expansion, completion additionally requires remote
Terraform state to advance from the authenticated predecessor and to contain
all fourteen exact resource attributes from the authorized saved
plan, including the target ARN and canonical desired policy document. Live IAM convergence with
the predecessor still in Terraform state is classified as
`LIVE_DESIRED_TERRAFORM_STATE_STALE`; it is not completion and never triggers a
second policy mutation.

The workflow bootstrap role has depth one. Its authorized local-root
installer can create only that exact OIDC role and its fixed inline policy. The
root transition is convergent and is documented in
`MSCQR_PRODUCTION_INITIAL_ACTIVATION_RECONCILER_BOOTSTRAP.md`. Root credentials
never enter GitHub, and neither the release-deployer nor legacy GitHub role is
expanded.

The bootstrap permissions document allows `iam:PutRolePolicy` only on
`arn:aws:iam::368992683803:role/mscqr-production-signer-policy-installer`, the
role targeted by the Terraform `aws_iam_role_policy.signer_policy_installer`
resource. It has no `iam:PolicyName` condition: AWS does not list that key for
`PutRolePolicy`, so the exact role resource is the supported IAM boundary.

This lifecycle does not mutate the InitialActivationLifecycle target policy,
reopen Stage A, change Stage B, publish images, or modify PR #448.

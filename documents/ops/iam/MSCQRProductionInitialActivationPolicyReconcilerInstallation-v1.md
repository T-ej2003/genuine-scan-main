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
The two predecessor policy documents are tracked independently: if one policy
converges before execution, the old saved plan fails its live-state recheck and
must be prepared again for the exact remaining update.

The QR version-selector authorizer's deployed policy can have the exact historical
task-definition ARN list. ECS evaluates `DescribeTaskDefinition` against `*`, so
that ARN-scoped read fails even for the current backend task definition. The
reconciler recognizes that authenticated dedicated policy and the historical
embedded-policy expansion predecessor, then updates only the relevant policy
document to the source-owned successor: `DescribeTaskDefinition` on
`*`, conditioned on `eu-west-2`. The source-bound selector still reads the task
definition referenced by the exact production backend service and checks its
exact QR secret selector. After this source change merges, prepare a new live
saved plan and obtain a fresh installation authorization; the failed selector
run and its approval are not reused.
If an interrupted expansion leaves both the embedded reconciler policy and
attached dedicated authorizer policy on their exact historical documents,
the reconciler classifies both together and accepts only their two canonical
policy updates plus creation of any still-missing canonical resources.
The interruption contract for this migration is:

| Authenticated state | Discovery | Saved-plan changes | Attachment reflection |
| --- | --- | --- | --- |
| Embedded historical; dedicated authorizer absent | `EXACT_EXPANSION` | Update reconciler; create missing canonical resources | Absent attachment: none |
| Embedded historical; dedicated policy created but unattached | `EXACT_DUAL_POLICY_CONVERGENCE` | Update both exact policies; create missing role or attachment | None until attached |
| Embedded historical; dedicated historical policy attached | `EXACT_DUAL_POLICY_CONVERGENCE` | Update both exact policies; create only other missing resources | Exact authorizer pair or none |
| Embedded successor; dedicated historical policy still pending | `EXACT_AUTHORIZER_POLICY_CONVERGENCE` when topology is partial, otherwise the existing exact authorizer update classification | Update authorizer only; create missing resources | Exact authorizer pair only if attached |
| Embedded historical; dedicated policy already successor | `EXACT_UPDATE` when complete, otherwise `EXACT_EXPANSION` | Update reconciler only; create missing resources | Exact authorizer pair only if attached |
| Evidence reader expansion from its captured predecessor | Existing exact evidence-reader expansion classification | Existing exact reader creates and authorizer update | Captured exact authorizer pair |
| Signer installer resources still missing | Existing exact signer expansion classifications | Create only missing signer resources and update only authenticated old policies | Exact authenticated pair for an already attached policy, or none |
| Both policies successor | `EXACT_COMPLETE` | No IAM changes | Exact authorizer pair or none |

Every reflection must be the exact `attachment_count: 0 -> 1` and
`managed_policy_arns: [] -> [canonical authorizer policy ARN]` pair, bound
to a no-op separate attachment and the refreshed predecessor fields of
the saved plan. Other drift remains rejected.

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

# Initial-activation reconciler Terraform state reconciliation

`PRODUCTION_INITIAL_ACTIVATION_RECONCILER_STATE_RECONCILIATION` is a one-purpose, protected-environment operation for the existing initial-activation reconciler Terraform backend. It does not reconcile IAM.

The operation accepts only a refresh-only saved plan whose complete drift envelope is:

- `aws_iam_policy.reconciler.attachment_count`: `0` to `1`.
- `aws_iam_role.reconciler.managed_policy_arns`: `[]` to the exact reconciler policy ARN.

Preparation binds protected source, backend identity, raw state lineage/serial/SHA-256, S3 VersionId and ETag, canonical live attachment topology, saved-plan bytes, and this exact drift envelope. Authorization is independently protected-environment approved. Execution applies only the authorized saved refresh-only plan through the bootstrap OIDC role.

The bootstrap role has two additional read-only prerequisites: `s3:GetBucketPolicy` on the exact production-artifacts bucket and `iam:GetRolePolicy` on its own exact role. They are used only to reauthenticate State B and the bootstrap-policy revision immediately before and after the saved-plan transaction; they grant no object, bucket-policy mutation, or unrelated IAM capability. The existing target-locked bootstrap installer must first converge that inline policy revision.

The operation rejects normal Terraform actions, IAM mutations, added drift, state substitution, authorization substitution, and post-state changes outside those two fields. It verifies the live IAM attachment remains unchanged, then generates a fresh normal installation plan and requires the existing strict installation validator to observe no `resource_drift` and exactly the already-reviewed `aws_iam_policy.reconciler` update. It never executes that update.

# Bootstrap operator v1 to v2 successor

The September 2026 legacy MFA transition is complete. Its IAM marker and S3
reservation both identify authorization
`ce90ee43553391abf7d334a5f563d077ae01ebc05c73514490e719a9e9a7aa2d`.
CloudTrail event `f5be0999-67f4-4911-a46f-6522f2c47ed2` records the root
`PutUserPolicy` on 2026-09-25 at 22:21:33 UTC; its policy document matches
`MSCQRProductionBootstrapOperator-v1.json`. This completed transition must
not be replayed. The historical rotation binding no longer matches live
Secrets Manager version labels.

The successor permits one separately approved update from the exact v1 inline
policy to the reviewed v2 policy. V2 preserves the existing effective
permissions and adds only MFA-gated `iam:GetPolicy`, `iam:GetPolicyVersion`,
`iam:ListPolicyVersions`, and `iam:ListEntitiesForPolicy` on
`MSCQRProductionGreenStageARelease`. It does not create, rotate, deactivate,
or delete access keys, read secret values, or grant deployment authority.
The RLS operator contract records this separate, one-policy-update exception
for the same two historical keys; the zero-key default remains unchanged.
Its generated certification package identity changes with the source contract,
but its SQL permissions and policies do not change.

The existing reconciler requires the exact completed predecessor marker and
historical reservation, the exact two-key/MFA user topology, and the exact
v1 policy. It creates a distinct conditional S3 reservation before the single
policy write. The existing protected GitHub environment issues a fresh,
source-bound authorization; the root executor rechecks all live preconditions
and reads back v2. A completed v2 readback does not repeat the policy write.

**Required ordering:** First install and read back the reviewed Stage A
`B_TO_B_SUCCESSOR_RESERVATION` bucket-policy transition through the governed
production-artifacts recovery and Terraform state reconciliation workflows.
The live predecessor is State B; the transition adds `If-Match` replacement
for only `bootstrap-operator-v2-successor.json` while retaining the legacy
key and all create, read and delete restrictions. Merging this PR does not
install the bucket policy. The reconciler checks the exact installed policy
before creating a successor reservation, so an interrupted execution can
renew its two-minute lease after expiry using the S3 ETag condition.
The governed Terraform state refresh may also observe the already-installed
checker `ReadCompletedInventoryReceipts` policy. Reconcile it only when the
refresh-only plan proves that exact policy addition; this does not change IAM.

After this change is reviewed and merged, prepare and authorize the successor
against the new protected-main SHA using `--v2-successor`. Do not reuse the
expired signer-policy-install authorization. Resume the existing signer
transition ID with fresh source-bound authorization. Keep the email worker at
0/0 until B03 compatibility and queue safety are independently verified.

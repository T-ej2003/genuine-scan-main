# MSCQR production initial-activation lifecycle

The production release deployer uses exactly two objects in `mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an`:

- `production-activation-lifecycle/claim.json`
- `production-activation-lifecycle/completion.json`

Both objects are created with S3 `PutObject` and the exact `If-None-Match: *` value. The administrator-converged `MSCQRProductionInitialActivationLifecycle` identity policy and the complete production-artifacts bucket policy allow reads and conditional creation only on those keys, deny writes by every other principal, deny a `PutObject` whose condition is absent or differs from `*`, and deny `DeleteObject` plus `DeleteObjectVersion`. This prevents governed automation from overwriting an object or creating a delete marker, including when bucket versioning is enabled.

The independently authenticated root operator has a separate, operation-specific single-writer boundary at `production-initial-activation-lifecycle-policy-reconciliation/reservations/<transition-sha256>.json`. The bucket policy permits exact-key readback and `PutObject` only beneath that prefix, requires `If-None-Match: *`, denies every other principal, and denies both deletion operations. Reservations are immutable coordination evidence: no `ListBucket`, release-deployer access, deletion, or unrelated-prefix access is introduced.

After the existing read-only activation preparation identifies the exact target task definition, the Release Gate creates the claim immediately before the first RLS mutation. A 412 response is resumable only after the stored canonical claim authenticates as the same source, rotation, overlap deployment/task definition, activation target task definition, image, runtime proof, and transaction. A 409 remains fail-closed and may only be retried as another conditional create with unchanged bindings.

After the checksum-bound RLS receipt and complete `produceOnboardingEvidence()` bundle are authenticated, the operator creates the completion marker with `manage-production-initial-activation-lifecycle.mjs --mode complete`, supplying the same byte-authenticated rotation state and SHA used by the claim. The command rereads the live claim, revalidates the unexpired overlap proof, verifies the strict evidence hash and exact source/rotation/state/task/task-definition/image bindings, and conditionally creates the completion marker; it never deletes or replaces either object. Future initial-overlap checks fail once completion exists, while final rotation cleanup continues on its original deadline.

The production artifacts bucket is pre-existing and is not created by this contract. Its live versioning status must be read during governed source-to-live convergence; monotonicity does not depend on versioning because governed principals are explicitly denied both deletion operations.

S3 `VersionId` values are opaque service-generated identifiers. The lifecycle reader preserves them exactly, accepts any non-empty valid UTF-8 value up to 1024 bytes (including the documented `null` value for unversioned or suspended-versioning objects), and rejects only structurally invalid values. An omitted response field remains represented as `UNVERSIONED`.

Before this lifecycle is provisioned, the authenticated production baseline has no live bucket policy, no Terraform bucket-policy owner, and no historical repository owner. Stage A therefore establishes the first and sole repository-controlled policy for the complete production-artifacts bucket-policy object. Its complete policy contains only the activation-lifecycle statements above and a self-protecting denial of subsequent `PutBucketPolicy` or `DeleteBucketPolicy` calls. Existing receipt access remains governed by its existing identity policies and is not migrated or redefined here.

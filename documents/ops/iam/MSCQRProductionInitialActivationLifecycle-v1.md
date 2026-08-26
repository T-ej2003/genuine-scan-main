# MSCQR production initial-activation lifecycle

The production release deployer uses exactly two objects in `mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an`:

- `production-activation-lifecycle/claim.json`
- `production-activation-lifecycle/completion.json`

Both objects are created with S3 `PutObject` and the exact `If-None-Match: *` value. The identity policy and bucket policy allow reads and conditional creation only on those keys, deny writes by every other principal, deny a `PutObject` whose condition is absent or differs from `*`, and deny `DeleteObject` plus `DeleteObjectVersion`. This prevents governed automation from overwriting an object or creating a delete marker, including when bucket versioning is enabled.

After the existing read-only activation preparation identifies the exact target task definition, the Release Gate creates the claim immediately before the first RLS mutation. A 412 response is resumable only after the stored canonical claim authenticates as the same source, rotation, overlap deployment/task definition, activation target task definition, image, runtime proof, and transaction. A 409 remains fail-closed and may only be retried as another conditional create with unchanged bindings.

After the checksum-bound RLS receipt and complete `produceOnboardingEvidence()` bundle are authenticated, the operator creates the completion marker with `manage-production-initial-activation-lifecycle.mjs --mode complete`, supplying the same byte-authenticated rotation state and SHA used by the claim. The command rereads the live claim, revalidates the unexpired overlap proof, verifies the strict evidence hash and exact source/rotation/state/task/task-definition/image bindings, and conditionally creates the completion marker; it never deletes or replaces either object. Future initial-overlap checks fail once completion exists, while final rotation cleanup continues on its original deadline.

The production artifacts bucket is pre-existing and is not created by this contract. Its live versioning status must be read during governed source-to-live convergence; monotonicity does not depend on versioning because governed principals are explicitly denied both deletion operations.

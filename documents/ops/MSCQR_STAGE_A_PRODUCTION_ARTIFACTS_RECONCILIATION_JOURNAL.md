# Stage-A production-artifacts reconciliation journal

## Scope

This journal is the single-use state-transition record for
`STAGE_A_PRODUCTION_ARTIFACTS_STATE_RECONCILIATION`. It is not a general
artifact store, a Terraform lock replacement, or a Stage-B apply-attempt
journal.

## Bootstrap order

The predecessor bucket policy (`P0`) cannot be updated by the ordinary
release-deployer. A protected-environment recovery authorization therefore
binds one root-operated `PutBucketPolicy` from `P0` directly to the final
policy (`P2`). `P2` contains the existing rebaseline-evidence rules plus the
isolated journal rules. There is no `P0 -> P1 -> P2` sequence.

The recovery runner requires the exact clean protected checkout, authorization,
state identity, and predecessor before it creates a root-attested conditional
`recovery/<authorization-sha256>/attempt.json` record. It then performs the one
policy write, reads back `P2`, and emits root-attested completion evidence. If
the process stops after the policy write, the same authorization may resume
only when that immutable signed attempt exists and live policy is exact `P2`;
the retry performs no policy write. An existing valid completion is idempotent.

## Namespace and permissions

The only namespace is:

`production-stage-a-production-artifacts-reconciliation/<reconciliation-authorization-sha256>/`

The release-deployer receives only `s3:GetObject` and `s3:PutObject` with
`s3:if-none-match = *` on that prefix. The resource policy denies
nonconditional writes, writes by every other principal, `DeleteObject`, and
`DeleteObjectVersion`. No list permission, overwrite, or cross-Stage-B access
is used.

Before `P2` exists, the already-governed bucket-owner recovery principal writes
only the signed attempt object with conditional create. After `P2`, the policy
prevents that principal from writing or deleting journal objects; completion
and reconciliation records use the release-deployer's narrow journal grant.

## Immutable records

Each authorized reconciliation has exactly two possible records:

1. `reservation.json` — atomically creates the exclusive execution right.
2. `result.json` — atomically records `COMPLETED`, `ABORTED_BEFORE_APPLY`, or
   `FAILED_OR_INDETERMINATE`.

Both are canonical JSON and bind the protected source, account, region,
release-deployer identity, recovery-completion digest, saved-plan digest,
pre-state lineage/serial/raw-byte digest, and desired-policy digest.

An existing reservation or result is terminal for that authorization. A
crashed or ambiguous execution must be investigated through the immutable
record and cannot be replayed automatically.

## Retention gate

Before any recovery execution, the root-operated runner must authenticate
bucket versioning and lifecycle configuration. It fails closed unless
versioning is enabled and no lifecycle expiration rule can remove this exact
journal prefix during the governed recovery window. Explicit delete denial is
required even when versioning is enabled.

## Runnable governed path

The protected-environment producers are
`.github/workflows/authorize-production-stage-a-production-artifacts-recovery.yml`
and
`.github/workflows/authorize-production-stage-a-production-artifacts-reconciliation.yml`.
They create independently reviewed, source-bound authorization artifacts; the
operator commands are not an authorization substitute.

After the corresponding workflow has completed with a legitimate independent
`production` approval, the only runners are:

1. `npm run stage-a:production-artifacts:recover -- --production ...` — exact
   `P0 -> P2` root recovery, exact readback, and a root-attested completion
   record.
2. `npm run stage-a:production-artifacts:reconcile -- --production ...` —
   fresh exact refresh-only plan, independently approved plan/state identity,
   conditional reservation, final state/live CAS, one state-only apply, and
   immutable result record.

The reconciliation runner fails if the recovery completion, exact plan,
pre-state lineage/serial/raw-byte hash, source, account, region, or release
principal differs. If protected main has advanced since the recovery, the
runner takes the historical recovery source SHA explicitly, requires it to be
an authenticated ancestor of current protected main, and preserves the
historical completion without replaying policy recovery. A subsequent ordinary
Stage-A plan is permitted only after that runner records `COMPLETED` and
produces a no-op plan.

If recovery has written `P2` but completion publication failed, recovery itself
may be retried with the current protected source and the historical recovery
source SHA. The existing authorization-namespaced signed attempt must be
present, the current source must satisfy the same descendant compatibility
contract, and live policy must be exact `P2`; this completion-only resume never
issues another policy write.

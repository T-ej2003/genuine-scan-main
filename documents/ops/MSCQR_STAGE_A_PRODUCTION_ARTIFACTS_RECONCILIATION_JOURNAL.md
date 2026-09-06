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

The reviewed reservation-retirement transition is the exact reverse from the
policy containing the six historical `InitialActivationLifecycle` reservation
statements to canonical `P2` without those statements. It is bound to
predecessor SHA-256
`0d5d20a784351f38712513252223fbdfaca52e4301bd00b5d0298882702842be` and
target SHA-256
`765e091f99ee56e186741aa2fd849d755dc19f0b668779801855105350db8ff3`.
The resolver rejects partial removal, additional statement changes, and
arbitrary bucket-policy replacements.

The recovery runner requires the exact clean protected checkout, authorization,
state identity, and predecessor before it creates a root-attested conditional
`recovery/<authorization-sha256>/attempt.json` record. It then performs the one
policy write, reads back `P2`, and emits root-attested completion evidence. If
the process stops after the policy write, the same authorization may resume
only when that immutable signed attempt exists and live policy is exact `P2`;
the retry performs no policy write. An existing valid completion is idempotent.

### Single-attempt recovery safety

The existing signed, conditional-create `attempt.json` is the durable mutation-intent
boundary. Absence is the only persisted pre-write representation; there is no
separate resumable `PRE_WRITE` record. Every existing attempt, including legacy
records, means `MUTATION_ATTEMPT_STARTED` conservatively. Only the invocation
whose exclusive attempt creation succeeds can enter the policy write. A crash
after persistence but before the child starts consumes that authorization too.
Conflicting or ambiguous journal creation never permits the policy write.

The exact root `s3api put-bucket-policy` child forces `AWS_MAX_ATTEMPTS=1`,
overriding inherited configuration without changing read subprocess environments.
Source, authorization, state, policy CAS and approval freshness are checked before
the write. A mutation exception immediately attempts read-only policy observation:
exact target proceeds to verified completion; exact predecessor remains ambiguous
and stops; unexpected policy or failed observation stops. No catch retries the write.
On restart, a persisted attempt plus predecessor is not retry authority. Target
plus authenticated attempt permits completion only; unexpected state fails closed.

The outer lock and existing immutable journal are reused. No new object namespace,
lock, principal, policy transition or authorization format is introduced. Existing
refresh-only state reconciliation and normal no-op closure remain unchanged.
Tests cover failure before/after marker persistence, lost response, failed readback,
post-write process loss, repeated invocation, and mutation-only CLI retry settings.

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
versioning is enabled and no enabled lifecycle expiration or current-version
transition can overlap this exact journal prefix. Journal records use immutable
unique keys, so noncurrent-only lifecycle actions do not affect the current
evidence read by recovery. Explicit delete denial is required even when
versioning is enabled.

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

Execute owns the canonical Stage-A S3 backend `.tflock` from its final pre-state
checks through exact post-state authentication and durable post-apply evidence.
The exact saved plan runs with nested Terraform locking disabled only inside
that exclusion. A reserved execution that cannot establish durable outcome
evidence retains the lock for explicit operator investigation; no automatic
force-unlock is permitted.

If recovery has written `P2` but completion publication failed, recovery itself
may be retried with the current protected source and the historical recovery
source SHA. The existing authorization-namespaced signed attempt must be
present, the current source must satisfy the same descendant compatibility
contract, and live policy must be exact `P2`; this completion-only resume never
issues another policy write.

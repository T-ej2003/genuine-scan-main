# Stage-B apply-attempt reconciliation v2

This contract never retries an occupied attempt automatically. A successor
requires canonical S3 reservation/transition history, a protected-environment
approval from a distinct reviewer, and a new successor identity bound to the
complete immutable predecessor. Caller-supplied evidence labels or digests do
not establish reconciliation authority.

The historical schema-v2 reservation
`1aefb5f358412d102e68be79c324e221c6a7af4114f12ce18a9ddbd465d85021`
is permanently non-retryable. It can be parsed and reported as immutable
incident evidence only. Current state, elapsed time, a human approval, a
signed operator observation, or caller-provided evidence descriptors cannot
turn it into successor authority. Any other schema-v2 reservation is rejected.

## v3 crash boundaries

`RESERVED` is durable before an apply intent is recorded. It is only a
reconciliation candidate; it is not executable without a new reconciliation
artifact and independent approval. `APPLY_INTENT_RECORDED` is also durable
before the spawn boundary and records `applyMayHaveOccurred=false`; its exact
append-only S3 history proves Terraform remains unreachable. Before the code
can invoke Terraform, it durably records `APPLY_SPAWN_UNCERTAIN` with
`applyMayHaveOccurred=true`. `APPLY_SPAWN_UNCERTAIN`, `APPLIED`, `FAILED`,
and `UNKNOWN` are terminal for successor preparation.

Because S3 persistence and child-process spawn are not atomic, a crash after
`APPLY_SPAWN_UNCERTAIN` is `INDETERMINATE_NO_AUTOMATIC_SUCCESSOR` and cannot
be downgraded by elapsed time, unchanged state, or a missing local marker.
Only the exact canonical pre-spawn S3 history plus fresh protected-environment
approval can establish a v3 successor; any post-spawn evidence remains
fail-closed. The producer is the reviewed apply wrapper, the verifier is the
canonical S3 history reader, and the trust root is the append-only conditional
S3 reservation/transition policy. Caller-supplied labels, hashes, or
`authenticatedBy` fields are not evidence.

## Evidence and freshness

The reconciliation artifact timestamp uses the shared Stage-B one-hour TTL
with sixty seconds of allowed clock skew. Preparation rechecks the artifact
and protected-environment approval; the approval's thirty-minute lifetime is
also rechecked immediately before successor preparation. This timing evidence
does not replace the canonical remote transition history.

## Canonical predecessor history

The reconciliation artifact contains the complete initial reservation and its
authenticated append-only transition history. The create and prepare commands
re-read that history from the canonical backend and require exact equality
with the artifact. A v3 `APPLY_INTENT_RECORDED` record is never an automatic
retry: it needs protected approval before it can prepare a successor. Any
other transition is indeterminate and cannot prepare a successor. The
workflow receives the artifact's canonical JSON SHA-256 identity, not the
hash of its transport formatting.

## New deployment generation

An old consumed attempt is never deleted, overwritten, or reused. A later
deployment generation starts only from a new protected source and fresh
state, plan, closure, and approval evidence. Its identity is the existing
canonical artifact-set identity over the fresh protected source, saved plan,
workspace, and backend identity; there is no retry nonce. The historical v2
object remains discoverable as unsafe evidence and cannot be bypassed merely
by choosing a new reservation key.

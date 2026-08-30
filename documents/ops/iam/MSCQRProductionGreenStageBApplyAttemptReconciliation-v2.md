# Stage-B apply-attempt reconciliation v2

This contract never retries an occupied attempt automatically. A successor
requires a fresh, bounded observation from the `LOCAL_EXECUTION` and
`REMOTE_STATE_AND_INFRASTRUCTURE` domains, a protected-environment approval,
and a new successor identity bound to the complete immutable predecessor.

The historical schema-v2 bridge is limited to reservation
`1aefb5f358412d102e68be79c324e221c6a7af4114f12ce18a9ddbd465d85021`.
Any other schema-v2 reservation is rejected.

## v3 crash boundaries

`RESERVED` is durable before an apply intent is recorded. It is only a
reconciliation candidate; it is not executable without a new reconciliation
artifact and independent approval. `APPLY_INTENT_RECORDED` is durable before
the non-atomic Terraform spawn boundary and therefore conservatively records
that mutation may have occurred. It may enter the same governed reconciliation
flow only when fresh independent evidence proves the entrypoint and Terraform
process were both unreachable. `APPLIED`, `FAILED`, and `UNKNOWN` are
terminal for successor preparation.

Because S3 persistence and child-process spawn are not atomic, a crash after
`APPLY_INTENT_RECORDED` is classified as
`INDETERMINATE_NO_AUTOMATIC_SUCCESSOR`. It cannot be downgraded from elapsed
time, unchanged state, or a missing local marker. Only a fresh reconciliation
artifact plus independent protected-environment approval can establish a
successor; any contradictory or post-spawn evidence remains fail-closed.

## Evidence and freshness

Observations use strict UTC timestamps and the shared Stage-B one-hour TTL
with sixty seconds of allowed clock skew. Preparation rechecks freshness, so
an authorization cannot outlive its observation. The two evidence entries
must have distinct required domains, kinds, digests, and authenticators.
Protected-environment approval evidence is independently rechecked against its
thirty-minute lifetime immediately before successor preparation.

## Canonical predecessor history

The reconciliation artifact contains the complete initial reservation and its
authenticated append-only transition history. The create and prepare commands
re-read that history from the canonical backend and require exact equality
with the artifact. A v3 `APPLY_INTENT_RECORDED` record is never an automatic
retry: it needs the same fresh evidence and protected approval before it can
prepare a successor. Any other transition is indeterminate and cannot prepare
a successor. The workflow receives the artifact's canonical JSON SHA-256
identity, not the hash of its transport formatting.

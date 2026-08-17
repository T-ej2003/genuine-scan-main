# Serial-98 cutover handoff recovery

The serial-98 continuation uses three explicit, identifier-only boundaries:

- `SUPERSEDE_STALE_PENDING`: the stale dual-slot rotation is accepted only when every reviewed secret slot still carries the exact stale source and rotation ID. The transition writes a new source/rotation identity with deterministic request tokens and records version IDs; it never logs secret values or silently rebinds the old identity.
- `POST_APPLY_STAGE_A_PLAN_RECOVERY`: when the historical binary Stage-A plan is unavailable, this is evidence of converged Stage-A state, signed handoff provenance, serial-98 Stage-B state, and a fresh read-only ingress postcondition. It is not a reconstructed Terraform plan and cannot authorize an apply.
- Root-drop evidence: `produce-production-root-drop-evidence.mjs` requires the exact account root caller, protected source SHA, fresh timestamp, and an integrity hash. The command stops before producing evidence unless the current AWS identity is the exact root ARN.

The cutover runtime accepts exactly one Stage-A input: a preserved saved plan or
the explicit post-apply recovery evidence. Existing saved-plan behavior remains
unchanged. All artifacts are written outside the repository with the Stage-B
private artifact contract (directory `0700`, file `0600`, atomic publication).

Recommended operator sequence after reviewed merge: obtain fresh protected-main
identity, run stale-rotation supersession only after its expected-state check,
produce root-drop evidence from an authenticated root boundary, generate
post-apply Stage-A recovery evidence from serial-98 read-only observations, and
then run the existing cutover wrapper. Never reuse stale rotation records or
run Terraform again for this continuation.

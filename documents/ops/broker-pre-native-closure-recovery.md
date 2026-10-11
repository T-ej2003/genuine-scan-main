# Bounded recovery of a pre-native broker closure attempt

A coordinator `closure:attempt:<round>` records an intended call. It does not prove that the native Terraform refresh began. Previously, advancing protected-main tooling rejected this marker before examining the native journal, leaving an expired pre-native attempt unable to obtain fresh closure authorization.

The explicit `PRE_NATIVE_ABORTED` classification requires all of:

- The immutable preparation, attempt and authorization identify the same release, operation and round.
- The original protected authorization is independently authenticated at its original issuance time and has now expired. Any saved pending/dispatch records must agree with it.
- `STATE_REFRESH_INTENT`, `STATE_REFRESH_UNKNOWN`, `RECONCILED_PENDING_RELEASE_CAS` and `STAGED_BROKER_TERMINAL_HANDOFF` are all absent for that authorization. Only canonical receipt absence is accepted; denied or uncertain reads fail closed.
- Live Terraform lineage, serial and exact byte digest equal the historical closure preparation's state identity.
- Live reviewed-alias identity, including revision, equals the authenticated completed CAS receipt.
- The hosted coordinator independently authenticates the original publication, completed CAS, historical tooling trees, ancestry and current protected-main tooling before classification.

The coordinator appends a retirement record containing the abort proof, preserves the old attempt and authorization, and creates a new immutable continuation preparation/round. The public protected-authorization producer repeats the abort authentication and live-state readback. The new authorization binds the exact new preparation and round. No timestamp, old receipt or historical identity is rewritten.

Native intent/result/uncertain-execution evidence blocks this path and requires the existing native recovery process. Changed live state, a different alias revision, active old authorization or an unavailable historical artifact also blocks it. Receipt absence alone never authorizes retry.

## Governed execution after merge

Resume the existing `recover-production-stage-b-successor.yml` request on current protected main. Authenticate and adopt the completed CAS at broker v13. The coordinator must create the new closure round and dispatch `authorize-production-stage-b-release-transition.yml` to the production approval gate. Approve only the exact fresh closure preparation. The native state-only reconciliation runs only after that approval and uses the existing refresh-only plan validator. Authenticate its durable closure receipt before Stage-B continuation.

Never replay alias CAS, broker publication, ECS registration or IAM convergence. Do not use this classification to retry an uncertain Terraform apply. If any corroborating evidence differs, stop and preserve it.

## Verification and maintenance recommendation

Regression coverage exercises the hosted request authenticator, coordinator, public protected-authorization producer and native closure entrypoint with external writes mocked. It covers fresh authority, immutable old records, successful state-only refresh and completed-result adoption, plus invalid signatures, active authority, altered state/alias, cross-round records and native/uncertain receipts.

Keep this fixture in the existing recovery regression suite: the coordinator marker and native intent must remain distinct. No additional deployment abstraction is needed.

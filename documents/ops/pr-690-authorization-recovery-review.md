# PR #690 authorization recovery review

This review is for the immutable PR diff against protected main. It uses mocked
GitHub and AWS writes; it is not evidence of production execution or approval.
The change affects approval-child recovery, not registration, IAM, Lambda,
Terraform, Release Gate, or application deployment behavior.

## Producer-to-consumer path

`release-train.yml` calls the regular coordinator through
`converge-stage-b-prerequisites`. That coordinator authenticates the release
START and image transport, adopts or executes registration, pruning and policy,
then publication, alias cutover and closure. Each mutation is preceded by its
own preparation, protected approval and native intent. The successor coordinator
starts from an authenticated publication and can execute only cutover and
closure. Both use `obtainReleaseTransitionAuthorization`, which writes a
source-bound dispatch journal before POST and reads the exact GitHub child.

The protected `authorize-production-stage-b-release-transition.yml` runner
hydrates the immutable preparation and validates the current round. For renewed
closure, it validates prior round terminal evidence before producing a new
authorization. Native recovery authenticates live state and native receipts;
neither coordinator may infer completion from an approval run alone. The regular
coordinator writes `PREREQUISITES_CONVERGED` after Stage B terminal closure.
Full Release Train then dispatches `release-gate.yml`; prerequisite-only mode
stops at that receipt. Release Gate retains its independent rotation, image,
database/RLS, deployment and health boundaries.

## Authorization outcomes

The runtime states are `AUTHORIZED`, `WAITING_FOR_APPROVAL`,
`APPROVAL_TIMED_OUT`, and `APPROVAL_FAILED`. A cancelled child is an authenticated
`APPROVAL_FAILED` conclusion. API or dispatch failure throws and leaves the
journal for exact-child reconciliation; it is not an authorization state.
Unknown statuses fail closed. The detailed record and replacement rules are in
[production-release-coordinator.md](production-release-coordinator.md#approval-child-recovery-contract).

## Adversarial findings and disposition

1. A newly dispatched child could fail before the caller's original `prior`
   reference changed. The helper now rereads the durable journal and authenticates
   that child before returning `APPROVAL_FAILED`.
2. The regular coordinator consumed `APPROVAL_FAILED`, while the successor did
   not. Both now write and reauthenticate the exact failed round before advancing.
3. The protected closure authorizer treated a valid failed predecessor as
   active. It now authenticates the failed marker, dispatch, exact GitHub child,
   terminal conclusion, no authorization artifact, and immutable preparation.
4. A failed round can also be retired when closure tooling advances. The
   successor reauthenticates the failed child in that case; contradictory timeout,
   preparation or retirement evidence fails closed.
5. A signed closure approval can expire before native intent. The authorizer
   now uses the existing pre-native verifier, requiring original approval,
   expiry, authenticated retirement, absent native and uncertain receipts,
   unchanged Terraform state, and the completed CAS alias. Missing intent alone
   is insufficient.
6. A timeout marker with a mismatched pending run or GitHub conclusion is
   rejected. Failed and timeout markers cannot authorize the same round.

## Regression map

| Scenarios | Executed test boundary |
| --- | --- |
| A, B, C, E, F, K, N, Q | Regular and successor coordinator suites exercise first success, immediate and previously dispatched failure/cancellation, missing journal, lost response and restart. |
| D, G, H, I, J | Successor suite exercises timeout, actual protected closure authorizer, replacement, consecutive failures and the 20-round bound. |
| L, O, R | Both coordinator suites restart after native intent/result and assert completed cutover, ECS/IAM and closure work is adopted without replay. |
| M | Shared approval-reader test fails closed on GitHub artifact HTTP 500 and 503, then resumes the same child. |
| P | Protected authorizer and pre-native tests reject wrong run, source, preparation, malformed markers, native intent/uncertainty, changed state and alias, and unauthorized artifacts. |
| S | Release Train and Release Gate contract tests verify terminal prerequisite handoff and independent gate requirements. |

The required governed Stage B Quality Gate job executes the successor and
pre-native verifier suites. The regular coordinator's targeted recovery tests
are already selected in that job. No test supplies live approval or authorizes
production writes. Production deployment still requires its own protected runs
and runtime acceptance.

## Local proof before push

The regular coordinator suite passed 103/103. The successor plus pre-native
suite passed 55/55. Relevant Stage B closure/bundle/session/gate integration
passed 57/57, Release Train/Release Gate routing passed 26/26, and OSV policy
tests passed 159/159. Workflow YAML validation passed 98 files. Unfiltered
OSV Scanner 2.6.0 reported only the existing dev-only `braces@3.0.3`
advisory; the canonical browser build transformed 3,993 modules, found 204
browser packages, excluded `braces`, and passed the runtime gate. The
time-bounded acceptance scope, owner and expiry are unchanged. Hosted required
CI and exact-head Codex review remain separate post-push checks.

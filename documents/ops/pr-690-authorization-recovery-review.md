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
7. The hosted successor reader rejected a signed closure round retired for
   `AUTHORIZATION_EXPIRED` before native intent was written. The coordinator
   itself can stop after that retirement and before the next preparation. The
   reader and next-round writer now consume the existing pre-native proof only
   when the immutable signed authorization, exact retirement identity, expired
   authority, absent native receipts, unchanged Terraform state and completed
   CAS alias all authenticate. An orphan retirement or missing signature fails
   closed. The existing record is not rewritten.
8. A second pass found that an unsigned closure round with an unrecognized
   retirement reason could be treated as an ordinary tooling advance. Both the
   hosted reader and coordinator now require the exact
   `TOOLING_ADVANCED_AFTER_CAS` reason for that branch; signed pre-native
   retirements remain on their separate authenticated path.

## Regression map

| Scenarios | Executed test boundary |
| --- | --- |
| A, B, C, E, F, K, N, Q | Regular and successor coordinator suites exercise first success, immediate and previously dispatched failure/cancellation, missing journal, lost response and restart. |
| D, G, H, I, J | Successor suite exercises timeout, actual protected closure authorizer, replacement, consecutive failures and the 20-round bound. |
| L, O, R | Both coordinator suites restart after native intent/result and assert completed cutover, ECS/IAM and closure work is adopted without replay. |
| M | Shared approval-reader test fails closed on GitHub artifact HTTP 500 and 503, then resumes the same child. |
| P | Protected authorizer and pre-native tests reject wrong run, source, preparation, malformed markers, native intent/uncertainty, changed state and alias, and unauthorized artifacts. |
| S | Release Train and Release Gate contract tests verify terminal prerequisite handoff and independent gate requirements. |

The real hosted `authenticateRequest` now reads a round-1 `authorized` plus
`AUTHORIZATION_EXPIRED` retirement with no attempt. A real successor coordinator
entrypoint then writes round-2 preparation and authorization. Injected process
stops immediately after each write resume against the same durable store;
closure runs once, CAS does not rerun, and completed closure is adopted on the
next invocation. The fixture rejects wrong ticket, missing round, forged
retirement fields, absent signature, native uncertainty, state drift and alias
drift. KMS and GitHub calls are deterministic mocks; live production approval
and native writes are not exercised.

## Durable-write audit

The successor's ordinary path writes START, then cutover and closure
`prepared`, `authorized`, `attempt`, and `result`. The fault matrix stops after
START, every content-addressed artifact put, and each of these eight step
writes; restarts finish without duplicate CAS or reconciliation. Its retirement
path stops after `closure:retired:0` and
resumes with the prior authority unchanged. The hosted test covers the
cross-tooling `closure:retired:1` boundary and both following writes. Existing
successor tests cover `pending`, `approval-timeout`, `approval-failed`,
dispatch-journal loss, consecutive failed rounds, and native cutover recovery.
The regular coordinator's public-entry lost-response matrix covers START,
phase preparations and authorizations, pre/post native intent for ECS, IAM,
publication, cutover and reconciliation, durable completion, and restart
without replay. Artifact puts are content-addressed and write-once; a saved
artifact without its referencing step is not authority. Native execution
uncertainty continues to require native receipt authentication and fails closed
when unprovable. This is a write-boundary audit with deterministic fixtures,
not a production fault-injection run.

The required governed Stage B Quality Gate job executes the successor and
pre-native verifier suites. The regular coordinator's targeted recovery tests
are already selected in that job. No test supplies live approval or authorizes
production writes. Production deployment still requires its own protected runs
and runtime acceptance.

## Local proof before push

The preceding counts describe the earlier PR head. For this revision, the
successor, hosted-reader and pre-native suites passed 71/71, the OSV policy
suite 159/159, and the exact-tree unfiltered scanner found only build-only
`braces@3.0.3`. A canonical browser build excluded it from 204 browser
packages and the OSV runtime gate passed. The complete regular coordinator
suite passed 103/103; its exact required-CI selection passed 11/11. Stage B
private evidence and dispatch integration passed 24/24, source/gate routing
passed 21/21, and all 98 workflow YAML files parsed with the hosted regression
included in the required Stage B job. A separate backend-health Release Gate
test file (unchanged by this PR) failed two standalone environment assumptions:
an unset `DEPLOY_SHA`, then a checkout-status expectation and isolated lifecycle
subprocess. The Stage B Release Gate contract tests in that combined run passed;
the backend-health failures are not claimed green or fixed here. Hosted required
CI and exact-head Codex review remain separate post-push checks.

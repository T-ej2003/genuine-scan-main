# Canonical rotation inventory correction

Status: local implementation and scoped hostile review complete; production installation requires merged protected source and clean exact-head review.
Production Terraform state 109 and the failed inventory replay claim are preserved.

The fixed operation calls `app_rls.production_rotation_inventory()` in a read-only
transaction. It returns the existing aggregate metadata shape, accepts no arguments,
and does not return application rows or secrets. The app receives EXECUTE only.
No read-role membership or direct application table grants are introduced.

The function uses the existing NOLOGIN, NOBYPASSRLS table owner and explicit
`pg_catalog,public` search path. Forced RLS remains enabled. Nine owner-only SELECT
policies are restricted to the canonical app session, read-only transaction and
function-local operation marker. Installation and expected-catalogue snapshots
must be included in the authenticated package; broad runtime-policy reinstallation
is not an acceptable substitute for the incremental production installation.

Forward recovery must retain the original launch-uncertain claim. An authenticated
stopped, failed task with no successful output may link exactly one successor
claim atomically. Succeeded or unknown outcomes cannot recover. The current failed
task is `fa5ad8eb6aa9443cad6ec600bfa8e82c`, exit 1 before inventory SELECT.
No recovery is executable until the current source/config/approval and predecessor
identity are authenticated and the transition is tested.

Completion gates: PostgreSQL 18 security proof; actual old-to-new replay tests;
inventory, broker, prepare/verified-overlap and deployment closure suites; canonical
package generation/verification; hostile review; exact-head CI and Codex review.

## Installation and forward recovery

The incremental installer uses the existing pinned administrator executor image,
execution role, secret and private-network configuration. It installs only one
function and nine owner-only policies in one transaction. It proves unchanged
existing ACLs, memberships, table ownership, forced RLS and policies. A partial or
already-installed contract fails closed rather than being blindly installed again.

Run `scripts/aws/apply-production-rotation-inventory-contract.mjs` only from the
approved clean protected-source checkout, supplying its full `--source-sha`, the
existing `--aws-profile` and a new private `--receipt-out`. The prepared receipt
and `.launch.json` retain the exact contract and task identity. After a reporting
failure, `--verify-only` reads those receipts and verifies that same task; it does
not register or launch another task. Missing launch evidence requires AWS
readback before any further action.

The canonical runtime producer automatically carries the preserved predecessor
identity for this rotation. The broker authenticates its original replay hash,
retained task definition, failed task/log outcome and absence of success output.
If ECS has aged out the task, the exact broker-issued CloudTrail StopTask record
plus the fixed CLI's uncaught CloudWatch failure provide the archived proof.
One DynamoDB transaction preserves and links the failed claim to exactly one new
claim. Unknown, successful, substituted or already-recovered predecessors fail.

Expected post-merge mutations are the narrowly governed broker package/policy
convergence, a genuinely necessary inventory-runtime image publication, the fixed
one-shot DB installation and the single recovered inventory attempt. No consumed
Terraform plan may be reused. Existing application/web image reuse remains subject
to the normal authenticated impact contract.

Local evidence so far: inventory/recovery/producer tests 133/133; actual PostgreSQL
18 aggregate boundary and incremental installation tests each passed. The local
full-package integration harness separately encountered its existing
`subscription_conninfo_acl` catalogue capability prerequisite; that result is not
represented as a pass. Final closure, security and review results remain pending.

Recommendation: retain the authenticated failed-launch evidence and install/task
receipts until the release completes; use verification-only recovery after any
reporting failure rather than repeating a consumed operation.

## Pre-push verification

- Focused inventory/producer/recovery/overlap suites: 155/155 passed.
- Deployment closure: PASS, including 777 control-plane and 345 closure tests.
- PostgreSQL 18 aggregate isolation and incremental installation: 2/2 passed.
- Canonical RLS package verification: 17/17 passed.
- Security guardrails, secret diff and whitespace checks: PASS. OSV: zero findings.
- Hostile review checked fixed SQL, owner/search-path/ACL isolation, immutable old
  task/hash authentication, atomic single-successor CAS and post-mutation reporting
  recovery. No unresolved P1/P2 before push.
- Production mutations during development: zero; Terraform state 109 preserved.

The only stale role literal in executable source is the exact legacy task-definition
authenticator for the preserved failed predecessor; it is never used by new tasks.

Exact-head CI exposed two verification siblings: the second app-only source-IAM
evaluator retained its predecessor Terraform digest, and the destructive-test
scanner needed its existing narrowly scoped exception for the new disposable
upgrade test. Both source-IAM evaluators now share one reviewed exact digest.
Both new PostgreSQL tests reject non-loopback or unexpected fixture identities
before SQL; the scanner exception applies only to this test's database cleanup.
The source evaluator passed 4/4, guarded PostgreSQL18 proof passed 2/2, and the
full source-security guardrail suite passed after these corrections.

## Emergency absent-claim recovery (one preserved operation only)

The original task `fa5ad8eb6aa9443cad6ec600bfa8e82c` has durable broker-issued
RunTask/StopTask events and an uncaught inventory failure, but its replay row
is absent. This branch never reconstructs that row. Existing row-based recovery
continues to require its original identity, nonce and task.

Immediately before the canonical prepare-overlap command, the independent
checker signs a 15-minute attestation produced by:

```sh
node scripts/aws/prepare-absent-inventory-recovery.mjs --config /private/release/rotation-config.json
```

Use the existing inherited checker session for signing and the authenticated
`mscqr-production-root` profile for read-only AWS collection. The producer
requires clean protected-main source, exact current config, absent canonical
state/fixture/readiness files, no rotation replay rows or recovery reservation,
exact historical approval signature, complete RunTask history, and complete
failed-task logs. It writes only a private sibling
`inventory-absent-claim-evidence.json`; the config and its hash are unchanged.
No MFA token is included in the evidence or command. An expired local attestation
can be atomically replaced by rerunning this same producer: all absence checks
run again before signing. Once the permanent recovery reservation exists, the
producer refuses refresh; local evidence replacement never resets replay state.

The normal prepare-overlap adapter reads this sibling, checks its exact config
hash and state absence, and passes it to the broker. The broker independently
verifies both KMS signatures, the retained original task definition, complete
launch history and failed-task output. Unknown/successful/substituted outcomes
fail closed. This is bounded to the exact original rotation, source, task,
authorization version and AWS event identities, not a generic recovery mode.

Before RunTask, one DynamoDB transaction checks predecessor absence, creates a
permanent recovery reservation, and conditionally creates the successor claim.
The reservation has **no TTL**, is independent of successor source SHA, and is
never deleted by failure cleanup. Existing row-based recovery also atomically
checks that reservation is absent, preventing a late predecessor restoration
from authorizing a second successor. Concurrent, repeated or cross-source
recovery attempts fail closed. If launch/reporting fails, inspect actual task
and successor claim; never repeat the operation or delete its reservation.

Post-deployment follow-up only: missing claim cause, PITR/backups, ECS Exec
readiness, catalogue-probe compatibility, and recovery retention hardening.
No Terraform state, SQL, RLS, IAM policy or inventory query changes are included.

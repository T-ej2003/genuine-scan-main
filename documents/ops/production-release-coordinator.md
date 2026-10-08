# Production release coordinator (PR A)

PR A ends at authenticated `PREREQUISITES_CONVERGED`. Release Gate deployment
ownership and automated business acceptance remain PR B and PR C. They are not
prerequisites for deploying the current business release through the existing
governed Release Gate after PR A is merged.

## Entry and identity

Release Train retains an explicit governed start; protected-main pushes do not
activate production automatically. A release binds its exact accepted source,
component deployment baseline and canonical change classification. Release IDs,
Stage-B transaction IDs and GitHub child run IDs are distinct. Advancing main
cannot replace any of these bindings.

If protected main advances during a release, the existing Stage-B checkout and
protected approval contracts block further writes from the frozen older source.
This is PR A's fail-closed source-advance outcome: the coordinator does not
rebind that release or its approval to newer tooling. Durable records remain
available for authenticated native recovery.

The coordinator saves the initial component baseline as an immutable referenced
artifact. Restart reads that accepted identity before reauthenticating the source;
it does not derive a different release from a later component-state generation.
Conditional encrypted records reuse the existing Stage-B receipt namespace and
its create/readback functions. They do not replace native mutation journals.

Each new phase refreshes its canonical planning inputs after earlier Terraform
state transitions. Restart instead hydrates that phase's immutable captured
preparation and saved material. Historical predecessor selection is restricted
to registration preparation and cannot leak into subsequent operation requests.

## Prerequisite sequence

One coordinator invocation owns the sequence below; callers do not select
internal phases:

1. Authenticate eligible source and component baseline.
2. Authenticate the governed start's canonical image-authorization transport
   and its source-bound published digests. An image-affecting change requires
   the existing image-publication workflow before this release start.
3. Authenticate exact-source required gate runs.
4. Adopt a compatible authenticated completed registration, or prepare,
   authorize, execute and verify fresh registration.
5. Authenticate policy inventory, ownership and recoverable transaction evidence.
6. At five-version capacity, protect the default and transaction-required
   versions, select the unique oldest eligible obsolete non-default, prepare
   and authorize exact pruning, execute once and authenticate its result.
7. Prepare, authorize and execute the exact successor policy; verify its document,
   default, version inventory and ownership completion.
8. Prepare and authorize broker publication, execute once and verify the immutable
   Lambda successor.
9. Prepare and separately authorize alias CAS; execute against the exact predecessor
   version and RevisionId, then reconcile Terraform through the existing governed
   state-only closure.
10. Authenticate and persist terminal prerequisite closure.

Human interaction is limited to deliberate production authorization. Successful
workflow dispatch or HTTP health alone does not establish deployment success.
An approval child that times out without approval consumes its exact round. The
coordinator may request a new round for the same preparation; failed or
cancelled children do not silently become new approvals.
If the runner stops after the authenticated dispatch journal but before the
pending marker, the exact journal-recovered child may still consume its timed-out
round. The child must match the release, phase, preparation and round; a new
approval child is dispatched only for the next round.

## Hosted authorization

The operator selected the repository's existing GitHub protected-environment
approval proof for the hosted coordinator. Stage-B authorizations keep exact
preparation, purpose, source, predecessor disclosure and thirty-minute TTL
bindings. The verifier reads back the exact successful authorization workflow,
first attempt, immutable archive digest, single authorization file, configured
environment protection and actual approval event. Local JSON and its digest
alone cannot authorize a mutation. Historical KMS authorizations retain their
existing verification path.

Alias cutover and Terraform state-only closure have separate authorization
purposes. A completed alias CAS is authenticated predecessor evidence for a
new closure preparation. If the cutover approval expires before the native
state-refresh intent, the coordinator obtains fresh closure authority for the
remaining write. That authority cannot approve another alias update. Once the
state-refresh intent exists, native recovery reconciles the result without a
second write.

Self-approval is recorded as `checkerIndependent=false` and
`soleOperatorModel=true`; it is never described as independent human review.
This change does not grant additional AWS permissions.

The executable fixture is not production execution evidence. The hosted writer
now freezes the OIDC credentials from the approved Release Train job. Read-only
held-owner recovery requires authentication of that exact completed job and an
AWS clock later than the bound credential expiry. An uncertain alias CAS without
its native execution receipt still fails closed; live alias shape alone cannot
establish which writer performed it.

## Evidence and recovery contract

Fresh schema-3 registration remains distinct from historical receipt-bound policy
provenance. Historical alias runtime, current IAM predecessor and fresh successor
maps remain distinct until their authorized lifecycle transitions converge them.
Pruning changes inventory and ownership generation, not the default policy's
semantic identity. Its signed preparation, exact deletion target, durable intent,
receipt and released ownership bind that transition into subsequent convergence.

Each mutation has immutable preparation/authorization and durable intent before
execution. Restart authenticates native transaction records and live state.
Completed outcomes recover without another mutation. Proved no-write outcomes
require fresh authority before any new mutation. Uncertain or contradictory
outcomes fail closed; a lost response never means the write was not issued.

The coordinator's `:attempt:` record means only that it invoked a public Stage-B
operation. On restart it reads that operation's native intent before selecting
native recovery; held policy ownership is also a native recovery boundary.
An absent intent before ownership acquisition permits the same authorized
operation to resume after fresh authentication and final checks. An expired
approval cannot authorize that new write. A reservation created before intent
may be reused only when its immutable bytes match exactly; native conditional
intent creation still prevents two writers from reaching the mutation. Intent
present, uncertain mutation, or completed result follows the native recovery
path. This rule covers registration, policy capacity and convergence, broker
publication, alias CAS and state-only terminal closure.

## Required executable proof

The public coordinator success test must itself call only one coordinator entry.
Transport fixtures reject real AWS/GitHub/production HTTP access. They use real
Stage-B public operations, serializers and verifiers at handoffs.

Both clean release and current-release adoption must reach closure. The current
fixture models completed registration
`1b2f41edaae551cc5785591f78e23ea368abcff3551b207d144cb923fa5b4495`,
12 successors, default v13 and inventory v9–v13. It must make zero additional
registration calls and exactly one authorized delete and successor create.

Fault injection covers both sides of every durable boundary for registration,
policy delete/create, publication and alias CAS. Tests assert exact call counts,
source advancement, expired authority, partial outcomes, substituted evidence,
changed inventory/default, protected-version retention, oldest-date ambiguity,
stale ownership generation and alias RevisionId conflict.

The current completed-registration fixture contains the consumed transaction's
original preparation, authorization and result, plus the public verification key.
It contains no signing key or inline credential environment variables. Tests
verify its original signature and operation identity offline, preserve all twelve
output bindings when checking compatible descendant adoption, and reject altered
outputs or incompatible images. Synthetic transport fixtures exercise subsequent
coordinator transitions without contacting production.

Production mutations during development are prohibited. No PR is merge-ready
until the complete public-operation lifecycle, required local/hosted checks and
fresh exact-head review pass.

## Current proving status

The one-entry current-operation fixture preserves the original signed
registration and its twelve output identities, then exercises the public pruning,
policy, publication, cutover and closure operations using offline transports.
There are zero additional simulated registrations. The preserved packet does not
include the original raw ECS responses; simulated readbacks check exact semantic
successors without claiming the old response-byte digests were independently
reverified. Production receipt/ECS authentication remains unchanged.

The existing source-bound dispatcher now supports a conditional external dispatch
journal. The immutable attempt binds repository, workflow ID/path, exact source,
ref, inputs and pre-dispatch child IDs. A lost dispatch response reconciles a
unique exact-source child on restart without a second POST. An attempt with no
visible authenticated child fails closed. A successful dispatch remains only a
child identity, never a production or prerequisite completion claim.

Protected-approval artifact retrieval shares the canonical authorization archive
checks: exact source/run, successful first attempt, exact artifact identity and
archive digest, single bounded JSON member. Retrieval alone is not authority;
the verifier additionally authenticates the protected environment and actual
approval event before the public Stage-B operation accepts it.

## Hosted boundary decision

The approved hosted path uses the existing GitHub protected-environment approval
proof for checker authority. It does not make a GitHub approval into an AWS
mutation receipt or proof that an old STS session has expired. Those independent
questions remain authenticated by the native recovery contract. The hosted
writer connection pins bounded session provenance before an IAM write;
uncertain alias outcomes still require authenticated native CAS execution
provenance. No release-role CloudTrail/administrator permission is being added.

Local coordinator, public Stage-B, deployment-closure, workflow, security,
capability, dependency, RLS, Terraform and OSV gates passed before the first
PR head. Hosted CI then exposed one missing credential-root inventory entry;
that exact checker workflow is now classified and retested. These are source
and deterministic-fixture results, not production execution evidence.

The coordinator now captures each prepared phase's exact package, manifest,
tfvars, backend metadata and saved plan into immutable content-addressed
material before recording that phase as prepared. It reauthenticates and
hydrates those bytes before authorization or execution, including on a new
runner. The Release Train resolves and waits for its exact source-bound gates
before its protected production job invokes the hosted coordinator. Its
explicit workflow dispatch supplies the immutable release ticket and source;
no protected-main push starts production. The
coordinator chooses the next public Stage-B operation from the durable journal,
dispatches the exact protected approval child, and resumes without a phase
argument from the operator. The child hydrates the same saved plan and calls
the public Stage-B authorizer. The hosted writer calls the same public executor
as the offline one-entry fixture. Release Train renews the existing OIDC
release-deployer session between bounded coordinator windows; every window
restarts from the durable release record. If protected approval exceeds the
bounded workflow run, rerunning the failed orchestrate job resumes that exact
release without selecting a Stage-B phase. A recovered held writer is bound to
the exact previous GitHub run attempt and its expired AWS session; a later
attempt cannot impersonate that writer.

The hosted coordinator is used for a Release Train target equal to current
protected `main`. Existing explicit historical `release-*` and `v*` tag
dispatches retain the prior Release Gate route after exact source/ancestry
checks; those older source trees do not claim to run current-main Stage-B
mutation tooling. The release classification treats only the coordinator's
reviewed composite action path as security infrastructure. A four-version
predecessor records a durable no-pruning decision, so a later policy creation
cannot cause restart to insert a pruning mutation out of order.

The release ID binds the ticket as well as the source, deployed baseline and
classification. Completed phase results are reauthenticated against their
native receipts. Historical recovery is not replayed after a later phase has
advanced Terraform or the alias; the next native phase authenticates its live
predecessor and terminal reconciliation authenticates the final live state.
A durable policy no-write outcome consumes its old authority and selects a new
approval round for the same exact prepared operation. An uncertain outcome
still enters native read-only recovery and cannot be retried as a write.

The runner-replacement fixture restarts the one public coordinator entry from
the same immutable external records with no manually selected phase and no
additional task registration. It models the already completed twelve-definition
registration and a five-version broker policy. Local tests do not contact
production; hosted execution remains unclaimed until a merged governed run.
An adopted registration is reauthenticated from its immutable handoff, native
registration receipt and twelve retained ECS definitions on every restart;
the next native pruning preparation checks live predecessor state. The hosted
runner does not regenerate exclusive registration planning files merely to
resume an already recorded adoption.

The dedicated approval runner initializes provider plugins without a backend,
then removes only that initialization's temporary backend metadata before
hydrating the exact captured preparation metadata. A conflicting existing
metadata file fails hydration rather than silently rebinding the saved plan.

The Release Train gate reader now exposes the exact workflow and child-run
payloads already used by the canonical gate checker. The coordinator verifies
those identities itself; a success-only summary or a substituted child run
cannot satisfy `GATES_PASSED`.

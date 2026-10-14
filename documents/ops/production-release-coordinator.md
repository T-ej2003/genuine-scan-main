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

Publication may advance Terraform state before cutover preparation. When its
outputs change, the output-reconciliation verifier authenticates the original
publication preparation and package identity, then checks the newly prepared
cutover artifact set against its own hash. The original artifact-set hash remains
bound to the immutable publication receipt; it is not substituted for the
current-state cutover inputs. A completed publication is adopted on restart.
The coordinator stores both output-reconciliation reports in its existing
encrypted phase-material capsule and verifies their preparation-bound hashes
before restoring them on a replacement runner.

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

### Adopting an independently completed broker closure

If a separately governed successor operation finishes publication, alias CAS and
Terraform reconciliation while Release Train is paused, dispatch Release Train
with `completed_broker_closure_source_sha` set to that operation's **original
release SHA**. This is an evidence locator, not authorization. The hosted
coordinator reads the immutable terminal handoff and uses the existing signed
closure verifier to authenticate the original publication, both protected
approvals, live Lambda alias/version, IAM prerequisites, Terraform state and
the current protected-main tooling ancestry. It also authenticates the
completed registration receipt, all 12 live ECS definitions and the exact task
map shared by the closure. It checks all 12 registered task bindings in the
exact authenticated Terraform state bytes. The current release retains its own source, image
authorization, change ticket, component baseline and required CI gates.

When a later release reuses a schema-2 registration receipt after an independently
governed broker closure, the registration preparation's alias is a historical
predecessor. The adoption reader accepts a newer live alias only after the
canonical closure verifier authenticates its immutable terminal receipt, live
Lambda and Terraform state, and protected tooling ancestry. The closure must
start from the registration preparation's exact alias and carry its completed
task map. This permits the later release to prepare a new source-bound broker
publication; it does not adopt the old broker as authorization for the new
source or repeat any completed registration or broker operation.

Only then does the coordinator persist `BROKER_CLOSURE_CANDIDATE` and its normal
terminal prerequisite summary in the encrypted evidence store. These are new
write-once audit records, not broker, IAM, ECS or Terraform operations. It does
not enter registration, pruning, policy,
publication, cutover or closure execution. A restart reauthenticates the saved
candidate against live state; a different source input, changed receipt, drift,
or an existing coordinator mutation phase fails closed. An absent locator keeps
the ordinary phase sequence unchanged. This route does not replace Stage B
approval, rotation, Release Gate or application deployment authorization.

The pre-merge read-only rehearsal on 2026-10-13 exercised the public hosted
coordinator with a mocked durable store in both prerequisite-only and strict
gate lifecycles. Restart reauthenticated the saved closure candidate; neither
route entered registration, IAM, publication, alias CAS or Terraform execution.
The full coordinator suite passed 97 tests, Stage B closure 360 tests, downstream
approval/Release Gate/initial-overlap contracts 58 tests, and deployment
eligibility/receipt/CAS/restart contracts 70 tests. The downstream workflow
fixture now supplies its actual checked-out `DEPLOY_SHA`, matching the hosted
job's input contract. These are non-production fixture tests, not production
approvals or deployment receipts.

Independent read-only production readback found reviewed alias v14 and
Terraform lineage `4e438e59-8b8b-194d-030c-5ede0c26344a`, serial 126.
The signed terminal broker closure and all twelve ECS registrations were
authenticated separately. After merge, reauthenticate these live identities,
the current-source image authorization and ticket scope. The prerequisite-only
dispatch can then adopt closure; Stage B approval and rotation remain separate
governed transitions. A later strict Release Train dispatch requires its own
exact-source gates and production approval before Release Gate or application
deployment. No protected approval, Release Gate outcome, deployed image, RLS
convergence, or Startex acceptance is established by this rehearsal.

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
Journaled dispatch paginates and checks the complete pre-dispatch run inventory,
including workflows with more than 100 historical runs. A changed run count,
changed latest page, or duplicate run ID fails before dispatch.

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

Each composite invocation checks the actual OIDC expiration before starting
another coordinator call. With 30 minutes or less remaining, it reports
the existing waiting status and the next composite invocation assumes the same
release-deployer role afresh. A newly issued session that already lacks this
window fails closed. This handoff does not authorize any phase: the next call
reauthenticates the immutable release journal, saved preparation, and any
operation-specific protected approval before a native write. If all seven
windows are used, rerun the failed Release Train job from durable state.

The hosted coordinator is used for a Release Train target equal to current
protected `main`. Existing explicit historical `release-*` and `v*` tag
dispatches retain the prior Release Gate route after exact source/ancestry
checks; those older source trees do not claim to run current-main Stage-B
mutation tooling. The release classification treats only the coordinator's
reviewed composite action path as security infrastructure. A four-version
predecessor records a durable no-pruning decision, so a later policy creation
cannot cause restart to insert a pruning mutation out of order.
While policy approval is pending, each read-only check of a skipped pruning
phase materializes fresh private inputs. The durable no-pruning decision and
policy preparation remain unchanged; the check still compares live policy
inventory and the no-op plan before any policy write.

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


## State-private standalone prerequisite handoff

The standalone prerequisite and state-reconciliation preparation workflows use
this same encrypted coordinator store. Their GitHub artifacts contain only
`private-evidence-reference.json` or `preparation-reference.json`. Raw state,
prerequisite ZIPs and saved Terraform plans stay in the existing Terraform
backend's apply-attempt namespace, with AES256 encryption, conditional creation,
content-addressed identity and exact readback. No new bucket or IAM policy is
introduced.

Use the existing production-protected producer, preparation, authorization and
execution workflows in that order. Dispatch fields and protected approvals
remain required. Consumers authenticate the exact successful producer run,
repository, source, attempt and GitHub artifact digest before reading the private
reference. The reference binds kind, workflow, run, source, byte size and payload
digest; the store independently verifies its immutable envelope and content hash.
The existing bundle manifest, state lineage/serial, plan and authorization checks
still run after private materialization. A missing object, access denial or any
substitution fails closed. Never upload the reconstructed ZIP or saved plan.

The authorization workflow uses the existing production release-deployer OIDC
role to read the referenced preparation. This does not grant new IAM permissions
or authorize Terraform execution. Execution still requires its separate protected
approval and exact authorization. New producer attempts require new authenticated
references; references from different runs cannot be combined. Historical
reconciliation receipt readers retain support for already-issued legacy artifacts,
but these workflows no longer publish state-bearing artifacts.

This transport does not satisfy rotation grace, current image bindings or Stage-B
approval prerequisites by itself. Keep an existing rotation and authenticate its
own durable evidence before Release Train. Recommended hardening is to keep the
reference-only artifact regression in required CI so future bundle additions
cannot accidentally expose production state.

Private reference readers require an explicit credential-bound AWS runner.
Hosted workflow hydration uses the existing OIDC release-deployer session;
local normal-activation convergence passes its explicit `--admin-profile` runner
for both evidence reads and policy execution. Neither path inherits ambient
credentials or falls back to another credential source. Legacy GitHub-only
receipt authentication remains compatible without AWS hydration.

## Durable registration adoption across protected-main updates

The existing release evidence transport can include `completedRegistrationSourceSha`.
For this continuation it is `2c2d63eaea623c0d9d55c98a949d0a47186fdd2e`.
The schema2 wrapper preserves the exact signed image authorization and its checksum.
It selects encrypted coordinator START and registration-result records under that
source and the same operator-issued ticket, never a local file or arbitrary receipt
body. Missing, substituted, incomplete or image-incompatible authority fails closed;
explicit selection never falls back to new registration.

The reader authenticates hashes, source/ticket/release/operation bindings, original
authorization and native TASK_REGISTERED receipt. Existing prepare-registration-adoption
verifies all twelve definitions, immutable images, live ECS and current Terraform
state. Historical preparation/authorization/results stay immutable; the current-source
adoption is separate. The reference is hash-bound in ARTIFACTS_RESOLVED and checked
on every restart. Workflow, RLS package, IAM and production approvals are unchanged.

If a current-source START already saved a different registration reference, do not
replace its immutable `ARTIFACTS_RESOLVED` record. An independently issued new CHG
ticket creates a new release identity. When the authenticated registration was made
under an older ticket, include both `completedRegistrationSourceSha` and
`completedRegistrationTicketId` in the checksum-bound evidence transport. The reader
loads that exact old source/ticket START and registration result, verifies the
original authorization and receipt, then checks image reuse and live task/state
bindings against the new release. Omission retains same-ticket behavior; invalid or
substituted tickets fail closed. New protected approvals remain separate. Preserve
the older START, completed broker closure and all receipts.

After merge, fetch exact protected main, authenticate image reuse and obtain fresh
current-source image authorization plus an issued or explicitly re-scoped CHG ticket.
Preserve serial123, alias13 and completed historical CAS/closure. Verify no concurrent
Release Train. Prepare private mode0600 inputs using the existing packer:

```js
const transport = packReleaseEvidenceTransport({
  authorizationJson, // exact fresh authenticated current-source envelope bytes
  authorizationSha256, // SHA256 of those exact bytes
  completedRegistrationSourceSha: '2c2d63eaea623c0d9d55c98a949d0a47186fdd2e'
});
const inputs = {
  git_ref: 'main', target_sha: authenticatedMainSha, ticket_id: authenticatedTicketId,
  prerequisites_only: 'true', release_lifecycle: 'authenticated-initial-overlap',
  rotation_id: 'rotation-20260913011819-98b062c4',
  normal_image_authorization_json: transport.json,
  normal_image_authorization_sha256: transport.sha256
};
```

Dispatch once after all bindings authenticate:

```sh
GITHUB_REPOSITORY=T-ej2003/genuine-scan-main GH_TOKEN="$(gh auth token)" \
  node scripts/github/dispatch-source-bound-workflow.mjs \
  --workflow release-train.yml --ref main --target-sha "$AUTHENTICATED_MAIN_SHA" \
  --inputs-file "$PRIVATE_RELEASE_INPUTS_FILE"
```

The template is not authorization. Adopt the twelve registrations without replay;
authenticate pruning ownership/native history and renew expired preparation/approval
through existing protected workflows. Rotation, RLS and deployment gates remain
mandatory. No raw state goes in the transport. Recommendation: select immutable
durable authority explicitly instead of inferring completion from revision numbers.

## Schema2 registration adoption before IAM convergence

A completed registration receipt identifies the new ECS map; its signed prerequisite
snapshot identifies the IAM policy and reviewed-alias runtime that existed before
registration. Those maps legitimately differ until independently authorized policy
convergence. The schema2 adoption reader selects the signed predecessor map only
when live IAM policy exactly matches that signed policy, and then authenticates
the complete predecessor snapshot. The twelve registered outputs remain separately
verified against receipts, images, live ECS and Terraform state.

If IAM already authorizes the registered map, existing converged adoption behavior
remains supported. Unknown revisions, changed predecessor role/policy/version, or
alias drift fail closed. Schema1 and schema3 paths and the shared task-map validator
are unchanged. The regression reproduces old IAM/new registered-map disagreement
using the real prerequisite reader and the public cross-source adoption entrypoint.

After merge, authenticate new protected main, ticket scope and fresh image reuse
evidence. Use the durable2c2d63e registration reference documented above. Never
retry Release Train38247736410 as a substitute for new tooling/source bindings.
Preserve all twelve definitions, state123, broker13, historical CAS/closure and
expired approvals. Obtain fresh pruning authorization before pending mutation.
Recommendation: keep IAM-authorized and registered task maps distinct until their
authenticated convergence; revision numbers alone are never authority.

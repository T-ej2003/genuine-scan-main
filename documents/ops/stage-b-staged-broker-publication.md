# Governed staged broker source-binding transition

This source-only extension closes the Lambda alias race in the pinned Terraform
provider. It does not execute production publication, infrastructure apply, RLS,
checker authentication, application cutover, or worker operations.

## Authority and phases

| Phase | Authority required before operation | Allowed effects | Success evidence |
|---|---|---|---|
| Prepare / A approval | Exact protected main, bound tfvars/image/refresh/backend and package; independent checker signs purpose-specific preparation | Reads, plan capture, signing | Exact saved publication plan and signed one-use authorization |
| A publication | Unexpired `STAGE_B_BROKER_PUBLICATION` authorization, conditional S3 reservation | Only `aws_lambda_function.broker` update, `publish=true`; every included dependency no-op | Qualified concrete version from the saved-plan result/state, independent version configuration/code/runtime readback; alias unchanged |
| B approval | Authenticated A receipt, exact qualified target, original alias predecessor, canonical IAM/role/task map, fresh diagnostic plan | Reads and distinct checker signature only | `STAGE_B_BROKER_ALIAS_CAS` approval binds target version/ARN/code/runtime, predecessor version/RevisionId/routing, plan/package/state/source, aggregate two-address census |
| C cutover | Unexpired B approval; exact immediate `GetAlias` predecessor; own one-use reservation | One native `UpdateAlias`, exact approved version and `RevisionId` | Returned and independently read alias agree; new revision, exact target |
| D reconciliation | B authority and authenticated C receipt; exact unchanged version/alias/prerequisites/state | Apply only the validated saved **refresh-only** state plan; no remote mutation | Full fresh normal plan is no-op, function and alias state/readbacks match approved target; durable pending terminal handoff |
| Release closure | Authenticated A/B signatures and A/C/D receipts; fresh target/state/IAM/role/task-map readback | Existing security component-state CAS | Actual CAS state readback binds `security.stagedBrokerEvidenceSha256`; only then `COMMITTED` |

The IAM policy is an authenticated prerequisite, never an invented mutation.
Aggregate mutation addresses are exactly `aws_lambda_function.broker` and
`aws_lambda_alias.reviewed`; each remote-mutation phase has one address.
The normal diagnostic alias plan is **never applied**. Terraform remains the
owner of the desired alias version; state-only refresh absorbs the native CAS
result without `state rm`, manual edits, lifecycle suppression, or provider patch.
A later publication invalidates reconciliation rather than changing the target.

## Canonical executor

The existing Stage B entry point dispatches the governed phases:

```sh
TF_WORKSPACE=default node scripts/apply-production-green-stage-b.mjs \
  --staged-broker --input /absolute/private/request.json \
  --input-sha256 <raw-file-sha256> --output /absolute/private/result.json
```

Input/output files and the containing artifact directory must be private,
external to the checkout, and output must not already exist. Requests select
`prepare-publication`, `authorize-publication`, `publish`, `prepare-cutover`,
`authorize-cutover`, `cutover`, or `reconcile`. All requests supply canonical
`files` (`backendMetadata`, `package`, `packageManifest`, `tfvars`), `directory`,
and `terraformDataDir`. Preparation additionally supplies the existing canonical
planning options/refresh and binding evidence. Authorization supplies the exact
preparation/plan path, maker identity, and human review identifier. Execution
supplies the preparation, signed authorization, and saved-plan path. Cutover
preparation supplies the original publication preparation/authorization/result;
reconciliation supplies the authenticated CAS result. No secret/OTP is an input.

The independent checker uses the existing checker session, signing key and
algorithm. Neither publication authority nor runtime RLS approval can authorize
alias cutover. Cutover approval cannot authorize publication. Changing any signed
preparation field, binary/logical plan, immutable version, code/configuration,
predecessor, artifact set or source invalidates authority.

## Durable handoff and normal deployment

The existing conditional S3 apply-attempt namespace stores purpose-bound
reservations and receipts. Each phase reuses the existing three-step history
limit. A protected-source reservation binds publication preparation and signature;
a source-bound terminal handoff links the authenticated four-phase history.
Missing/denied/ambiguous history blocks; only explicit `NoSuchKey` means no staged
transaction. Full-RLS and the terminal writer discover this authority directly,
so omitting optional environment transport cannot hide an incomplete transaction.
No new signing system, store, AWS resource or IAM role is introduced.

The staged preparation returns `NOT_REQUIRED` when the complete normal plan is
no-op and the live reviewed alias/function already have the desired source.
Ordinary application-only deployment follows its existing DAG. Releases needing
a broker transition finish this protocol before Full-RLS operations. Terminal
success uses the existing component-state CAS, not a caller-supplied boolean.

## Read permissions and no-traffic prerequisite

Authenticate immutable predecessor/target configuration; canonical broker role,
trust, attachments, inline-policy census, exact IAM document/task map; all alias,
qualified/unqualified resource-policy, function URL, and event-mapping routes.
The canonical release caller's attached/inline policies must allow broker
invocation only through the reviewed alias; unknown attachments and broad
invocation grants fail closed. Privileged administrative out-of-band operations
are outside normal release authority and are never inferred to be safe traffic.

The source permission manifest adds the read-only inventory requirements to the
existing ProviderReadOnly policy: exact broker aliases/URL configurations/policies,
regional event-source mapping census, and exact release-role/policy metadata.
These source changes do not converge live IAM. Live permission authentication is
required before any future production execution; existing credential breadth
never authorizes an operation outside its phase.

## Failures, concurrency and orphans

A predecessor mismatch or AWS 412 consumes/abandons that attempt and fails closed.
AWS CLI mutation retries are disabled. There is no new-RevisionId retry, automatic
replan, approval regeneration, Terraform alias fallback, or automatic rollback.
An uncertain mutation preserves its durable intent/UNKNOWN status and permits
read-only diagnosis; it cannot gain a second mutation from readback. A source
reservation cannot be reused for a second publication under another authorization.
A separately reviewed recovery is required after an incomplete/uncertain attempt.

An unused published version receives no reviewed-alias traffic and has no
approval authority. No automatic deletion or latest-version selection occurs.
The numeric version census is only a guard against a newer publication changing
Terraform's desired target, never a target selector. Publication-only,
cutover-only, failed refresh, missing normal no-op proof, or failed component-state
CAS cannot become terminal success.

## Validation and next boundary

Run `node --test scripts/tests/stage-b-staged-broker*.test.mjs`, the existing
Stage B/control-plane, closure/normal/state/workflow suites, capability graph and
Deployment Audit. Tests use mocks and local packaging only; they are not live
production proof. The separately authorized security-owner revalidation is recorded
in `documents/security/staged-broker-osv-revalidation-2026-10-04.md`. It changes only
the existing broad input hash; scope, owner, advisory/version and expiry remain
unchanged. Future source changes require fresh review before commit/push/review.

Recommendation: retain the permanent native-command concurrency tests and strict
phase/receipt guards as this path evolves. No worker lifecycle or broader deployer
abstraction is needed for this correction.

### Local implementation review, 2026-10-04

The following checks use deterministic fixtures/mocks, not live AWS proof.
The initial local implementation stopped before commit/push for separately
authorized security-owner revalidation; that review now passed. The protected-main base is
`be45d6bf0dc79e81f7ecd5db7a71eeeedf9e395e`.

| Hostile attack | Required and observed result |
|---|---|
| Publish without prior authorization, or with expired/unsigned/wrong-phase authority | Reject before publication |
| Substitute saved binary, source, checkout tree, backend/state or artifact set | Reject |
| Add alias, IAM, duplicate function or unknown mutation to publication | Reject |
| Change role, code, timeout, task map or unrelated configuration | Reject |
| Substitute orphan/latest version, code hash, runtime or configuration | Reject; concrete execution result alone selects target |
| Use publication approval for cutover or cutover approval for publication | Reject |
| Replay publication or cutover approval | Reject; conditional durable reservation precedes mutation |
| Change predecessor version, RevisionId, alias or routing | Reject before cutover |
| Race the immediate alias read | Exact RevisionId supplied to native mutation; one CAS winner |
| Return AWS 412 or uncertain write result | Conflict/UNKNOWN; exactly one write attempt, no revision retry |
| Invoke low-level mutation without this executor's reservation | Reject |
| Expose unqualified/version traffic using alternate Invoke actions or wildcard resources | Reject |
| Add remote action, wrong target, extra drift or output effect to refresh | Reject |
| Replay uncertain refresh using a different saved binary | Reject using fixed parent-approval reconciliation reservation |
| Reconcile after unrelated newer publication | Reject; version census is a guard, not target selection |
| Leave alias mutation in normal post-refresh plan | Reject closure |
| Omit phase history, substitute raw `authenticated: true`, or disguise access denial as absence | Reject |
| Substitute terminal state/readback or attempt closure before component-state CAS | Reject; branded verified proof and actual CAS readback required |
| Enter staged flow for unchanged application-only broker | Skip; existing no-op/full-profile/reference contracts remain covered |

Validation evidence:

- Focused staged broker suites: **94/94 pass**, including native saved-plan,
  native CAS and native refresh-only/normal-plan command tests.
- Existing Stage B/control-plane suite: **966/966 pass**.
- Additional closure, normal-deployment/state, workflow and OSV-policy suites:
  **283/283 pass**. Counts describe test executions, not distinct tests across suites.
- Capability/dependency closure: 60 phases, 729 capabilities, 160 unique actions;
  239 classified new AWS calls; no unmapped calls or missing runtime bindings.
- All 95 workflow YAML files parse. Production dependency audit and AWS DR static
  safety/contract checks pass. Fresh frontend compilation succeeds.
- Raw OSV still discovers the existing advisory. After separately authorized fresh
  reachability revalidation and exact hash rebinding, runtime enforcement passes
  with one visible time-bounded accepted finding. Acceptance scope, advisory/version,
  owner, broad boundary, expiry and enforcement are unchanged.
- Hostile self-review: **0 unresolved findings**. `git diff --check` passes.

No live permission, alias concurrency, Terraform backend reconciliation or
production readiness is claimed from these local checks. Future execution still
requires exact protected main, current live permissions/prerequisites, separate
publication authorization and then separate concrete-target cutover approval.

## Ordinary Terraform apply boundary

The ordinary Stage B production Terraform executor refuses Lambda function/alias
mutations. The authenticated saved-plan census is passed to the physical executor
and checked before spawning Terraform. Existing full-profile plan classification
remains usable for auditing and capture, without granting an unconditional alias
update path. Broker publication and alias cutover use their separately authorized
staged phases. Broker no-op and ordinary application deployments retain their paths.

## Terminal broker-policy successor adoption

When a later protected-main release must consume a policy successor whose
preparation was signed under an earlier source SHA, use
`prepare-policy-adoption` with the historical policy preparation,
authorization, result and the current release's registration prerequisite.
The command emits a `TERMINAL_POLICY_SUCCESSOR_ADOPTION` binding; it does not
rewrite historical artifacts or create mutation authority.

The adoption verifier rechecks the historical source tree and ancestry,
KMS authorization, policy intent and one-use reservation, terminal S3 receipt,
the exact DynamoDB transaction in `RELEASED`/`SUCCEEDED` state, live default
policy version/document, and the Terraform lineage/serial/state hash. It also
checks the historical registration chain used by policy preparation and the
current registered task-definition adoption. The adoption is bound to one
consumer source/tree and one Terraform state identity; later releases or state
changes require a new read-only adoption. Publication reauthenticates these
facts before accepting the chain, and its independent-checker signature binds
the resulting preparation. Same-source policy preparation remains unchanged.

This path is distinct from `recover-policy`: recovery terminalizes a held
transaction, while adoption consumes an already-terminal released successor.
Both paths remain read-only with respect to AWS resources during preparation;
adoption permits only `GetItem` for ownership verification in addition to the
existing adoption reads. It cannot create, delete or promote an IAM policy
version.

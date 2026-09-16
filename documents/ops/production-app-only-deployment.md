# Governed app-only ECS deployment — implementation status

Status: **implemented locally; not yet reviewed, merged or authorized for production**.

Working branch: `codex/governed-app-only-ecs-activation`.
Base: `fbc47fd83699403b8708f87d757e552d5bc02dd8`.
The deployment chain is wired but is not yet approved for release. Do not
treat passing local tests as deployment authorization. Bootstrap approval,
read-only preparation, verifier execution, application preparation, separate
permission provisioning and activation entrypoints now exist. Complete generated
contract registration and local integration checks exist. Clean-head closure,
exact-head CI/review and protected merge remain required before production use.

## Security boundary

The compatibility reader's exact secret-metadata allowlist is the deterministic
union of static backend task-definition references and protected Terraform's
`runtime_rotation_and_artifact_secret_arns`. These additional runtime secrets
receive metadata reads only—never `GetSecretValue`. The identity policy retains
all regional/read constraints; its outer managed boundary removes only duplicate
read-only conditions needed to stay within IAM's 6,144-character quota. RunTask,
PassRole, KMS alias, exact secret resources and all mutation constraints remain
unchanged.

ECS deployment IDs are opaque strings matching `ecs-svc/` followed by one or
more decimal digits, including leading zeros (for example,
`ecs-svc/0559890711032160707`). Capture, preparation, activation and rollback
preserve these bytes in evidence and compare them exactly for CAS/ownership.
Never parse them numerically, trim them, or remove leading zeros.

Three independent identities are required:

1. The compatibility verifier launcher may run only the exact reviewed ephemeral
   verifier task. Its task uses the existing dedicated read-only database
   credential. Neither identity may update the application service.
2. The IAM provisioner may provision only reviewed deployment permissions after
   protected production approval. It is not the application deployer.
3. The app deployer may register the image-only candidate and update the exact
   production service. It cannot run tasks, use ECS Exec, access database
   credentials, mutate IAM, or write Terraform state.

The implementation must not require clearing the ten stale Terraform IAM state
observations. Live runtime semantics, not Terraform state equality, determine
compatibility.

## Implemented locally

- Source-delta classification identifying domains requiring live proof; unknown
  executable paths remain unproven.
- Three-state non-application eligibility evaluation.
- Task-definition cloning permitting only the backend image digest change,
  shared AWS default normalization, separate tag binding, registration readback.
- Stable-service/task predecessor capture and exact pre-mutation CAS.
- Evidence identity, integrity and freshness checks. Content hashes explicitly
  do not substitute for workflow/artifact provenance authentication.
- Activation state machine with durable intents, candidate readback, readiness
  checks, exact-predecessor rollback, and concurrent-deployment rejection.
- Separate proposed app-deployer and verifier-launcher IAM policy builders.
- Fixed read-only catalogue collector using a single Prisma interactive
  transaction and `SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY`.
- Catalogue comparison for required function identity/body/security/grants,
  table columns/constraints/grants, policy definitions and forced RLS.
- Fixed ECS read/activation adapters and exact verifier RunTask/completion
  adapter, with bounded polling and fixed-origin HTTP reads. These remain
  internal until workflow authentication and principal provisioning are complete.
- Real PostgreSQL 18.4 catalogue regressions using the repository's tmpfs P2
  harness and Prisma interactive transactions. No remote database override or
  mock fallback is accepted by this integration test.
- Canonical requirements producer reusing full production-package certification
  in the isolated PostgreSQL harness, including the source-owned read-only
  canary provisioning contract. The source-only workflow has no AWS identity.
- Fixed verifier command tested over TLS against that complete local package,
  reusing the existing canary credential/environment validator. Detailed
  requirements remain in the artifact; the command binds ordered collection
  hashes and exact identity sets to stay within its explicit size budget.
- Exact GitHub run/artifact download with private materialization and bounded
  ZIP member reads. These internal consumers still need wiring into the live
  verification and activation workflows before deployment is possible.
- Verifier task construction reuses the source-managed read-only canary
  template. Before RunTask, full registered-definition readback must match the
  fixed command, immutable image, roles, secret reference, logging and platform.
  Completion binds the exact task and image; output comes only from that task's
  derived log stream, with bounded pagination and a single authenticated result.
- Backend runtime IAM expectations are evaluated from the reviewed Terraform
  policy expressions in a provider-free, backend-free local console. No live
  policy or Terraform state supplies its own expected value. The evaluator is
  deliberately restricted to the reviewed Stage-B source-wiring fingerprint;
  a changed wiring must be reviewed and tested before compatibility is claimed.
- Source/runtime requirements and the existing resource-consumability collector
  are connected internally, including exact-inline logging simulation rather
  than incorrectly requiring the legacy wildcard managed-policy grant.
- Image authentication consumes exact publication/authorization artifacts,
  preserves the signed report's original source and 24-hour expiry, verifies
  its signature with the repository-pinned public key, and independently derives
  current-source image reuse. No KMS signing or key-policy change is introduced.
- Separate permission provisioning now has exact predecessor/boundary readback,
  source-bound preparation, repeated approval/freshness checks before writes,
  durable write intents, and no automatic retry after an ambiguous IAM response.
  Its fixed effective-permission probes include allowed candidate/rollback paths
  and denied unrelated service/cluster/family, RunTask, Exec and state writes.
  The draft production entrypoint consumes an exact authenticated preparation
  artifact and a separately authenticated production review event.
- Provisioning preparations select exactly one phase: verifier-launcher or app
  deployer. The verifier phase cannot create/update the deployment role. The app
  phase binds fresh, authenticated deployment eligibility and all domain proofs;
  the production authentication callback must validate that producer artifact,
  not merely its content hash. Both phases retain a full two-role CAS census.
- Verifier execution records launch intent before RunTask and the returned task
  identity before polling. Approval/CAS is checked before launch and again after
  completion. Lost responses and timeouts leave recovery evidence; they never
  trigger an automatic second launch. Task success is not yet authenticated
  compatibility until the exact task output has also passed validation.
- Artifact consumers re-read both the run and artifact census after downloading
  and hashing exact bytes. Reruns, expiration, deletion and replacement invalidate
  consumption before private materialization.
- Verifier preparation binds the exact fixed task-definition content, command
  contract, private network, source-owned canary secret identity, requirements,
  candidate image and predecessor. It explicitly reports `eligible=false`:
  permission to collect live compatibility is never proof of compatibility.
- The verifier launcher reuses only the exact ECS observation statements needed
  for predecessor CAS. It gains no registration, service update or database
  credential access. Verifier registration belongs to the separate provisioner and requires
  an independent registered-definition readback before its revision can be used.
- The same compatibility identity performs source-derived IAM/runtime/image
  reads. Five exact non-database secret resources permit JSON selector inspection;
  other backend secrets permit metadata reads only. The app deployer receives
  none of these secret permissions. Evidence never includes secret values.
- Verifier preparation also independently censuses both existing canary roles.
  The task role must have no inline or attached permissions; the execution role
  must match the protected Terraform expression for the exact canary secret,
  repository and logs. Unexpected policies, trust, boundaries or changing role
  identities fail closed. Reusing network connectivity does not waive this check.

### Read-only preparation handoff

`prepare-production-app-only-verifier.yml` accepts `source_sha`,
`candidate_digest`, and three compact JSON artifact references:
`publication_reference`, `image_authorization_reference`, `requirements_reference`.
Each reference contains exactly `sourceSha`, `runId`, `runAttempt`, `artifactId`,
`artifactDigest`, and `fileSha256`. No task definition, SQL, role, network,
filesystem root or file-content input is accepted. The CLI validates these
before credential use, authenticates current protected main, downloads exact
upstream artifacts and performs fresh readbacks. Its private single-file output
is `production-app-only-verifier-preparation` / `app-only-verifier-preparation.json`.
The output binds verifier-role evidence but explicitly remains `eligible=false`.

Credential transport reuses the existing sanitized checker-session mode; the
entrypoint additionally requires exact GitHub OIDC workflow context and STS
verifier-role identity. Provisioning and deployment use their existing canonical
policy-reconciler and release-deployer session modes with their own exact role
checks. New transport labels are unnecessary: changing the shared credential
module would also change the clean-room RLS source contract and generated image
inputs without adding a security boundary. That shared source remains unchanged.

The focused preparation/workflow and credential-inventory checks cover this
handoff. Final workflow chaining, full generated-contract registration and the
complete clean-head deployment closure remain required before the first push.

### Verifier execution and bootstrap installation

`verify-production-app-only-compatibility.yml` first displays the authenticated
preparation identity without AWS credentials. Its protected production job
requires the actual review event, then uses separate provisioner and launcher
sessions. Registration is read back independently, launcher permission selects
only that revision, and the fixed private-network RunTask request has no overrides.
Registration handoff files are private and hash-authenticated within that same
run/attempt. Failure journals upload independently of success. A task's exit code
alone is not compatibility: its exact log stream and all required domain results
must authenticate before publishing `production-app-only-compatibility`.

Bootstrap is isolated from the production Stage-B backend. The new canonical
`run-production-app-only-bootstrap.mjs --mode prepare` validates protected main,
requires all four reserved IAM objects absent, and prepares only the six reviewed
creates in a consumer-owned private local Terraform root. It accepts an explicit
administrator profile for this installation, never for application activation.
The existing credential sanitizer strips ambient sessions and Terraform overrides.

`authorize-production-app-only-bootstrap.yml` accepts only six compact identities:
source SHA, preparation hash, saved-plan hash, plan-JSON hash, preparation timestamp,
and authenticated caller ARN. It reconstructs the source-owned scope and binds an
actual production approval; it has no AWS credentials or file-content inputs.
The local execution entrypoint authenticates the exact successful authorization
artifact, re-renders JSON from the same saved binary, enforces IAM absence again,
and applies only that plan. A host-local exclusive hash-derived claim prevents
copied-file replay on that host. This is not a distributed lease; operators must
not start the same installation on another host. Exact-name IAM absence checks
reject an existing or partial installation rather than automatically retrying it.

Preserve the printed private execution directory, its **local Terraform state**,
and journal after success or failure. These are installation recovery evidence,
not disposable test artifacts. No remote Stage-B state is read, written, imported,
or reconciled. Failed/ambiguous applies leave an intent and explicit recovery
status; successful apply without successful readback is not clean closure.
The plan validator also binds the complete embedded provider/resource expressions,
not just the six resource changes. Extra provisioners, modules, provider endpoints,
variables, outputs, pre-existing state and unreviewed Terraform versions fail
closed. Terraform 1.15.8's JSON expression/reference and provisioner representation
was checked with a disposable built-in-provider plan; that probe never applied
anything and did not contact AWS.

## Remaining preparation closure

`prepare-production-app-only-deployment.yml` reauthenticates the exact verifier
task output, then collects fresh image/IAM/runtime proof. Its final read-only
step switches to the separate provisioner to capture the exact IAM predecessor
and desired policy. One immutable `production-app-only-preparation` artifact
contains both the deployment and permission preparations. The original private
handoff is SHA-authenticated and never rewritten.

`provision-production-app-only-deployer.yml` displays that concrete subject before
its production approval, then installs only the approved permission phase and
publishes readback/simulation evidence. `deploy-production-app-only.yml` requires
both exact artifact references and a separate production approval. It assumes
only the app deployer, repeats source/authentication/ECS CAS before registration
and activation, and retains failure journals independently of its success
artifact. Rollback is bounded to the authenticated predecessor and owned failed
deployment; ambiguous outcomes are not automatically retried.

Preparation freshness remains 15 minutes, including time spent awaiting approval.
An expired subject is not extended or silently regenerated by a mutation workflow.
These workflows are under development and have not been dispatched.

- Preparation closure now binds fresh image, IAM, runtime, database, requirements,
  source-impact and ECS predecessor identities. It requires positive live proof
  for every non-application domain; retained release environment metadata never
  substitutes for image provenance or waives live checks. Production artifact
  producer/consumer wiring remains required before this function is executable.

The collector accepts no SQL input and invokes no application/security-definer
functions. It checks that the database session has the expected non-inheriting,
non-superuser role, no role memberships, no table/column/schema/database write
privileges, and read-only defaults. Failed or missing proof must block activation.

## Confirmed read-only observations

The existing canary task was observed at revision 7, with a dedicated read-only
database secret reference, read-only root filesystem and fixed Node entrypoint.
Its task role currently has no attached or inline IAM policies. The live backend
remains candidate revision 14, desired/running/pending 2/2/0, on private subnets
with public IP assignment disabled. These observations are discovery evidence,
not a fresh deployment authorization or full compatibility result.

The source-owned canary DB provisioning contract enables
`default_transaction_read_only=on` and restricts the identity. The new collector
must verify the actual live attributes; source declarations alone are not proof.

The latest read-only diagnostic compared both backend runtime roles twice
against source-derived expectations: zero semantic differences, with no
unexpected inline/attached policies or permissions boundary. Diagnostic hash:
`0104eba7d92b8bf9edcb089a2f2a53e6533b93eb097de37aaa55e91f3e037a01`.
This is limited to backend runtime roles, not all account IAM, and must be
regenerated for the post-merge deployment. No state readback equality was used.

## IAM semantics and local simulation

AWS documents service resource scoping plus `ecs:cluster` and
`ecs:task-definition` conditions for UpdateService, and task-definition resource
scoping for RegisterTaskDefinition. The proposed app policy uses the exact
production service/cluster and candidate family, not a hard-coded revision.

Family-level IAM permission does not authorize arbitrary revisions in the
application contract: activation is bound to the registered/read-back candidate,
and rollback only to the captured predecessor. Registration with preserved tags
requires TagResource authorization constrained to
`ecs:CreateAction=RegisterTaskDefinition`; no separate tagging API is exposed.

`DescribeTaskDefinition` has no resource-level authorization in the
[AWS ECS service authorization reference](https://docs.aws.amazon.com/it_it/service-authorization/latest/reference/list_amazonelasticcontainerservice.html).
Its read-only grant therefore uses `Resource: "*"` with the production region,
not a family ARN that would deny readback. Exact family/revision selection remains
mandatory in the adapters. This exception does not widen registration, service
updates, task launch or PassRole. Fargate task listing uses the exact cluster
condition; it has no container-instance ARN to authorize.

Read-only AWS SimulateCustomPolicy results for the proposed app policy:

| Case | Observed result |
| --- | --- |
| New candidate-family revision | allowed |
| Recorded predecessor family/revision | allowed |
| Other service | implicitDeny |
| Other cluster | implicitDeny |
| Other task family | implicitDeny |
| App principal RunTask | implicitDeny |
| App principal ExecuteCommand | implicitDeny |
| Exact task role / execution role PassRole | allowed |
| Other role PassRole | implicitDeny |
| PassRole to non-ECS service | implicitDeny |

This simulates the proposed policy; it does not prove the policy is installed,
or account for effective SCPs, boundaries and other policies on a live principal.
Post-provision effective readback/simulation is still required.

The provisioner cannot install, version or remove the outer permissions
boundaries. A separately approved bootstrap must install the exact source-owned
boundaries first. Role creation requires the corresponding boundary, existing
trust cannot be edited, and policy replacement accepts only an already-reviewed
predecessor policy. The verifier's identity policy selects one exact revision;
its reusable outer boundary caps future revisions to the verifier family.
Provisioning must not silently repair an unexpected trust, policy or boundary.

The isolated bootstrap source creates six IAM resources: two outer boundaries,
the provisioner role/policy, and the verifier role with its initial read-only
policy. This resolves initial preparation without granting RunTask or creating
an app-deployer role. After authenticated verifier task registration, the
provisioner may replace only that exact initial read policy with the reviewed
single-revision launcher policy. The deployment role remains a later, separate
eligibility-bound provisioning phase. Bootstrap still needs its executable
protected-approval binding before any installation is permitted.

The verifier managed boundary omits non-semantic Sid labels to remain within
IAM's 6144-character managed-policy quota; all actions, resources and conditions
remain intact. Tests enforce both managed and inline policy size limits. RDS
reads use exact database/parameter-group ARNs; storage-key readback uses the
source-owned alias condition, never a KMS mutation or Decrypt permission.

- [RDS action/resource support](https://docs.aws.amazon.com/it_it/service-authorization/latest/reference/list_amazonrds.html)
- [KMS resource-alias conditions](https://docs.aws.amazon.com/kms/latest/developerguide/conditions-kms.html#conditions-kms-resource-aliases)

References:

- [AWS ECS authorization reference](https://docs.aws.amazon.com/it_it/service-authorization/latest/reference/list_amazonelasticcontainerservice.html)
- [AWS PassRole constraints](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html)

## Remaining closure — required before PR/push

The producer, verifier, collectors, isolated provisioning and activation workflows
are wired locally. Artifact inventory now has 126 entries; the capability graph
has 56 phases and 652 nodes, with separate app-only identities and executor
classification. Dependency closure explicitly maps the new direct calls without
changing the historical unknown-call baseline fingerprint.

Still required: final clean-head validation and exact-head PR review. Composed
preparation/approval checks, real PostgreSQL, native Terraform mock-provider
planning and the affected local contract suites have passed. Passing generated
inventory checks is not evidence of live IAM/DB compatibility. Do not dispatch
these draft workflows or accept caller-authored compatibility claims.

## Validation so far

The hostile review added predecessor-image viability checks: the app adapter
reuses the existing exact-digest ECR validator for both images before activation
and for the selected target before update/rollback. Its new permission is only
`ecr:DescribeImages` on `mscqr-backend`, not publication authority.

Candidate image source must also match the reviewed session-risk implementation
hash `13fd24e7427f4e2cb91b6629d5b34a485ae22c8902133442c471fa8270a7c8c9`.
That implementation accepts only positive parsed thresholds and falls back to
85 for unset/empty input. A future change to this security implementation requires
reviewing this pin; task release metadata or a health response cannot substitute
for authenticated image-source proof. No login is performed by this lane.

Terraform 1.15.8 native `mock_provider` planning was also run against the actual
six-resource source and installed AWS 6.64.0 schema without AWS credentials or
apply. Its real planned resource representation passed the create-scope validator.
This verifies provider-schema planning, not live IAM authorization or mutation.

- Focused app-only tests including real PostgreSQL: 208 passed after workflow
  integration. Full integrated closure is still pending; these are local results,
  not live proof.
- Changed-file ESLint: passed.
- Provider maintenance must run `terraform providers lock -platform=linux_amd64
  -platform=darwin_arm64` in the isolated permission root. Linux CI exposed the
  missing Linux package hash; HashiCorp-signed lock generation and a regression
  now bind both reviewed platform packages without weakening readonly init.
- Final handoff regression rejects rehashed cross-phase, source, verifier and
  eligibility substitutions. CI lint includes all app-only CLI entrypoints.
- The secret guard permits exact source-derived IAM resource identifiers only
  in the two canonical generated capability inventories. It still rejects
  substituted identifiers, credentials and those identifiers in arbitrary files;
  regression tests cover both boundaries. Runtime fixtures use synthetic VPC IDs.
- Stage-B control-plane: 747 tests passed; full production RLS package passed
  against disposable PostgreSQL 18.4 with no skipped test.
- Canonical `npm run rls:full-verify`: passed (16 tests; 27 checksums).
- Proposed-policy AWS simulation: the eleven cases above passed.
- No live database verification or production mutation performed.

### Pre-push hostile review findings addressed

### PR #524 current-head review corrections

- Enum compatibility now binds ordered `pg_enum` labels for scalar and array
  columns, not only the PostgreSQL type name. A real PostgreSQL label substitution
  with an unchanged type name must reject compatibility.
- ECS CAS hashes every service field except enumerated observations and identities
  bound separately. Newly introduced mutable fields are retained automatically;
  service-connect, managed tags, grace periods and unknown settings cannot evade
  deployment or rollback ownership checks.
- Role trusts require exact role-specific reusable `job_workflow_ref` claims,
  immutable repository/owner IDs and `refs/heads/main` in addition to the protected
  production subject. Dispatch wrappers retain concurrency; reusable implementations
  retain actual production approval. Unrelated production workflows cannot assume
  these roles directly, and the deploy implementation is trusted by neither the
  verifier nor provisioner role. The two preparation/verification implementations
  intentionally use separate verifier/provisioner sessions for their fixed phases;
  neither is trusted by the app deployer. No generic execution input is provided.
  This uses the current AWS-documented GitHub claim support, not a repository-wide
  subject customization or an unsupported `workflow_ref` condition. See
  [AWS IAM OIDC condition keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html)
  and [GitHub reusable-workflow OIDC](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-with-reusable-workflows).

- Corrected AWS task-definition read scope; no unsupported resource restriction.
- Bound private handoffs, actual approval events and semantic preparation closure;
  altered eligibility flags or rehashed candidate/report substitutions fail.
- Preserved exact source/current ECS checks before registration and activation,
  and required real `ecs-svc/<numeric-id>` identities. Missing IDs cannot compare
  equal merely because task `startedBy` is also absent.
- Added exact predecessor/candidate ECR availability checks without publication
  authority. Rollback still requires ownership and the recorded predecessor.
- Bound the session-risk source fix separately from retained release metadata.
- Registered exact app-only source/action/principal tuples, keeping the previous
  unknown-call baseline unchanged; the app deployer has no RunTask, Exec, secret,
  IAM-write or state-write authority.
- Registered only the disposable Docker PostgreSQL test's database cleanup in
  the existing DR safety inventory. Its fixed tmpfs/container/loopback and initial
  absence checks remain mandatory; no production SQL exception was added.

Limits: ECS has no atomic expected-task-definition parameter on UpdateService.
The contract combines the repository's shared `production-deploy` concurrency
group with immediate readback/CAS and rollback ownership checks. It does not
claim an atomic lock against unrelated out-of-band administrators. Do not run a
manual concurrent deployment. Private runner files protect against other users,
not a compromised same-user protected runner; protected-source integrity and
GitHub environment approval remain required trust boundaries.

Local environment: approximately 1.7 GiB free; Docker's socket reported
`Docker Desktop is unable to start`. An unresponsive read-only Docker listing was
terminated. No Docker data, user files, worktrees or production evidence were
deleted. Existing dependencies from an identical-lockfile worktree are linked
locally to avoid another large installation; no files in that dependency tree were
modified by this task.

### Resumption and real-server validation

The old disk/Docker condition below is historical and resolved. On resumption,
all historical `/private/tmp` worktree paths, including the protected active
checkout and dependency supplier, were unexpectedly absent; retained Git
metadata marked them prunable. No pruning was performed. The same active
checkout was restored from its retained index and the eleven original files
were recovered by replaying the exact patches in the existing Codex session
log, including subsequent fixes. All original 102 tests passed after recovery.
Dependencies were installed from the unchanged lockfiles; no branch was created.

`npm run test:p2:db:up` started the canonical isolated PostgreSQL 18.4 harness.
The new test verifies container/project identity, loopback port and tmpfs before
creating any local fixture. Its temporary database and role are removed after
testing. It proved repeatable-read/read-only transaction behavior, actual
catalogue syntax, defaults/generated/identity columns, ACLs, policy expressions,
forced RLS, and rejection of writable/inheriting/member/owning verifier roles.
The first run corrected a fixture assumption: PostgreSQL 18 records NOT NULL
constraints in `pg_constraint`; these are now explicitly asserted, not ignored.

Integration review also replaced an incorrect string-valued readiness
assumption with the existing canonical readiness validator. Runtime health
metadata and immutable image provenance are authenticated independently.
No production verifier, IAM provisioning or ECS activation has run.

### Image source versus runtime release metadata

Read-only task-definition observation confirmed revision 14 explicitly sets
`RELEASE_GIT_SHA` and `GIT_SHA` to
`7e93853e6c48ad3020915f551ef89155825ae403`. An image-only deployment must preserve
those environment values. The readiness check therefore derives expected
metadata using the backend's actual environment precedence, while running-task
digest and publication evidence independently prove the deployed image source.
It must neither reject a healthy image-only deployment merely because unchanged
runtime metadata names the predecessor nor treat that metadata as image proof.
Secret-backed, duplicate or externally supplied release metadata fails closed.
The deployment evidence records both identities explicitly.

Several live secret references use a JSON scalar envelope in the same
source-owned secret resource. The runtime checker preserves these selectors;
it accepts only the source selector, or the reviewed scalar `value`/environment
name selector where source expects a scalar. It does not claim key availability
from a matching ARN: the canonical resource reader must verify the exact key
and current version before full compatibility is established. Secret values
are never included in evidence, and this reader is not the app deployer.

### Runtime network/database readback

The read-only runtime adapter now checks the two source-owned private subnets,
VPC/account identity, private NAT route resolution, exact database security-group
ingress from the observed runtime group and source-owned verifier group, RDS
identity/version/private/encrypted/Multi-AZ state, pending changes, enforced TLS,
and storage-key identity/state. Collection repeats around dependency observation;
a changing configuration cannot authorize deployment. The Stage-A source mapping
is fingerprint-gated: unreviewed infrastructure source changes fail closed.

The current read-only diagnostic passed for PostgreSQL 18.4 and two private
subnets; database configuration hash:
`aeb226c26f17eceb7eed19d521d4257b834f3dc2f71a8b717082358cdc428872`.
This is not a live SQL compatibility result or deployment authorization.
RDS materializes `rds.force_ssl=1` with `Source=system`; the adapter checks the
effective value, not merely `Source=user` overrides. Missing, disabled or pending
TLS configuration remains a failure. No production configuration was changed.

The subsequent complete runtime capability diagnostic **did not pass**. All 32
non-logging base dependencies simulated as allowed; `logs:CreateLogStream` and
`logs:PutLogEvents` returned `implicitDeny` for the exact log-stream namespace.
The live execution-role policy contains the reviewed exact allow statement.
Both a concrete existing stream ARN and a future stream ARN reproduced the
result. Even an unattached all-allow diagnostic policy returned implicit deny
on the concrete stream, while an all-allow `Resource=*` simulation succeeded.
None of these diagnostic policies was installed.

The isolated cause was simulator action-name casing: the same principal, policy
and existing stream returned **allowed** for `logs:createlogstream` and
`logs:putlogevents`, with the exact inline policy reported as the match. The
shared simulator adapter now lowercases action inputs and compares returned
action names case-insensitively, preserving exact resource and denial checks.
IAM actions are case-insensitive; this changes neither policy scope nor live
permissions. Regression coverage retains KMS context and all resource checks.
The complete fresh runtime collection must still pass; the individual diagnostic
alone is not deployment authorization. No wildcard policy was installed.

After action-name normalization, the complete read-only collection passed all
34 runtime dependencies, repeated network/database configuration comparison and
the ECS predecessor CAS. Diagnostic evidence hash:
`c30d3da332c24c1a8412a3c437bd349cf469ea3ef833c40946f5cf0cc4b643f0`.
This resolves the simulator discrepancy without changing IAM. It remains a local
diagnostic, not a protected workflow artifact or fresh post-merge authorization.

- [AWS simulator limitations](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html)
- [CloudWatch Logs resource scoping](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/iam-identity-based-access-control-cwl.html)
- [IAM action names are case-insensitive](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html)

### Canonical package and verifier integration

The complete generated production RLS package has now been installed and
verified on the disposable PostgreSQL 18.4 server. The restricted verifier
successfully collected its catalogue and ran the fixed task command over TLS.
No production database was contacted. Local fixture provisioning temporarily
grants the canonical function owner schema CREATE, then revokes it before
observation; it does not authorize any corresponding production change.

The collector now binds managed database-role attributes and both directions
of role membership, including PostgreSQL's ADMIN/INHERIT/SET options. Matching
table policies alone cannot establish isolation when a runtime role gains
BYPASSRLS or inherited authority. Both attacks are real-server regressions.

Run the existing local harness and enable TLS with:

```sh
npm run test:p2:db:up
node scripts/p2-test-db-tls.mjs
node --test scripts/tests/production-app-only-*.test.mjs
MSCQR_PRODUCTION_PACKAGE_POSTGRES18_TEST=true \
MSCQR_PRODUCTION_PACKAGE_POSTGRES18_ADMIN_URL=postgresql://mscqr_p2_test@127.0.0.1:55432/mscqr_p2_admin_test \
node --test scripts/tests/production-full-rls-package-postgres18.test.mjs
```

The PostgreSQL client (`psql`) must be on PATH. TLS setup accepts no inputs,
checks the exact compose container/port/tmpfs, creates a private one-day test
certificate inside that disposable container, and reloads PostgreSQL without
restarting Docker. It neither deletes storage nor accesses production.

The app-only Quality Gate job runs the focused real-server suite, full disposable
production-package certification, then static RLS verification **sequentially**.
The production-package fixture temporarily regenerates SQL and restores it in
`finally`; concurrent static checks can observe that temporary fixture. A local
parallel invocation reproduced this race; the sequential rerun passed. Do not
remove either gate or weaken its assertions. The job has no AWS credentials or
production environment and also checks generated permission source, locked
backend-free Terraform validation, ESLint and source restoration.

The source-only requirements workflow uses compact source identities and emits
one private `app-only-requirements.json`. This artifact is not live compatibility
proof or deployment approval. Cross-run consumers verify the workflow, source,
run attempt, immutable artifact ID/digest, exact ZIP closure and file hash. They
read archive bytes without filesystem extraction, so link/traversal entries
cannot become filesystem authority.

### Local test-capability audit — 2026-09-16

Historical blocker below is resolved. Docker and the canonical disposable
PostgreSQL 18.4 harness are working; real catalogue and restricted-role tests
have passed. No further disk cleanup is part of this task.

Read-only disk census found 1.7 GiB available on the Data volume. Allocated
storage totals (not promises of reclaimable space): Docker Desktop 41.9 GiB,
`/private/tmp` 30.8 GiB, npm cache tree 0.77 GiB, and application caches
1.15 GiB. Most large temporary directories are registered historical MSCQR
worktrees, approximately 1.4–1.6 GiB each; their source, evidence and dependency
ownership have not been cleared for deletion. No deletion is authorized by
their age or size. Preserve this active worktree and
`/private/tmp/mscqr-stage-b-reconcile.sPVBQU`, which supplies dependencies.

No substantial disposable directory created by the current task was identified.
Recommend at least 8 GiB free before full closure, preferably 10 GiB. Cleanup
outside current-task disposable files requires explicit operator authorization;
do not prune Docker or remove historical worktrees automatically.

The installed Homebrew `libpq` 18.6 includes `psql`, `initdb`, and `pg_ctl`,
but not the `postgres` server executable. No PostgreSQL server process or
listener on the inspected local test ports was found. The repository's
disposable RLS harness can use a local test database without Docker, but does
not itself supply a PostgreSQL server. Therefore the installed client tools
are not yet a usable non-Docker test backend. After disk recovery, use an
isolated PostgreSQL 18 test server or restore Docker; do not connect the test
harness to production and do not replace the real regression with mocks.

## Deferred obligations

- Governed ten-record Terraform state reconciliation (historical expected count
  ten; not recomputed or executed here).
- Stage-B preparation transport fix: the historical 177592-character tfvars
  base64 scalar exceeds workflow-dispatch capacity.

## Operational recommendation

Keep one source-bound evidence chain and one deployment transaction per approval.
Complete real PostgreSQL and AWS adapter tests before exposing the lane. Additional
features and unrelated release refactors should wait until this boundary is proven.

### Image-impact audit

The new permission root was initially unknown to the bounded image classifier.
The canonical publisher and backend Dockerfile do not copy its source or lockfile
into any of the four image targets. Classification now registers exactly
`production-app-only-permissions/main.tf.json` and `.terraform.lock.hcl` as
infrastructure-only; adjacent scripts, Dockerfiles and unknown roots still fail
closed. Existing path classifications and the historical image-reuse report
format remain unchanged. No image publication or signature was performed.
Full current-source reuse authentication remains mandatory after merge; this
local path audit does not extend signed evidence freshness or retention.

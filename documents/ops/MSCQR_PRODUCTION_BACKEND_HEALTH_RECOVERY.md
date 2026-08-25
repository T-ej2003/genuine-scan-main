# Production backend health recovery

This mode exists only to restore `mscqr-backend-servi-euw2` when its exact
currently deployed immutable `mscqr-backend` digest has disappeared from ECR
and the resulting image-pull failure prevents the mandatory production
dual-slot rotation.

## Security boundary

The `backend-health-recovery` release-gate mode requires:

- a full protected-main source SHA;
- the exact current `mscqr-backend:<revision>` ARN;
- canonical signed image authorization for the replacement digest;
- ECR readback proving the current digest is absent and the replacement exists
  in the immutable `mscqr-backend` repository;
- stopped-task or service-event evidence identifying a missing-digest
  `CannotPullContainerError`;
- descriptive human metadata bound to the source SHA, current task-definition
  ARN, and replacement digest; and
- the protected GitHub `production` environment, with at least one required
  reviewer and administrator bypass disabled.

GitHub's protected-environment gate is the approval authority. The workflow
authenticates its live reviewer principals and self-review policy through the
GitHub API and binds the resulting private, source/run-specific evidence into
recovery authorization before configuring AWS credentials. `approvedBy` must
name one of those configured principals, but it is audit metadata rather than
standalone proof of identity. When GitHub has `Prevent self-review` enabled it
must differ from the dispatcher; when disabled, GitHub may accept the configured
solo operator as both dispatcher and reviewer. `approverRole` remains descriptive
audit metadata.

The workflow creates a dedicated operator-owned `0700` directory below
`RUNNER_TEMP`; the shared artifact contract atomically publishes the approval
evidence there as mode `0600` without changing the runner temp directory or
dirtying the checkout.

Release Gate also directs disposable PostgreSQL certification evidence to
`RUNNER_TEMP`. Local certification keeps its reviewed repository evidence path,
but production preflight must not rewrite tracked generated evidence before the
recovery CLI authenticates the clean protected-main checkout.

Before dispatch, the canonical administrator capability preflight and the
release-deployer direct-read preflight must report
`backend-health-recovery-describe-images`,
`backend-health-recovery-describe-repositories`,
`backend-health-recovery-register-legacy-task-definition`, and
`backend-health-recovery-update-service` as allowed. Both ECR reads are limited
to `arn:aws:ecr:eu-west-2:368992683803:repository/mscqr-backend`; a failed direct
read stops before the GitHub production approval is requested. Registration is
limited to the legacy `mscqr-backend:*` family with the
reviewed Fargate, non-privileged, 2048 CPU, and 4096 MiB shape. The service
update is limited to the exact production backend service and
cluster and a legacy
`mscqr-backend:*` revision. The application contract still binds the exact
current revision, replacement digest, candidate diff, and human approval.

The candidate task definition is derived from the current AWS readback. Its
named delta profile permits only the backend image,
`GIT_SHA`/`RELEASE_GIT_SHA`, and the four mandatory artifact-signing ECS secret
references. Both identity fields equal the image authorization's authenticated
release SHA. The four references are resolved read-only from the exact
source-controlled production names, written to the canonical source-bound
private runtime-binding file, and authenticated again immediately before task
registration. Recovery reads and validates the key pair, active version, and
public-key registry in process but never writes or emits their values. The
private key and all three companion values remain ECS `valueFrom` references;
none may appear in task-definition environment values, workflow inputs, logs,
authorization, or recovery evidence. Roles, existing secrets, database
bindings, networking, ports, command, health check, logging, resources, and
every other runtime field remain byte-semantically equal.

An execute invocation writes durable `PENDING` signing-verification evidence
before its first live signing lookup. Authenticated resolution advances that
state to `VERIFIED`; STS, reference-discovery, secret-value, or domain
validation failures persist only a fixed `FAILED` classification. Provider
errors and secret material are never copied into recovery evidence or recovery
CLI errors.

Because recovery preserves the legacy execution role, the final candidate is
now the authority for runtime dependency closure. Before registration, the
governed administrator path derives every dependency from container images,
`secrets`, log `secretOptions`, repository credentials, S3 environment files,
log configuration, and IAM-enabled EFS volumes. Each dependency is bound to
the ECS execution role or application task role that actually consumes it,
the exact AWS action and resource, source policy ownership, the complete live
role-policy identity, and an exact-principal IAM simulation. The signed result
is rechecked against the same candidate, current resource metadata, current
role-policy identity, exact ECS-tasks trust, secret resource policies, and any customer-managed KMS
key policy immediately before registration and again before `UpdateService`.
Changing the candidate, execution role, secret reference, encryption key,
resource policy, role policy, or dependency set stops before the next ECS
mutation.

The administrator signature is durable transaction authorization, not a cache
of live AWS availability. Its 35-day maximum age matches GitHub's maximum
workflow-run lifetime, including environment approval, so queue and reviewer
latency cannot consume a 15-minute mutation-safety window. The signed source,
candidate fingerprint, roles, dependency set, resource-policy identities, and
live-policy identities remain immutable. KMS signs the binding that includes
the authorization timestamp, so its lifetime cannot be extended by rewriting
an unkeyed envelope checksum. After production approval, the
release-deployer independently refreshes those exact resources and policies;
that result has a separate 60-second maximum handoff to each ECS mutation.
The contract checks the fresh timestamp after the final census/evidence write
and immediately before `RegisterTaskDefinition` or `UpdateService`. The release
role can confirm the signed identities remain live but cannot redefine them.
GitHub documents a 35-day workflow-run ceiling (including waits and approvals)
and a 30-day environment-approval ceiling; those platform bounds, plus the
workflow's source-controlled 180-minute job timeout, are exercised by the
deterministic freshness tests rather than replaced by an arbitrary TTL.

- [GitHub Actions limits](https://docs.github.com/en/actions/reference/limits)
- [GitHub deployment approvals](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/control-deployments)

The adjacent signed-evidence freshness audit found no second conflated
recovery lifetime. GitHub environment evidence is run-bound and generated
after the environment gate. Stage-B permission, reference-audit, and partial-
apply evidence is live-plan-bound and regenerated in its governed apply chain.
Image evidence retains its separate 24-hour revocation/verification model;
recovery also rechecks the exact digest in ECR. Root-drop and Stage-A recovery
evidence are operation-local, not pre-dispatch runtime authorization. Their
short lifetimes continue to protect the live operation they describe.

Secrets with no resource policy are supported. A non-empty Secrets Manager
resource policy fails closed until its full condition and principal semantics
are represented by the canonical evaluator; it is never reduced to a
substring or partial-deny heuristic. Customer-managed KMS key policies permit
only an unconditional exact-role grant or unconditional account-IAM
delegation, reject deny/inverse semantics, and still require exact IAM
simulation. S3 environment files derive both `s3:GetObject` and
`s3:GetBucketLocation`; because no current source-owned production execution
policy owns those actions, introducing one fails CI/preflight instead of
silently becoming a runnable dependency.

Runtime secret proof resolves the complete ECS `valueFrom` selector, not just
the base secret ARN. Metadata binds the canonical `VersionIdsToStages` map, the
complete paginated version census (including unlabeled/deprecated versions), and
the exact resolved version for default `AWSCURRENT`, explicit version stage,
explicit version ID, or a consistent stage-and-ID pair. Missing, duplicated,
malformed, deleted, or changed version metadata fails closed without reading
`SecretString` or `SecretBinary`. The same metadata is reread at both runtime
consumability mutation boundaries, so rotation or deletion cannot hide behind
an older signed resource identity.

The legacy execution-role correction is generated from the final candidate.
It grants `secretsmanager:GetSecretValue` only for the candidate's exact secret
ARNs, `logs:CreateLogGroup` only where the candidate explicitly requests it,
and `kms:Decrypt` only for exact customer-managed keys with an exact
`kms:ViaService` condition. `Resource="*"`, caller-supplied additions, task-role
substitution, release-deployer substitution, and administrator substitution
are rejected. The convergence command defaults to plan-only and requires a
separate source-, candidate-, and exact live-to-source policy-transition human
authorization before its sole `iam:PutRolePolicy` operation. IAM policy hashes
use decoded, canonical JSON semantics rather than transport bytes. Immediately
before the write, the executor performs a final `GetRolePolicy` and requires
its hash to equal the approval-bound expected-live hash; the next network call
is `PutRolePolicy`. A mismatch is `LIVE_POLICY_CHANGED_SINCE_APPROVAL` with zero
IAM writes. The post-write `GetRolePolicy` must equal the protected-source hash
and policy semantics, while attachments and trust must read back unchanged.
`PutRolePolicy` has no response body on success; the executor treats only empty
successful stdout as bodyless success, still rejects malformed non-empty JSON,
and then reaches the authenticated post-write readback.
This is application-level optimistic concurrency because IAM has no conditional
`PutRolePolicy`; the final read/write pair minimizes but cannot eliminate that
service-side race window.

Production incident `mscqr-backend:49` is the regression fixture for this
boundary. Its six tasks failed before container start because
`mscqr-ecs-execution-role` lacked `secretsmanager:GetSecretValue` for the newly
materialized artifact-signing private-key reference. A terminal failed
recovery revision may be reconciled only when operator-bound evidence names
the exact workflow, service, source, digest, evidence hash, task-definition
fingerprint, and terminal status. It remains visible in evidence, can never be
selected as the corrected candidate, and does not weaken rejection of any
other newer revision. Its image may still exist; that path is eligible only
when the exact historical evidence authenticates the service's current
revision and the current service has both zero running and zero pending tasks.
A healthy or progressing revision remains ineligible. Revision census and
runtime-consumability checks are both repeated at the pre-registration and
pre-update TOCTOU boundaries.

Runtime closure is a four-phase transaction with two distinct candidate
hashes. `candidateFileSha256` is the SHA-256 of the exact persisted,
pretty-printed bytes, including the trailing newline, and protects every file
handoff. `candidateCanonicalSha256` is the canonical semantic JSON identity;
`candidateFingerprint` is the task-definition fingerprint used by ECS revision
reconciliation. These names are not interchangeable.

1. `prepare-production-backend-recovery-candidate.mjs` writes the candidate and
   reports all three identities.
2. `prepare-production-ecs-runtime-consumability.mjs --mode inventory` performs
   read-only candidate-derived resource discovery and signs a deterministic
   inventory. It deliberately does not require IAM simulation to pass, so a
   missing execution-role permission is convergence-plan data rather than a
   circular prerequisite.
3. `converge-production-ecs-runtime-policy.mjs` verifies the signed inventory,
   plans the exact source policy, and requires operator authorization binding
   source SHA, candidate identities, inventory SHA, expected live-policy SHA,
   and desired source-policy SHA. Its final `GetRolePolicy` immediately
   precedes the single application-level compare-and-swap `PutRolePolicy`.
4. `prepare-production-ecs-runtime-consumability.mjs --mode consumability`
   reauthenticates the inventory, recollects resource metadata, re-reads live
   role policies, and requires every candidate-derived simulation to pass
   before emitting the signed artifact transportable to Release Gate.

The post-convergence artifact remains durable across legitimate workflow queue
and production-environment approval latency. Release Gate independently
refreshes secret deletion state, KMS state and policy, ECR repository-policy
state, live IAM policy identity, and candidate dependency closure immediately
before registration and again before `UpdateService`; the short live-verification
age never starts before long build, certification, queue, or reviewer waits.

Release Gate transports image authorization, operator approval, signed runtime
consumability evidence, and known-failed-revision evidence in one canonical
transaction-bound dispatch bundle plus its byte hash. The repository extractor
authenticates the outer transaction, every embedded canonical JSON value, and
every component hash before producing private runner files. This keeps the
workflow below GitHub's 25-input limit without dropping an authorization edge.

Runtime image closure authenticates the exact candidate ECR repository-policy
state and immutable image-digest availability in addition to execution-role
identity simulation. Account, repository, and digest come from the selected
`DescribeImages.imageDetails[]` entry, matching the AWS CLI response contract.
`RepositoryPolicyNotFoundException`
is the only accepted no-policy result; read errors, malformed responses, and
any repository policy semantics fail closed. Secret metadata is likewise bound
to an explicit available/not-scheduled-for-deletion state. Repository policy
and secret availability metadata are refreshed before registration and again
before `UpdateService`.

The same candidate parser is mandatory for normal Stage-B backend/worker/
executor/canary definitions, rotation overlap and cleanup definitions, and
pre-deployment inventory definitions. Terraform derives each Stage-B
execution-role secret resource set from the same rendered candidate secret
references, while direct legacy recovery additionally requires signed live
consumability evidence. Normal activation registers no task definition and
must activate only an already authenticated Stage-B candidate; rollback and
post-deploy paths retain their independent image-viability and runtime-health
checks. CI rejects an unknown production AWS call, workflow input, candidate
runtime reference type, consumer principal, source-policy owner, or production
mode dependency.

The IAM model follows the AWS ECS service-authorization reference: the
registration write stays scoped to the `mscqr-backend:*` task-definition
resource with the supported compute/privileged/CPU/memory conditions, while
`UpdateService` stays scoped to the exact backend service, cluster, and target
task-definition condition. Application-side candidate equality and exact
legacy-role `PassRole` boundaries remain mandatory because IAM is not the
task-definition semantic-diff engine.

- [Amazon ECS actions, resources, and condition keys](https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonelasticcontainerservice.html)
- [Amazon ECS identity-based policy examples](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/security_iam_id-based-policy-examples.html)
- [Amazon ECR actions, resources, and condition keys](https://docs.aws.amazon.com/service-authorization/latest/reference/list_ecr.html)

The mode registers at most one matching legacy revision, updates only the
backend service, reconciles ambiguous registration/update outcomes from live
ECS, waits for stability, verifies running digests, and verifies the canonical
`/api/health/ready` payload. Readiness requires `success=true`,
`status=ready`, and ready production database, Redis, and object-storage
dependencies. Recovery additionally requires the readiness release SHA to
equal the authenticated replacement image release SHA; HTTP 200 alone is never
recovery evidence.

The public production readiness URL is exactly
`https://www.mscqr.com/api/health/ready`. Frontend Nginx rewrites that path to
the backend's direct `/health/ready` route; the direct route is not itself a
public frontend path. Normal release smoke and governed backend recovery reject
other origins and redirects, then parse the canonical response's JSON readiness
payload rather than accepting frontend reachability.

The private, atomic recovery evidence is written before AWS discovery and
updated immediately before and after each ECS mutation. Its source,
environment approval, authorization bytes, current task definition, and target
digest bindings survive registration, service-update, waiter, running-digest,
or readiness failure. The workflow uploads this evidence on success or failure
when present. A retry reconciles the live revision census and service before
registering or updating, so a failed run cannot create duplicate recovery
revisions blindly. The mode never deploys frontend/worker workloads, applies
Stage B, or satisfies/bypasses rotation freshness.

Revision-census reconciliation is a global recovery concurrency boundary, not
a rollback-only check. Every recovery authenticates an initial census, requires
the same semantic identities immediately before registration, and then permits
only the exact target ARN and candidate fingerprint registered by that
transaction to appear before `UpdateService`. Reordering identical census
entries is harmless; any other added, removed, duplicated, malformed, or
changed revision fails closed independently of service-state concurrency.

Accumulated recovery history is reconciled as an ordered, monotonic lineage.
The first signed record must have no predecessor-history reference; every later
record must bind a prior immutable-history reference, its initial census must
equal the lineage produced by the preceding authenticated generation, and a
confirmed registration may add only its exact task-definition ARN and semantic
fingerprint. A historical record is never compared directly with the final
census: later authenticated generations may extend it. Missing, reordered,
forked, duplicated, conflicting, or skipped generations and any live revision
without exactly one lineage provenance fail closed. The final lineage may have
only the current transaction's one exact candidate extension.

Schema 7 evidence also commits each generation to the canonical hash of every
preceding authenticated history record. Once present, this rolling binding
cannot be omitted by a later record, so histories cannot be reordered,
truncated, duplicated, or forked even when two generations observed the same
ECS revision census.

A later authenticated generation closes live reconciliation for every earlier
interruption in its predecessor lineage. Only an interrupted final generation
is compared with current ECS service/task health; older interrupted candidates
remain fingerprint-checked lineage entries but cannot authorize supersession.

Before registration, the initially observed service must identify the approved
legacy source revision unless it already identifies the single exact recovery
revision authenticated by the candidate fingerprint. The service is read again
immediately before `UpdateService`, so a later concurrent change still fails
closed without an update.

A failed historical recovery revision without the four bindings is not a
matching candidate and is never reused. During an authenticated stalled
rollback, the live rollback proof separately binds the failed forward task
definition ARN and its semantic task-definition fingerprint. That exact
revision may remain in the ACTIVE revision census without blocking a corrected
registration even when its image or source SHA predates the current recovery.
It remains audit evidence, never a candidate. A missing or changed failed
revision or any additional newer revision fails closed. Rollback viability
reads remain conditional on rollback recovery, while census checks apply to
all recovery transactions.

Known failed revisions are not accepted as caller-authored summaries. Before
dispatch, `prepare-production-backend-failed-recovery-evidence.mjs`
authenticates the exact prior recovery-evidence, GitHub production-environment
evidence, and signed runtime-consumability bytes in one KMS-signed,
self-contained bundle. The producer verifies every component byte hash and the
chain from repository/workflow run through source, mode, service, recovery
digest, terminal failure status, target task definition, candidate fingerprint,
and the governed zero-or-one registration/update counts.

`publish-production-backend-failed-recovery-evidence.mjs` stores that bundle as
a content-addressed asset in an immutable GitHub release and emits a bounded
reference containing the exact repository, protected source, release and asset
IDs, asset digest, byte hash, and envelope hash. Only that reference is carried
in `workflow_dispatch`; the dispatcher measures the complete serialized input
map and rejects it above the protected 60,000-character budget (below GitHub's
65,535-character platform limit). The production job resolves the asset using
its existing `contents: read` permission, requires immutable release and asset
readback, verifies the exact bytes, then verifies the KMS-signed bundle before
any history can influence revision census. Immutable releases have no workflow
artifact-expiry dependency. Missing, mutable, unavailable, malformed,
substituted, duplicate, or conflicting history therefore fails before recovery
mutation eligibility.

The immutable bundle admits at most 32 records and 8 MiB. These limits apply to
the authenticated release asset, while workflow dispatch continues to carry
only the bounded content-addressed reference. Exceeding either limit requires
operator archival/reconciliation under a newly reviewed contract; it cannot be
silently truncated or converted back into caller-authored summaries.

Signed historical evidence distinguishes terminal failure from interrupted
mutation intent. Registration/update attempted or confirmed records are never
treated as failed revisions by themselves. A retry re-authenticates their
candidate fingerprint and initial/expected revision censuses, then resolves
the exact candidate against fresh ECS service, deployment, running-task,
stopped-task, digest, and readiness state. An old service may resume the exact
orphan candidate after an ambiguous update attempt; a healthy current candidate
is accepted as completed; a progressing candidate blocks supersession; and a
failed candidate requires at least two unique current-deployment startup
failures bound by `ecs-svc/<numeric-id>`, task definition, deployment timing,
and error reason. Any foreign service revision, changed census, historical task,
or ambiguous state fails closed. The same proof is re-read immediately before
registration and `UpdateService`, allowing only this transaction's exact new
registration at the latter boundary.

Publication is an idempotent remote transaction. Before each mutation the
publisher re-reads the deterministic tag and accepts only absence, the exact
mutable draft without an asset, the exact mutable draft with one downloaded and
byte-authenticated asset, or the exact immutable published release. It creates,
uploads, and publishes only the missing next state and performs authoritative
readback after every mutation. An already-valid immutable release is reused,
including after local reference persistence failed; the local bounded reference
is recreated without remote mutation. A wrong source, title, notes, tag, asset
name, asset count, size, digest, downloaded bytes, mutable published release, or
concurrent state transition fails closed. The publisher never deletes,
overwrites, retags, or replaces remote historical evidence.

Rollback reconciliation distinguishes
none, progressing, successful, failed, ambiguous, stalled with a recoverable
target, and stalled with an authenticated unrecoverable target. Elapsed time is
never authority. Supersession is permitted only for the final state, after two
bounded authenticated observations bind the exact service deployment, distinct
forward/source/rollback revisions, rollback task-definition ARN, immutable
digest, repeated exact rollback-target pull failures, and
canonical ECR `ImageNotFoundException` for that digest. Access denial, timeout,
or malformed ECR output is unknown and fails closed.

Stopped-task evidence exhausts the AWS CLI paginator using opaque continuation
tokens, deduplicates and canonically orders task ARNs, and describes every task
in batches of at most 100. Token cycles, malformed pages, later-page errors,
incomplete `DescribeTasks` batches, or the configured 1,000-task bound fail
closed; current rollback failures therefore cannot depend on page position.

Each pull failure counted toward supersession is authorization-bearing ECS
evidence. Its `Task.startedBy` must equal the exact `ecs-svc/<numeric-id>` from
the single authenticated `DescribeServices.deployments[]` entry for the
rollback task definition, as documented for service-started tasks. The newer
`serviceDeploymentArn` is a separate opaque identity and is never suffix-mapped
to `Task.startedBy`. The task-definition ARN and immutable digest must equal the
authenticated rollback revision, and the exact `CannotPullContainerError`
reason is hash-bound. Task creation and stop timestamps must be valid and may
not predate `rollback.startedAt`. Matching historical, malformed, duplicate, or
mixed-deployment attempts make the proof ambiguous. Unrelated stopped tasks are
ignored, while at least two distinct current-deployment task ARNs remain
mandatory. Bounded and pre-mutation rereads bind both deployment identities and
the complete attempt set, so any identity change between observations fails
closed.

ECS deployment identities remain distinct throughout that proof. The
deployment's `targetServiceRevision` is the attempted forward workload;
`sourceServiceRevisions` are independently resolved source workloads; and
`rollback.serviceRevisionArn` is the authoritative revision ECS deploys during
rollback. Rollback viability is derived only from the last field. All supplied
revision ARNs are resolved through `DescribeServiceRevisions`, their exact task
definitions and immutable backend digests are read independently, and their ECR
states are recorded without aliasing. A missing or malformed relationship, an
unknown ECR response, or equality between the failed forward revision and the
rollback revision is ambiguous and cannot authorize supersession. The failed
forward task definition is also prohibited from matching or becoming the
corrected recovery revision; recovery must register a distinct immutable
revision.

The operator approval and generated authorization bind that rollback deployment,
target ARN, and target digest. Immediately before registration and again before
`UpdateService`, the workflow rereads the same evidence; any independently
running task, changed deployment, target, count, or image viability stops before
mutation. A corrected recovery always registers a new immutable revision. A
failed historical revision is never modified or relabeled.

Every normal or rotation deployment through `deploy-ecs-service.sh` also reads
the currently running task definition and proves its exact immutable backend
digest still exists before replacing it. A task-definition record alone is not
a viable rollback path.

### Assumption graph and retention finding

The incident exposed three connected assumptions: the recovery eligibility
guard treated every `IN_PROGRESS` rollout as recoverable; the deployment wrapper
treated a stable task-definition ARN as sufficient rollback evidence; and ECR
lifecycle controls retain only untagged images by age and release images by
count. The first two are repaired here. The lifecycle policy in
`infra/aws/terraform/main.tf` and `scripts/aws/apply-ecr-repository-controls.sh`
does not protect digests referenced by active or rollback-candidate task
definitions. That separate retention defect requires a governed design because
ECR lifecycle policies cannot dynamically express ECS references; this repair
does not silently broaden retention or mutate AWS.

## Transitive production dependency closure

`npm run stage-b:dependency-closure:verify` is a permanent CI gate backed by
`MSCQRProductionDependencyClosure-v1.json`. It binds each AWS call introduced
by this repair to its release mode, release-deployer identity, exact source IAM
resources, generated manifest capability, administrator simulation, and live
read preflight. It also verifies the real ECS service-deployment then
service-revision response chain, the six unchanged workflow transport inputs,
the exact four artifact-signing bindings, rollback evidence producer/consumer
joins, and normal/rotation rollback-image checks. An unknown production AWS
operation or runtime dependency fails Stage-B deployment closure.

## Operator sequence

1. Run the canonical administrator/release capability preflight after the
   reviewed IAM policy versions are published. Require both exact ECR direct
   reads and both recovery mutation evaluations to pass before dispatch.
2. Produce exact JSON bytes for canonical image authorization and human
   approval. Record each file's SHA-256. The approval object must contain
   `ticket`, `approvedBy`, `approverRole`, `reason`, `verificationRef`,
   `sourceSha`, `currentTaskDefinitionArn`, and `recoveryImageDigest`. A stalled
   rollback supersession additionally requires the exact
   `rollbackDeploymentArn`, `rollbackTargetTaskDefinitionArn`, and
   `rollbackTargetDigest` from authenticated reconciliation.
3. If authenticated failed-recovery history exists, produce its KMS-signed
   bundle and publish it with
   `publish-production-backend-failed-recovery-evidence.mjs`; use the emitted
   immutable reference. With no history, use a private file containing exactly
   `null`. Bind both the evidence envelope SHA-256 and reference SHA-256 in the
   human approval when history exists.
4. Dispatch through `scripts/aws/dispatch-production-backend-health-recovery.mjs`.
   It serializes each JSON input once and derives the workflow value and SHA-256
   from those exact transport bytes; do not compose byte-sensitive inputs with
   shell command substitution. The dispatcher authenticates both canonical image
   paths: a fresh publication uses the protected source SHA, while `IMAGE_REUSE`
   retains its earlier authenticated `imageReleaseSha`; recovery writes that image
   release identity, not the newer tooling SHA, into `GIT_SHA` and `RELEASE_GIT_SHA`.
   It resolves the checked-out repository from its own script location, so private
   authorization and approval files remain outside the worktree from any caller cwd.

   ```bash
   node scripts/aws/dispatch-production-backend-health-recovery.mjs \
     --source-sha <protected-main-sha> \
     --current-task-definition <exact-legacy-task-definition-arn> \
     --recovery-image-digest sha256:<64-hex> \
     --service mscqr-backend-servi-euw2 \
     --release-mode BACKEND_HEALTH_RECOVERY_LEGACY_RUNTIME \
     --image-authorization /secure/operator/image-authorization.json \
     --approval /secure/operator/recovery-approval.json \
     --runtime-consumability /secure/operator/runtime-consumability.json \
     --failed-recovery-evidence-reference /secure/operator/failed-recovery-evidence-reference.json
   ```
5. Have an authorized reviewer approve the GitHub `production` environment
   deployment. Repository administrators must first configure that environment
   with required reviewers and administrator bypass disabled. Configure
   `Prevent self-review` to match the repository's actual multi-operator or
   solo-operator governance model.
6. Retain the uploaded `backend-health-recovery-evidence` artifact.
7. After backend health is proven, resume the canonical dual-slot rotation.
   This recovery does not create or refresh rotation evidence.

Do not use this mode when the current digest still exists, for frontend or
green candidate families, or to migrate roles/secrets/runtime topology.

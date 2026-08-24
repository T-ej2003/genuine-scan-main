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

Because recovery preserves the legacy execution role, that role must already
permit `secretsmanager:GetSecretValue` for each of the four exact resolved
secret ARNs (and `kms:Decrypt` only when the secret uses a customer-managed
KMS key). This repair does not add, replace, or broaden execution-role IAM.

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

Before registration, the initially observed service must identify the approved
legacy source revision unless it already identifies the single exact recovery
revision authenticated by the candidate fingerprint. The service is read again
immediately before `UpdateService`, so a later concurrent change still fails
closed without an update.

A failed historical recovery revision without the four bindings is not a
matching candidate and is never reused. Rollback reconciliation distinguishes
none, progressing, successful, failed, ambiguous, stalled with a recoverable
target, and stalled with an authenticated unrecoverable target. Elapsed time is
never authority. Supersession is permitted only for the final state, after two
bounded authenticated observations bind the exact service deployment, target
service revision, task-definition ARN, immutable digest, repeated exact-target pull failures, and
canonical ECR `ImageNotFoundException` for that digest. Access denial, timeout,
or malformed ECR output is unknown and fails closed.

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
3. Dispatch through `scripts/aws/dispatch-production-backend-health-recovery.mjs`.
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
     --approval /secure/operator/recovery-approval.json
   ```
4. Have an authorized reviewer approve the GitHub `production` environment
   deployment. Repository administrators must first configure that environment
   with required reviewers and administrator bypass disabled. Configure
   `Prevent self-review` to match the repository's actual multi-operator or
   solo-operator governance model.
5. Retain the uploaded `backend-health-recovery-evidence` artifact.
6. After backend health is proven, resume the canonical dual-slot rotation.
   This recovery does not create or refresh rotation evidence.

Do not use this mode when the current digest still exists, for frontend or
green candidate families, or to migrate roles/secrets/runtime topology.

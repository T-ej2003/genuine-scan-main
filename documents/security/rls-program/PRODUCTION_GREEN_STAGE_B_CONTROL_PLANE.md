# Production green Stage B control plane

This package is repository-only. It does not create an AWS resource, write a secret,
connect to PostgreSQL, execute SQL, register an ECS task definition, or switch traffic.

## Immutable images

The backend-only publisher and the four-image Stage B publisher use disjoint immutable
tag namespaces. Backend-only publishes `mscqr-backend:<release_sha>-backend-only` while
retaining source labels bound to `<release_sha>`. Stage B alone owns the canonical
`<release_sha>` backend tag and the reviewed worker, executor, and canary tags. Missing
or mismatched Stage B source-contract or migration labels remain a hard reuse failure;
tags are never overwritten or merged across workflows.

The Stage B image dispatcher is loaded from protected `main`; its `release_sha` input is
the independent, canonical build source. Use
`node scripts/aws/dispatch-production-green-stage-b-images.mjs <release_sha>`, which
dispatches with `--ref main -f release_sha=<release_sha>` and rejects nonexistent or
commit-valued workflow refs. The workflow verifies the exact merged release SHA before it calls
`.github/workflows/production-green-stage-b-image-build.yml`. The reusable workflow is
the only job with GitHub OIDC publication authority: it verifies the generated RLS package,
builds backend, worker, executor, and canary images for `linux/amd64`, requires immutable
digest references, creates SBOM and provenance attestations, signs images, and fails on
critical vulnerabilities. Before any dependency installation or AWS credential acquisition,
both workflow layers require that exact 40-character SHA to be checked out and merged into
`origin/main`. A pre-existing SHA tag is reusable only when its image revision,
source-contract, migration digest, and service identity labels exactly match the reviewed
Stage B bindings.

The dispatcher records the exact workflow file `production-green-stage-b-images.yml`,
workflow name `Production Green Stage B Images`, artifact name
`production-green-stage-b-images`, and canonical file `stage-b-images.jsonl`. Stage B
evidence accepts only that four-record artifact; the one-record backend-only artifact is
not a Stage B release. The failed release attempt for SHA
`3c4c6cd49b1faa5a3521b8f4c419632b74def7a3` is invalidated because its canonical backend
tag was occupied by the incompatible backend-only publisher. A new merged SHA is
required for the next Stage B release; the occupied image is not deleted automatically.

`infra/aws/terraform/production-green-stage-b-image-publisher/` is an isolated future
apply root for the dedicated `mscqr-production-stage-b-image-publisher` role. It trusts
only the default OIDC subject of the dedicated protected
`production-stage-b-image-publish` environment and grants ECR publication only for
`mscqr-backend` and `mscqr-worker`. The repository-wide OIDC subject template remains
default, leaving unrelated OIDC consumers unchanged. An MFA-backed non-root operator must
apply that root through the approved production state backend, verify its output hashes,
then set only the dedicated environment variable
`PRODUCTION_STAGE_B_IMAGE_PUBLISH_ROLE` to its ARN. This PR does not apply Terraform, set
the variable, or access AWS.

The executor is `backend/Dockerfile` target `production-rls-executor`; it contains only
the reviewed executor scripts, generated package, Prisma tooling, PostgreSQL client, and
runtime dependencies. Its entrypoint is fixed. The canary target is
`production-rls-canary`; backend and worker use the `runtime` target.

## Fixed control plane

Task templates are under `infra/aws/terraform/production-green-stage-b/task-definitions`.
They require digest images, `awsvpc`, Fargate, private subnets, the frozen executor SG,
disabled public IPs, fixed entrypoints, no command overrides, no privileged or interactive
container, and awslogs. Backend, worker, and canary templates cannot reference the
RDS-managed administrator secret. The executor alone receives the password JSON key from
that secret; no value is recorded in a template, receipt, log, image, or approval.
Each template has a dedicated execution role. In particular,
`mscqr-production-full-rls-green-executor-execution` is the only execution role that may
read the RDS-managed administrator secret. The executor and canary intentionally retain a
writable ephemeral root filesystem because their reviewed Node entrypoints use `/tmp`; the
backend and worker remain read-only.
The backend alone mounts a Fargate ephemeral `backend-uploads` volume at `/app/uploads`,
which covers incident attachments, compliance packs, and legacy QR reports without making
the image root filesystem writable. No other Stage B task receives that mount.

During a reviewed task-definition rollover, Terraform plan JSON uses the provider's
singular `volume` field. The rotation contract compares its semantic volume shape, not
provider-empty representation details: an omitted `configure_at_launch` is equivalent
only to `false`; `true` is outside the reviewed domain. `host_path` is limited to the
observed provider-empty `""` representation (or omission), and each nested Docker/EFS/FSx/S3
configuration is limited to omission or an empty array. Volume names, mounts, paths, configured volume drivers, EFS settings, duplicate
names, and unsupported fields remain fatal. The same provider-empty normalization applies
to `ipc_mode` and `pid_mode` (`""` and `null` only); nonempty process-sharing modes are
outside the reviewed domain and remain fatal.
and to omitted empty container arrays. This normalization does not authorize a delete-only
operation or any ECS address outside the exact twelve root-managed task definitions.

The broker Lambda source is under `infra/aws/terraform/lambda/production-rls-approval-broker`.
Its `reviewed` alias must receive the separately deployed policy represented by
`broker/invocation-policy.json`; that file is a design contract, not an `AddPermission`
payload. The next AWS package must create the alias-qualified permission for only the
protected release role.
It accepts only `{ approvalId, mode }`, validates canonical signed approval JSON, claims
each approval/mode once in the replay store, starts one fixed Fargate task with no
overrides, and writes a write-once receipt. The deployment contract requires a DynamoDB
conditional-write replay store and a versioned receipt-bucket prefix.
Normal activation and canary modes reject expired approvals. Only the fixed rollback mode
may use the signed approval for the documented 24-hour grace period, and only when its
broker/executor call explicitly enables that path.

The pre-cutover release-candidate smoke exception is limited to the exact known blue
login response (`HTTP 500` with the fixed internal-error JSON) after both health checks
pass and only when every changed path is in the reviewed Stage B control-plane allowlist.
Denied runs emit safe predicate codes and offending paths; unknown, mixed, blue, runtime,
frontend, traffic, secret, database, and Stage A changes remain blocking.

## Executor networking decision

Choose VPC endpoints, not a NAT gateway. Fargate image pull and log delivery require ECR
API, ECR Docker, S3, and CloudWatch Logs. The executor itself additionally calls Secrets
Manager, KMS verification, and S3 receipt writes, and connects to the green database on
TCP/5432. The canary needs only its injected runtime secrets, the green database, and the
same Fargate image/log path; it does not call STS, KMS, or S3 itself. Broker Lambda calls
ECS, DynamoDB, KMS, Secrets Manager, and S3, and must remain outside the VPC because it
does not need database network access. Use interface endpoints for ECR API, ECR Docker,
CloudWatch Logs, Secrets Manager, and KMS, plus an S3 gateway endpoint. Enable private DNS
and allow endpoint-SG TCP/443 only from `sg-051a24aedff773761`.

This is the smaller security boundary: endpoint policies and SGs name AWS services and
the executor explicitly, while NAT admits arbitrary internet destinations. The approval
record must carry a current eu-west-2 AWS Pricing Calculator estimate for the selected
endpoint topology; no illustrative price is encoded in this release contract.

## Deployment stop gates

1. Stop unless four signed, scanned, immutable image digests match the exact merged SHA.
2. Stop unless the endpoint plan, new broker/replay resources, and task roles are separately approved.
3. Stop unless runtime and canary secret handles are intentionally populated by the approved broker path.
4. Stop unless the independent MFA-backed checker signs the canonical approval artifact.
5. Stop on any broker receipt, executor receipt, catalogue, or canary mismatch.
6. Never change `mscqr-frontend:20` or traffic before mandatory green canaries pass.

## Pre-deployment inventory broker boundary

The pre-deployment rotation inventory is a separate, terminating Fargate task. The broker
requires the normalized `mscqr-production-rls-green-predeployment-inventory` task definition
to contain exactly one `inventory` container, the approved immutable backend digest, fixed
`node /app/scripts/production-rotation-state-inventory.mjs` execution, the reviewed
`DATABASE_URL` secret reference, read-only root filesystem, and the reviewed awslogs target.
The broker requests `DescribeTaskDefinition` with `TAGS` and validates tags from the AWS
response's top-level `tags` field; nested mock-only tags are rejected.

The broker polls at most 30 times at 2 seconds, with a 100-second operation deadline and a
20-second log-retrieval budget. Its Lambda timeout is 180 seconds, leaving a 30-second
cleanup margin so timeout and `StopTask` handling execute before the platform deadline.
`RunTask` is fixed to one Fargate task in the reviewed private subnets/security group with
public IP assignment disabled and no overrides. Any sidecar, extra environment/secret,
mount, port, capability, privilege, image, command, entrypoint, role, or log target fails
before launch. The post-deployment governed ECS Exec selector remains a separate later gate.

The release-deployer invokes this synchronous broker operation with the explicit finite AWS
CLI `--cli-read-timeout 150` setting. This provides 20 seconds of response headroom beyond
the 100-second broker deadline plus the 30-second cleanup margin; an infinite client timeout
is forbidden. Before `RunTask`, the broker verifies the signed approval, source/image binding,
and exact task definition, then conditionally claims the replay row. The pre-deployment replay
key is a deterministic SHA-256 identity of approval ID, release SHA, rotation ID, operation,
and authorized image; the exact task-definition ARN is also stored in the claimed row. A
conditional claim collision fails closed, including retries after caller disconnect or Lambda
termination, so no second task can launch. Known pre-launch failures may delete the claim;
any outcome after a launch attempt retains `launch-uncertain` state and task identity for
reconciliation. Claims are never released after a launch may have occurred.

## Next AWS deployment package

Create the endpoint/endpoint-SG policy, Lambda function/version/`reviewed` alias and
alias-qualified `aws_lambda_permission`, DynamoDB replay table (S key `approvalMode`, TTL
`expiresAt`), receipt-prefix bucket policy, broker policy, four dedicated ECS execution
roles and task roles, log groups, task definitions, the image-publish role, and bounded
Stage B release-role permissions. The broker needs DynamoDB `PutItem`, conditional
`DeleteItem`, and conditional `UpdateItem` on the exact replay table to implement its
claim/release/uncertain-launch recovery. None of those resources is created by this PR.

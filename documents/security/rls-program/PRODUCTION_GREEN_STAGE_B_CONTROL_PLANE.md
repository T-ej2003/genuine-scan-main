# Production green Stage B control plane

This package is repository-only. It does not create an AWS resource, write a secret,
connect to PostgreSQL, execute SQL, register an ECS task definition, or switch traffic.

## Immutable images

Run `.github/workflows/production-green-stage-b-images.yml` only for the exact merged
release SHA. It verifies the generated RLS package, builds backend, worker, executor,
and canary images for `linux/amd64`, requires immutable digest references, creates SBOM
and provenance attestations, signs images, and fails on critical vulnerabilities.
Before any dependency installation or AWS credential acquisition, the workflow requires
that exact 40-character SHA to be checked out and merged into `origin/main`. A pre-existing
SHA tag is reusable only when its image revision, source-contract, migration digest, and
service identity labels exactly match the reviewed Stage B bindings.

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

## Next AWS deployment package

Create the endpoint/endpoint-SG policy, Lambda function/version/`reviewed` alias and
alias-qualified `aws_lambda_permission`, DynamoDB replay table (S key `approvalMode`, TTL
`expiresAt`), receipt-prefix bucket policy, broker policy, four dedicated ECS execution
roles and task roles, log groups, task definitions, the image-publish role, and bounded
Stage B release-role permissions. The broker needs DynamoDB `PutItem`, conditional
`DeleteItem`, and conditional `UpdateItem` on the exact replay table to implement its
claim/release/uncertain-launch recovery. None of those resources is created by this PR.

# Production green Stage B control plane

This package is repository-only. It does not create an AWS resource, write a secret,
connect to PostgreSQL, execute SQL, register an ECS task definition, or switch traffic.

## Immutable images

Run `.github/workflows/production-green-stage-b-images.yml` only for the exact merged
release SHA. It verifies the generated RLS package, builds backend, worker, executor,
and canary images for `linux/amd64`, requires immutable digest references, creates SBOM
and provenance attestations, signs images, and fails on critical vulnerabilities.

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

The broker Lambda source is under `infra/aws/terraform/lambda/production-rls-approval-broker`.
Its `reviewed` alias must receive the resource policy in `broker/invocation-policy.json`.
It accepts only `{ approvalId, mode }`, validates canonical signed approval JSON, claims
each approval/mode once in the replay store, starts one fixed Fargate task with no
overrides, and writes a write-once receipt. The deployment contract requires a DynamoDB
conditional-write replay store and a versioned receipt-bucket prefix.

## Executor networking decision

Choose VPC endpoints, not a NAT gateway. The executor and canary need TCP/5432 only to
`sg-0703d3f227f35b81c`, plus TCP/443 to interface endpoints for ECR API, ECR Docker,
CloudWatch Logs, Secrets Manager, KMS, and STS only when task credentials require it.
Use an S3 gateway endpoint for ECR layer downloads and receipt writes. Enable private DNS
on interface endpoints; allow inbound TCP/443 to endpoint SGs only from
`sg-051a24aedff773761`. Broker Lambda calls ECS, DynamoDB, KMS, Secrets Manager, and S3;
it does not need database network access.

This is the smaller security boundary: endpoint policies and SGs name AWS services and
the executor explicitly, while NAT admits arbitrary internet destinations. For a planning
baseline only, six interface services across two AZs at the AWS published example rate of
`$0.01/hour` is about `$87.60/month`, plus `$0.01/GB`; the S3 gateway endpoint is free.
Two NAT gateways at the published example rate of `$0.045/hour` are about `$65.70/month`,
plus `$0.045/GB` and any internet-transfer charges. Those examples are not eu-west-2
quotes: the approver must obtain the current eu-west-2 calculator estimate before apply.

## Deployment stop gates

1. Stop unless four signed, scanned, immutable image digests match the exact merged SHA.
2. Stop unless the endpoint plan, new broker/replay resources, and task roles are separately approved.
3. Stop unless runtime and canary secret handles are intentionally populated by the approved broker path.
4. Stop unless the independent MFA-backed checker signs the canonical approval artifact.
5. Stop on any broker receipt, executor receipt, catalogue, or canary mismatch.
6. Never change `mscqr-frontend:20` or traffic before mandatory green canaries pass.

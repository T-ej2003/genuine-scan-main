# Green backend activation reliability, 2026-10-26

This document maps the reachable `backend-health-recovery` green candidate path on protected main `d785aa7f1e154f37c0dc621082e3f6c46d5d5aec`. It records the nonsecret facts from Release Gate run `40248378928`. It is an incident checkpoint, not authorization to repeat a production mutation.

## Execution graph

| Order | Stage and source | Principal and side effect | Required binding, output and failure boundary |
| --- | --- | --- | --- |
| 1 | Dispatch helper `dispatch-production-backend-health-recovery.mjs` | Local operator; GitHub workflow dispatch | Exact protected main, ticket, image authorization, signed runtime closure, database artifact reference and operator approval are serialized into a SHA-256 bound bundle. Dispatch is one use. |
| 2 | `release-gate.yml` `resolve-deploy-target` | GitHub, read only | Resolves the exact main SHA and required gate state. A different source fails closed. |
| 3 | `deploy-production-ecs` setup and certification | Unprivileged runner, then protected `production` with release-deployer OIDC | Source tests run without release credentials. Full RLS and PostgreSQL 18.4 certification, environment approval and exact AWS principal precede recovery preparation. |
| 4 | `recover-production-green-backend-health.mjs --prepare-handoff` | Release-deployer; readbacks, conditional S3 claims, task registration when needed | Authenticates image publication, six-domain database result, signed runtime evidence, missing predecessor image, ECS fingerprint, component generation and registration request. Registration intent, dispatch and completion are durable in the existing S3 journal. A completed revision is reused. Preparation writes a hash-bound, run-bound handoff. It does not claim UpdateService. |
| 5 | `execute-green-backend-recovery` environment and checkout | Protected `production-normal-deploy`; normal-deployer OIDC | Rechecks exact source, preparation artifact bytes, OIDC role, live IAM policy, runtime IAM, authorization freshness, component generation and predecessor. A stale or changed binding fails before any new claim. |
| 6 | `runGreenBackendHealthRecovery` and `journalEcsServiceUpdate` | Normal-deployer; conditional S3 claim followed by one `ecs:UpdateService` | Reauthenticates historical registration dispatch, exact task definition and service predecessor. `BACKEND:UPDATE:DISPATCH` is atomically claimed before the single-attempt ECS call. A lost response leaves an unresolved claim; a later run may only adopt the exact native target after authentication. |
| 7 | Stabilization and health | Normal-deployer; read only | ECS service must converge to one completed deployment, desired/running 2, pending 0, with two healthy tasks on the authorized digest. Both task IPs must be healthy in the exact ALB target group. Public readiness must report the exact source and ready database. |
| 8 | Recovery completion and receipt | Normal-deployer; S3 write, GitHub artifact | Native update completion and `BACKEND:RECOVERY:COMPLETE` are written only after target, ALB and application checks pass. The receipt is bound to journal and source. The workflow uploads it even when later steps fail. If execution fails earlier, the S3 journal remains the authoritative checkpoint. |
| 9 | `commit-production-component-recovery-state.mjs` | Normal-deployer; conditional DynamoDB state update | Reauthenticates every S3 phase, live ECS task health/digest/configuration, protected-main ancestry and component generation. CAS commits the backend component only after recovery completion. A lost CAS response requires native state readback. |

The workflow job timeout is 45 minutes. The previous `recover-production-green-backend-health.mjs` subprocess limit was 120 seconds for every AWS command, including the long-running ECS stability waiter. The corrected path uses bounded read-only ECS polling for stabilization and retains single-attempt mutating calls behind the S3 claim. No AWS retry is authorized by a process timeout.

| Evidence | Consumption rule |
| --- | --- |
| Six-domain compatibility | Internal `database.generatedAt` must be no older than 13 minutes when a new recovery phase is authorized (15-minute evidence age minus two-minute reserve). The outer artifact timestamp is not the freshness origin. |
| Operator approval | `authorizedAt` must be no older than 28 minutes at authorization. It binds source, ticket, digest, candidate, deployment and full native service fingerprint. |
| Prepared handoff | Must be no older than ten minutes when the normal-deployer job authenticates it. It binds the GitHub run, component generation and signed evidence. |
| Image and runtime IAM | Signed image evidence, exact ECR digest and live execution-role policy identity are reauthenticated in the execution job after protected approval. |
| Historical dispatch | A continuation checks the immutable authorization and artifact at the S3 dispatch commit time. It cannot create a second dispatch claim for that operation. |

## Run 40248378928: authenticated outcome

- At `2026-10-26T00:19:51Z`, the existing S3 journal recorded `BACKEND:UPDATE:DISPATCH` for operation `10d4eb81a0b0ff5f1858bba685d01c41bf0f3826b28b3c67b84279a1896152c8`, target task definition `:37`.
- CloudTrail event `af14fafb-126c-468b-9dee-616c955a0f1b` records a successful `ecs:UpdateService` at `00:19:53Z` by `mscqr-production-normal-deployer/GitHubActions`, request ID `bd333d49-4679-4f08-a96d-d715989a3755`. The target is `:37`.
- The activation process reported `spawnSync aws ETIMEDOUT` at `00:21:55Z`. Its generic error omitted the AWS subcommand. The elapsed time after the update and the source sequence strongly implicate `ecs wait services-stable`, but the old log cannot prove whether the local UpdateService response or the waiter timed out. Both cases require native reconciliation and prohibit replay.
- Native ECS recorded deployment completion at `00:24:27Z`. Subsequent readbacks showed task definition `:37`, desired 2, running 2, pending 0, two `HEALTHY` tasks on digest `sha256:5a84bcf035c0d73435b87f14b90ead02185f93e236af85716a187e7b13168694`, and two healthy targets in the exact ALB target group. The public readiness endpoint returned HTTP 200 and reported database ready and release SHA `d785aa7f1e154f37c0dc621082e3f6c46d5d5aec`.
- The S3 journal has registration completion and UpdateService dispatch, but no UpdateService completion or recovery completion. Component state is still generation 1 and points to task definition `:24`. The failed workflow produced no final recovery receipt. **Do not issue another UpdateService.**

## Failure and continuation rules

The current repair addresses the confirmed subprocess timeout without changing approval TTLs, IAM, source binding or one-use journal semantics. Read-only stabilization can tolerate a slow response and polls native ECS for at most ten minutes. A competing target, failed rollout, desired-count drift, unhealthy tasks, ALB failure or elapsed deadline stops without another ECS mutation. A timed-out mutating call remains outcome-unknown and requires journal plus native AWS reconciliation.

The current healthy service still lacks a committed component-state receipt. A source merge will advance protected main, while the original recovery CLI requires the original source to equal main and requires a fresh outage predecessor. This historical-claim completion is a separate governed continuation problem; it must authenticate the original dispatch at its commit time, the current live target and fresh protected approval before writing S3 completion or DynamoDB state. Do not forge a receipt or use the ordinary outage dispatch on the now-healthy service.

Database compatibility has a short age limit measured from the internal database verdict timestamp. Protected environment approval time can consume that reserve. Renew the verdict through the existing read-only verifier when needed; a stale verdict cannot authorize a new ECS claim. Runtime IAM and normal-deployer principal must be rechecked after approval.

## Hostile review and test boundary

| Challenge | Finding and disposition |
| --- | --- |
| UpdateService succeeds but its local response is lost | Demonstrated by CloudTrail and native ECS. The S3 dispatch claim prevents a second call; the existing journal only adopts a uniquely authenticated target. Regression tests cover a timed-out response and later native adoption. |
| ECS stabilization takes longer than a subprocess limit | Confirmed source defect. The old waiter inherited a 120-second process timeout despite ECS taking over four minutes to settle. The replacement polls native ECS for a bounded ten minutes and then verifies tasks, digest and ALB. |
| A slow read-only ECS response | Bounded `ETIMEDOUT` can be retried inside stabilization. Other AWS failures stop. The individual command remains limited to 120 seconds; mutating commands remain single attempt. |
| Transient previous primary deployment | The poll tolerates an old primary while the service's authorized target is taking ownership. A competing service target, target rollout failure or desired-count drift stops. |
| Error logging leaks command arguments | Timeout diagnostics name only the AWS service and operation. They do not print the serialized task definition, credentials, environment or captured process error. |
| Approval expires while waiting | Current authorization checks fail closed. The patch does not lengthen TTLs or treat an old approval as fresh. A new dispatch requires a renewed verifier result and approvals. |
| Runner cancellation or failure loses receipt | No final receipt was uploaded in the failed run, but the conditional S3 journal retained the exact update dispatch. A completion receipt cannot be created until native convergence and application health are authenticated. |
| Component CAS commits before healthy backend | The existing commit contract requires the durable recovery completion, exact ECS service configuration, two healthy tasks and source ancestry. Current generation 1 was not changed. |

Focused recovery, journal, IAM, component-state and workflow-graph tests pass locally. Local PostgreSQL is 18.6; the required PostgreSQL 18.4 certification must run in the pinned CI environment on the final PR head. No production mutation is part of this patch or its tests.

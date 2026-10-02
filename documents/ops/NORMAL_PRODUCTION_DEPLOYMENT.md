# Normal production deployment

Ordinary backend and frontend application changes deploy from protected `main` through `.github/workflows/production-deploy.yml` and the canonical component transaction:

`PR -> required CI/security checks -> merge -> Lane A eligibility -> one production approval -> GitHub OIDC -> reconcile durable transaction -> derive work from committed component state -> immutable ECR image -> durable deployment intent -> ECS task definition/service -> stability -> authenticated smoke -> component-state CAS`

The component-state bootstrap is the one-time CAS anchor. Every later ordinary deployment records its exact predecessor and candidate before service mutation and cannot complete without atomically replacing that receipt with component-scoped `NORMAL_APPLICATION` provenance. A missing state record, stale generation, unknown live predecessor, failed verification, or failed terminal write stops or reconciles the transaction; direct ECS state is never adopted as deployment evidence.

The protected `production-normal-deploy` environment requires explicit approval from GitHub User `T-ej2003` (`183396573`), allows self-review for the solo-operator model, disables administrator bypass, and permits only `main`. The job assumes only `mscqr-production-normal-deployer`; no local AWS profile, root session, MFA handoff, Terraform plan/apply, broker, transition ID, operator-supplied preparation or authorization artifact, or Codex production session participates.

## Canonical transaction state machine

The exact-key DynamoDB component state is authoritative. Git history classifies work only after any stored receipt is reconciled; ECS and ECR are authenticated observations, never self-authorizing history. The states are:

| State | Durable authority | Transition and retry behavior | Stage B visibility |
| --- | --- | --- | --- |
| S0 unbootstrapped | No component-state item | Only the governed bootstrap may create generation 1 from bounded live identities. Normal deployment stops. | Rejected. |
| S1 committed baseline | Component identities and component-scoped provenance; no normal receipt | Reconciliation authenticates live ECS/ECR against the committed identities. Only then is protected-main history classified from each `establishedThroughSha`. | `BOOTSTRAP` is rejected; committed `NORMAL_APPLICATION` may qualify. |
| S2 prepared | `PREPARED` receipt binds source, plan, exact predecessors, images, workflow and run | Generation CAS permits one preparation. A competing receipt or predecessor change stops. | Rejected because a receipt exists. |
| S3 candidate recorded | The same receipt contains the exact registered task-definition ARN and digest | Candidate readback is authenticated before its ARN is persisted. A crash before service mutation is reconciled to the predecessor. | Rejected. |
| S4 activation in progress | S3 receipt plus local append-only activation evidence | ECS may be predecessor, candidate, or temporarily non-stable. Reconciliation accepts only the exact receipt-bound identities; unknown identity stops. | Rejected. |
| S5 candidate healthy | S3 receipt; live candidate has passed service stability and component health | A crash before whole-release verification rolls every recorded candidate back to its exact predecessor. | Rejected. |
| S6 whole release verified | `VERIFIED` receipt binds all candidates and authenticated smoke | Reconciliation freshly verifies every live candidate. Failure rolls back; success advances to S7. | Rejected. |
| S7 committed normal state | One CAS replaces all affected components with component-scoped `NORMAL_APPLICATION` provenance and removes the receipt | A lost response is resolved by strongly reading the exact-key item. Same terminal replay is idempotent. | Accepted when the reference audit authenticates the component provenance. |
| S8 closed workflow | S7 plus non-authoritative runner journal/artifact | Process death here cannot change authority. A rerun starts by authenticating S7 and derives no work for the same source. | Same as S7. |

At every interruption boundary the next invocation reconciles first. `PREPARED` work that is not fully verified returns to the exact predecessor; a fully `VERIFIED` candidate is reverified and committed; an unknown live identity, stale generation, malformed receipt, or unprovable outcome fails closed. The workflow never prepares or publishes new normal work from a transient candidate or retained image tag.

The hostile interruption matrix is part of the deployment contract:

| Cases | Required disposition |
| --- | --- |
| A, Y, Z | Clean bootstrap-to-normal and normal-to-normal releases persist intent, verify, and atomically commit component provenance. |
| B, C, D, E, P | Death before service mutation leaves the exact predecessor authoritative. Reconciliation clears only authenticated prepared work; an unobserved task-definition registration cannot authorize ECS. |
| F, G, H | A candidate or pending rollout is accepted only when bound by the stored receipt. Non-stable readback waits or fails; pre-verification candidates roll back. |
| I, AI, AN | Candidate health without a durable verified/terminal state is not success. The verified receipt remains recoverable when the terminal write fails or is denied. |
| J, K, AD, AO | A lost terminal response or same-commit rerun strongly reads state, reauthenticates live services, performs no duplicate mutation, and derives an empty work set. |
| L, AE | A later normal commit reconciles first, then derives only the range after the committed candidate. |
| M, O | Exact receipt-bound candidate or predecessor observations reconcile deterministically to commit or rollback. |
| N, Q, AQ | Unknown ECS identity or disagreement with authenticated state fails closed; legacy evidence cannot override state. |
| R, S, AL, AM | Generation CAS and exact predecessor comparison allow one authoritative writer; same-component and competing receipts are rejected. |
| T, U, V, W, X | Replayed or cross-source, digest, task-definition, component, service, or environment evidence is rejected by receipt/state identity checks. |
| AA, AB, AT | Stage B shares the production deployment concurrency group, rejects any pending receipt and `BOOTSTRAP` provenance, and accepts only committed component-scoped `NORMAL_APPLICATION` provenance. |
| AC, AS | Classification is regenerated after reconciliation from committed component baselines; stronger-lane or changed classifications stop before mutation. |
| AF, AG, AH | `establishedThroughSha` controls history. Image source is identity evidence only; stale, ambiguous, or missing ECR metadata fails authentication. |
| AJ, AK | Cancellation or timeout is treated as an unknown outcome. The stored receipt and exact live readback decide the next action; the workflow does not infer success from process exit. |
| AP, AR | Malformed state and an absent bootstrap anchor reject normal deployment. ECS cannot bootstrap or authorize itself. |

## Lane A

Lane A accepts source-owned backend/frontend application paths only. It builds only affected services, pushes a full-Git-SHA tag to immutable `mscqr-backend` or `mscqr-web`, deploys the returned digest reference, waits for ECS stability, verifies the backend release SHA when applicable, and runs public plus authenticated smoke checks. A failed deployment or smoke check restores each exact predecessor task definition in reverse order; rollback refuses an unrelated concurrent service target.

Before publishing, the protected job reconciles any incomplete normal receipt, authenticates live ECS/ECR against the committed component identities, and classifies each committed `establishedThroughSha` to the candidate. This prevents an earlier undeployed infrastructure, RLS, schema, worker, security, recovery, or ambiguous change from riding along with a later application commit. The legacy live-image range check remains only for the reviewed baseline and bounded B01 prerequisite paths, which do not have normal component-transaction authority.

## Lane B

Terraform, IAM, networking, database infrastructure, Prisma/schema/migrations, RLS packages/policies, secrets topology, workers without a production service, authentication/tenant-isolation security boundaries, and recovery/control-plane changes are rejected from Lane A. They retain their existing reviewed infrastructure or privileged procedures. The normal workflow reports `LANE_B_REQUIRED` and performs no AWS action.

## One-time baseline deployment

The bounded printing-routine reconciler emits exactly one non-secret JSON failure record containing a source-owned stage and bounded error class. A stage names the operation being attempted; raw database, Prisma, SQL, URL, payload, stack, and secret data are never logged. This telemetry does not retry, alter transaction behavior, or authorize a deployment.

Protected main currently contains application/security/infrastructure work newer than the live backend and frontend image source tags. It is therefore not eligible for the first Lane A deployment. The same workflow has one manual `baseline: true` route that requires the exact current protected-main source to descend from GitHub's authenticated merge commit for PR #558 and requires the exact reviewed historical backend and frontend image identities. It then uses the same protected environment, OIDC role, immutable-image build and scan, ECS rolling deployment, stability wait, smoke checks, and best-effort runner rollback as Lane A. Advancing either live image consumes the historical predecessor guard and makes the escape hatch unusable.

Both ECS services must already have circuit-breaker rollback and the exact source-owned target-5xx and unhealthy-host deployment alarms enabled. The workflow rejects the deployment before image publication when that AWS configuration is absent or different. ECS-native rollback is primary; the runner-local rollback remains secondary. No authenticated synthetic alarm exists today, so adding one is a separate AWS configuration decision rather than part of this source change.

Before the first deployment from a protected-main revision that changes `normal-deployer-policy.json`, the configuration operator converges the existing inline policy with `npm run production:normal-deployer-policy -- --source-sha <protected-main-sha> --admin-profile mscqr-production-root`. The command accepts only the source-owned role and policy name, requires the exact reviewed predecessor (or exact target), performs at most one `PutRolePolicy`, and authenticates the exact source policy by readback. Unknown predecessors, additional inline or attached policies, another role, and another AWS identity fail closed. This is bounded IAM configuration maintenance; ordinary deployments continue to use only GitHub OIDC and never invoke the convergence command.

The four alarms are the `AWS/ApplicationELB` contracts exported by `scripts/aws/production-ecs-native-rollback.mjs`: target 5xx uses `Sum`; unhealthy hosts uses `Maximum`; both use 60-second periods, two evaluation periods, two datapoints to alarm, `GreaterThanThreshold` at zero, and `notBreaching` missing data. Each alarm is bound to the production ALB and exactly one backend or frontend target group, with no CloudWatch alarm action. ECS observes these alarm states and performs the rollback.

## Dedicated production smoke identity

Authenticated smoke uses the existing `production-green-pretraffic-canary-v1` ordinary canary only. It is the deterministic user `556f5cfa-0820-4e05-a0e0-7357699546f4`, has role `LICENSEE_ADMIN`, belongs to the dedicated green-canary organization/licensee, has independent password and MFA credentials, and has a distinct audit identity. The environment secrets must reference this canary; the operator's human Super Admin account is prohibited.
The workflow passes the canary's exact source-owned user, role, organization, and licensee identities to the smoke runner; `/auth/me` must match all four before authenticated smoke can continue.

The environment-secret contract is:

- `PRODUCTION_SMOKE_LOGIN_EMAIL` and `PRODUCTION_SMOKE_LOGIN_PASSWORD`: required and sourced from the existing ordinary-canary Secrets Manager values through a non-printing operator handoff.
- `PRODUCTION_SMOKE_ADMIN_MFA_SECRET`: the ordinary canary's independent Base32 seed. It is required when login enters `MFA_BOOTSTRAP`; the smoke derives the current six-digit TOTP at runtime.
- `PRODUCTION_SMOKE_ADMIN_MFA_CODE`: optional manual override and unset during normal CI.
- `PRODUCTION_SMOKE_VERIFY_CODE`: optional until a dedicated non-customer QR is issued. Its absence skips only public verification.

After authenticating protected main, the operator installs the existing ordinary-canary values without displaying them or writing plaintext to disk:

```bash
npm run production:smoke-secret-handoff -- --source-sha <protected-main-sha> --aws-profile mscqr-production-root
```

The command authenticates the three exact source-owned Secrets Manager ARNs, pipes each value directly to `gh secret set` over stdin, verifies names only, and refuses to run while either the static MFA-code or public-verify secret is present.

The final pre-baseline RLS comparison reuses the existing canonical disposable-package requirements workflow and the installed private read-only canary task boundary. Dispatch `.github/workflows/produce-production-app-only-requirements.yml` with identical protected/candidate SHAs, then use its compact authenticated artifact reference:

```bash
npm run production:rls-catalogue-probe -- --source-sha <protected-main-sha> --requirements-reference '<compact-requirements-artifact-reference-json>' --aws-profile mscqr-production-root
```

The probe accepts no requirements file path. It independently authenticates the successful producer workflow, protected-main SHA, run attempt, immutable artifact ID/digest, exact ZIP member, and original file SHA before parsing the certified requirements. It then registers only a new revision of the existing compatibility-verifier task definition and runs it once with no overrides. Its PostgreSQL transaction is repeatable-read and read-only under `mscqr_prod_rls_canary_read`; the result is exactly `MATCH`, `EXPECTED_THREE_ROUTINE_DELTA_ONLY`, or `UNEXPECTED_DRIFT`. It never applies an RLS change.

`EXPECTED_THREE_ROUTINE_DELTA_ONLY` is not a name-only exception. It requires all three routines to be present with the exact catalogue hashes authenticated by the last compatible production proof at source `6d5a48ce7c32b12ce8671731392f92ddfa625a88` (requirements `647841407b6bbba43d45ecc880dca713e73cacae4e1d27e74ce3dcdf977a2f88`). A missing routine, another predecessor definition, or any additional catalogue difference is `UNEXPECTED_DRIFT`.

When a fresh probe returns exactly `EXPECTED_THREE_ROUTINE_DELTA_ONLY`, the bounded one-time apply is:

```bash
npm run production:apply-printing-routine-delta -- --source-sha <protected-main-sha> --aws-profile mscqr-production-root
```

The pinned historical executor image does not contain this one-time entrypoint. The command therefore sends one tracked, source-hashed executor through `node -e`; all source-dependent requirements, SQL, host and hash bindings travel separately as deterministic gzip/Base64-encoded canonical JSON data. The executor never evaluates that data as JavaScript, and the registered task-definition readback authenticates both fixed program bytes and payload bytes before launch. The data payload is non-secret; the database password remains an ECS secret injected only into the task environment.

The command searches the bounded complete requirements-producer history newest-first and fully authenticates each candidate; an authenticated artifact for another candidate is skipped, while a malformed or ambiguous artifact fails closed. Its sanitized GitHub runner permits only the fixed producer query, protected-main read, positive-ID run and ZIP reads, and the literal bounded artifact query `?per_page=100`. It accepts no SQL, routine, database, secret, ECS, or hash override. A dedicated fixed ECS task reuses the existing production RLS executor image, execution role, private network, and database administrator secret. The canonical payload is deterministically gzip/Base64 transported, authenticated after bounded decompression by its original uncompressed SHA-256, and the exact serialized registration request must remain at or below 60 KiB before `RegisterTaskDefinition`. One serializable PostgreSQL transaction authenticates the full predecessor catalogue, takes a transaction advisory lock, temporarily grants the exact routine owner `CREATE` on `app_rls` through the exact schema owner, replaces only `app_rls.printing_readiness`, `app_rls.printing_create_job`, and `app_rls.printing_connector_identity` as their existing owner, revokes that temporary privilege, authenticates the full successor catalogue and restored privilege boundary, and commits once. Any failure rolls back the grant and all replacements together. Exact successor state reports `ALREADY_CONVERGED` without any grant, replacement, or revoke.

ECS materializes an omitted host-volume configuration as `host: {}` on task-definition readback. The shared exact-readback contract normalizes only that empty object to absence; `sourcePath`, EFS, Docker, FSx, unknown volume fields, and every other task-definition field remain exact and fail closed on drift.

Task timeout, missing evidence, nonzero exit, or unavailable readback is ambiguous. Do not rerun the writer. Run the read-only catalogue probe and reconcile `MATCH`, `EXPECTED_THREE_ROUTINE_DELTA_ONLY`, or `UNEXPECTED_DRIFT` first. Only `MATCH` permits the one-time baseline deployment.

Do not use `seed-launch-smoke-users.js` in production: that executable deliberately refuses protected-environment mutation. The already-provisioned ordinary canary is reused instead of creating a second identity system.

A permanent public-verification fixture must use the normal QR lifecycle: the dedicated canary licensee submits one QR allocation request, a human platform operator approves it with normal MFA in the application, governed printing/issuance completes, and the resulting non-customer raw QR code is transferred directly into the GitHub environment secret without terminal or workflow-log output. Do not use a customer QR, a generated random string, the risk-blocked platform canary, or the operator's human credentials in CI. Until that fixture exists, leave `PRODUCTION_SMOKE_VERIFY_CODE` unset.

## Retirement inventory

- **KEEP:** protected-main CI/security checks, ECR repositories, ECS cluster/services/task roles, production smoke tests, GitHub OIDC provider, `production-normal-deploy`, historical recovery evidence, component deployment-state planning, normal-release intents/receipts/journals, and exact-key DynamoDB CAS authority. The latter make ECS mutation and authenticated component provenance one fail-closed transaction.
- **HISTORICAL_ONLY:** completed broker generations, successor closures, failed recovery transitions, and their immutable evidence. Do not rewrite or delete them as part of application deployment.

## Operator response

If classification selects Lane B, use the appropriate reviewed privileged process. If deployment fails and rollback succeeds, fix forward in a new PR. If rollback refuses because ECS targets an unrelated task definition, stop and reconcile live ECS state before any retry.

# Normal production deployment

Ordinary backend and frontend application changes deploy from protected `main` through `.github/workflows/production-deploy.yml`:

`PR -> required CI/security checks -> merge -> Lane A classification -> one production approval -> GitHub OIDC -> immutable ECR image -> ECS task definition/service -> stability -> authenticated smoke`

The protected `production-normal-deploy` environment requires explicit approval from GitHub User `T-ej2003` (`183396573`), allows self-review for the solo-operator model, disables administrator bypass, and permits only `main`. The job assumes only `mscqr-production-normal-deployer`; no local AWS profile, root session, MFA handoff, Terraform plan/apply, broker, transition ID, preparation artifact, authorization artifact, or Codex production session participates.

## Lane A

Lane A accepts source-owned backend/frontend application paths only. It builds only affected services, pushes a full-Git-SHA tag to immutable `mscqr-backend` or `mscqr-web`, deploys the returned digest reference, waits for ECS stability, verifies the backend release SHA when applicable, and runs public plus authenticated smoke checks. A failed deployment or smoke check restores each exact predecessor task definition in reverse order; rollback refuses an unrelated concurrent service target.

Before publishing, the protected job resolves each live image digest back to exactly one 40-character ECR source tag and classifies the complete live-source-to-candidate range. This prevents an earlier undeployed infrastructure, RLS, schema, worker, security, recovery, or ambiguous change from riding along with a later application commit.

## Lane B

Terraform, IAM, networking, database infrastructure, Prisma/schema/migrations, RLS packages/policies, secrets topology, workers without a production service, authentication/tenant-isolation security boundaries, and recovery/control-plane changes are rejected from Lane A. They retain their existing reviewed infrastructure or privileged procedures. The normal workflow reports `LANE_B_REQUIRED` and performs no AWS action.

## One-time baseline deployment

Protected main currently contains application/security/infrastructure work newer than the live backend and frontend image source tags. It is therefore not eligible for the first Lane A deployment. The same workflow has one manual `baseline: true` route that accepts only GitHub's immutable merge commit for this final pre-baseline PR (#556) and the exact reviewed historical backend and frontend image identities, then uses the same protected environment, OIDC role, immutable-image build and scan, ECS rolling deployment, stability wait, smoke checks, and best-effort runner rollback as Lane A. A later main commit or either live image advancing makes the escape hatch unusable.

Both ECS services must already have circuit-breaker rollback and the exact source-owned target-5xx and unhealthy-host deployment alarms enabled. The workflow rejects the deployment before image publication when that AWS configuration is absent or different. ECS-native rollback is primary; the runner-local rollback remains secondary. No authenticated synthetic alarm exists today, so adding one is a separate AWS configuration decision rather than part of this source change.

The four alarms are the `AWS/ApplicationELB` contracts exported by `scripts/aws/production-ecs-native-rollback.mjs`: target 5xx uses `Sum`; unhealthy hosts uses `Maximum`; both use 60-second periods, two evaluation periods, two datapoints to alarm, `GreaterThanThreshold` at zero, and `notBreaching` missing data. Each alarm is bound to the production ALB and exactly one backend or frontend target group, with no CloudWatch alarm action. ECS observes these alarm states and performs the rollback.

## Dedicated production smoke identity

Authenticated smoke uses the existing `production-green-pretraffic-canary-v1` ordinary canary only. It is the deterministic user `556f5cfa-0820-4e05-a0e0-7357699546f4`, has role `LICENSEE_ADMIN`, belongs to the dedicated green-canary organization/licensee, has independent password and MFA credentials, and has a distinct audit identity. The environment secrets must reference this canary; the operator's human Super Admin account is prohibited.

The environment-secret contract is:

- `PRODUCTION_SMOKE_LOGIN_EMAIL` and `PRODUCTION_SMOKE_LOGIN_PASSWORD`: required and sourced from the existing ordinary-canary Secrets Manager values through a non-printing operator handoff.
- `PRODUCTION_SMOKE_ADMIN_MFA_SECRET`: the ordinary canary's independent Base32 seed. It is required when login enters `MFA_BOOTSTRAP`; the smoke derives the current six-digit TOTP at runtime.
- `PRODUCTION_SMOKE_ADMIN_MFA_CODE`: optional manual override and unset during normal CI.
- `PRODUCTION_SMOKE_VERIFY_CODE`: optional until a dedicated non-customer QR is issued. Its absence skips only public verification.

Do not use `seed-launch-smoke-users.js` in production: that executable deliberately refuses protected-environment mutation. The already-provisioned ordinary canary is reused instead of creating a second identity system.

A permanent public-verification fixture must use the normal QR lifecycle: the dedicated canary licensee submits one QR allocation request, a human platform operator approves it with normal MFA in the application, governed printing/issuance completes, and the resulting non-customer raw QR code is transferred directly into the GitHub environment secret without terminal or workflow-log output. Do not use a customer QR, a generated random string, the risk-blocked platform canary, or the operator's human credentials in CI. Until that fixture exists, leave `PRODUCTION_SMOKE_VERIFY_CODE` unset.

## Retirement inventory

- **KEEP:** protected-main CI/security checks, ECR repositories, ECS cluster/services/task roles, production smoke tests, GitHub OIDC provider, `production-normal-deploy`, and historical recovery evidence.
- **DEPRECATE:** custom component deployment-state planning, normal-release intents/receipts/journals, and duplicate normal-deployment approval stages.
- **RETIRE_AFTER_NEW_LANE_PROVEN:** normal-deployment DynamoDB writer access and deployment-only broker/reconciler/Stage-B workflow surfaces, through a separate reviewed deletion change after one successful deploy and rollback proof.
- **HISTORICAL_ONLY:** completed broker generations, successor closures, failed recovery transitions, and their immutable evidence. Do not rewrite or delete them as part of application deployment.

## Operator response

If classification selects Lane B, use the appropriate reviewed privileged process. If deployment fails and rollback succeeds, fix forward in a new PR. If rollback refuses because ECS targets an unrelated task definition, stop and reconcile live ECS state before any retry.

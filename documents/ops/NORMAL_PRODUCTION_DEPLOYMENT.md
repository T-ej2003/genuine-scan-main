# Normal production deployment

Ordinary backend and frontend application changes deploy from protected `main` through `.github/workflows/production-deploy.yml`:

`PR -> required CI/security checks -> merge -> Lane A classification -> one production approval -> GitHub OIDC -> immutable ECR image -> ECS task definition/service -> stability -> authenticated smoke`

The protected `production-normal-deploy` environment requires explicit approval from GitHub User `T-ej2003` (`183396573`), allows self-review for the solo-operator model, disables administrator bypass, and permits only `main`. The job assumes only `mscqr-production-normal-deployer`; no local AWS profile, root session, MFA handoff, Terraform plan/apply, broker, transition ID, preparation artifact, authorization artifact, or Codex production session participates.

## Lane A

Lane A accepts source-owned backend/frontend application paths only. It builds only affected services, pushes a full-Git-SHA tag to immutable `mscqr-backend` or `mscqr-web`, deploys the returned digest reference, waits for ECS stability, verifies the backend release SHA when applicable, and runs public plus authenticated smoke checks. A failed deployment or smoke check restores each exact predecessor task definition in reverse order; rollback refuses an unrelated concurrent service target.

Before publishing, the protected job resolves each live image digest back to exactly one 40-character ECR source tag and classifies the complete live-source-to-candidate range. This prevents an earlier undeployed infrastructure, RLS, schema, worker, security, recovery, or ambiguous change from riding along with a later application commit.

## Lane B

Terraform, IAM, networking, database infrastructure, Prisma/schema/migrations, RLS packages/policies, secrets topology, workers without a production service, authentication/tenant-isolation security boundaries, and recovery/control-plane changes are rejected from Lane A. They retain their existing reviewed infrastructure or privileged procedures. The normal workflow reports `LANE_B_REQUIRED` and performs no AWS action.

## First migration deployment

Protected main currently contains application/security/infrastructure work newer than the live backend and frontend image source tags. It is therefore not eligible for the first Lane A deployment. Establish a reviewed Lane B runtime baseline first; after both live ECR digests identify that protected source, later ordinary application commits can use Lane A.

## Retirement inventory

- **KEEP:** protected-main CI/security checks, ECR repositories, ECS cluster/services/task roles, production smoke tests, GitHub OIDC provider, `production-normal-deploy`, and historical recovery evidence.
- **DEPRECATE:** custom component deployment-state planning, normal-release intents/receipts/journals, and duplicate normal-deployment approval stages.
- **RETIRE_AFTER_NEW_LANE_PROVEN:** normal-deployment DynamoDB writer access and deployment-only broker/reconciler/Stage-B workflow surfaces, through a separate reviewed deletion change after one successful deploy and rollback proof.
- **HISTORICAL_ONLY:** completed broker generations, successor closures, failed recovery transitions, and their immutable evidence. Do not rewrite or delete them as part of application deployment.

## Operator response

If classification selects Lane B, use the appropriate reviewed privileged process. If deployment fails and rollback succeeds, fix forward in a new PR. If rollback refuses because ECS targets an unrelated task definition, stop and reconcile live ECS state before any retry.

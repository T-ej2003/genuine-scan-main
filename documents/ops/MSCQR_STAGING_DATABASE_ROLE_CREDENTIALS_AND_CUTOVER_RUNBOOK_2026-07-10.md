# MSCQR staging database-role credentials and ECS cutover runbook

Date: 2026-07-11
Scope: staging account `368992683803`, `eu-west-2`, database `mscqr_staging`, cluster `mscqr-staging-euw2-main`, service `mscqr-staging-backend-service-euw2`.

## Launch decision

The former Mac-side `psql` workflow is retired. A confirmation variable cannot create VPC reachability. PostgreSQL and secret-value phases now run only in the reviewed disposable Fargate task `mscqr-staging-database-role-admin`, using the same backend image, private subnets, security groups, execution role, and private RDS path as the staging backend. The task has no public IP, service, load balancer, inbound rule, or package-install step. The controller refuses a different image or network topology.

The Mac controller performs sanitized discovery, starts/waits for the task, inventories consumers, and performs the separately approved ECS cutover. It never calls `psql`, retrieves a database secret, receives a generated password, or puts a secret value. Executor overrides contain only the fixed mode `probe`, `provision`, or `verify`; no password or URL is placed in a command, argument, log, or evidence file.

The executor must first be present in a reviewed backend image and the Terraform-created admin task definition must be reviewed/applied through the normal infrastructure process. This workflow does not rebuild, replace, or install software in a running container.

## Safety invariants

- No public RDS endpoint, public task IP, security-group opening, RLS enablement, RLS policy creation, running-image change, or runtime package installation.
- All three staged route flags remain explicitly `false`.
- Generated passwords exist only in the disposable task's process memory. No credential file transfer is used.
- The admin URL is injected by ECS from the preserved staging admin secret and is never returned to the Mac.
- The executor uses Prisma in the reviewed image; local `psql`, `PGPASSWORD`, psql variables, and shell-expanded password handling do not exist in this workflow.
- Controller files contain only non-secret ECS JSON and use mode `0600`; signal handlers remove them on `SIGINT`, `SIGTERM`, and `SIGHUP`.
- The executor emits only status, phase, role names, secret version IDs, permission-test results, rollback result, and failure classification.
- `CreateSecret` uses three separate `Resource="*"` IAM statements because a not-yet-created secret has no ARN. Each statement requires one exact staging name, `eu-west-2`, all five reviewed request tags, and the name-correlated `Role` tag. Every post-creation secret action remains scoped to the three exact ARN patterns.
- The ECS execution role preserves its existing backend-secret reads and adds only the app-role secret ARN pattern needed after cutover. It cannot read the migrator or RLS-read credential.
- Every denial probe that could change database or session state runs on one Prisma interactive-transaction connection. Expected denial, unexpected success, and infrastructure failure all reject the transaction; connection reuse is then proven. A rollback or reuse failure fails verification. Object names are unique per executor run.

## Password and secret state machine

1. `inventory`: enumerate all active staging task definitions, services, EventBridge ECS scheduled targets, containers, `DATABASE_URL`, `RLS_READ_DATABASE_URL`, and admin-secret references.
2. `reachability`: a disposable task proves `current_database() = mscqr_staging` and `current_user = mscqr_staging_admin` before mutation.
3. `capture-secret-metadata`: capture every version ID and staging label without secret values. Exactly zero target secrets means first-time provisioning; exactly three with one `AWSCURRENT` each means rotation. Mixed state blocks.
4. `password-transaction`: generate three independent 48-byte passwords and execute all three `ALTER ROLE ... PASSWORD` statements in one Prisma interactive PostgreSQL transaction. A failure after the first statement rolls back the whole transaction.
5. `pending-versions`: for rotation, write each new URL directly as `AWSPENDING`. For first-time provisioning, create an `AWSCURRENT` non-credential placeholder (`{"status":"unprovisioned"}`), then add the credential as `AWSPENDING`. This avoids exposing an unverified credential as current while respecting Secrets Manager's first-version `AWSCURRENT` behavior.
6. `role-verification`: connect with each in-memory URL. Verify identities; app read/write inside an intentional rollback plus forbidden DDL/role operations; migrator `SET LOCAL ROLE` DDL inside an intentional rollback plus forbidden role creation; RLS-read access to the reviewed graph plus forbidden writes, DDL, owner role, and outside-graph reads. Every mutating denial probe is transactionally rolled back even when it unexpectedly succeeds. Infrastructure, authentication, rollback, and post-rollback connection failures fail verification.
7. `promote-versions`: move `AWSCURRENT` to each verified pending version, which preserves the former current version as `AWSPREVIOUS`, then remove `AWSPENDING`. Any partial promotion triggers compensation.
8. `consumer-cutover`: separately register one backend revision changing only `backend.secrets[DATABASE_URL].valueFrom`, update the single staging service, wait, prove runtime identity `mscqr_staging_app`, run health/smoke checks, and re-inventory.
9. `complete`: success requires all three role tests, all three current secret versions, the complete consumer gate, runtime identity, health, and smoke checks.

AWS documents that `file://` makes the CLI read parameter content from the named file. This workflow uses it only for non-secret task-definition and override JSON; secret values use the in-task SDK and never cross the CLI. Moving `AWSCURRENT` with `UpdateSecretVersionStage` preserves the displaced version under `AWSPREVIOUS`.

## Compensation and interruption

- First-time failure at any placeholder/pending/promotion boundary: one transaction restores all three roles to `PASSWORD NULL`; failed pending labels are removed where supported; compensation creates any missing non-credential placeholders and verifies the consistent three-placeholder state before reporting `restored`. A retry detects `first-time-recoverable` and proceeds automatically. Mixed credential/placeholder states remain blocked.
- Rotation failure: prior `AWSCURRENT` URL versions, read only inside the task, restore all three database passwords in one transaction. Any moved `AWSCURRENT` labels are moved back to their captured version IDs. Failed `AWSPENDING` labels are removed; versions are not destroyed.
- ECS registration failure: the service is unchanged. The registered revision, if any, is preserved.
- ECS service-update or post-update verification failure: restore the captured previous task-definition ARN, wait for stability, and rerun health.
- `SIGINT`, `SIGTERM`, and `SIGHUP`: the executor invokes the same compensation path before exit; the controller deletes temporary files and prints the recovery command class.
- If compensation cannot be proven after process death, task loss, or network loss, the workflow returns failure and blocks retry/cutover. It never guesses.

Operator recovery uses the same reviewed VPC task, never local PostgreSQL:

1. Preserve the controller evidence directory and sanitized admin-task log stream.
2. Re-run read-only discovery and the reachability probe.
3. For first-time mode, confirm the three roles are `PASSWORD NULL`, current target secrets are non-credential placeholders, and failed credential versions are not staged.
4. For rotation, use the captured prior `AWSCURRENT` version IDs inside the VPC recovery task to restore all three passwords and labels.
5. Confirm the old runtime still authenticates and all three route flags are false before retrying.
6. Never delete a secret or version during recovery.

## Complete staging database-consumer classification

The repository-managed staging API root declares one long-running service and no separate worker service or EventBridge scheduled ECS task. The live dry-run remains authoritative and fails on any extra active consumer.

| Consumer | Credential decision | Reason |
|---|---|---|
| `mscqr-staging-backend` / `backend` long-running service | `mscqr_staging_app` | API, background timers enabled in this process, and Prisma runtime DML |
| `mscqr-staging-database-role-admin` / `db-admin` disposable task | preserved admin only during reviewed provisioning/recovery | Ephemeral executor; not a service or scheduled runtime consumer |
| Future migration/Prisma deploy task | `mscqr_staging_migrator` | DDL only; must be disposable and explicitly migration-named |
| Worker service | no declared staging consumer | Any discovered worker with an admin secret blocks cutover until reviewed; if introduced for runtime DML it uses app, never migrator |
| EventBridge scheduled ECS tasks | none declared | Any live target is enumerated and must be explicitly classified |
| Sidecars | no database credential | Any sidecar `DATABASE_URL`, `RLS_READ_DATABASE_URL`, or admin-secret reference blocks |
| `RLS_READ_DATABASE_URL` | not injected | All staged RLS route flags are exactly `false` |

Every active task-definition revision is listed in sanitized output. The reviewed active backend service task definition fetched directly from `describe-services` is always inventoried, even if `list-task-definitions` omits it; full ARNs, `family:revision`, and family task-definition references are normalized and deduplicated. Inactive historical revisions are evidence only, are not runtime consumers, and are not modified or destroyed.

Discovery fails closed unless exactly one active `mscqr-staging-backend-service-euw2` consumer uses container `backend` variable `DATABASE_URL`. That consumer must classify as `admin` before cutover or `app` after cutover. Zero matches, duplicate backend matches, sidecar credentials, or any additional active service or EventBridge database consumer block probe, provisioning, verification, and cutover. A service/scheduled consumer classified `no-runtime-credential`, an unreviewed admin reference, RLS-read injection while flags are false, or migrator credential in a service also blocks.

## Exact pre-APPLY commands

These commands are for the reviewed operator. The work documented on 2026-07-11 did not run them against AWS.

```bash
export AWS_PROFILE='<reviewed-staging-assumed-role-profile>'
export AWS_REGION='eu-west-2'
export MSCQR_STAGING_VPC_EXECUTOR='disposable-ecs-admin-task'
export MSCQR_STAGING_DB_ADMIN_TASK_DEFINITION_ARN="$(terraform -chdir=infra/terraform/staging-api output -raw database_role_admin_task_definition_arn)"

# Fully read-only AWS discovery: proves selected mechanism/topology and lists consumers.
node scripts/aws/staging-database-role-credentials.mjs discover

# Sanitized provisioning plan. It performs no PostgreSQL or Secrets Manager mutation.
scripts/aws/provision-staging-database-role-credentials.sh

# Reachability/identity probe. It starts one disposable ECS task but performs no
# PostgreSQL or Secrets Manager mutation. Review this separate ECS RunTask action.
scripts/aws/provision-staging-database-role-credentials.sh --probe

# Runs the complete permission matrix using the three AWSCURRENT credentials
# inside the disposable task. It is not a connectivity-only probe.
export MSCQR_STAGING_DATABASE_VERIFY_CONFIRM='MSCQR_VERIFY_STAGING_DATABASE_ROLE_CREDENTIALS'
scripts/aws/verify-staging-database-role-permissions.sh --apply

# Sanitized cutover plan; no task registration or service update.
export MSCQR_STAGING_HEALTH_URL='https://<reviewed-staging-host>/healthz'
scripts/aws/cutover-staging-ecs-database-role.sh
```

Only after separate human approvals:

```bash
export MSCQR_STAGING_DATABASE_CREDENTIALS_CONFIRM='MSCQR_PROVISION_STAGING_DATABASE_ROLE_CREDENTIALS'
scripts/aws/provision-staging-database-role-credentials.sh --apply

export MSCQR_STAGING_REPRESENTATIVE_SMOKE_URLS='https://<reviewed-staging-host>/<safe-smoke-1>,https://<reviewed-staging-host>/<safe-smoke-2>'
export MSCQR_STAGING_ECS_DATABASE_ROLE_CUTOVER_CONFIRM='MSCQR_CUTOVER_STAGING_ECS_TO_APP_DATABASE_ROLE'
scripts/aws/cutover-staging-ecs-database-role.sh --apply
```

Provision approval does not authorize cutover. The reachability probe's ECS `RunTask` is not implicit authorization for database or secret mutation.

## Local validation

```bash
npm run test:staging-database-role-credentials
node --check scripts/aws/staging-database-role-credentials.mjs
node --check scripts/lib/staging-database-role-credentials-core.mjs
node --check backend/scripts/staging-database-role-vpc-executor.mjs
terraform -chdir=infra/terraform/staging-api fmt -check
terraform -chdir=infra/terraform/staging-api validate
git diff --check
npm run check:documents
npm run check:fixture-secret-shapes
npm run check:aws-dr-safety
npm run check:branch-secret-diff
```

## CTO recommendations

Before production adoption, use RDS Proxy with independently budgeted app/migration pools, build a dedicated minimal admin image instead of sharing the API image, add a Step Functions rotation coordinator with idempotent recovery checkpoints, alarm on any admin-secret runtime reference, and continuously reconcile ECS/EventBridge consumer inventory. Keep the RLS-read credential uninjected until each route has policy, runtime, telemetry, load, and rollback proof.

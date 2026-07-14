# MSCQR staging database-role credentials and ECS cutover runbook

Date: 2026-07-14
Scope: staging account `368992683803`, `eu-west-2`, database `mscqr_staging`, cluster `mscqr-staging-euw2-main`, service `mscqr-staging-backend-service-euw2`.

## 2026-07-14 live cutover failure and parser fix

The first operator-run cutover after PR #120 registered `mscqr-staging-backend:3` and the service became healthy, but runtime identity proof returned the sanitized failure `Runtime identity output was missing.` Automatic rollback restored `mscqr-staging-backend:2`; `/health/live` and `/health/ready` passed after rollback, `cutover-failure.json` recorded `rollbackResult = restored`, and RLS remained disabled. Revision `:3` is intentionally preserved for investigation and must not be deregistered by this workflow.

The failure was in controller parsing, not a demonstrated database-authentication failure. The old controller regex-matched one compact JSON shape in ECS Exec `stdout`. ECS Exec and Session Manager can add banners, terminal control sequences, CRLF, framing on `stderr`, or line breaks around otherwise valid command output.

The runtime command now emits exactly one marked payload using only `SELECT current_database(), current_user`:

```text
MSCQR_DB_IDENTITY_BEGIN
{"database_name":"mscqr_staging","database_user":"mscqr_staging_app"}
MSCQR_DB_IDENTITY_END
```

The controller checks both captured streams independently, removes terminal control framing, normalizes line endings, requires exactly one ordered delimiter pair, trims only the enclosed payload, and calls `JSON.parse`. The payload must be an object with exactly two string fields, `database_name` and `database_user`; their values must be exactly `mscqr_staging` and `mscqr_staging_app`. Duplicate or ambiguous marked payloads fail closed. Raw ECS Exec output, database URLs, credentials, secret values, and any SQL beyond the two identity functions are never written to normal logs or evidence.

Runtime identity proof retains only these sanitized failure classifications: `command_failed`, `delimiters_missing`, `invalid_json`, `unexpected_database`, and `unexpected_user`. Every classification enters the same automatic previous-task-definition rollback path. A failed rollback records only `operator_recovery_required` as the rollback result and requires the documented operator recovery procedure.

## 2026-07-14 post-PR #121 transport failure and versioned probe

The next operator-run cutover after merged PR #121 passed dry-run, registered and deployed `mscqr-staging-backend:4`, and reached service stability. Runtime proof then failed closed with `delimiters_missing`. The sanitized `scratch/staging-database-role-credentials-20260714T072135Z/cutover-failure.json` confirms `previousTaskDefinitionArn = mscqr-staging-backend:2`, `newTaskDefinitionArn = mscqr-staging-backend:4`, and `rollbackResult = restored`. RLS remained disabled. Revisions `:3` and `:4` are retained and must not be deregistered as part of this workflow.

PR #121 fixed consumer parsing, but its producer remained a shell-interpreted inline program. The exact command value passed to ECS Exec was:

```text
node -e 'const{PrismaClient}=require("@prisma/client");const p=new PrismaClient();p.$queryRawUnsafe("SELECT current_database() AS database_name,current_user AS database_user").then(r=>process.stdout.write("MSCQR_DB_IDENTITY_BEGIN\n"+JSON.stringify(r[0])+"\nMSCQR_DB_IDENTITY_END\n")).finally(()=>p.$disconnect())'
```

That command crossed JavaScript template construction, AWS CLI argument handling, the ECS Exec interactive PTY, and a remote shell before Node parsed it. Shell quoting, command echo, or Session Manager stream behavior could therefore omit or transform the marked block even when the session itself returned success.

The controller now passes this exact command value with no nested program or quote characters:

```text
node /app/scripts/runtimeDatabaseIdentity.js
```

`backend/scripts/runtimeDatabaseIdentity.js` is copied into `/app/scripts` by the backend runtime Dockerfile. It runs only `SELECT current_database(), current_user`, disconnects before reporting success, and writes one compact marked block to stdout. Failure writes one fixed sanitized code to stderr, exits nonzero, and suppresses internal messages and stack traces.

Before cutover registration or service update, the controller invokes the same direct command against the active admin-credential backend task and requires exact identity `mscqr_staging` / `mscqr_staging_admin`. Missing script, command failure, uncaptured output, unexpected database, or unexpected role blocks before mutation. Post-deployment proof reuses the same command and requires `mscqr_staging` / `mscqr_staging_app`; any failure after service update retains automatic rollback.

### Required image sequence before another cutover

The current staging backend image was built from SHA `82cc14631f0bdc552fa369f66ecc4ac3c1dbdaea` and cannot contain the newly added script. A new backend image is therefore mandatory before another database-role cutover:

1. Merge this fix and build/publish the backend image from the resulting reviewed SHA through the existing signed ECS image workflow.
2. Deploy that image to staging while preserving the current admin `DATABASE_URL` reference and keeping every staged RLS flag exactly `false`.
3. Verify `/version`, `/health/live`, and `/health/ready` against the new SHA.
4. Generate a fresh database-role verification receipt bound to the new active backend task definition.
5. Run the cutover dry-run. Its active-task capability proof must report `runtimeIdentityCapability.passed = true` before any APPLY approval is considered.
6. Treat the later database-role cutover as a separate approval. Image deployment does not authorize credential cutover.

## Launch decision

The former Mac-side `psql` workflow is retired. A confirmation variable cannot create VPC reachability. PostgreSQL and secret-value phases now run only in the reviewed disposable Fargate task `mscqr-staging-database-role-admin`, using the same backend image, private subnets, security groups, execution role, and private RDS path as the staging backend. The task has no public IP, service, load balancer, inbound rule, or package-install step. The controller refuses a different image or network topology.

The Mac controller performs sanitized discovery, invokes the fixed-input broker Lambda only for probe/provision/verify, waits for the returned reviewed-cluster task ARN, inventories consumers, and performs the separately approved ECS cutover. Cutover never invokes the broker; it requires a fresh sanitized verification receipt and corroborates the stopped executor task through ECS read APIs. The controller never calls `ecs:RunTask`, `psql`, retrieves a database secret, receives a generated password, or puts a secret value. The broker accepts only `{ "mode": "probe|provision|verify" }`, rejects extra fields, and constructs the sole reviewed container environment override; no password or URL is placed in a command, argument, log, or evidence file.

The executor must first be present in a reviewed backend image and the Terraform-created admin task definition must be reviewed/applied through the normal infrastructure process. This workflow does not rebuild, replace, or install software in a running container.

## Operator identity split

- Read-only discovery uses the staging Terraform plan role. That identity may run only `discover` or the default non-probe/non-apply planning output; it must not start the disposable task.
- `--probe`, provision `--apply`, and verify `--apply` require an STS session for `mscqr-staging-database-role-operator`. The controller checks the exact assumed-role ARN before inventory, executor planning, or broker invocation.
- The dedicated IAM user `mscqr-staging-database-role-operator-user` may assume only that operator role through `documents/ops/iam/MSCQR_STAGING_DATABASE_ROLE_OPERATOR_ASSUME_ROLE_POLICY_2026-07-12.json`.
- The reviewed trust template is `documents/ops/iam/MSCQR_STAGING_DATABASE_ROLE_OPERATOR_TRUST_POLICY_2026-07-12.json`. It trusts only the dedicated operator user and requires MFA. Root, wildcard principals, broad IAM users, and the Terraform plan/apply roles are forbidden. Replacing the user with an approved bootstrap principal requires a separate written approval naming one exact non-root, non-plan, non-apply principal and a matching trust-template update.
- The assumed-role permissions template is `documents/ops/iam/MSCQR_STAGING_DATABASE_ROLE_OPERATOR_POLICY_2026-07-12.json`. It can invoke only `mscqr-staging-database-role-executor-broker` and inspect the reviewed staging ECS/EventBridge inventory. Consumer classification uses secret references already present in task definitions, so the human role has no Secrets Manager permission, `ecs:RunTask`, or `iam:PassRole`.
- Cutover and rollback require the separate MFA-gated `mscqr-staging-database-role-cutover` role. Its trust, source-user assume, and runtime templates are `documents/ops/iam/MSCQR_STAGING_DATABASE_ROLE_CUTOVER_*_2026-07-13.json`. Registration preserves the reviewed backend task-definition tags, so `ecs:TagResource` is permitted only on `task-definition/mscqr-staging-backend:*`, only in `eu-west-2`, and only when `ecs:CreateAction` is `RegisterTaskDefinition`; it cannot tag services, tasks, clusters, or unrelated task-definition families. The database-role operator and Terraform plan/apply roles are not trusted to assume it.
- The broker is the only task-launch path. It accepts exactly one `mode` field with enum `probe`, `provision`, or `verify`; hard-codes the cluster, exact Terraform-produced admin task-definition revision, Fargate/count-one launch, private subnets, ECS security group, disabled public IP, `db-admin` container, and sole `MSCQR_VPC_EXECUTOR_MODE` override. It accepts no caller command, environment, task definition, role, network, count, launch type, platform version, or tag input and returns only sanitized task ARN/status metadata.
- The broker execution role alone has exact-cluster `ecs:RunTask` and ECS-tasks-only `iam:PassRole` for the database-admin task and execution roles. It has no secret-value permission. The human operator role cannot register task definitions, update services, execute commands in containers, mutate IAM, retrieve or write secrets, or perform consumer cutover. Cutover requires its separately reviewed identity and approval and is never implied by broker invocation.

Local AWS config uses separate profiles. The source profile must belong to the dedicated operator user; do not use the plan/apply profiles as the source:

```ini
[profile mscqr-staging-database-role-plan]
role_arn = <reviewed-staging-plan-role-arn>
source_profile = <reviewed-plan-source-profile>
region = eu-west-2

[profile mscqr-staging-database-role-operator]
role_arn = arn:aws:iam::368992683803:role/mscqr-staging-database-role-operator
source_profile = mscqr-staging-database-role-operator-user
role_session_name = reviewed-database-role-workflow
mfa_serial = <dedicated-operator-user-mfa-device-arn>
region = eu-west-2

[profile mscqr-staging-database-role-cutover]
role_arn = arn:aws:iam::368992683803:role/mscqr-staging-database-role-cutover
source_profile = mscqr-staging-database-role-cutover-user
role_session_name = reviewed-database-role-cutover
mfa_serial = <dedicated-cutover-user-mfa-device-arn>
region = eu-west-2
```

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
8. `consumer-cutover`: require and corroborate a fresh verification receipt, prove the active admin-role task contains and transports the versioned identity script, separately register one backend revision changing only `backend.secrets[DATABASE_URL].valueFrom`, update the single staging service, wait, prove runtime identity `mscqr_staging_app`, run health/smoke checks, and re-inventory.
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

Cutover captures the pre-cutover task-definition ARN and preserved admin-secret ARN before the service update. Post-cutover inventory receives that preserved admin identifier and the app-secret ARN separately; it never derives the admin identifier from the updated service definition. Equal admin/app identifiers are an ambiguity and fail closed. A failed post-cutover inventory restores the captured pre-cutover task definition.

## Exact pre-APPLY commands

These commands are for the reviewed operator. The work documented on 2026-07-13 did not run any mutating command against AWS.

```bash
export AWS_PROFILE='mscqr-staging-plan'
export AWS_REGION='eu-west-2'
export MSCQR_STAGING_VPC_EXECUTOR='disposable-ecs-admin-task'
export MSCQR_STAGING_DB_ADMIN_TASK_DEFINITION_ARN='arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-staging-database-role-admin:2'

# Fully read-only AWS discovery: proves selected mechanism/topology and lists consumers.
node scripts/aws/staging-database-role-credentials.mjs discover

# Sanitized provisioning plan. It performs no PostgreSQL or Secrets Manager mutation.
scripts/aws/provision-staging-database-role-credentials.sh

# Switch to the exact assumed operator role before any broker invocation.
export AWS_PROFILE='mscqr-staging-database-role-operator'

# Reachability/identity probe. It starts one disposable ECS task but performs no
# PostgreSQL or Secrets Manager mutation. The human invokes only the broker;
# the broker constructs the fixed ECS request.
scripts/aws/provision-staging-database-role-credentials.sh --probe

# Runs the complete permission matrix using the three AWSCURRENT credentials
# inside the disposable task. It is not a connectivity-only probe.
export MSCQR_STAGING_DATABASE_VERIFY_CONFIRM='MSCQR_VERIFY_STAGING_DATABASE_ROLE_CREDENTIALS'
scripts/aws/verify-staging-database-role-permissions.sh --apply

# Switch away from the database-role operator. Cutover is outside its policy and
# requires a separately reviewed cutover identity even for its sanitized plan.
export AWS_PROFILE='mscqr-staging-database-role-cutover'

# Sanitized cutover plan; no task registration or service update.
export MSCQR_STAGING_DATABASE_ROLE_VERIFICATION_RECEIPT='use-the-exact-verification-receipt-path-printed-above'
export MSCQR_STAGING_HEALTH_URL='http://mscqr-stg-alb-euw2-1729860344.eu-west-2.elb.amazonaws.com/health/live'
export MSCQR_STAGING_REPRESENTATIVE_SMOKE_URLS='http://mscqr-stg-alb-euw2-1729860344.eu-west-2.elb.amazonaws.com/health/ready'
scripts/aws/cutover-staging-ecs-database-role.sh
```

Only after separate human approvals:

```bash
export AWS_PROFILE='mscqr-staging-database-role-operator'
export MSCQR_STAGING_DATABASE_CREDENTIALS_CONFIRM='MSCQR_PROVISION_STAGING_DATABASE_ROLE_CREDENTIALS'
scripts/aws/provision-staging-database-role-credentials.sh --apply

export AWS_PROFILE='mscqr-staging-database-role-cutover'
export MSCQR_STAGING_HEALTH_URL='http://mscqr-stg-alb-euw2-1729860344.eu-west-2.elb.amazonaws.com/health/live'
export MSCQR_STAGING_REPRESENTATIVE_SMOKE_URLS='http://mscqr-stg-alb-euw2-1729860344.eu-west-2.elb.amazonaws.com/health/ready'
export MSCQR_STAGING_ECS_DATABASE_ROLE_CUTOVER_CONFIRM='MSCQR_CUTOVER_STAGING_ECS_TO_APP_DATABASE_ROLE'
scripts/aws/cutover-staging-ecs-database-role.sh --apply
```

Provision approval does not authorize cutover. Broker invocation for a reachability probe is not implicit authorization for database or secret mutation. Provision and verify retain their separate exact confirmation gates.

## Local validation

```bash
npm run test:staging-database-role-credentials
npm run test:staging-database-role-runtime-identity-parser
npm run check:staging-database-role-operator-iam
npm run check:staging-database-role-cutover-iam
node --check scripts/aws/staging-database-role-credentials.mjs
node --check scripts/lib/staging-database-role-credentials-core.mjs
node --check backend/scripts/runtimeDatabaseIdentity.js
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

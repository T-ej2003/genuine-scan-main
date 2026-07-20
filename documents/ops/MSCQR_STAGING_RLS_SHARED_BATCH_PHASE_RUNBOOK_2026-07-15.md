# MSCQR staging shared batch RLS phase runbook — 2026-07-15

## Scope and current state

This is a staging-only, manually approved transition. It adds the reviewed
`app_auth` boundary and enables and forces RLS on `Organization`, `Licensee`,
`User`, and `ManufacturerLicenseeLink`. It does not alter the six already
protected batch-domain tables or any printer-domain table.

Before apply, `Batch`, `InventoryStatusRollup`, `QRCode`, `PrintJob`,
`PrintSession`, and `PrintItem` are already protected and each has its reviewed
SELECT policy assigned only to `mscqr_staging_rls_read`. Shared tables are not
protected and have no candidate policies. Stable backend revision 7 remains the
only serving service revision. Revision 9 is canary-only and correctly refuses
startup because its posture check requires all ten batch-read tables to have
ENABLE and FORCE RLS.

The helper task image and broker must first be released from this reviewed
commit by the separately approved infrastructure release process. The helper
image must contain `psql`, the three shared-phase SQL files, and the updated VPC
executor. The broker must accept only its fixed reviewed modes. Releasing those
two operator components is not authorization to update the backend ECS service.

## Review resolution: apply is blocked

Do not execute the shared-table apply in the current revision-7/revision-9
topology. The 2026-07-15 review proved that revision 7 performs `User` reads and
writes after its authentication context transaction has ended. The reviewed
`User` policy also permits only actor-self UPDATE and has no INSERT or DELETE
policy, so merely adding request context to `requestPasswordReset` and
`changeMyPassword` would still break user administration. RLS is database-wide;
an isolated revision 9 task cannot shield the serving revision 7 tasks.

The apply controller now refuses `apply` before any AWS call. This is the
fail-closed resolution until a separate reviewed compatibility change proves
all existing shared-table paths and either supplies the missing authorized
admin mutation boundary or explicitly retires those operations. That future
change must name an exact compatible service task-definition revision and
remove the controller block in the same review. Verification and rollback stay
available for catalog inspection and emergency recovery.

## Hard safety rules

- Database: exactly `mscqr_staging`; executor: exactly `mscqr_staging_admin`.
- Stable service revision 7 remains serving and is never updated by these scripts;
  therefore the shared-table apply remains prohibited.
- Revision 9 remains a one-off canary until every gate below passes.
- `MSCQR_STAGING_RLS_BATCHES_READ_ENABLED=true` exists only on revision 9.
- `MSCQR_STAGING_RLS_BATCH_ALLOCATION_MAP_ENABLED=false` everywhere.
- `MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED=false` everywhere.
- No local process retrieves `DATABASE_URL`; ECS injects the administrative secret.
- Never enable RLS or create policies on printer-domain tables in this phase.
- Never run either SQL file through Prisma, CI/CD, Terraform, or application startup.
- A failed SQL assertion aborts the transaction; do not retry until the mismatch is understood.

## Preflight checklist

1. Confirm the reviewed commit passed all local checks listed at the end of this document.
2. Confirm a recent RDS snapshot or equivalent staging restore point and named rollback operator.
3. Assume `mscqr-staging-database-role-operator`; it must have no secret-value access and no direct ECS `RunTask` authority.
4. Install the reviewed operator policy update that grants only
   `logs:GetLogEvents` on
   `/ecs/mscqr-staging-backend/database-role-admin/db-admin/*`; the controller
   must validate the SQL evidence rather than trusting exit code alone.
5. Obtain the exact active `mscqr-staging-database-role-admin:<revision>` ARN
   and immutable `mscqr-backend@sha256:<digest>` image reference from the same
   reviewed infrastructure release output.
6. Confirm its single `db-admin` container uses that exact digest reference,
   the administrative `DATABASE_URL` secret, private subnets, the staging ECS
   security group, no public IP, a read-only root filesystem, and all three
   route flags `false`.
7. Confirm the service is still exactly revision 7 with desired count equal to running count and no secondary deployment.
8. Confirm revision 7 has all three route flags `false` and revision 9 has only batches-read `true`.
9. Confirm the current catalog matches the state described above. Do not use the broad 2026-07-09 candidate template.
10. Through the same ECS administrative helper, run a read-only/rolled-back
   capability rehearsal that begins a transaction, grants
   `mscqr_staging_auth_owner` to `mscqr_staging_admin` with `ADMIN FALSE,
   INHERIT FALSE, SET TRUE`, revokes it, and rolls back. PostgreSQL 18 requires
   the executor to hold ADMIN OPTION (or equivalent managed administrative
   authority); `CREATEROLE` alone is insufficient. No membership may remain.
11. Create a private evidence directory and disable shell tracing:

```bash
set +x
set -o pipefail
umask 077
export MSCQR_SHARED_RLS_EVIDENCE_DIR="documents/ops/evidence/staging-rls-shared-batch-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$MSCQR_SHARED_RLS_EVIDENCE_DIR"
chmod 700 "$MSCQR_SHARED_RLS_EVIDENCE_DIR"
```

## Exact apply command — intentionally blocked

Replace only the helper revision placeholder with the exact reviewed ARN. The
controller independently proves stable revision 7, canary revision 9 flags,
helper topology, immutable helper image, and the administrative secret reference.
In the current reviewed code the final command exits with status 2 before an
AWS call and reports the revision-7 `User` compatibility block.

```bash
export AWS_PROFILE='mscqr-staging-database-role-operator'
export AWS_REGION='eu-west-2'
export MSCQR_STAGING_VPC_EXECUTOR='disposable-ecs-admin-task'
export MSCQR_STAGING_DB_ADMIN_TASK_DEFINITION_ARN='arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-staging-database-role-admin:<reviewed-revision>'
export MSCQR_STAGING_RLS_HELPER_IMAGE_REF='368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:<reviewed-digest>'
export MSCQR_CONFIRM_STAGING_RLS_SHARED_BATCH_PHASE='MSCQR_APPLY_STAGING_RLS_SHARED_BATCH_PHASE'
scripts/aws/apply-staging-rls-shared-batch-phase.sh 2>&1 | tee "$MSCQR_SHARED_RLS_EVIDENCE_DIR/apply-task.json"
unset MSCQR_CONFIRM_STAGING_RLS_SHARED_BATCH_PHASE
```

Do not treat this expected refusal as an apply failure to retry. After the
separate compatibility review removes the hard block, success will require
exit code zero and controller-validated CloudWatch SQL JSON with `protectedTableCount: 10`,
`candidateSelectPolicyCount: 10`, `sharedPolicyCount: 7`,
`printerTablesChanged: false`, `batchPoliciesChanged: false`, and a non-empty
CloudWatch log stream. A non-zero helper exit means PostgreSQL rolled back the
transaction.

## Exact verification command

```bash
scripts/aws/verify-staging-rls-shared-batch-phase.sh 2>&1 | tee "$MSCQR_SHARED_RLS_EVIDENCE_DIR/verify-task.json"
```

Success proves the ten-table ENABLE/FORCE posture, exact policy roles and
counts, the two SECURITY DEFINER signatures and ownership, exact auth-owner
object/column grants, empty-context fail-closed reads, no read-role writes,
preserved app CRUD, and zero protected printer tables.

## Immediate password-login and MFA smoke

This sequence is retained for the future compatible rollout; it is not
authorized while apply is blocked. Run it against the reviewed compatible
staging service immediately after catalog verification. Use an existing enrolled staging admin test account. Do
not place passwords, TOTP codes, cookies, tickets, tokens, or raw response bodies
in the evidence directory. Shell tracing stays disabled.

1. In a private temporary directory, submit `POST /api/auth/login` with the
   normalized staging email and password, storing cookies and the JSON response
   only in that directory.
2. Require HTTP 200, `success=true`, `data.auth.sessionStage=MFA_BOOTSTRAP`,
   `data.auth.mfaRequired=true`, and a non-empty challenge ticket. Record only
   those booleans and the status code.
3. Read the `aq_csrf` value from the private cookie jar. Submit
   `POST /api/auth/mfa/challenge/complete` with header `x-csrf-token`, the ticket,
   `method=totp`, and a freshly entered TOTP code. Require HTTP 200,
   `success=true`, `data.auth.sessionStage=ACTIVE`, and a non-null
   `data.auth.mfaVerifiedAt`.
4. With the resulting private cookie jar, call `GET /api/auth/me`. Require HTTP
   200, `data.authenticated=true`, and `data.mfaVerified=true`.
5. Delete the temporary directory. Save only a compact pass/fail summary as
   `$MSCQR_SHARED_RLS_EVIDENCE_DIR/auth-smoke-safe-summary.json` with no identity,
   cookie, token, ticket, code, password, or response-body fields.

Any login lookup, lockout update, MFA completion, session issue, or `/auth/me`
failure is an immediate rollback trigger. Do not start revision 9.

## Exact revision 9 canary sequence

This historical revision 9 sequence is not safe to run after shared-table apply
until the compatibility prerequisite is resolved. A future deploy-capable
staging operator may use it only after apply, verification, and auth smoke pass.
It starts one isolated task; it does not update the service or
register a task definition. The network configuration is copied read-only from
the stable service.

```bash
# Use the same separately reviewed identity that launched the existing revision
# 9 one-off canary; do not substitute the database-role operator.
export AWS_PROFILE='<reviewed-one-off-staging-canary-profile>'
export AWS_REGION='eu-west-2'
export MSCQR_STAGING_CLUSTER='mscqr-staging-euw2-main'
export MSCQR_STAGING_SERVICE='mscqr-staging-backend-service-euw2'
export MSCQR_CANARY_TASK_DEFINITION='arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-staging-backend:9'
export MSCQR_CANARY_NETWORK_JSON="$(aws ecs describe-services --cluster "$MSCQR_STAGING_CLUSTER" --services "$MSCQR_STAGING_SERVICE" --query 'services[0].networkConfiguration' --output json)"
export MSCQR_CANARY_TASK_ARN="$(aws ecs run-task --cluster "$MSCQR_STAGING_CLUSTER" --task-definition "$MSCQR_CANARY_TASK_DEFINITION" --launch-type FARGATE --count 1 --enable-execute-command --network-configuration "$MSCQR_CANARY_NETWORK_JSON" --query 'tasks[0].taskArn' --output text)"
aws ecs wait tasks-running --cluster "$MSCQR_STAGING_CLUSTER" --tasks "$MSCQR_CANARY_TASK_ARN"
aws ecs describe-tasks --cluster "$MSCQR_STAGING_CLUSTER" --tasks "$MSCQR_CANARY_TASK_ARN" --query 'tasks[0].{taskArn:taskArn,lastStatus:lastStatus,healthStatus:healthStatus,taskDefinitionArn:taskDefinitionArn,containers:containers[].{name:name,lastStatus:lastStatus,healthStatus:healthStatus,exitCode:exitCode,reason:reason}}' --output json | tee "$MSCQR_SHARED_RLS_EVIDENCE_DIR/revision-9-canary-task.json"
aws ecs execute-command --cluster "$MSCQR_STAGING_CLUSTER" --task "$MSCQR_CANARY_TASK_ARN" --container backend --interactive --command "node -e \"fetch('http://127.0.0.1:4000/health/ready').then(async r=>{console.log(JSON.stringify({status:r.status,ok:r.ok}));process.exit(r.ok?0:1)}).catch(()=>process.exit(1))\""
```

Inspect the revision 9 CloudWatch stream for the ten-table startup-posture pass,
absence of secret output, and no auth/RLS errors. Stop only the one-off canary
after evidence capture:

```bash
aws ecs stop-task --cluster "$MSCQR_STAGING_CLUSTER" --task "$MSCQR_CANARY_TASK_ARN" --reason 'Reviewed shared batch RLS canary evidence complete'
aws ecs wait tasks-stopped --cluster "$MSCQR_STAGING_CLUSTER" --tasks "$MSCQR_CANARY_TASK_ARN"
```

## Service cutover criteria

Cutover is a separate approval and is permitted only when all of these are true:

- Apply, catalog verification, login/MFA/`auth/me`, and revision 9 one-off
  startup/readiness evidence all pass in the same change window.
- Stable revision 7 is still healthy and remains the sole service deployment.
- Revision 9 still has exactly batches-read `true`; allocation-map and printer
  flags remain `false`.
- No shared-table assertion, empty-context leak, read-role write, auth bootstrap
  failure, printer-domain change, or batch-policy drift exists.
- The rollback operator is present with the exact command below.

This runbook does not authorize or automate the ECS service update. After a
separately reviewed cutover, immediately validate password login, MFA, `/auth/me`,
and `GET /api/qr/batches`; stop and restore revision 7 on any regression. Do not
test allocation-map or manufacturer-printer flags in this phase.

## Rollback triggers and exact command

Rollback immediately for any SQL/helper non-zero exit, auth or MFA regression,
revision 9 startup/readiness failure, unexpected policy/role/grant/catalog row,
row exposure with empty context, read-role write capability, batch-policy drift,
or printer-domain RLS/policy change. If a service cutover occurred under separate
authority, restore revision 7 and drain revision 9 before database rollback.

```bash
export AWS_PROFILE='mscqr-staging-database-role-operator'
export AWS_REGION='eu-west-2'
export MSCQR_STAGING_VPC_EXECUTOR='disposable-ecs-admin-task'
export MSCQR_STAGING_DB_ADMIN_TASK_DEFINITION_ARN='arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-staging-database-role-admin:<same-reviewed-revision-used-for-apply>'
export MSCQR_STAGING_RLS_HELPER_IMAGE_REF='368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:<same-reviewed-digest-used-for-apply>'
export MSCQR_CONFIRM_STAGING_RLS_SHARED_BATCH_PHASE_ROLLBACK='MSCQR_ROLLBACK_STAGING_RLS_SHARED_BATCH_PHASE'
scripts/aws/rollback-staging-rls-shared-batch-phase.sh 2>&1 | tee "$MSCQR_SHARED_RLS_EVIDENCE_DIR/rollback-task.json"
unset MSCQR_CONFIRM_STAGING_RLS_SHARED_BATCH_PHASE_ROLLBACK
```

The rollback must report zero protected shared tables, six preserved protected
batch tables, six preserved batch policies, unchanged runtime table grants, and
no printer changes. Re-run the auth smoke against revision 7 after rollback.

## Expected final posture and evidence

This posture is a future target, not the current authorized state. After a
future compatible apply and before service cutover: ten batch-read tables have
ENABLE and FORCE RLS; ten candidate SELECT policies exist; shared SELECT
policies target app plus read roles; the six batch SELECT policies still target
only the read role; two exact `app_auth` functions are owned by the NOLOGIN auth
owner; printer tables remain RLS OFF; revision 7 still serves; revision 9 remains
canary-only.

Keep only sanitized artifacts under the private directory created above:

- `apply-task.json`
- `verify-task.json`
- `auth-smoke-safe-summary.json`
- `revision-9-canary-task.json`

CloudWatch is the authoritative task log; the controller reads the exact helper
stream, validates the mode-specific SQL evidence fields, and merges them into
the apply/verify/rollback JSON alongside the group, stream, and image digest.
Never copy raw database URLs, ECS secret values, passwords,
cookies, access/refresh tokens, MFA tickets/codes, or raw auth bodies into repo
evidence.

## Local validation before operator handoff

```bash
npm --prefix backend run build
npm --prefix backend run test:rls:read-client
npm --prefix backend run test:rls:auth-bootstrap
npm run test:staging-rls-shared-batch-phase
npm run test:staging-database-role-credentials
git diff --check
```

## CTO recommendations after this phase

1. First design a separately reviewed shared-table compatibility phase covering
   authenticated request context, password-reset token context, background jobs,
   and admin INSERT/DELETE/cross-user UPDATE authorization. Do not weaken the
   current candidate predicates ad hoc.
2. Add a brokered, credential-safe canary route probe before any future service
   cutover; the current one-off canary proves startup/readiness but not ALB route
   selection.
3. Add staged latency and RLS-denial metrics for the batch read pool before
   enabling another route; expand only after measured p95 and denial rates are stable.
4. Keep allocation-map and printer rollout as separate, independently reversible
   phases with their own table graph, policies, canary proof, and rollback.

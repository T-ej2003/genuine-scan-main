# November 12 print diagnostic scope and authorization boundary

This is a review package, not production execution approval. No production business rows were read and no diagnostic execution receipt exists.

## One-use execution package

The fixed implementation is `backend/scripts/production-incident-diagnostic-{queries,sql,task}.mjs` with its authorization contract in `scripts/aws/production-incident-diagnostic-authorization.mjs`. It is bound to the deployed incident source `7407b80b7919ca88f53e4a6d05596701fe00d0e0`; the diagnostic image must be built from the exact future protected-main commit containing these files. The existing backend-only image publisher supplies the immutable digest and signed publication evidence. The incident-specific authorization workflow reuses GitHub's existing protected `production` environment; it adds no second human approval.

The approved task would use the existing `mscqr_prod_admin` credential only to atomically create and later remove schema `mscqr_incident_20261112`, one fixed `SECURITY DEFINER` function, and eleven exact-scope `SELECT` policies. The canary database identity `mscqr_prod_rls_canary_read` gets `USAGE` only on that temporary schema and `EXECUTE` only on that function. It receives no table grant, `BYPASSRLS`, or membership. The function uses `search_path=pg_catalog,pg_temp`, checks the source, database, role, application name, execution ID, expiry and read-only transaction, and returns fixed bounded metadata. The task runs no application startup migration or print action. **The setup and cleanup are production catalogue mutations** and require explicit authorization of their SQL digests; they are not a permanent migration.

The ECS execution role is the existing 49-object executor execution role, which already reads the exact admin-password secret and can pull `mscqr-backend`. It needs one temporary, expiry-bound `GetSecretValue` grant on the existing read-only canary URL secret. The task role is the existing canary task role; it needs only two exact S3 journal object keys under the one-use execution ID. Both temporary IAM policies must be absent before installation, read back exactly after installation, and removed/read back after the task stops. `mscqr-ops-admin` IAM simulation permits the scoped register/run/pass-role and inline-policy operations; this simulation does not replace live permission or Organizations checks. AWS root is not needed for the proposed execution path.

The task writes an S3 reservation with `If-None-Match:*` before SQL, reads it back, executes one provision/read/cleanup cycle, and writes a terminal receipt with redacted results, row counts, execution identity, SQL digests and readback hash. A missing terminal receipt, failed cleanup, or expired window is **indeterminate**, not success. The temporary function has a 30-minute clock gate even if task cleanup fails. An abnormal task stop after provision requires exact reviewed cleanup; the same one-use task must not be replayed. No business-table update, print retry or job-state change is authorized.

Disposable PostgreSQL 18.4 verification: provision/read/teardown passed, canary direct `Printer` SELECT was denied, a wrong execution ID was denied, exact printer metadata returned without embedded payload bytes, foreign synthetic printer data was absent, schema ownership and function `EXECUTE` grants were inspected, and no schema/policies or synthetic rows remained after cleanup. This proves local behavior only. Production role/grant and target-catalogue preflight remain mandatory at execution time.

## Verified identity and target

- `aws sts get-caller-identity --profile default --region eu-west-2` returned account `368992683803` and `arn:aws:iam::368992683803:root`. STS did not establish MFA status. Root was used only for that identity readback.
- The active backend ECS service uses task definition `mscqr-production-rls-green-backend-candidate:46`. Its `DATABASE_URL` and `AUTHENTICATED_APP_DATABASE_URL` reference the existing phase2 application database secret. Its value was parsed in memory without printing the credential: host `mscqr-production-rls-green-phase2.c3ewey6o6mq5.eu-west-2.rds.amazonaws.com`, database `mscqr_production_rls_green_phase2`, user `mscqr_prd_rls_phase2_app`.
- RDS instance `mscqr-production-rls-green-phase2` is available, PostgreSQL 18.4, in `eu-west-2`. RDS `DBName` is the instance's initial database name, not proof of the application's current database selection.

## Existing paths

| Path | Established contract | Decision |
| --- | --- | --- |
| `mscqr-production-full-rls-green-read-only-canary:20` | Fixed source-controlled canary command; reviewed `mscqr_prod_rls_canary_read` role has no business-table read grants. | Cannot inspect `PrintJob`, `PrintSession`, or `Printer.metadata`. Live grants were not queried; the fixed command alone excludes these reads. |
| Manufacturer `GET /api/manufacturer/print-jobs` and `GET /api/manufacturer/print-jobs/:id` | Existing authenticated, tenant-scoped `printing_readiness` projection. | Can read authorized job and session status through a valid manufacturer application session. No such session is available in this CLI context; AWS root cannot substitute for it. The response includes QR details, which must be withheld from diagnostic output. |
| Manufacturer printer maintenance inventory | Authenticated `POST` invoking `printing_printer_administration`; its SQL uses `FOR UPDATE` and maintenance state gates. | Not a strictly read-only diagnostic operation. |
| Older `mscqr-production-full-rls-green-readonly-diagnostic:10` | Inline `psql` with `mscqr_prod_admin` credentials and an old release identity. | Not tenant-scoped or authorized for this incident. Do not run or override it. |

## Exact subjects for independent diagnostic review

- Print creation request `970e5ca7-19d3-46bb-a05d-e8533def35be`, UTC 2026-11-12 11:35:48–11:35:50.
- Manufacturer `cd8ddbcd-ce8f-4cc1-8178-9e65140c1c68`, licensee `07083e4d-3891-4afe-ad23-6c16bbdeb8c3`, batch `3f0eb49e-7536-46d4-8ff9-b680a5c7b58a`, production printer `ac73d03e-69de-4c71-a793-07afa6b36937`.
- Historical job candidate `197d65b3-cbea-4ff4-8a2f-258e4dcf5493`, session `a2b67795-d8dc-4d3e-8674-bd41e3da16c3`, created 2026-11-10 22:59:20 for that batch/manufacturer. It is not proven to be the current conflicting job.
- Test-label request `dc0d47a4-e71e-436b-aa95-396fd29208f7`, UTC 2026-11-12 11:45:21–11:45:25, printer `3983f773-9383-4a42-a176-e733ff049163`. This differs from the production printer profile above; equivalence must not be assumed.

The proposed diagnostic must be independently reviewed and authorized before execution. It must bind the exact RDS instance and database, tenant/manufacturer, batch, two printer IDs, request IDs, execution identity, reviewed command digest, and one execution window. It must use a `NOBYPASSRLS` identity with verified effective read permissions and tenant context, a read-only transaction, bounded statements, and no `FOR UPDATE`. Return only:

1. `PrintJob`/`PrintSession` IDs, statuses, printer IDs, creation/update/completion timestamps, and bounded lifecycle transition metadata for the matching batch and manufacturer. Apply the guard's exact active status predicates (`PrintJob` `PENDING/SENT/PAUSED`; `PrintSession` `ACTIVE/PAUSED/RESUME_PENDING`).
2. For the exact test printer, `Printer.metadata.pendingLocalAgentTestLabel` fields `testJobId`, `status`, `createdAt`, `expiresAt`, `claimedAt`, `ackedAt`, `confirmedAt`, `failedAt`, `deviceJobRef`, and redacted acknowledgment/confirmation metadata. Correlate only the exact test request and any signed connector record actually present.
3. No QR codes, serialized payloads, credentials, session capabilities, or raw printer command bytes.

Before execution, obtain independent exact-head technical review of the source-bound read command, role/grant and FORCE RLS readback, tenant-binding proof, IAM/task definition, output redaction, evidence destination, and expiry. The existing `production` environment then requires the actual operator approval for the exact one-use package. MSCQR currently has one technical operator; the environment permits that operator to approve the run. Do not invent a second human approver. AWS root identity alone is not database authorization. The execution receipt must be generated only after an actual approved read and must record caller, role, target, scope, command digest, UTC time, row counts, and redacted result digest.

The repository's production recovery runbook requires separate technical review and explicit authorization for any new privileged action, and prohibits arbitrary ECS launches and direct privileged SQL sessions. The existing backend-log diagnostic and catalogue canary do not authorize business-row reads. This package uses one incident-specific task and the existing protected `production` environment approval model. The task's temporary diagnostic schema, eleven scoped RLS policies, and function are production catalogue mutations, so they must be included explicitly in the approved execution package. They are provisioned and removed in bounded transactions; a task crash after provision requires reviewed cleanup before another diagnostic attempt.

## Other approved investigation domains

The operator additionally authorized dashboard, authentication, support-report and batch-consistency diagnosis. The source path for dashboard is `operational_read_bind_actor` (which calls `app_auth.require_authenticated_session`), then `dashboard_scope_fingerprint`, then a mandatory `AuditLog` insert inside `authorize_dashboard_snapshot`; a strictly read-only task must inspect their definitions and retained telemetry, not execute this write-bearing function. Production telemetry identifies the outer `dashboard_snapshot_scope` call as exceeding its 5-second transaction budget, but not its slow internal statement. The RDS parameter group has no configured `auto_explain.log_min_duration` or `log_min_duration_statement`; inner-statement timing is not established by those sources.

Any one-time diagnostic extension must separately enumerate bounded catalogue/telemetry reads and tenant-scoped business-row reads for these domains, with their exact predicates and output fields reviewed before task registration. Do not grant blanket table access or infer support-report authorization failure from a screenshot without a retained request ID or backend rejection event.

## Current result

`ACTIVE_PRINT_JOB_EXISTS` is confirmed for the November 12 request. The exact conflicting row, current session, lifecycle transition history, test-label queue record, claim, spool outcome, and acknowledgment remain **unverified**. No production database mutation, job action, printing action, task launch, or business-row read occurred.

The November 12 backend emitted `print_job_created` for the rejected request before the transaction failed. That event records an in-transaction stage, not a committed job; it must not be used as proof of another durable print job.

## Local correction and evidence limits

- The exact `P2010/P0001 ACTIVE_PRINT_JOB_EXISTS` error is locally classified as tenant-safe HTTP 409. The browser now directs the operator to review the existing run without suggesting a retry. The SQL active-job guard remains unchanged. `node backend/tests/printJobLifecycleErrorResponse.test.js` and `npx vitest run src/test/batch-print-operations.test.ts` pass; neither test proves the production job's current state.
- At 2026-11-12 11:23:51 UTC the backend logged `GET /api/events/dashboard` diagnostic request `413fe429-fa4d-4bdb-827e-0f6da0cb4663`: `scope` stage 7881.3 ms, Prisma P2028 after 7880 ms against a 5000 ms transaction budget. The scope wrapper binds the actor before aggregation, and the inner scope function writes an AuditLog record. The retained event does not time individual internal SQL statements. No read-only task may execute the write-bearing scope function.
- At 2026-11-12 11:35:50 UTC print creation request `970e5ca7-19d3-46bb-a05d-e8533def35be` logged `P2010/P0001 ACTIVE_PRINT_JOB_EXISTS` and HTTP 500. The SQL guard compares active job and session states for the same batch and manufacturer; the row that satisfied it is not logged.
- At 2026-11-12 11:45 UTC the operator observed test-label HTTP acceptance for request `dc0d47a4-e71e-436b-aa95-396fd29208f7`, without physical output. The queue lives in `Printer.metadata.pendingLocalAgentTestLabel`; no retained log in the inspected backend evidence reveals the queue ID or subsequent claim/acknowledgment.
- `POST /api/support/reports` traverses authentication, `requireOpsUser`, tenant isolation and CSRF before the controller. The inspected backend log has no correlating request ID for the reported 403, so the rejecting gate is unknown. Authoritative batch/count rows were not read, so production count consistency is unknown.
- The sanitized Windows acceptance network record captures simultaneous HTTP 503 responses labelled `Authentication is temporarily unavailable` at 11:39:35 UTC for attention queue (`f1cb837c-5e8c-42fc-9791-4337e99414e9`), manufacturer printers (`f4c22780-82c5-40e4-a6da-593cb8181ff5`), and QR stats (`a49f1f7e-79c1-41fa-bdcb-1e9bb1fe0e8f`). It also captures a successful refresh at 11:39:33 UTC and a later successful batch response taking 15,106.962 ms. These observations establish intermittent failures and latency, not the failing authentication SQL or a shared database root cause.

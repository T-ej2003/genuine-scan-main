# Scheduled-job database identity

## Implemented boundary

The compliance-pack scheduler no longer finds or impersonates a platform user. Its database authority is a 32-byte, base64url opaque capability whose SHA-256 digest is stored in `ScheduledJobCredential`. The row binds the credential to `identity-scheduled-job`, the `compliance-pack` family, one schedule ID, expiry, revocation state, and rotation lineage. Raw capabilities are held only by the scheduled runtime and are never persisted, logged, returned by SQL, or placed in job/audit payloads.

The production path is:

`scheduler -> withB03ScheduledContext -> exact app_rls scheduled function -> scheduled_job_prepare -> locked credential hash verification -> live Organization/Licensee scope -> FORCE-RLS operation`.

`CompliancePackJob.scheduledScheduleId` durably binds every scheduled job to the verified schedule. Terminal transitions are atomic compare-and-set updates requiring the same verified schedule, so a credential for one schedule cannot complete or fail another schedule's job.

## Roles and grants

- The dedicated scheduled and operator runtime identities are LOGIN, NOINHERIT, non-superuser and non-`BYPASSRLS` roles.
- The shared reviewed auth function owner is NOLOGIN, non-`BYPASSRLS`, and owns no application table.
- The operator can execute only credential provision and revocation signatures.
- The scheduler can execute only claim, get, complete and fail signatures.
- Internal verification and audit helpers have no runtime grant.
- Runtime identities have no direct table privileges for credentials, compliance jobs, idempotency keys, reports, or audit outbox rows.
- Every boundary revokes PUBLIC execution and fixes `search_path` to `pg_catalog,public`.

## Lifecycle and concurrency

Provisioning stores a unique `sha256-v1` digest and enforces one active credential per identity/family/schedule. Rotation revokes the predecessor and inserts the successor in one transaction. Explicit revocation is idempotent. Verification atomically updates `lastUsedAt` while locking the matching active row, which gives deterministic revoke-versus-use ordering.

Claiming creates one daily idempotency key per schedule and licensee, one RUNNING scheduled job, its tenant-scoped report, and audit outbox evidence atomically. Duplicate claims return no new work. Completion and failure use RUNNING-to-terminal compare-and-set updates; concurrent terminal operations produce one winner. Rollback removes the credential-use timestamp update, job, idempotency state, report linkage and audit outbox effects together.

## Migration and rollback

The forward migration adds the nullable schedule binding to existing compliance jobs, so historical and manual rows remain compatible. Only new reviewed scheduled claims populate it. The scheduled credential table is new and contains no deploy-time secret. Runtime provisioning must occur after schema/package installation and before enabling the scheduler.

Rollback order is: disable the scheduled caller, revoke active scheduled credentials, execute the generated function/policy rollback, remove the package roles through the clean-room cleanup entrypoint, and roll back the Prisma migration only after proving no scheduled job depends on the new schedule binding. Generated rollback SQL removes exact functions and policies; it never broadens access as a compatibility fallback.

## Local certification evidence

`backend/tests/rls-wave-b/b03/scheduledJobIdentityPostgres18.test.js` runs through the actual restricted operator, scheduled, application and bootstrap identities on fresh PostgreSQL 18. It covers hash-only storage, exact ACLs, owner attributes, FORCE RLS, malformed/forged/expired/revoked credentials, forged GUC denial, direct-table denial, concurrent single-winner claims, terminal compare-and-set behavior, rotation, rollback and transaction-local context cleanup. `scripts/tests/scheduled-job-identity-contract.test.mjs` seals the source contract and rejects blanket grants or runtime helper exposure.

This is local disposable certification only. It does not enable a production scheduler or certify any staging/production database.

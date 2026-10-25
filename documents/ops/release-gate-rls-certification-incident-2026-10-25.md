# Release Gate RLS certification incident — 2026-10-25

Release Gate run `40193506815` failed in disposable PostgreSQL certification before AWS credentials or the backend recovery mutation step. The production backend remained on task definition `mscqr-production-rls-green-backend-candidate:24` at 0/2. This correction makes no production database or ECS change.

## Cause and correction

1. `authenticationClosurePostgres18.test.js` looked up MFA and manufacturer audit rows by their original request ID. The B03 audit trigger intentionally gives each bare SQL event its own immutable `requestId` and stores the original in `authorityProvenance.originalRequestId`. The test now verifies that provenance and the full B03 audit-record contract. Its logout rollback fixture now supplies the canonical payload digest and idempotency key, so the intended transaction rollback is actually exercised.
2. The QR scan analytics SQL mixed a UTC `timestamp` with a session-zone `timestamptz` when deriving its default 90-day window. Across the Europe/London daylight-saving change, the window became 90 days plus one hour and failed `QR_INVALID_INPUT`. The source now computes both boundaries as UTC timestamps. A fixed-date PostgreSQL test compares the default and explicit windows with the session timezone set to Europe/London.

The RLS package was regenerated with `npm run rls:full-generate`. No Prisma migration, RLS policy, role grant, or FORCE RLS rule changed. Generated hashes changed because the certified executable inputs and SQL function changed.

## Verification and recovery

`npm run rls:full-verify` and the full disposable PostgreSQL 18 certification passed locally on PostgreSQL 18.6. The certification reported 78 FORCE RLS targets, 374 generated policies, 11 application-path workflows, exact catalog-tamper rejection, rollback verification, and zero green-database or managed-role residue. The existing PostgreSQL 18 CI certification loop now also runs `manufacturer-scope`, so this failure is exercised before merge on the pinned CI database image.

After this PR merges, authenticate the new protected-main SHA, reconcile run `40193506815` and live ECS before any new dispatch, and renew source-bound image, runtime, database, ticket, operator, and protected-environment evidence as their contracts require. Resume the existing `backend-health-recovery` Release Gate lane. Verify ECS 2/2, ALB target health, database connectivity, smoke tests, and component-state commit before declaring recovery complete.

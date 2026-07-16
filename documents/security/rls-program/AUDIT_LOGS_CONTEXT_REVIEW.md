# Audit Logs Context Boundary Review

Workflow: `workflow-http-backend-src-controllers-audit-controller-ts-get-logs`.

## Registered boundary

`GET /api/audit/logs` runs the pre-auth rate limiter, authentication, `requireAuditViewer`, fresh administrator MFA, tenant isolation and authenticated route/IP/actor limiters before `getLogs`. Approved callers are licensee/organization administrators, manufacturer roles and platform administrators. No ordinary authenticated role is admitted.

Tenant administrators are fixed to their authenticated licensee. Manufacturers are fixed to their own actor ID and one authenticated or linked licensee. Platform administrators must provide one UUID licensee plus a non-empty purpose; the role name alone never creates platform-wide access. All callers require an active actor, request ID and fresh MFA. Optional organization, manufacturer and actor identifiers may only match or narrow the proven boundary.

## Query and response contract

`withCanonicalDbContext` installs all eight approved `app.*` keys transaction-locally. `queryAuditLogs` receives only the transaction client. One shared `where` object is used by count and list inside a `REPEATABLE READ` transaction; user-name enrichment and `AUDIT_LOGS_READ` attribution use the same client before commit. Ordering is `createdAt DESC, id DESC`; limit is 1–500, offset is 0–20,000, cursor and non-zero offset cannot be combined, and supplied date ranges require both endpoints and may span at most 90 days.

Protected tables are `AuditLog` for SELECT/INSERT and `User` for SELECT. Audit rows use explicit projections and never select `ipHash`. Non-platform callers receive null IP address and user-agent values. User enrichment selects only ID and name and retains the existing `email` response key as an empty string. Nested details, arrays, before/after objects and delivery metadata are recursively redacted for password, token, secret, credential, authorization, cookie, private-key, MFA, OTP, hash, session, API-key and signing keys without changing stored data.

## Proof and remaining work

`backend/tests/auditLogQueryContext.test.js` proves the three approved actor boundaries, filter narrowing, shared count/list scope, same-transaction ordering, enrichment and attribution, response compatibility, global-client exclusion, pre-context rejection, foreign/blank/tampered scope denial, assurance and purpose denial, bounded date/pagination validation and recursive nested redaction. Route and response-surface regression tests remain supporting evidence.

This is application compatibility proof only. Disposable PostgreSQL certification must still prove exact grants, `AuditLog` and `User` policy enforcement, empty-context denial and cross-tenant denial before production readiness.

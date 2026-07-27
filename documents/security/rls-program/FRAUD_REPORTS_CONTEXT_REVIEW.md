# Fraud Reports Context Boundary Review

Workflow: `workflow-http-backend-src-controllers-audit-controller-ts-get-fraud-reports`.

## Approved HTTP boundary

The registered path is `GET /api/audit/fraud-reports`: pre-auth rate limiting, authentication, platform-administrator authorization, fresh administrator MFA, tenant-isolation middleware, authenticated rate limits, then `getFraudReports`. Tenant administrators, manufacturers and ordinary users are not approved callers; this slice does not broaden that route.

Every approved request supplies one UUID `licenseeId`, a non-empty purpose of at most 240 characters, an authenticated request ID and a fresh active platform-administrator session. Limit is 1–500, offset is 0–20,000, status is restricted to the existing status vocabulary, and no date-range input exists on this endpoint. Missing or blank scope is denial rather than a platform-wide wildcard.

## Transaction and projection

`withCanonicalDbContext` installs `app.user_id`, `app.role`, `app.organization_id`, `app.licensee_id`, `app.manufacturer_id`, `app.auth_assurance`, `app.request_id` and `app.purpose` transaction-locally. `queryFraudReports` receives only the transaction client and rejects a query licensee that differs from installed context. Count, report rows, response rows and the immutable read-attribution event complete before the transaction closes; JSON response serialization follows it.

The only protected table is `AuditLog`. Report reads explicitly select ID, creation time, licensee, details and IP address; response reads select ID, creation time, actor and details. Ordering is deterministic by creation time then ID. The public response shape is retained, while secret-bearing keys inside delivery metadata are recursively replaced with `[REDACTED]`; raw hashes, tokens, MFA material and credentials are not projected as top-level fields.

## Contract proof and remaining work

`backend/tests/fraudReportQueryContext.test.js` proves fresh-MFA platform access, bounded filters, same-client ordering, scope mismatch denial, blank and missing context denial, non-platform denial, global-client exclusion, explicit projections, attribution and recursive redaction. `backend/tests/routeSecurityContracts.test.js` remains route-registration evidence.

This is application-boundary proof only. Disposable PostgreSQL certification must still prove exact grants, the future `AuditLog` SELECT/INSERT policy behavior, foreign-licensee denial and empty-context denial before the workflow can be production-certified.

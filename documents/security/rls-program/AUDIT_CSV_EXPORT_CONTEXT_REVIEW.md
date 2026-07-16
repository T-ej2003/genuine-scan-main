# Audit CSV export context-boundary review

Workflow: `workflow-http-backend-src-controllers-audit-controller-ts-export-logs-csv`

Status: context boundary implemented; disposable PostgreSQL RLS certification pending.

## Execution path

`GET /api/audit/logs/export` is registered by `backend/src/routes/auditRoutes.ts`. The route applies the pre-authentication, actor and IP rate limits, authenticates the signed session, checks the audit-viewer role, requires recent administrator MFA where the role ceiling applies, and enforces tenant isolation before `exportLogsCsv` validates the bounded query.

The controller delegates database work to `auditCsvExportService.ts`. The service resolves scope from authenticated claims, opens one interactive Prisma transaction, installs canonical context through `canonicalDbContext.ts`, reads the scoped `User` identifiers and `AuditLog` projection, reads display names, and appends one immutable `AUDIT_CSV_EXPORT` attribution event. The bounded result is materialized before the transaction closes; CSV serialization and the HTTP response occur afterwards.

## Boundary contract

- Licensee and organization administrators use their authenticated `licenseeId`; a different requested tenant or a missing authenticated tenant fails before a transaction begins.
- Manufacturer roles remain actor-scoped. A supplied licensee must be one of the authenticated durable links and never broadens the audit predicate beyond the manufacturer actor.
- Platform administrators require an active session, fresh admin MFA, one explicit licensee UUID, a nonblank purpose of at most 240 characters, and request attribution. A platform role string alone grants no unbounded export.
- Installed keys are `app.user_id`, `app.role`, `app.organization_id`, `app.licensee_id`, `app.manufacturer_id`, `app.auth_assurance`, `app.request_id`, and `app.purpose`; all use transaction-local `set_config`.
- Audit queries remain bounded to 20,000 rows and deterministic by `createdAt DESC, id DESC`. Entity and action filters only narrow the resolved scope.
- The database projection excludes `AuditLog.details`, IP fields, hashes, user agent and User email/security fields. Existing CSV headers remain stable; excluded values serialize blank. Recursive redaction remains a defence-in-depth guard if details are ever passed to the formatter.
- The export-attribution insert uses trusted context values and commits atomically with the protected reads. A failed read, context install or audit insert fails the export transaction.

## Verification

`backend/tests/auditCsvExportContext.test.js` proves tenant and platform allow cases, filter narrowing, context/query/audit ordering on one transaction client, foreign and blank scope denial, role and assurance denial, bounded platform scope, required purpose, deterministic ordering, restricted column selection, trusted attribution, and recursive CSV secret redaction. Route and response-surface contracts cover the MFA middleware position and stable tenant CSV shape.

Disposable PostgreSQL certification must still prove the eventual application role, grants and RLS policies deny foreign and empty context at the database boundary. No policy, RLS state, database role, ownership or environment was changed in this slice.

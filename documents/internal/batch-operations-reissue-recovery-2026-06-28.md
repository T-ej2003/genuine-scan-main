# Batch Operations, Re-Issue, and Print Recovery - 2026-06-28

## Purpose

This note documents the production behavior for MSCQR batch Operations for brand admins and manufacturers. The goal is to keep replacement labels clear for operators while preserving the secure print lifecycle: labels are not treated as physically printed until the backend receives valid connector or printer confirmation.

## Operator Views

Manufacturer batch Operations is separated into focused sections:

- Confirmed prints: print runs with backend-confirmed labels.
- Stopped prints: failed, stopped, partial, or unconfirmed runs that need recovery or replacement approval.
- Replacement labels: approved re-issue requests that can create linked replacement print jobs.
- Pending re-issue requests: requests waiting for brand admin or super admin review.

Brand/admin Operations re-issue cards must show the requested count, label range, requester, request date, related print job, approval state, reason, and print evidence summary before approve or reject actions.

## Recovery Semantics

Recovery is backend-authoritative. The frontend may display the recovery range, but it must not calculate or override it.

For an original print job with requested range `A..B`:

- If zero labels were physically confirmed, the recovery range starts at `A`.
- If `C` labels were physically confirmed, the recovery range starts at the first unconfirmed label in the same original print job.
- The recovery range ends at the original requested range end unless a future approved policy explicitly changes that behavior.
- A later print range is blocked while an earlier unresolved recovery range exists.
- Replacement printing consumes the approved re-issue request and creates a new controlled print job linked to the original print job.
- Print counts are not advanced by a UI click, approval, allocation, or queue intent. They advance only through existing connector/helper confirmation rules.

## Backend Contract

The print re-issue endpoint must return safe structured errors instead of unhandled 500s for expected business conflicts:

- `403`: caller is outside the authorized manufacturer/licensee scope.
- `404`: request or original print job is not visible in the caller scope.
- `409`: request is not approved, original job is not recoverable, printer trust is stale, another recovery is blocking, or replacement is already allocated.
- `422`: the backend-calculated recovery range cannot be reserved safely.

Internal logs and audit records retain precise diagnostic details. User-facing responses stay plain English and do not expose QR secrets.

## Manual Validation

1. Brand admin opens a real batch and checks Operations.
2. Re-issue review cards show count, range, reason, requester, date, status, and related print job.
3. Manufacturer opens assigned batch Operations and sees the four-section menu.
4. Stopped prints shows only stopped or failed runs and the first unconfirmed recovery range.
5. Manufacturer requests re-issue from the stopped run with an audit reason.
6. Brand admin approves the request.
7. Manufacturer opens Replacement labels and clicks Print replacement labels.
8. If printer trust is stale, the UI shows the refresh action and no print job is created.
9. If printer trust is fresh, a linked replacement print job is created, but labels are not marked printed until connector/helper confirmation.
10. A later range remains blocked until the earlier recovery is resolved.

## Scalability Notes

Recovery detail for re-issue list and review cards is served through a backend summary projection. The projection aggregates requested, confirmed, pending, failed, and recovery range values in the database instead of hydrating every `PrintItem` for large print sessions.

Full print-item evidence is still loaded only on the controlled print-start/allocation path, where the backend must prove the exact reusable labels before creating a linked replacement print job. This keeps list views scalable while preserving DB-backed recovery safety.

The release E2E guard `e2e/batch-reissue-recovery.spec.ts` covers the trust-critical UI path:

- manufacturer submits a replacement-label request from a stopped print run
- brand admin reviews and approves it
- manufacturer attempts replacement print and sees a backend trust block
- manufacturer retries after the backend accepts print-start
- the UI states that physical confirmation still comes from the connector

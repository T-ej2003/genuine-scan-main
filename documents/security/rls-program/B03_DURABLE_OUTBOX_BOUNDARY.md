# B03 durable audit and security-event outbox boundary

## Production contract

The audit-recovery and SIEM workers now use eight exact PostgreSQL boundaries instead of direct table mutation. Authenticated enqueue calls require a database-verified session in the same transaction. Worker transitions require the exact worker login role, a row identifier, the immutable SHA-256 payload digest, a current five-minute lease, and the expected attempt. The function owner is the existing `NOLOGIN`, non-`BYPASSRLS` authentication function owner and owns no application table.

Durable authority is stored outside the JSON payload: request ID, payload digest, idempotency key, tenant identifiers, initiating user, expiry, claim time, and lease expiry. Existing rows remain migration-compatible because newly introduced authority fields are nullable; only newly enqueued reviewed jobs are eligible for the exact workers.

## Lifecycle and atomicity

- Enqueue is idempotent only when the same idempotency key resolves to the same immutable digest and event family.
- Claim uses `FOR UPDATE SKIP LOCKED`, a bounded batch, an expiry check, a ten-attempt limit, and a five-minute lease.
- Audit consumption locks the claimed row, writes one `AuditLog`, queues its matching `AUDIT_LOG` security event, and terminalizes the recovery job in one transaction.
- SIEM completion binds the external sink identifier. A later completion with a different sink identifier is rejected.
- Failure compare-and-sets the claimed attempt and releases the lease. A `SENT` row is terminal.
- Transaction rollback removes claims, audit rows, SIEM projections, and terminal updates together.

## Grants and FORCE RLS

The application role receives only the two enqueue signatures. The worker role receives only the six claim/consume/complete/fail signatures. The internal binding helper is owner-only. `PUBLIC` execution is revoked. Neither runtime identity has direct table privileges. Owner policies require the function-owner identity, the exact session login identity, an operation marker overwritten by the reviewed function, and row-specific digest or identifier state. Caller-set generic actor GUCs provide no authority.

## Migration and rollback

Deploy the Prisma migration before the generated RLS package. The generated rollback drops the eight boundaries and their internal helper before removing generated policies and grants. It intentionally does not drop durable columns during an application rollback, avoiding destructive loss of queued evidence. A later schema rollback may remove the nullable fields only after all reviewed queues are drained and archived.

## Certification and scale

`scripts/tests/b03-outbox-contract.test.mjs` seals the source/contract/generator relationship. `backend/tests/rls-wave-b/b03/outboxPostgres18.test.js` performs restricted-role PostgreSQL 18 probes for grants, forged context, idempotency, leases, concurrency, rollback, audit/SIEM atomicity, terminal replay, and connection reuse. The composite due-work indexes support bounded polling without full-table scans; `SKIP LOCKED` permits horizontally scaled workers without duplicate claims.

No AWS, staging, production, or shared database is used by this certification.

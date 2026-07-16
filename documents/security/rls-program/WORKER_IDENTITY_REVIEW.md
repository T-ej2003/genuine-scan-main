# MSCQR worker and scheduled-job identity review

This review defines authorization contracts only. It changes no worker runtime, SQL function, database role, policy, RLS state, queue, schedule or database.

Selected execution workflows: 3 (workers: 2; scheduled: 1).

## Approved boundaries

| Boundary | Class | Runtime | Durable authority | Tables read | Tables written | Named function |
|---|---|---|---|---|---|---|
| worker-boundary-audit-outbox-delivery | actor-derived-job | identity-worker | table-audit-log-outbox; the row ID, immutable canonical payload digest, scope fields, job type, request ID, expiry and idempotency key are authority; payload JSON alone is not | table-audit-log-outbox | table-audit-log-outbox, table-audit-log | worker-fn-consume-audit-outbox |
| worker-boundary-scheduled-compliance-packs | scheduled-maintenance-job | identity-scheduled-job | table-compliance-pack-job plus a durable schedule-run key; each tenant partition is claimed before report generation | table-licensee, table-user, table-compliance-pack-job, table-incident, table-incident-handoff, table-audit-log, table-evidence-retention-policy | table-compliance-pack-job, table-audit-log, table-evidence-retention-policy | worker-fn-claim-compliance-pack-slice |
| worker-boundary-siem-outbox-delivery | platform-scoped-system-job | identity-worker | table-security-event-outbox; durable row ID, allowlisted event type, immutable payload digest, scope version, request ID, expiry and idempotency key are authority | table-security-event-outbox | table-security-event-outbox | none |

## Context, idempotency and audit

Every protected transaction installs only these transaction-local keys from verified durable evidence: `app.system_identity`, `app.job_id`, `app.job_type`, `app.organization_id`, `app.licensee_id`, `app.manufacturer_id`, `app.initiating_user_id`, `app.request_id`, `app.auth_assurance`. Human role and platform-admin context are forbidden; `app.auth_assurance` is fixed to `system-verified`.

Audit-outbox delivery preserves the initiating actor as origin evidence while recording `identity-worker` as executor. SIEM delivery uses the durable outbox ID as the stable external event ID. Scheduled compliance uses a unique licensee/schedule partition and `identity-scheduled-job`; its current platform-user lookup must be removed rather than converted into impersonation.

All retries retain the same job ID, digest and idempotency key. Conflicting payloads are denied, terminal results are returned rather than repeated, database row/CAS or unique constraints enforce concurrency, and retry exhaustion retains immutable dead-letter evidence.

## Remaining implementation work

Before activation, add the durable scope/digest/idempotency/expiry fields described by the contracts, implement the two exact `app_rls` SECURITY INVOKER functions, replace scheduled platform-user lookup, add database claims/uniqueness, migrate callers, and certify allow/deny/replay/concurrency/cancellation behavior in disposable PostgreSQL. No generic query function or broad worker grant is permitted.


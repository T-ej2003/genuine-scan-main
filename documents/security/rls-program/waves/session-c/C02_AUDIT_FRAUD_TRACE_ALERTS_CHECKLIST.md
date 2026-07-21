# Session C / C02 audit, fraud, trace and alerts checklist

Coordination SHA: `22bfdb0cfd19d7b435b1390611b452a419923f9f`
Database namespace: `mscqr_rls_wave_c_admin_governance_operator`
Ownership contract: `workflow-ownership-session-c.json` / `c-02-audit-fraud-trace-alerts`

## Owned workflows (17)

- `workflow-http-backend-src-controllers-audit-controller-ts-export-logs-csv`
- `workflow-http-backend-src-controllers-audit-controller-ts-get-fraud-reports`
- `workflow-http-backend-src-controllers-audit-controller-ts-get-logs`
- `workflow-http-backend-src-controllers-audit-controller-ts-respond-to-fraud-report`
- `workflow-http-backend-src-controllers-trace-policy-controller-ts-acknowledge-policy-alert-controller`
- `workflow-http-backend-src-controllers-trace-policy-controller-ts-export-batch-audit-package-controller`
- `workflow-http-backend-src-controllers-trace-policy-controller-ts-get-policy-alerts-controller`
- `workflow-http-backend-src-controllers-trace-policy-controller-ts-update-policy-config-controller`
- `workflow-http-backend-src-services-attention-queue-service-ts-get-attention-queue-snapshot-uncached`
- `workflow-internal-backend-src-services-audit-service-ts-create-audit-log`
- `workflow-internal-backend-src-services-audit-service-ts-get-audit-logs`
- `workflow-internal-backend-src-services-audit-service-ts-resolve-org-id`
- `workflow-internal-backend-src-services-immutable-audit-export-service-ts-build-immutable-batch-audit-package`
- `workflow-internal-backend-src-services-trace-event-service-ts-backfill-trace-events-from-audit-logs`
- `workflow-internal-backend-src-services-trace-event-service-ts-create-trace-event`
- `workflow-internal-backend-src-services-trace-event-service-ts-create-trace-event-from-audit-log`
- `workflow-internal-backend-src-services-trace-event-service-ts-get-trace-timeline`

## Pre-edit reading and mapping

- [ ] Production roots and every registered call chain read completely once.
- [ ] Frozen workflow, command, table, context-family and architecture contracts read.
- [ ] Current focused tests read.
- [ ] Exact Prisma schema fields and relations verified.
- [ ] Every protected database access and transaction boundary mapped.
- [ ] Shared dependencies and C03 consumers identified; root agent notified before shared-boundary edits.
- [x] Owned production files, existing tests and allowed new paths confirmed from the authoritative manifest.

## Implementation invariants

- [ ] Revalidate actor plus active organization/licensee/manufacturer parent in the canonical transaction.
- [ ] Install exact role, assurance and purpose through `withCanonicalDbContext`; never trust request/JWT strings as database authority.
- [ ] Execute protected reads and writes through the transaction client; no protected global-Prisma access.
- [ ] Preserve exact response/export projections and redact before serialization.
- [ ] Preserve immutable actor/tenant attribution, compare-and-set/locking and deterministic replay where state changes.
- [ ] Couple audit and outbox effects atomically with the protected state change.
- [ ] Serialize or emit files only after commit.

## Planned executable evidence

- [ ] Registered HTTP paths: positive result plus foreign tenant, stale membership, disabled actor, wrong role and wrong assurance denial.
- [ ] Mutation paths: permitted columns, immutable attribution, concurrent update/duplicate replay, audit and outbox atomicity.
- [ ] Internal trace/audit paths: bounded scope, append-only history, deterministic backfill and exact projection.
- [ ] Focused TypeScript/syntax checks and current family tests green.
- [ ] Fresh PostgreSQL 18 C02 application-path gate green with RLS enabled and forced.
- [ ] All 17 workflow dispositions include exact executable evidence; mapping alone is not certification.

## Integration seams

- [ ] Record any required Session A/global generator, command-contract or route-owner change with exact signature and evidence in the Session C result manifest; do not edit global artifacts here.

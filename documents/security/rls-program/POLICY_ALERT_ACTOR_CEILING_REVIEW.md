# Policy Alert Actor-Ceiling Review

## Decision

`decision-context-policy-alert-actor-ceiling` is resolved by `policy-alert-actor-ceiling-v1`. This is an architecture contract only. It changes no runtime, SQL, role, grant, policy, function, database, infrastructure, staging, or production behavior.

The product has two distinct human read surfaces: tenant policy review and incident-bound platform triage. The tenant route is approved only for an active licensee administrator under one canonical licensee. The IR route is approved only after an active, expiring incident authorization exists. A platform role is never a global alert selector.

## Current mixed actor behavior

- `GET /policy/alerts` uses `requireAnyAdmin` without recent MFA. Tenant actors are scoped by hydrated `licenseeId`, while platform actors can omit `licenseeId` and read without a tenant predicate. It returns full `PolicyAlert` rows plus manufacturer and acknowledgement emails.
- `POST /policy/alerts/:id/ack` uses recent MFA but performs a read followed by an unconditional update, returns the full row, and writes audit and notification side effects outside one transaction.
- `GET /ir/alerts` is platform-only but has optional filters, no recent MFA, no required incident, no purpose or request attribution, offset pagination to 200, and rich nested personal data.
- `PATCH /ir/alerts/:id` combines acknowledgement toggling and incident linking/unlinking. It validates neither incident tenant nor incident authorization and has no database concurrency guard.
- The dashboard attention queue mixes alerts with incidents, audit, support, and printing. Its platform path treats missing scope as broad, while its manufacturer alert slice uses `manufacturerId`. It must split before any alert slice is approved.
- SIEM delivery has an approved worker identity contract, but current code still needs a per-row database claim, immutable payload digest/scope, bounded terminal failure, and secret-free event schemas.

## Approved actor ceilings

- Licensee administrators (`LICENSEE_ADMIN`, `ORG_ADMIN`) may read and acknowledge alerts whose mandatory `PolicyAlert.licenseeId` equals their database-verified canonical licensee. They may not suppress, resolve, assign, escalate, or access platform-only detection details.
- Manufacturers have no approved current alert route. A future isolated safe-summary may show only alerts with `manufacturerId` equal to the verified actor and batch/QR ownership under one active linked licensee. A link never grants whole-licensee visibility.
- Platform administrators may use bounded platform triage with fresh MFA or incident-response access with step-up, one active incident authorization, exact tenant ceiling, purpose, request ID, expiry, projection, bounds, and immutable attribution. Role alone grants nothing.
- Incident responders may read and link alerts only inside the active incident and its tenant. No unrelated browsing, unlinking, or reassignment is approved.
- Operators use `operator-boundary-tenant-incident-summary`; they do not receive ordinary table access.
- Workers use `worker-boundary-siem-outbox-delivery` with system identity and durable row authority. Human impersonation is prohibited.
- Public access is denied. The next public-read decision cannot silently broaden this contract.

## Read model

Tenant and platform alert lists use explicit projections, keyset order `createdAt DESC, id DESC`, a maximum page of 100, and a maximum 31-day window. Manufacturer safe-summary, when separately implemented, is limited to 50. Count, list, and read attribution share one canonical transaction and repeatable-read snapshot.

Allowed tenant fields are alert ID, type, severity, safe message, incident/batch/QR/manufacturer references, acknowledgement time, and creation time. Incident triage additionally permits score and policy-rule reference. `details` and nested raw JSON are never serialized.

## Scope chains

`PolicyAlert.licenseeId` is non-null and terminal. Every optional parent must agree:

- `policyRuleId -> PolicyRule` must resolve to the same licensee/organization and manufacturer when present.
- `batchId -> Batch.licenseeId` must equal the alert licensee; manufacturer must agree when present.
- `qrCodeId -> QRCode.licenseeId -> Batch.licenseeId` must equal the alert licensee.
- `incidentId -> Incident.licenseeId` must be non-null and equal the alert licensee.
- `manufacturerId -> active manufacturer User -> ManufacturerLicenseeLink -> active Licensee -> active Organization` must be consistent.

NULL, blank, orphaned, disabled, conflicting, or ambiguous scope fails closed. No parent is allowed to override the mandatory tenant key.

## Mutation model and lifecycle transitions

The schema does not contain a PolicyAlert status enum. The only supported states are derived from nullable columns:

- Acknowledgement: `acknowledgedAt NULL` and `acknowledgedByUserId NULL` to both populated by the verified tenant administrator. The database must compare-and-set the exact alert under canonical licensee scope. Clearing acknowledgement is denied.
- Escalation: `incidentId NULL` to one exact active same-licensee incident. The database must compare-and-set after incident authorization validation in the same transaction. Unlinking and reassignment are denied.

Assignment, PolicyAlert resolution, and suppression are not approved. The schema has no assignee, resolution, suppression, expiry, reason, approval, version, or unique transition row. Incident lifecycle and append-only fraud-report responses are separate domains and cannot be projected onto PolicyAlert states.

Every mutation requires an actor/scope/action idempotency key, payload digest, one-row database guard, immutable audit, and deduplicated notification/outbox side effects. An application pre-check is insufficient.

## Incident escalation

Escalation requires step-up assurance, purpose `alert-escalation`, request ID, reason, exact alert, exact incident, matching licensee, active incident authorization, and authorization expiry no greater than 60 minutes. Until durable incident authorization exists, the application workflow remains blocked and the operator may use only the approved redacted incident-summary procedure.

## Worker delivery and operator mapping

`flushSecurityEventOutbox` is `worker-alert-delivery` under `worker-boundary-siem-outbox-delivery`. The durable row ID, allowlisted event type, immutable payload digest, authoritative tenant references, expiry, and idempotency key are authority. Payload JSON never grants scope. Delivery uses system identity, bounded retries, compare-and-set row claim, and no human role.

`operator-boundary-tenant-incident-summary` remains the only alert-related operator mapping. It accepts one tenant, one incident, and page size 1..100, returning a redacted summary. It cannot be replaced by direct `PolicyAlert`, `Incident`, or audit-table browsing.

## Public-access disposition

Public alert access is prohibited. No current route has an unguessable proof, signed verification reference, non-enumerable lookup, rate limit, and exact non-sensitive projection. A public alert status would require its own reviewed contract and must not reveal tenant identity, internal reasoning, score, rule, incident, or forensic data.

## Fields allowed and prohibited

The exact per-class projections are recorded in the JSON authority. Globally prohibited fields include raw `PolicyAlert.details`, detection payloads, rule/model secrets, credential or token material, MFA/WebAuthn data, private keys, full IP/device fingerprints, forensic metadata, raw audit details, customer personal data, unrelated tenant identifiers, and SIEM credentials. Nested values are omitted or recursively allowlisted; unknown keys are denied.

## Implementation requirements

Later runtime work must isolate one workflow per alert class, install canonical context before protected queries, use a transaction client only, validate all parent chains, use explicit selects, enforce keyset/date bounds, record fixed purpose and request attribution, and commit before serialization. Acknowledgement and escalation need database compare-and-set plus idempotency and same-transaction audit/outbox behavior.

No runtime workflow is implemented by this decision. PostgreSQL policies and all four existing certifications remain pending.

## Workflows potentially unlocked

- `family-simple-tenant-scoped-reads-tracepolicycontroller-c2ecdef3b3` is semantically unblocked by the actor decision but remains runtime-blocked on MFA, fixed purpose, bounds, projection, canonical transaction, attribution, and focused tests.
- `family-incident-governance-workflows-tracepolicycontroller-07820d4e64` now has exact tenant acknowledgement semantics but remains blocked on database CAS/idempotency and atomic audit/outbox.
- `family-platform-admin-bounded-reads-iralertcontroller-0cf5698bdc` has an exact incident-response ceiling but remains blocked on durable incident authorization and runtime hardening.
- `family-multi-table-atomic-mutations-iralertcontroller-212fd714f3` has an approved escalation slice but remains blocked until the mixed patch is narrowed/split and incident authorization/CAS exists.
- `family-contract-worker-boundary-siem-outbox-delivery` keeps its exact worker mapping and remains contract-only pending worker hardening and PostgreSQL certification.

The attention-queue family could expose a manufacturer safe-summary only after its multi-table, multi-actor workflow is split. Fraud-report response remains blocked on its separate append-only status/idempotency contract. Policy-rule alert creation and generic notification creation remain separate lifecycle/root-transaction blockers.

## Retained blockers

- Durable incident-read authorization, target scope, and expiry do not exist.
- The tenant read route lacks fresh MFA, fixed purpose, request attribution, date/keyset bounds, explicit projection, and one transaction.
- Acknowledgement lacks database compare-and-set, idempotency, atomic attribution, and outbox ordering.
- The platform patch mixes acknowledgement, escalation, unlinking, and generic metadata mutation.
- PolicyAlert cannot represent assignment, resolution, suppression, reason, approval, expiry, or version.
- The dashboard attention queue is a mixed-root workflow with a platform blank-scope fallback.
- Generic notifications are not yet split by the owning alert/incident transaction.
- SIEM runtime lacks durable payload digest/scope, row claim, and terminal failure enforcement.

## CTO recommendations

The next implementation should be a narrow tenant read/ack pair, not a generic alert repository: one projected keyset query and one CAS acknowledgement command sharing canonical context and an outbox. After that, add a durable `IncidentReadAuthorization` model before enabling IR alert routes. For scale, index the exact read order and scope (`licenseeId, createdAt, id`) and the unacknowledged queue shape, but design and certify those indexes in a separate SQL-reviewed task. Do not add assignment or suppression until product ownership, expiry, reason, approval, and version semantics are explicit.

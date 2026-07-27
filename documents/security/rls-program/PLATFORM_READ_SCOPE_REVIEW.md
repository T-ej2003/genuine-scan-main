# Platform administrator read-scope review

This review resolves `decision-context-platform-read-scope` as an architecture contract only. It changes no runtime, SQL, role, grant, policy, RLS, database, infrastructure, staging, or production behavior. The normative machine-readable contract is `platform-read-scope-boundary.json`.

## Existing unsafe fallback patterns

The registered routes prove that platform roles currently bypass tenant predicates in several controllers. `enforceTenantIsolation` returns immediately for `SUPER_ADMIN` and `PLATFORM_SUPER_ADMIN`, and `getEffectiveLicenseeId` returns `null` when those callers omit a selector. Incident evidence then selects by storage key, support detail selects by ticket ID, IR alerts accept only optional filters, telemetry aggregates without a required time range, and licensee list/export read the complete table. These are role-string fallbacks, not approved platform scope.

Current route guards also vary. Licensee reads and support reads authenticate and check the platform role but do not require recent MFA. Incident evidence and telemetry use `requireAnyAdmin` plus tenant isolation, whose platform branch permits missing tenant scope. IR alert list is platform-only but lacks the recent-MFA guard used by IR mutations. Existing audit-log and fraud-report services demonstrate the safer pattern: reload actor state, require an active session and fresh administrator MFA, require a request ID, require one licensee and purpose, install canonical context, share one transaction snapshot, use an explicit projection, and append attribution before commit.

## Approved scope classes

Every platform-admin read covered by this decision has exactly one primary class. Tenant-, organization-, licensee-, manufacturer-, and actor-bounded reads require one database-validated selector and fresh MFA. Platform aggregates require a dedicated aggregate projection. Incident-response reads require a durable incident authorization and step-up assurance. Diagnostics and administrative catalog inspection are operator-only. Unrestricted exports and any unmatched broad read are prohibited.

There is no generic `platform-admin = all rows` class. A blank selector denies access unless the workflow is the one explicitly approved telemetry aggregate. Client input can request a selector but never establishes authority; every selector is resolved against active database rows, and multiple selectors must describe the same scope.

## Bounded read model

The normal application model is a transaction-client-only repository behind a database-verified active platform actor. It validates the selector, installs transaction-local actor and scope context, reads only the workflow projection, appends immutable attribution, and commits before serialization or file delivery. Count and list use identical predicates and one repeatable-read snapshot. Global Prisma inside the repository and blank-scope fallbacks are forbidden.

The affected bounded reads are:

- incident evidence: exactly one evidence object joined through its incident to one validated licensee;
- support list/detail: one validated licensee, maximum 100 keyset rows and at most 90 days for lists;
- compliance jobs: one validated licensee, maximum 100 keyset rows and at most 90 days;
- feature flags: one validated licensee, maximum 100 rows, without raw `config`;
- licensee detail: exactly one validated licensee;
- licensee directory: normalized 3-100 character name/prefix search, maximum 50 keyset rows, and a minimal directory projection.

## Aggregate model

Only the route-transition telemetry summary qualifies as a platform aggregate. Product behavior requires platform health totals, and the result can be expressed without raw rows. The approved projection is limited to counts and averages plus at most 20 allowlisted `routeTo` dimensions over at most 31 days. It excludes user IDs, tenant identity dimensions, role, source, device/network data, verification results, and raw metrics. Tenant-private rows may not be materialized in application memory. Runtime work remains blocked until a dedicated database-enforceable aggregate projection and its PostgreSQL proof exist.

Dashboard and analytics helpers are not automatically approved as global aggregates. Dashboard snapshot code currently uses an `all` cache key and can omit platform scope; it remains blocked by mixed root/transaction and named-function prerequisites. The low-risk analytics service family remains blocked by unresolved root, scope, and transaction evidence. Neither family references this boundary because this decision did not establish their exact product projection.

## Incident-response model

`listIrAlerts` is classified as `incident-response-read`, not ordinary platform browsing. It requires an active incident ID, fixed `incident-response-alert-triage` purpose, a tenant ceiling derived from the incident authorization, step-up assurance, a maximum 31-day window, 100 keyset rows, immutable access attribution, and authorization expiry no later than 60 minutes. Optional licensee or manufacturer selectors may only narrow that incident set.

The current schema and routes do not provide a durable incident-read authorization or expiry. The HTTP workflow therefore remains blocked. The existing `operator-boundary-tenant-incident-summary` is the only approved fallback for an exact operator-controlled incident summary; containment remains within the existing exact operator procedures.

## Directory and listing model

`GET /licensees/:id` may become a one-row licensee-bounded read. `GET /licensees` may become a dedicated keyset directory projection only when a bounded name/prefix search token is supplied. Both exclude contacts, location, metadata, suspension reason, users, invites, QR ranges, credentials, and security state. The current unrestricted `/licensees/export` CSV is classified `prohibited-platform-read`; no bulk export is approved.

## Assurance requirements

Ordinary bounded reads and the telemetry aggregate require `mfa-verified` within `ADMIN_STEP_UP_WINDOW_MINUTES`, whose current default is 30 minutes. Incident response requires `step-up-verified` and the same freshness ceiling. Operator diagnostics require `operator-approved` assurance and the expiry recorded by their exact boundary, normally no more than 60 minutes. Password-only platform reads are not approved.

## Purpose and audit model

Authorization purpose is one fixed code: `tenant-incident-evidence`, `incident-response-alert-triage`, `licensee-directory-lookup`, `platform-telemetry-health`, `tenant-support-triage`, `tenant-compliance-status`, or `tenant-feature-flag-review`. Free text may supplement an audit note only after authorization and never creates authority.

Every attempt records actor ID, database role, assurance, request ID, purpose code, selected scope, workflow and route, result count or bounded summary, timestamp, and outcome. Sensitive or incident denials are recorded. Returned payloads and secret-bearing values are never logged. Successful attribution is appended in the same transaction as the read.

## Operator-only mappings

Catalog ownership/grant/RLS verification maps to `operator-boundary-catalog-verification`; component readiness maps to `operator-boundary-health-readiness`; failed jobs map to `operator-boundary-failed-job-summary`; tenant incident summaries map to `operator-boundary-tenant-incident-summary`; print diagnostics map to `operator-boundary-print-diagnostic`; deployment and RLS readiness map to their existing operator boundaries. These do not become application routes and require no change to `operator-boundaries.json`.

## Prohibited platform reads

The contract prohibits unrestricted raw global listings, the existing licensee CSV export, raw audit-detail aggregation, tenant identity dimensions in platform aggregates, secret/security columns, full tenant records, arbitrary free-text purpose, blank-scope fallback, conflicting selectors, and application access to catalog, role, grant, ownership, policy, migration, or readiness diagnostics.

## Implementation requirements and tests

Later runtime batches must use verified database actor state, the configured recent-MFA window, exact selector schemas, active-scope validation, allowlisted purpose codes, transaction-local canonical context, explicit projections, keyset pagination, bounded dates, deterministic ordering, recursive redaction, one repeatable-read snapshot where count/list coexist, and same-transaction attribution. The dedicated telemetry and directory projections require separate database design and disposable PostgreSQL certification. No workflow is marked implemented by this decision.

Mutation validation now rejects role-only authority, blank-global scope, missing MFA or purpose, free-text authorization, missing pagination/date ceilings, raw audit details, tenant-private aggregate rows, missing incident binding or expiry, directory security fields, ordinary application diagnostics, omitted attribution, conflicting selectors, unsupported selector combinations, workflow boundary drift, and an incompletely resolved decision.

## Workflows potentially unlocked

The decision removes the product-semantics blocker from the ten affected workflows. None is immediately implementation-eligible:

- incident evidence still needs explicit tenant/incident binding, MFA, purpose, transaction propagation, projection, and attribution;
- telemetry still needs the dedicated aggregate projection and certification;
- IR alerts still need a durable expiring incident-read authorization;
- licensee detail and directory need separate bounded runtime shapes; the export remains prohibited;
- support list/detail need tenant binding, keyset/date bounds, PII projection, and attribution;
- compliance jobs still need its registered controller to own the actor transaction;
- feature flags need verified licensee selection, config exclusion, and attribution.

The audit-log and fraud-report families were inspected as existing safe references and remain implemented with PostgreSQL certification pending. Dashboard/analytics families, governance mutation children, audit writers, and broader incident lifecycle families retain their existing independent blockers.

## Remaining blockers

After this decision, the remaining product decisions are `decision-context-policy-alert-actor-ceiling` and `decision-context-public-read-contract`. Runtime implementation, dedicated projection design, incident authorization product state, and disposable PostgreSQL certification are explicitly separate work.

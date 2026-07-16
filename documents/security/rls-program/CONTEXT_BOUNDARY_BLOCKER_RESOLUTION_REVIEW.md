# Context-boundary blocker-resolution review

This bounded review considered only the 17 named low/medium-risk read families (24 workflows). It made no RLS, SQL, role, grant, policy, ownership, function, database, AWS, ECS, Terraform, staging or production change.

## Outcome

- Families considered: 17
- Workflows considered: 24
- Families reclassified: 2
- Families split: 4
- Child families created: 8
- Workflows moved to contract-only: 2
- Workflows newly implemented: 0
- Reviewed workflows retaining exact blockers: 22
- PostgreSQL certifications pending: 4
- Next deterministic family: family-simple-tenant-scoped-reads-analyticsservice-2c20deef24

No newly isolated ordinary read met every implementation gate. Production code was intentionally unchanged.

## Reclassified families

| Previous family | Governing boundary | Classification | Status |
|---|---|---|---|
| family-simple-tenant-scoped-reads-analyticsrollupservice-b5739f1d6f | system-boundary-analytics-rollup-worker | worker boundary | contract-only; full rollup worker contract pending |
| family-simple-tenant-scoped-reads-localagentclaimservice-47404e413d | system-boundary-local-agent-device-claim | device-authenticated internal system path | contract-only; full claim lifecycle contract pending |

Neither boundary has human actor context. Neither may install ordinary authenticated context.

## Split lineage

| Parent family | Child family |
|---|---|
| family-simple-tenant-scoped-reads-governanceservice-e3aa1df885 | family-split-governanceservice-platform-feature-flag-administration-7bb4b15607 |
| family-simple-tenant-scoped-reads-governanceservice-e3aa1df885 | family-split-governanceservice-public-verification-policy-80f0c95935 |
| family-simple-tenant-scoped-reads-manufacturerscopeservice-bea2e91ac1 | family-split-manufacturerscopeservice-manufacturer-id-scope-hydration-d04d198c46 |
| family-simple-tenant-scoped-reads-manufacturerscopeservice-bea2e91ac1 | family-split-manufacturerscopeservice-manufacturer-link-auth-and-invite-407543caef |
| family-platform-admin-bounded-reads-supportcontroller-6ce17f93fa | family-split-supportcontroller-platform-support-message-mutation-2b4b2be0d0 |
| family-platform-admin-bounded-reads-supportcontroller-6ce17f93fa | family-split-supportcontroller-platform-support-ticket-read-4ce4ce4858 |
| family-simple-tenant-scoped-reads-auditservice-964272fbb7 | family-split-auditservice-audit-write-org-resolution-60e107aefa |
| family-simple-tenant-scoped-reads-auditservice-964272fbb7 | family-split-auditservice-unregistered-audit-reader-bfe36f6eba |

Each child is uniform by actor ceiling, scope model, assurance/command contract, execution surface, protected-table boundary and transaction behavior. The planner rejects lost/duplicated workflows, circular lineage, evidence-free splits and incompatible child membership.

## Retained blockers

| Blocker | Affected reviewed workflows |
|---|---:|
| actor-command-contract | 1 |
| authentication-bootstrap-scope-model | 1 |
| incompatible-shared-auth-roots | 1 |
| incomplete-root-transaction | 1 |
| out-of-scope-mutation-root | 1 |
| out-of-scope-shared-mutation-root | 1 |
| platform-admin-scope-contract | 2 |
| public-command-contract | 5 |
| unbounded-platform-scope | 8 |
| unregistered-dead-path | 1 |

## Product decisions required

| Decision | Question | CTO recommendation |
|---|---|---|
| decision-context-public-read-contract | Which public QR-policy, replacement and support-tracking fields may be disclosed, and what exact token or reference proof authorizes each lookup? | Approve separate minimal token-bound projections; require optional-email support tracking to become proof-bearing rather than existence-bearing. |
| decision-context-platform-read-scope | Which organization, licensee or manufacturer ceiling, assurance and purpose authorize each current platform-wide read? | Require an explicit bounded scope, fresh assurance where commanded, immutable read attribution, explicit projection and bounded pagination/date windows; deny omitted scope. |
| decision-context-policy-alert-actor-ceiling | May licensee administrators read policy alerts, or is the route platform-admin only as the command contract currently states? | Choose one actor ceiling and align route, tenant scope, MFA and read attribution before implementation. |
| decision-context-manufacturer-bootstrap | How may verified manufacturer identity enumerate linked licensees before a single tenant context exists? | Approve an actor-bound bootstrap projection using the verified manufacturer ID and one supplied transaction client; never use blank tenant context as a wildcard. |

## Exact before/after programme counts

| Metric | Before | After |
|---|---:|---:|
| Workflow families | 316 | 320 |
| Implemented workflows | 4 | 4 |
| Contract-only workflows | 38 | 40 |
| Blocked workflows | 386 | 384 |
| Blocked families | 295 | 297 |
| PostgreSQL certifications pending | 4 | 4 |

## Implementation and validation boundary

- Production code files changed: 0
- Test files changed: 1 (`scripts/tests/full-database-rls-program.test.mjs`)
- No targeted production-family test was added because no reviewed family was implemented.
- Planner/system-boundary tests prove reclassification, contract-only state, split lineage and certification preservation.

## Recommended commit groups

1. Planner, validator, status and focused manifest tests.
2. Workflow, system-boundary, decision and read-batch manifests.
3. Architecture, migration report and this human review.

## CTO recommendations

1. Approve the manufacturer bootstrap actor-scope model first; it unlocks authentication hydration without weakening tenant isolation.
2. Replace every platform-wide fallback with an explicit scope selector, purpose, immutable read attribution and pagination/date ceiling before implementation.
3. Design public verification/support tracking as narrow proof-bound functions or repositories; do not reuse authenticated policies.
4. Review the complete analytics worker and local-agent claim lifecycle next as separate high-risk system-boundary programmes, including durable replay/idempotency proof.

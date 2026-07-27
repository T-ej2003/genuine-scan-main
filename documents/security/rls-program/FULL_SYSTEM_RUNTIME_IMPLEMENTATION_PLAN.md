# Full-System Runtime Implementation Plan

Status: in progress after workflow-level authorization freeze. The clean-room foundation is local only; current staging and production databases remain unchanged.

## Objective and invariant

Implement every active protected-table workflow against its frozen boundary, then certify the complete intended RLS system in a fresh disposable PostgreSQL 18 database. The programme must not activate RLS or claim completion from the current five implemented workflows alone. A partial workflow certification is explicitly prohibited as release, staging or production evidence.

The authorization sources are `command-semantics.json`, `context-boundary-families.json`, `pre-auth-functions.json`, `worker-boundaries.json`, `operator-boundaries.json`, `system-boundaries.json`, `manufacturer-bootstrap-boundary.json`, `platform-read-scope-boundary.json`, `policy-alert-actor-ceiling.json` and `public-read-contract.json`. Runtime code may implement these contracts; it may not widen them.

## Runtime progress

Batch 001 implemented the tenant-admin slice of `family-simple-tenant-scoped-reads-analyticsservice-2c20deef24`. Foundation follow-up added its frozen platform slice: a database-hydrated platform administrator requires fresh MFA and one active database-validated licensee/organization selector in the same attributed transaction. Database `User` and membership state remains authoritative and every populated unresolved-alert parent is validated before scoring. The current manifest records 428 workflows exactly once across 318 families: five implemented workflows, 59 contract-only workflows and 364 blocked workflows. Every implemented workflow remains application-path PostgreSQL pending.

The batch stopped at `family-simple-tenant-scoped-reads-auditcontroller-627bac35ff`. Its `POST /api/audit/fraud-reports/:id/respond` root is a platform mutation with report lookup, audit append and delivery semantics, so it is incompatible with the batch's read-only repeatable-read transaction model. The exact evidence, limits and retained blocker are recorded in `FULL_SYSTEM_RUNTIME_BATCH_001_REVIEW.md`.

## Tier ordering

1. Foundation and scanner: freeze generated manifests, direct-access inventory, context keys, transaction helper behavior, error/redaction primitives and mutation-test validator gates.
2. Exact special boundaries: auth and public pre-auth functions; manufacturer bootstrap; worker/scheduled/device identities; operator procedures; migration/bootstrap paths. No special identity may be emulated with human context.
3. Simple authenticated reads: actor-scoped reads, then tenant-scoped reads, with explicit projections, keyset bounds, recursive redaction, same-client ordering and immutable read attribution where required.
4. Bounded administration: platform/licensee/manufacturer directory/detail projections, dedicated aggregates and incident-authorized reads. Prohibited exports remain disabled.
5. Append-only writes and intake: audit/outbox/telemetry/public intake with server-derived scope, idempotency, immutable attribution and bounded payloads.
6. Simple mutations: one-row tenant/actor updates with protected-column guards and database compare-and-set/version semantics.
7. Lifecycle and multi-table mutations: account/security, alert acknowledgement/escalation, incident/governance and retention flows with exact source/target states, locks/CAS, replay and atomic side effects.
8. Batch/QR lifecycle: allocation, signing, public verification, release/readiness, replacement and ownership chains; signed and raw compatibility paths remain separate.
9. Print lifecycle: printer trust, print jobs/sessions/items, reissue and connector/gateway paths with device identity, terminal completion and immutable lineage.
10. Full disposable PostgreSQL certification, complete runtime route/job certification, staging review package and separately approved activation planning.

## Deterministic family order

Within a tier use `context-boundary-families.json.familyOrder` and then stable family ID:

1. simple actor-scoped reads
2. simple tenant-scoped reads
3. platform-admin bounded reads
4. append-only audit writes
5. tenant-scoped creates
6. tenant-scoped updates
7. lifecycle/state transitions
8. multi-table atomic mutations
9. batch/QR lifecycle
10. print lifecycle
11. incident/governance workflows
12. account and security mutations
13. worker/scheduled workflows
14. pre-auth function-backed workflows
15. startup/bootstrap workflows
16. CLI/manual workflows
17. operator-boundary workflows
18. migration-only workflows
19. public or anonymous workflows
20. prohibited or legacy workflows

Special-boundary prerequisites override category position: implement/certify the governing function, identity or operator procedure before any dependent application family. Within each category the next family is the first stable ID whose prerequisites are complete and whose exact blocker is resolved. A family is never skipped by forcing canonical human context through a special boundary.

## Batch limits and review units

Each code-review batch may contain at most 12 families, 30 workflows, 12 production files, 12 test files and 3,000 net production/test lines. Stop before—not after—the first limit. One batch must have one dominant boundary type and compatible transaction behavior. Public/pre-auth, worker, operator, migration, lifecycle mutation and authenticated read changes are separate review groups.

Every batch records before/after workflow/family/blocker counts, files, exact tests, remaining blockers, PostgreSQL status and next deterministic family. Generated manifest changes and their generator/validator/tests form one review group; production implementation and focused tests form later family-specific groups; disposable SQL/policy/certification artifacts are separately reviewed and are never generated or activated implicitly by runtime work.

## Per-family implementation gate

Before editing runtime code, prove:

- registered production root and every internal caller;
- exact actor/system identity and assurance;
- authoritative tenant/actor/job/proof scope source;
- compatible command, lifecycle and transaction semantics;
- complete protected-query/write trace, including helpers and side effects;
- exact input bounds, projection, redaction and deterministic ordering;
- database concurrency/idempotency mechanism for mutations;
- transaction-client-only feasibility with no global Prisma fallback;
- focused deterministic test plan and required disposable database cases.

If any item fails, preserve an exact runtime, SQL, schema, concurrency or test blocker. Do not create a new broad product-decision category unless a concrete contradiction to a frozen contract is documented.

## Runtime implementation pattern

Authenticated families validate the database-reverified actor and authoritative scope, open one transaction, install transaction-local canonical context, execute every protected command through the supplied client, write required attribution in the same transaction, commit, then serialize the explicit redacted projection. Blank keys never mean all; query/body values only narrow verified scope; counts, lists and aggregates share scope and snapshot.

Pre-auth/public families validate syntax and proof before protected access and execute only their exact named function through the restricted runtime. Worker/scheduled/device families load durable authority and never install human context. Operators execute only exact procedures. No generic repository or public function is added.

## Required focused tests

Every applicable family proves:

- own/verified scope allow and foreign, blank, missing, stale, inactive, ambiguous and conflicting denial;
- actor ceiling, role revalidation, assurance freshness and purpose/request attribution;
- no query before context/proof and no global Prisma access;
- same transaction/client and commit-before-serialization;
- explicit projection, nested sensitive-field exclusion, input/date/page bounds and deterministic ordering;
- count/list/aggregate scope and snapshot consistency;
- protected-column denial and exact lifecycle transition;
- database lock/CAS/version/unique-idempotency behavior under concurrency and replay;
- atomic audit/outbox/notification side effects and denial attribution where required;
- special identity cannot impersonate a human or obtain table/bypass/owner authority;
- public enumeration resistance, generic failures, signature no-fallback, one-time expiry/replay, path containment and rate limits.

## Special-boundary implementation order

1. Implement and certify the seven existing `app_auth` functions and login/invitation/reset/email callers.
2. Implement manufacturer post-password actor bootstrap and fresh tenant-scope switch repository.
3. Implement `app_public` QR/session/support/intake functions and remove direct public protected-table access; support tracking waits for proof-version schema support.
4. Implement worker/scheduled/device identities, durable job claims and exact worker functions/CAS.
5. Implement exact operator and migration broker procedures with environment/approval ceilings.
6. Implement bounded platform projections and incident authorization state; prohibited global exports stay prohibited.
7. Implement policy-alert read/acknowledgement/escalation slices after incident authorization and database concurrency primitives exist.
8. Proceed through ordinary authenticated families in deterministic category/family order.

## Full-system disposable PostgreSQL certification

Certification starts from a fresh template0-derived disposable database on an isolated PostgreSQL 18 cluster and deploys the complete reviewed schema, newly created roles, grants, ownership, functions, policies, FORCE RLS settings and verification queries intended for green activation. It must cover every protected table, runtime identity, command equivalence class, context/proof class, dependency chain and active workflow family—not a representative sample.

Required evidence includes catalog ownership/grants/policies/functions/search paths; empty/forged/stale/cross-scope denial; own-scope allow; pre-auth/public function isolation; worker/operator/migration separation; recursion and timeout checks; mutation concurrency/replay; planner/index evidence; checksum-paired clean-room destruction/marked-role cleanup; unchanged blue sentinel state; and complete route/job tests against the disposable database. Results are redacted, deterministic and checksum-bound to the reviewed artifacts.

The existing five workflow certifications remain `pending` until the full-system workflow integration run passes. The local table-enforcement harness proves the 75 intended FORCE targets and residue-free failure cleanup, but it certifies zero essential application workflows; table/catalog proof cannot authorize green staging creation or traffic.

## Accelerated local enforcement package progress

The local package exists under `scripts/rls/sql/generated/` and `documents/security/rls-program/generated/`. It deterministically derives 77 table dispositions, 75 FORCE targets, exact certification-candidate grants for the runtime-implemented reads, fail-closed command policies for every other surface, canonical context helpers, ownership transfer, exact verification and clean-room destruction/marked-role cleanup. The generated contract inventory preserves all 59 contract-only workflows.

`essential-workflow-allowlist.json` deliberately has zero enabled workflows and `launchBlocked=true`. The centralized protected-route shutdown therefore denies unsupported protected reads and mutations before business data access; auth, health and public routers are merely kept on their separate boundaries and are not declared SQL-ready by that exemption. Disposable PostgreSQL foundation proof does not change application-path status.

## Completion criteria

Runtime implementation is complete only when:

- all active workflows belong to an implemented or explicitly prohibited/retired family;
- every direct protected access is transaction-client-only or behind its exact named special boundary;
- every runtime/schema/SQL/concurrency/test blocker is closed with evidence;
- focused unit/route/job/concurrency tests pass;
- generated manifests are deterministic and validators/mutation tests pass;
- the clean full-system disposable PostgreSQL certification passes for every intended table, identity, function, policy and workflow class;
- apply, verification and clean-room destruction/role-cleanup artifacts are checksum-paired and reviewed at the defined wave/system gates;
- no staging/production activation occurs without its distinct authorization, preflight, evidence and rollback gates.

The next deterministic work item is emitted by `scripts/rls/context-boundary-next-family.mjs` with `programmeStage=full-system-runtime-implementation` and `workflowAuthorizationArchitecture=frozen`.

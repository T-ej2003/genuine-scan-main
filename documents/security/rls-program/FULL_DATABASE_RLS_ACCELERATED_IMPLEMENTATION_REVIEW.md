# Full-Database RLS Clean-Room Foundation Review

Date: 2026-07-20

Scope: complete uncommitted foundation diff

Review policy: the sole three-reviewer independent foundation review
Staging/production: not accessed or changed

## Outcome

No P0 finding was reported. Eight real P1/P2 findings were reproduced and corrected by the sole independent review. The subsequent PostgreSQL gate exposed three additional concrete generator/certification defects; those were corrected without starting another review cycle. Speculative comments without an executable failure path, frozen-contract violation or supported security consequence were rejected. All foundation gates are now green.

## Standardized findings

| Severity | File and line | Concrete exploit or regression path | Violated frozen contract | Required correction | Blocks checkpoint | Status |
| --- | --- | --- | --- | --- | --- | --- |
| P1 | `scripts/rls/generate-clean-room-rls-sql.mjs:274` | An operator could invoke a later mutating SQL file directly and bypass the clean-room emptiness test. | Every mutating entrypoint must refuse dirty or out-of-order green state before mutation. | Repeat clean-room preflight inside role creation and require the exact install marker, source checksum and prior phase in every later file. | Yes | Fixed |
| P1 | `scripts/rls/generate-clean-room-rls-sql.mjs:318` | Count-only or privilege-presence checks could accept a changed policy expression, routine body/ACL or unexpected grant. | Expected policy, routine, owner and ACL state must match exactly in both directions. | Seal expected policy/routine definitions and compare policy, routine, schema, table, column, type, database and default ACL catalogs bidirectionally; add tamper tests. | Yes | Fixed |
| P1 | `scripts/rls/verify-full-rls-package.mjs:100` and `scripts/rls/certify-clean-room-database.mjs:603` | Source or migration files could change after generation and stale SQL could still reach the first database mutation. | Generated SQL and evidence must be deterministically bound to current authoritative inputs. | Hash the schema, ordered migrations, manifests and generator inputs; recompute package validity immediately before database work. | Yes | Fixed |
| P1 | `backend/src/services/auditLogQueryService.ts:168` and `scripts/rls/generate-clean-room-rls-sql.mjs:536` | Tenant reads could become actor-self only, while platform metadata enrichment could require unsafe direct `AuditLog`/`User` columns. | Preserve tenant-wide audit behavior and bounded platform access without exposing network or account-security fields to ordinary runtime SQL. | Keep tenant-wide scope, preserve manufacturer actor-self semantics, and route platform-only metadata through one MFA/purpose/selector-bound exact function in the same transaction. | Yes | Fixed |
| P1 | `backend/src/services/auth/mfaAdapter.ts:136`, `backend/src/services/auth/mfaAdapter.ts:779`, `backend/src/services/auth/webauthnService.ts:422` | A one-time MFA/WebAuthn/backup challenge could be consumed while session issuance, refresh replacement or durable audit failed, enabling denial of service or inconsistent replay state. | One-time consumption, session state and required audit/outbox effects must be atomic and concurrency-safe. | Propagate one Prisma transaction client through challenge CAS, factor/backup consumption, session/refresh mutation and durable audit; commit explicit invalid-attempt state only where the contract requires it. | Yes | Fixed |
| P1 | `backend/scripts/staging-database-role-vpc-executor.mjs:68` | The old blue staging executor could be selected for full-RLS modes and mutate the current database. | Blue staging remains untouched; full RLS may target only a separately reviewed green executor. | Reject every full-RLS mode before constructing a database client and bind future full-RLS execution to a distinct green task/image/contract. | Yes | Fixed |
| P1 | `documents/security/rls-program/FULL_DATABASE_RLS_ROLLBACK_RUNBOOK.md:1` and `scripts/rls/lib/program-inventory.mjs:1483` | Legacy provenance/restoration instructions could direct an operator to rewrite arbitrary historical owners and ACLs in place. | Failed clean-room environments are destroyed; no legacy role/ACL/default-ACL/ownership restoration is supported. | Remove restoration machinery and rewrite authoritative ownership, staging, production, preflight and rollback documents around untouched blue plus disposable green. | Yes | Fixed |
| P2 | `scripts/tests/full-database-rls-program.test.mjs:157` and `scripts/tests/full-database-rls-enforcement.test.mjs:91` | Stale counts/actor assertions could either reject the reviewed platform slice or continue blessing the retired in-place package. | Tests must enforce the current exact workflow, actor, grant and clean-room lifecycle contracts. | Update exact actors/assurance/columns/counts and replace legacy restoration expectations with dirty-state refusal and residue-free destruction assertions. | Yes | Fixed |

## Certification-exposed corrections

These are executable failures found by the PostgreSQL gate, not a second independent review.

| Severity | File and line | Concrete exploit or regression path | Violated frozen contract | Required correction | Blocks checkpoint | Status |
| --- | --- | --- | --- | --- | --- | --- |
| P2 | `scripts/rls/certify-clean-room-database.mjs:217` | The table loop selected the first licensee-admin policy by array order, so `User` risk fixtures were tested under the distinct audit-read contract. A future policy regression could be misclassified or hidden. | Every certification probe must bind to the exact workflow purpose and actor contract it claims to prove. | Key certification policies by table plus explicit purpose; declare the audit and trace exceptions and default the risk fixtures to `tenant-risk-analytics`. | Yes | Fixed |
| P1 | `scripts/rls/generate-clean-room-rls-sql.mjs:172` | Unqualified outer `id`/`orgId` references inside a `Licensee` subquery resolved to the inner row. `Organization` denied a legitimate platform selector and nullable organization checks could become tautological. | Platform selectors must be database-revalidated against the selected active licensee and its exact organization. | Qualify every correlated outer column with its protected table, including the internal organization helper policy; assert the generated qualification. | Yes | Fixed |
| P1 | `scripts/rls/generate-clean-room-rls-sql.mjs:178` | A licensee administrator could insert an `AuditLog` row with another user's `userId`; platform inserts also lacked exact organization-parent validation. | Audit attribution is immutable, actor-bound and parent-consistent. | Require `AuditLog.userId=current_user_id()` for every direct human INSERT, exact tenant organization for tenant actors, and the selected licensee's qualified organization for platform actors. | Yes | Fixed |

## Workflow inventory 428 versus 429

The temporary 429th record was not a new production workflow. The scanner emitted the private nested `revoke` closure inside refresh-token rotation as a standalone module-level record. It had no independent registered root, actor contract, response contract or business lifecycle. The inventory generator now delegates that closure to `workflow-internal-backend-src-services-auth-refresh-token-service-ts-rotate-refresh-token`; related transaction-local MFA/audit helpers are likewise folded into their functional roots.

The production scan now reports exactly 428 workflows. The programme validator asserts 428 unique IDs, one family per ID, and no standalone technical revoke/helper workflow. This rules out a newly discovered workflow, duplicate and inventory-generation regression; the cause was a synthetic module-level record.

## Clean-room simplification

The pivot deleted approximately 1,450 lines of obsolete blue-executor full-RLS mode/provision/verify plumbing. Compared with the rejected uncommitted in-place draft, it also avoids an estimated 600-900 lines of role/ACL/default-ACL/ownership provenance capture, reconstruction and failure fixtures. These are estimates because the rejected draft was never committed as a stable baseline.

Operationally, rollback moves from arbitrary historical-state reconstruction to four bounded facts: green consumers stopped, no required data accepted, green database absent, and exact package-marked roles absent. That removes grantor reconstruction, reverse ownership graphs, reused-role normalization and partial legacy-state branches—an estimated 35-45% reduction in deployment-state complexity while retaining exact apply, catalog verification and every package-stage failure injection.

## Preserved security and business boundaries

- 77 tables retain exact dispositions; 75 remain FORCE targets and two remain migration-only.
- Runtime roles remain `NOSUPERUSER`, `NOBYPASSRLS`, non-owning and outside owner-role membership.
- Runtime grants are column-specific; named-function paths receive no direct table privilege.
- Blank, malformed, stale and foreign context fail closed.
- Authentication, MFA replacement, WebAuthn, refresh rotation and audit/outbox effects retain atomic one-time/concurrency semantics.
- The centralized shutdown is a temporary fail-closed deployment control, not a substitute for implementing supported workflows.
- Foundation table/catalog proof does not certify any of the 428 application paths or authorize staging.

## P3 record

No P3 cleanup is required for the foundation checkpoint. Future observability and operational improvements are recommendations, not blockers.

## CTO recommendations

1. Provision green on an isolated encrypted RDS instance so cluster-wide role names cannot collide with blue.
2. Add a machine-verifiable green write-acceptance counter to the traffic switch and rollback gate.
3. Keep exact catalog tamper cases and the PostgreSQL-backed MFA race test in the permanent release-candidate suite.
4. Alert on any runtime connection authenticated as an administrator, migration identity or NOLOGIN owner and on any `relforcerowsecurity=false` drift.
5. Track policy query plans and pool saturation during each workflow wave so correctness fixes do not accumulate into a late scalability surprise.

## Certification record

PostgreSQL 18 certification passed with status `clean-room-full-table-enforcement-certified-workflows-pending`.

- Source contract SHA-256: `2c1d2c305b7f788d56ac78a231597285cceaf1dae399302f090c4a6fa110319f`
- Package checksum-manifest SHA-256: `8c03b5e6bbcb1e16676e5ebeed44b545bf338b26fb18ce268c639762c6808a4c`
- Cleanup SQL SHA-256: `691cfbf7eba1b886e2d359c783d03d5f94eb08217ea5b329872127aac3809d0b`
- Certification evidence SHA-256: `fd003009dc041578a18721270eadf9cd4f31784af9322cf8f3df0d361b8d113b`
- Certified: 75 FORCE-RLS tables, 39 policies, 78 column cells, 11 failure stages, nine dirty-state refusals, five direct-phase refusals and nine catalog-tamper dimensions.
- Cleanup result: zero candidate database residue, zero managed-role residue and unchanged blue fingerprint.
- Workflow application-path certification remains `0/428`; this foundation result does not authorize staging traffic.

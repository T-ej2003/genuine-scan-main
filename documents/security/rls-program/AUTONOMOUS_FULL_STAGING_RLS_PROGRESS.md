# Autonomous full staging RLS progress

Last updated: 2026-07-20 (Europe/London)

## Current checkpoint

- Branch: `refactor/full-database-rls-program`
- Foundation base commit: `8b58ece86aa96e9f11a79623e3cd385b14889957`
- Inventory: 77 tables, 75 intended FORCE targets, 428 workflows, 318 families, 1,063 registered production access sites and 55 potentially dead access sites requiring later exact resolution.
- Workflow disposition: five runtime-implemented/application-path-PostgreSQL-pending, 59 contract-only, 364 blocked and zero launch-enabled.
- Generated foundation: 39 policies, 34 direct policy slices and 78 exact column-privilege cells.
- Deployment model: clean-room blue/green only. Current staging and production databases are untouched.
- Foundation artifact commit: pending logical commit creation; all gates are green.
- Full workflow worktrees: not permitted until the committed foundation SHA and green PostgreSQL 18 result are recorded.

## Foundation findings A-D

- **Finding A — exact risk `User` columns:** the runtime predicate uses `id`, `name`, `role`, `isActive`, `status`, `deletedAt`, `disabledAt`, `licenseeId` and `orgId`. Only the exact display/predicate union is selectable. Email, password/hash, token, MFA, WebAuthn, recovery, metadata and platform-security fields remain unreadable. Active `ManufacturerLicenseeLink -> Licensee -> Organization` state is authority; stale legacy fields cannot grant it.
- **Finding B — deployment pivot:** legacy role/ACL/default-ACL/ownership restoration is removed. Clean-room preflight rejects reused managed roles and any dirty application catalog before mutation. Failure cleanup stops green consumers, proves no required data was accepted, drops green, drops only exact package-marked roles and proves blue unchanged.
- **Finding C — executable administrator model:** SQL is split into administrator bootstrap, restricted zero-based Prisma migration, administrator ownership, runtime policy, verification and maintenance cleanup phases. Direct mutating subphases require exact prior markers. The existing blue staging executor rejects full-RLS modes before creating a database client; future staging requires a separate private green executor whose actual RDS capabilities are proven behaviorally.
- **Finding D — bounded shutdown denial:** disabled protected routes are limited before logging through privacy-preserving network buckets, horizontally shared backend support and a conservative fail-safe fallback. Logs are sampled/suppressed after threshold, identifier-free and exclude query/body/token data. Unknown routes remain fail closed; this control cannot replace a supported workflow implementation.

## Sole independent foundation review

The authorized three-reviewer foundation review completed once. It found no P0 and eight real P1/P2 issues: direct phase bypass, non-exact catalog checks, stale-package mutation risk, audit scope/projection drift, non-atomic MFA/WebAuthn/session/audit state, blue executor reachability, stale legacy rollback contracts and stale tests. All are fixed in the working tree. The standardized evidence is in `FULL_DATABASE_RLS_ACCELERATED_IMPLEMENTATION_REVIEW.md`.

No further independent review will run for ordinary edits, generated artifacts, documentation or checksums. Each completed workflow wave receives one standardized read-only review; one complete system review runs only after all 428 workflow dispositions are integrated and stable.

## Why 429 returned to 428

The apparent 429th record was the private nested refresh-token `revoke` closure emitted as a standalone module-level inventory item. It had no independent registered production root, actor, request/response contract or business lifecycle. The scanner now delegates it to the refresh-token rotation workflow. Transaction-local MFA and audit helpers are also folded into their functional roots. Tests require exactly 428 unique IDs, one family per ID and no standalone technical revoke/helper workflow.

Therefore it was a synthetic module-level inventory record caused by scanner behavior—not a newly discovered product workflow, duplicate supported path or accepted count increase.

## Clean-room simplification and complexity reduction

- Approximately 1,450 lines of obsolete blue-executor full-RLS mode, provision and verification plumbing were deleted.
- The new generator avoids an estimated 600-900 lines of uncommitted provenance capture, historical ACL/default-ACL reconstruction, reverse ownership logic and matching failure fixtures from the rejected in-place draft.
- These are estimates because the rejected draft was never committed as a stable comparison baseline.
- Deployment rollback now has four bounded state assertions—green consumers stopped, no required data accepted, green database absent and marked roles absent—rather than arbitrary historical catalog reconstruction. Estimated deployment-state complexity is reduced by 35-45% while exact role attributes, ownership, grants, policies, catalog verification, phase ordering and failure injection remain intact.

## Foundation security behavior

The clean-room package refuses pre-existing managed roles, user schemas, application objects, policies, publications/subscriptions, database/schema grants, memberships and default ACLs. `10-roles.sql` repeats clean-room preflight so it cannot be invoked as a bypass. Every later phase binds the environment, database, deployment ID, administrator, source checksum, role marker, prior phase and `traffic_enabled=false`.

Expected policy and routine definitions are sealed during apply. Verification compares policy definitions, routine definitions/security/search paths/ACLs, direct schema/table/column/type/database ACLs, default ACLs, ownership, role attributes/memberships and the private install inventory in both directions. The disposable harness tampers each catalog dimension separately and requires exact rejection.

MFA challenge/backup-code and WebAuthn one-time state, factor changes, session issuance/refresh replacement and required durable audit outbox writes now share one transaction. Compare-and-set and rollback tests prevent consumed-but-no-session and session-without-audit outcomes.

## Validation state

Serial inventory and generation pass at 428 workflows, 318 families, 77 tables, 75 FORCE targets, 39 policies, 34 direct slices, 78 column cells and 26 checksummed artifacts. PostgreSQL 18 certification passed for all 75 FORCE targets with all 11 failure-injection stages, nine clean-room preflight refusals, five direct-phase refusals, nine catalog-tamper dimensions, zero green database/role residue and an unchanged blue fingerprint. Application-path workflow certification remains `0/428` and is the next programme phase.

Exact certified artifact values:

- Source contract SHA-256: `2c1d2c305b7f788d56ac78a231597285cceaf1dae399302f090c4a6fa110319f`
- Package checksum-manifest SHA-256: `8c03b5e6bbcb1e16676e5ebeed44b545bf338b26fb18ce268c639762c6808a4c`
- Cleanup SQL SHA-256: `691cfbf7eba1b886e2d359c783d03d5f94eb08217ea5b329872127aac3809d0b`
- Certification evidence SHA-256: `fd003009dc041578a18721270eadf9cd4f31784af9322cf8f3df0d361b8d113b`

Exact next task: create the logical foundation commits while excluding preserved unrelated ops/QA/scratch files, record the resulting SHA, then generate and validate the exhaustive 428-workflow session partition before creating any worktree.

## Environment state

- No staging or production database connection was made.
- No AWS, ECS, RDS, ALB, secret, task definition, image or Terraform mutation was made.
- The current staging and production databases remain blue rollback targets.
- Future `staging-rls` green must be a separate encrypted PostgreSQL instance or cluster because roles are cluster-wide and managed role names must be absent.

## CTO recommendations

1. Add a database-backed write-acceptance watermark to green so destructive rollback eligibility is machine-verifiable.
2. Alarm on any runtime connection using an administrator/migration identity and any loss of `relforcerowsecurity`.
3. Keep query-plan and pool saturation thresholds in each wave gate; RLS correctness without predictable performance is not staging-ready.
4. Use isolated green capacity and weighted traffic so certification load cannot starve blue rollback capacity.

# MSCQR RLS final closure — 2026-07-24

## Status

**READY FOR STAGING ACTIVATION. The MSCQR RLS programme is not yet closed.**

The Phase 2 implementation removes the three staged route fallbacks and their
separate database client, installs one capability-bound runtime model, closes
restricted-owner row projections, and adds isolated checksum-bound staging and
production database executors. Local release and PostgreSQL 18.4 gates pass.
Staging and production have not been activated by this evidence revision.

## Candidate boundary

- Starting commit: `def002eb922b4e4b3350412a2803b969cbff709d`
- Branch: `rls-full-integration`
- Generated source contract:
  `68be98736423be84c0eb0baa9423a78109abe61835d8479dd61b656a68c423dc`
- Generated package checksum:
  `2a72417d23d08c5ea296e7d914b24f869adb64ad53e2c100341d7538b6d1119d`
- Deterministic generated-tree checksum:
  `061af08772dd717364c797e611c1c141762b170b5621937caaf2f2d3c722b57c`

## Removed compatibility authority

The active batch list, batch allocation-map, and manufacturer-printer routes
now use the already reviewed authenticated capability projections. The
following legacy authority was removed:

- `RLS_READ_DATABASE_URL` and the independent Prisma client;
- the three `MSCQR_STAGING_RLS_*_ENABLED` process flags;
- caller-installed staged batch context;
- the manufacturer-printer staged read service;
- route-specific fallback wiring, proof fields, disposable scripts, and stale
  tests for that model;
- staging credential and Terraform inputs for the retired read role and flags.

Application health now reports the authoritative application database rather
than a removed compatibility connection. Existing domain-error translation
and unknown-database-error fail-closed behaviour are unchanged.

## Restricted-owner projection closure

All 20 active restricted-owner SQL source files now use reviewed explicit
columns. The generated-package gate rejects:

- `%ROWTYPE`;
- `RETURNING *`;
- direct table `SELECT *` and table-alias wildcard projections;
- direct whole-row JSON serialization;
- untyped `record.field` projection targets.

The only exclusion is `session-c/c04/operatorProcedures.sql`: it is
operator-only, absent from the named runtime-function inventory and generated
package, and the scanner fails if it becomes active or disappears without a
contract update. This is a source-contract exclusion, not runtime authority.

## Isolated staging executor

The green staging executor implements eight fixed modes: capability preflight,
role provisioning, role verification, administrative bootstrap,
ownership/grants installation, runtime-policy installation, full-package
verification, and exact rollback.

It accepts no caller-selected SQL, path, role, network, secret, task definition,
or package. Every mutation requires its own exact confirmation token. The task
requires the staging account, region, cluster, task definition, database,
administrator identity, TLS connection, source contract, and package checksum
declared by the repository contract. Receipts are immutable and sanitised.
The retired blue executor explicitly rejects all full-RLS modes.

## Checksum-bound production database phase

The protected production release workflow now verifies and binds one release
SHA to the application commit, immutable backend/worker/frontend image digests,
source contract, and package checksum. An isolated production executor applies
the fixed package only after preflight and rollback-readiness checks. Application
deployment is gated on a matching verified database receipt.

Production Terraform grants only the exact secrets and receipt-prefix access
required by the executor. ECS execution roles may read only the exact
environment administrator secret needed to start the isolated task; mutation
and receipt authority remains on the task role. No database credential enters
general application tasks or GitHub command output. The workflow stops before
application deployment on receipt, checksum, catalogue, or executor mismatch.

## Generated package and certification

The generated package verifies:

- 79 inventoried tables;
- 77 FORCE-RLS targets;
- 339 policies;
- 60 column-privilege cells;
- 338 registered workflow call paths;
- 27 checksums;
- zero PUBLIC execution and exact runtime grants under the certification
  contract.

The full PostgreSQL 18.4 clean-room proof passed migrations from zero,
ownership, roles, grants, policies, application-path probes, catalog-tamper
denials, failure injection, rollback, and zero database/role residue.
Focused evidence is retained separately for:

- `c03-authenticated-boundaries`;
- `printing-lifecycle`;
- `public-verification`;
- `b03-durable-outbox`.

Focused runs no longer overwrite the full certification result.

## Local gate evidence

- Backend build and full backend regression: passed.
- Frontend typecheck, 61 test files / 241 tests, and production build: passed.
- Disposable P2 PostgreSQL 18.4 release-readiness and system integration:
  passed.
- The P2 harness installs the exact generated package through the canonical
  certification administrator, then removes its database and temporary roles.
- Prisma migration replay and drift checks include the schema-declared
  `RefreshToken.sessionCapabilityHash` unique constraint.
- Release-candidate gate and staging-smoke configuration contracts: passed.
- Security release gate and Prisma-scope guardrails: passed.
- Frontend/backend production dependency audit: zero high or critical
  findings.
- Public verification records scan history only for ready-state
  `FIRST_SCAN`, `LEGIT_REPEAT`, and `SUSPICIOUS_DUPLICATE` decisions.
  Report-session proof is independent of ownership eligibility, reviewed
  signed-token denials map to the public 400 contract, and unknown manual
  codes receive bounded 15–25 ms padding before the generic not-found result.
- Failed-login evidence, QR batch rename, and QR export completion now use
  exact capability functions. C03 audit projections strip session capability
  material before the shared audit writer, while retaining it only for the
  database call that verifies authority.
- C03 incident and governance paths now bind through the reviewed authenticated
  actor wrapper, narrow platform requests to database-validated resource scope,
  queue protected audit evidence through the durable B03 boundary, and read
  tenant feature flags through an exact five-column capability projection.
- The root development tree now resolves `minimatch@10.2.5`,
  `brace-expansion@5.0.8`, and `js-yaml@4.3.0`; the backend resolves
  `tar@7.5.22`. Production audits and OSV Scanner 2.4.0 report no findings.
- RLS generation repeated byte-identically and full package verification:
  passed.
- Restricted-owner projection contract: 20 active sources passed; one
  fail-closed inactive exclusion.
- Staging/production executor, IAM, broker, receipt, and Terraform contracts:
  99 tests passed.
- Staging and production Terraform formatting and offline validation: passed.
- Root-owned RLS scanners resolve the root lockfile's TypeScript dependency,
  allowing minimal CI jobs to run guardrails without a second backend install.
- Disposable P2 and certification containers, networks, databases, and roles:
  removed after the local gate.

## Rollout decision

The candidate is ready for Git review and protected staging activation. This
document does not claim that a push, merge, staging apply, production apply, or
deployment has occurred. Final programme closure requires immutable remote CI
evidence, staging receipts and smoke evidence, production approval, production
receipts, observation-window evidence, and matching deployed image digests.

## Accepted risks and stop conditions

- The inactive C04 operator SQL remains outside the runtime package; activating
  it requires explicit projection review and source-contract registration.
- Database rollback is exact for the generated RLS package; application and
  schema rollback must continue to use the documented compatibility runbook.
- Any receipt mismatch, cross-tenant visibility, authentication regression,
  elevated 5xx rate, unexpected RLS denial, unhealthy service, or incomplete
  backup evidence blocks promotion.

## CTO recommendations

- Make the exact-column SQL scan a generated-package gate so future schema
  additions cannot silently widen a function result. Implemented in Phase 2;
  keep it required in remote CI.
- Require the database package receipt and application image digest to share
  one release SHA before either service becomes healthy. Implemented in the
  protected production workflow.
- Keep blue/green database package installation isolated per environment and
  retain the previous immutable application digests until the observation
  window closes.
- Next, add automated receipt retention verification and a dashboard alarm for
  package-fingerprint drift before increasing rollout concurrency.

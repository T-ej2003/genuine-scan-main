# Full-Database Disposable PostgreSQL 18 Certification Runbook

This runbook is local-only. The harness refuses non-loopback hosts and non-disposable database names. It must never receive staging or production credentials.

## Prerequisites

- PostgreSQL 18, Docker/Compose, Node/npm and `psql`.
- A serially generated package from the reviewed branch.
- No concurrent manifest or SQL writer.

## Generate and verify

Run, serially:

```bash
node scripts/rls/scan-production-access.mjs
node scripts/rls/context-boundary-plan.mjs
node scripts/rls/generate-full-rls-sql.mjs
node scripts/rls/verify-full-rls-package.mjs
node --test scripts/tests/full-database-rls-enforcement.test.mjs
```

The verifier recomputes every authoritative input hash, including the Prisma schema and ordered migration files. Any stale source input or generated checksum blocks database mutation.

## Start and execute

```bash
docker compose -f docker-compose.rls-certification.yml up -d --wait rls-cert-postgres
MSCQR_FULL_RLS_CERTIFICATION_CONFIRM=MSCQR_RUN_LOCAL_FULL_RLS_CERTIFICATION \
MSCQR_FULL_RLS_CERTIFICATION_ADMIN_URL='postgresql://mscqr_rls_cert_admin@127.0.0.1:55434/mscqr_full_rls_admin' \
node scripts/rls/certify-full-database.mjs
```

For each run, the harness creates a new template0-derived database. Clean-room preflight requires zero application objects, zero managed roles, zero policies, zero unexpected grants/memberships and zero default ACLs. It applies every Prisma migration from zero with the restricted migration identity, installs package-created roles and exact ownership, helpers, grants and policies, enables and forces RLS, and verifies the exact catalog.

## Required proof

A foundation pass requires:

- 77 exact table dispositions and 75/75 `ENABLE` plus `FORCE ROW LEVEL SECURITY` targets;
- the current generated policy and exact column-privilege inventories, with no table-wide runtime grant;
- correct NOLOGIN ownership and zero runtime/migration ownership or owner-role residue;
- exact schema, table, column, type, routine, database and default ACL state in both directions;
- exact policy expressions, routine definitions/security modes/search paths and EXECUTE ACLs;
- blank, malformed, stale and foreign scope denial plus reviewed own-scope success;
- exact risk-analytics predicate columns while password, token, MFA, WebAuthn, recovery, metadata and platform-security columns remain unreadable;
- direct-subphase refusal before mutation when prerequisite markers/phases are absent;
- clean-room refusal for every dirty role/object/ACL/policy/default-ACL scenario;
- transactional failure injection for every package-created phase;
- verification-tamper detection for policy, routine body, routine ACL, schema ACL, table ACL, column ACL, enum ACL, database ACL and default ACL;
- green database residue count zero, managed-role residue count zero and blue sentinel fingerprint unchanged after failure cleanup.

The generated execution report is the source of truth for current counts and checksums. Table-layer certification does not certify the 428 application workflows; `workflowCertificationStatus` must remain pending until real application-path gates pass.

## Teardown

```bash
docker compose -f docker-compose.rls-certification.yml down -v
```

Confirm no disposable green database or package-marked managed role remains. Cleanup residue is a certification failure.

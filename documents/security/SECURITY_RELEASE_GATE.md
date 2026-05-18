# Security Release Gate

Run:

```sh
npm run security:release-gate
```

## What It Checks

The gate runs:

- `git diff --check`
- backend TypeScript build and Prisma client generation
- tenant isolation regression tests
- public response-surface regression tests
- route/controller security surface regression tests
- Prisma protected-model scope scanner
- Prisma scanner unit tests
- backend trust-critical compiled security suite
- frontend TypeScript check
- frontend production build
- targeted security-scope lint for changed security files

## What Passing Means

Passing means the multi-tenant isolation hardening release has working backend scope enforcement on the covered critical paths, no broad Prisma scanner bypasses, no stale scanner allowlist entries, no known public verification response leakage from the tested builders, and no changed-file security lint issues covered by `lint:security-scope`.

## What It Does Not Guarantee

Passing does not mean the whole platform is security-perfect. It does not replace penetration testing, DB-level Row Level Security, full route integration coverage with a real test database, or cleanup of historical repo-wide lint debt.

## Deferred Items

- PostgreSQL RLS is formally deferred in `documents/security/RLS_DEFERRED_DECISION.md`.
- Full `npm run lint` still has historical debt documented in `documents/security/LINT_DEBT_SECURITY_RELEASE_NOTE.md`.
- Remaining Prisma allowlist entries are exact and documented, but should be reduced further by moving legacy direct Prisma access into scoped repository/helper layers.

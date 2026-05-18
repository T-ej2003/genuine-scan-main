# Lint Debt Security Release Note

Last full command run during this release pass:

```sh
npm run lint
```

Result: failed with 1045 errors and 27 warnings across the repository.

## Classification

- The dominant failure class is historical `@typescript-eslint/no-explicit-any` in existing backend controllers/services, frontend pages, and tests.
- Changed security files still include pre-existing `no-explicit-any` findings in legacy code paths, but the release pass removed the one `no-useless-escape` finding introduced on a changed incident export header.
- The release gate uses `npm run lint:security-scope`, which runs ESLint on changed security-scope files with `no-explicit-any` disabled and separately blocks debugger statements, non-test `console.log`, temporary markers, and undocumented `scope-guardrail-ignore` comments.
- No debug logging, broad scanner bypass, public response leak, or temporary security marker was left by this pass.

## Security Impact

The full repo lint debt is not treated as a blocker for this multi-tenant isolation hardening release because tenant isolation is gated by backend build, targeted security lint, scoped Prisma scanner, isolation tests, trust-critical backend tests, typecheck, and production build.

## Follow-Up

Create a separate lint-debt cleanup track to reduce `no-explicit-any` in:

1. backend controllers and services that touch auth, QR, audit, incident, notification, user management, and licensee management;
2. frontend pages that handle admin filters or export workflows;
3. tests that currently rely on loose mocks.

Do not mix that cleanup with tenant-isolation security fixes unless a type is needed to prove or enforce scope.

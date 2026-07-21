# Session C C04 operator, recovery, startup, migration and CLI checklist

Status: owned application boundary and local PostgreSQL 18 proof complete; Session A integration seams remain.

## Read before editing

- [x] Production roots and complete registered call chains read: `backend/prisma/seed.ts`, the seven owned `backend/scripts/*` roots, `superAdminBootstrapService.ts`, its startup registration, and the auth/audit/printing services currently called by the supported roots.
- [x] Frozen contracts read: the C04 ownership family, all intersecting `operator-boundaries.json` entries, the exact supporting `command-semantics.json` rules, workflow records, runtime-identity decision and contract-only implementation inventory.
- [x] Current owned tests read: admin repair, break-glass gate, launch-smoke seed, migration drift/replay, password setup link, Prisma checksum, staging RLS seed and super-admin bootstrap tests.
- [x] Schema fields verified for User, Organization, Licensee, ManufacturerLicenseeLink, QRRange, Batch, QRCode, PrintItem, Invite, PasswordReset, RefreshToken, MFA credential/factor/backup-code and audit/outbox records.
- [x] Database accesses and transaction boundaries mapped. Supported roots currently perform protected global-Prisma reads and multi-transaction side effects; only the staging fixture is grouped in one global-Prisma transaction. Startup bootstrap locks and creates in one transaction but writes audit after commit.
- [x] Shared dependencies identified: database client, audit service, invite/password-reset services, MFA/session revocation services, printing services, startup registration, canonical context helper and generated GREEN RLS package. These are not C04-owned and will not be edited.
- [x] Owned files confirmed against `workflow-ownership-session-c.json`; this family will use only its production/test files and `backend/src/rls-waves/session-c/**`, `backend/tests/rls-wave-c/**` and this documentation path.
- [x] Positive and negative evidence planned: exact procedure call/columns, environment and confirmation refusal, malformed IDs, missing/stale approval, wrong identity/assurance/environment, foreign target, replay, atomic audit/outbox, RLS/FORCE catalogue state, protected direct-table denial and post-commit serialization.

## Frozen dispositions

- Supported bounded procedures (12 workflow IDs): print diagnostic (1), account setup-link reissue selectors (2), production break-glass MFA reset (1), staging RLS validation fixture (7), and migration-only super-admin bootstrap (1).
- Product-prohibited paths (15 workflow IDs): Prisma seed (2), admin-account role repair (3), enterprise E2E seed (6), and launch-smoke user seed (4). Their production entrypoints must fail closed; they are not application-path certifications.

## Integration seams

- The generated GREEN package must install and grant only the exact reviewed `app_ops.print_diagnostic(uuid)`, `app_ops.reissue_account_setup_link(uuid,uuid,text,uuid)`, `app_ops.reset_account_mfa(uuid,uuid,text,uuid)`, `app_ops.prepare_rls_validation_fixture(uuid,text,uuid)`, and migration bootstrap function used by the owned application client.
- Each function must revalidate the database actor/identity, environment, assurance, approval/ticket/purpose, active target scope and lifecycle; constrain exact columns and returned projection; lock or compare-and-set mutations; make replay deterministic; append immutable audit/outbox evidence atomically; and deny direct protected-table access to the operator/migration LOGIN roles.
- Startup registration currently invokes bootstrap through the ordinary application client. Session A must provide a deployment-only migration invocation seam; the running application role must not receive migration authority or credentials.

## Family boundary gate

- [x] Supported application roots call only the canonical reviewed functions for protected access; ordinary startup bootstrap fails closed unless an explicit migration client is supplied.
- [x] Prohibited roots refuse before any database access.
- [x] Focused syntax/type and application-path tests pass.
- [x] PostgreSQL 18 family gate proves supported allow/deny/replay/atomicity and all 27 dispositions locally.
- [x] Workflow evidence and exact integration seams supplied in the Session C result manifest.

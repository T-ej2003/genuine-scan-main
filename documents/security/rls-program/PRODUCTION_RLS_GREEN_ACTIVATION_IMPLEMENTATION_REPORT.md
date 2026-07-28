# Production RLS green activation implementation report

Date: 2026-07-28
Repository state: repository implementation complete and locally committed after review; no AWS apply, secret value creation, deployment, production connection, or production database mutation.

## Root cause and outcome

Backend `d355a77675d4320c2bfa975ebf3682995ba54a2f` requires the pre-authenticated and authenticated restricted database identities, but production has only `DATABASE_URL`. The clean-room generator previously prohibited all production execution, so the required roles, credentials, `app_auth`/`app_rls` routines, grants, and policies could not be installed.

The repository now contains an explicit production-only, KMS-signed approval contract; an immutable broker-only executor; an isolated PostgreSQL 18 green design; exact secret/task wiring; pre-traffic application canaries; receipt verification; and residue-free pre-traffic cleanup. The normal runtime still fails closed on missing or partial restricted credentials. The PR #130 legacy fallback flag and runtime path are removed.

Production login is not live-fixed until the isolated green AWS database is created, the package is broker-executed, restricted secret values are populated, and ECS traffic is activated. The repository is ready for that activation. First-user onboarding is supported from an empty green database through the reviewed invitation/setup-link flow; no broad production-data migration is fabricated. Staging smoke may be skipped only for the known broken endpoint mismatch, and mandatory green pre-traffic canaries replace that check.

## Sealed local package

- Source contract SHA256: `d94b0e4fa868cc4b43daf576f3359c6d7910fdb2ceab92b030c9bb68173e4d88`
- Ordered migration-set digest: `6642442a81cd98c7a132d241fa98e50ae231510896c9da67ab70d86b050d02db`
- Checksum-manifest SHA256: `a17a446a4be535ae00267746547ee8535fdaac1023469664623acf4cdd184171`
- Sealed package counts: 79 tables, 77 FORCE-RLS targets, 347 policies, 60 column-grant cells.

## Validation results

- Production approval/release tests: 12 passed, 0 failed.
- Full package verification: valid; 79 tables, 77 FORCE-RLS targets, 347 policies, 60 column privilege cells, 27 checksums.
- Full enforcement unit tests: 13 passed, 0 failed.
- Disposable production-target PostgreSQL 18 execution: 1 passed, 0 failed; all 54 Prisma migrations applied from zero; cleanup left zero green databases and zero production managed roles.
- Full clean-room PostgreSQL 18 certificate: passed catalog, migration, policy, privilege, exact-drift, failure-injection, login, refresh, MFA challenge completion, `/auth/me`, dashboard, QR statistics, and tenant-isolation probes; zero database/role residue and blue fingerprint unchanged.
- Focused PostgreSQL 18 certificates: B03 durable outbox passed; C03 authenticated boundaries passed; public verification passed; printing lifecycle passed. Every focused run left zero database/role residue.
- Release smoke tests: 10 passed, 0 failed after rerunning outside the filesystem sandbox so the test HTTP server could bind loopback. The first sandboxed run had seven `listen EPERM` environment failures.
- B01 production fail-closed static test: passed, including missing and partial restricted credentials.
- Security-scope lint: passed for 17 changed security files.
- Backend Prisma generation and TypeScript build: passed.
- Frontend TypeScript check and production Vite build: passed.
- Terraform formatting and provider-backed validation: passed.
- Release workflow YAML parse, shell syntax checks, JavaScript syntax checks, and `git diff --check`: passed.
- Corrected standalone `backend/tests/authMfaPostgres18.test.js`: passed against disposable PostgreSQL 18 through the B01 capability transaction, covering challenge creation, failed-code recording, successful completion, one-time consumption, and the resulting session capability.
- First-user authentication components passed: invitation creation/consumption and password setup through the B01 pre-auth PostgreSQL proof; setup-link operator boundary; email-delivery policy; first-enrolment MFA bootstrap; admin MFA cycle; refresh/session boundary; authenticated login, `/api/auth/me`, dashboard, QR, tenant isolation, and logout revocation through the full PostgreSQL certificate.
- Staging/release smoke configuration: 20 passed, 0 failed outside the sandbox. The sandboxed attempt had seven `listen EPERM` fixture failures; no deployed endpoint was called.

The aggregate result remains `clean-room-full-table-enforcement-certified-workflows-pending`: 11 workflows have aggregate application-path certification and 24 generated contracts remain outside that aggregate evidence set. Focused certificates improve route evidence but do not rewrite that aggregate status.

## Files changed

### Approval, execution, canary, and release

- `.github/workflows/release-gate.yml`
- `backend/Dockerfile`
- `backend/package.json`
- `backend/package-lock.json`
- `backend/scripts/full-rls-green-executor-core.mjs`
- `backend/scripts/production-full-rls-green-executor.mjs`
- `backend/scripts/production-green-canary-provision.mjs`
- `backend/scripts/production-green-application-canary.mjs`
- `backend/scripts/production-rls-approval.mjs`
- `package.json`
- `scripts/aws/apply-production-full-rls-release.mjs`
- `scripts/aws/deploy-ecs-service.sh`
- `scripts/aws/publish-ecs-images.sh`
- `scripts/rls/create-production-rls-approval.mjs`
- `scripts/smoke-release.mjs`

### Restricted runtime and database proof

- `backend/src/rls-waves/session-b/b01/runtimeClients.ts`
- `backend/tests/qrSystemPostgres18.test.js`
- `backend/tests/authMfaPostgres18.test.js`
- `backend/tests/rls-wave-b/b01/authenticationClosurePostgres18.test.js`
- `backend/tests/rls-wave-b/b01/securityBoundary.test.js`
- `scripts/rls/certify-clean-room-database.mjs`
- `scripts/rls/generate-clean-room-rls-sql.mjs`
- `scripts/rls/lib/clean-room-source-contract.mjs`
- `scripts/tests/production-full-rls-package-postgres18.test.mjs`
- `scripts/tests/production-full-rls-release.test.mjs`
- `scripts/tests/production-rls-approval.test.mjs`
- `scripts/tests/smoke-release-pr-soft.test.mjs`

### Infrastructure

- `infra/aws/terraform/.terraform.lock.hcl`
- `infra/aws/terraform/lambda/production-rls-approval-broker/index.mjs`
- `infra/aws/terraform/main.tf`
- `infra/aws/terraform/outputs.tf`
- `infra/aws/terraform/production-rls-green.tf`
- `infra/aws/terraform/providers.tf`
- `infra/aws/terraform/terraform.tfvars.example`
- `infra/aws/terraform/variables.tf`
- `infra/aws/terraform/versions.tf`

### Human and machine-readable contracts

- `documents/security/rls-program/FULL_DATABASE_PRODUCTION_ACTIVATION_RUNBOOK.md`
- `documents/security/rls-program/PRODUCTION_RLS_GREEN_ACTIVATION_DECISION.md`
- `documents/security/rls-program/PRODUCTION_RLS_GREEN_ACTIVATION_IMPLEMENTATION_REPORT.md`
- `documents/security/rls-program/production-full-rls-executor-contract.json`
- `documents/security/rls-program/generated/checksums.json`
- `documents/security/rls-program/generated/disposable-certification-result.json`
- `documents/security/rls-program/generated/disposable-certification-result.b03-durable-outbox.json`
- `documents/security/rls-program/generated/disposable-certification-result.c03-authenticated-boundaries.json`
- `documents/security/rls-program/generated/disposable-certification-result.printing-lifecycle.json`
- `documents/security/rls-program/generated/disposable-certification-result.public-verification.json`
- `documents/security/rls-program/generated/expected-catalog-snapshot.json`
- `documents/security/rls-program/generated/full-rls-implementation-manifest.json`
- `documents/security/rls-program/generated/package-execution-report.json`
- `documents/security/rls-program/generated/role-lifecycle-report.json`

### Generator-owned SQL outputs

- `scripts/rls/sql/generated/10-roles.sql`
- `scripts/rls/sql/generated/11-ownership-grants.sql`
- `scripts/rls/sql/generated/15-migration-preflight.sql`
- `scripts/rls/sql/generated/20-context-helpers.sql`
- `scripts/rls/sql/generated/21-runtime-grants.sql`
- `scripts/rls/sql/generated/30-policies.sql`
- `scripts/rls/sql/generated/40-post-apply-verification.sql`
- `scripts/rls/sql/generated/90-clean-room-role-cleanup.sql`

## Approval and production blockers

1. Obtain independent checker, change-ticket, protected-environment, saved Terraform-plan, database-operator, and traffic-switch approvals.
2. Confirm the actual production VPC, subnet, security-group, task-role, worker-service, artifact-bucket, RDS engine/version availability, and immutable image inputs through an AWS read-only plan/review.
3. Approve and implement a read-only-blue to green data-transfer/reconciliation contract if customer data is required. The zero-based package intentionally does not copy customer data; the brokered ownership phase provisions only marked pre-traffic canary identities and an isolation-control tenant.
4. Populate only the pre-created approval, runtime, and canary secret handles through an authorized secret-write procedure; never expose values.
5. Decide whether the bounded aggregate/focused application evidence is acceptable for the activation window or require the remaining 24 aggregate application-path certificates.
6. Populate the pre-created canary secret handles through the authorized secret-write procedure. The approval-bound ownership task then creates or reconciles only its exact marked canary identities, fails closed on unrelated users, and never logs credentials. Use the resulting platform canary identity to invite first pilot users through the normal audited invitation/password-setup flow.

## CTO recommendations

- Treat production data transfer and reconciliation as the next release-blocking design, with row counts, immutable source/target digests, foreign-key checks, sequence reconciliation, and a no-divergent-writes cutover rule.
- Add the remaining aggregate application-path certificates before calling the whole route surface production-certified; prioritize password reset/invitation, public incident/support, audit/SIEM workers, and scheduled compliance jobs.
- Add private VPC endpoints for Secrets Manager, KMS, ECR, CloudWatch Logs, and S3, then replace the executor security group's broad egress with endpoint- and database-specific egress.
- After a successful observation window, formalize blue retirement and approval-key/green-credential rotation; do not leave a temporary dual-environment operating model indefinitely.

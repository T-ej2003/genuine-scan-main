# Production full-RLS green activation runbook

Status: executable contract implemented; no AWS resource, secret value, production database, or ECS service has been changed.

## Hard boundaries

- Currently deployed broken backend release: `d355a77675d4320c2bfa975ebf3682995ba54a2f`. Activation uses the exact reviewed commit containing this contract; substitute that full SHA consistently below.
- Frontend remains `mscqr-frontend:20`.
- Blue production database is read-only for this procedure and is never a package target.
- Green database is exactly `mscqr_production_rls_green_phase2` on a separate PostgreSQL 18 instance.
- Only the `mscqr-production-rls-approval-broker:reviewed` Lambda alias may launch fixed executor tasks.
- The protected workflow role may read/verify the approval, invoke that alias, observe its tasks, and read receipts; it has no `ecs:RunTask` permission.
- Do not run if green contains application objects, any `mscqr_prd_rls_phase2_*` role exists, the approval is absent/expired, or required production data lacks an approved transfer contract.
- Never print, copy into command arguments, or save database URLs, passwords, MFA seeds, or approval signatures in evidence.

## Approval artifact

Stage B activation accepts only the strict v2 artifact defined by
`infra/aws/terraform/production-green-stage-b/approval-contract.schema.json`.
`scripts/rls/create-production-rls-approval.mjs` remains a legacy v1 compatibility
tool and must not be used for Stage B activation.

The JSON object has exactly these fields:

```json
{
  "schemaVersion": 2, "environment": "production", "account": "368992683803", "region": "eu-west-2",
  "releaseSha": "<40 lowercase hex>", "sourceContractSha256": "<64 lowercase hex>", "migrationSetDigest": "<64 lowercase hex>", "packageChecksumSha256": "<64 lowercase hex>", "deploymentId": "phase2",
  "greenDatabaseIdentifier": "mscqr-production-rls-green-phase2", "greenDatabaseName": "mscqr_production_rls_green_phase2", "administratorIdentity": "mscqr_prod_admin", "databaseSecurityGroupId": "sg-0703d3f227f35b81c", "executorSecurityGroupId": "sg-051a24aedff773761",
  "backendImageDigest": "<immutable backend @sha256>", "workerImageDigest": "<immutable worker @sha256>", "executorImageDigest": "<immutable backend @sha256>", "canaryImageDigest": "<immutable backend @sha256>",
  "taskDefinitionArns": { "<mode>": "<registered task-definition ARN>" }, "taskDefinitionTemplateHashes": { "<template>": "<64 lowercase hex>" }, "brokerAliasArn": "arn:aws:lambda:eu-west-2:368992683803:function:mscqr-production-rls-approval-broker:reviewed", "brokerVersion": "<positive integer>",
  "checkerIdentity": "arn:aws:sts::368992683803:assumed-role/mscqr-production-rls-independent-checker/<session>", "deployerIdentity": "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/<session>", "executorIdentity": "arn:aws:iam::368992683803:role/mscqr-production-full-rls-green-executor-task",
  "approvalId": "<reviewed approval id>", "ticketId": "<change ticket id>", "issuedAt": "<ISO-8601>", "expiresAt": "<ISO-8601, no more than two hours after issuedAt>", "nonce": "<UUID>", "signatureAlgorithm": "RSASSA_PSS_SHA_256", "signatureBase64": "<KMS signature>"
}
```

The checker authentication boundary is the exact checker IAM user assuming
`mscqr-production-independent-checker` with MFA. That source role may assume
only `mscqr-production-rls-independent-checker`; the target trust therefore
contains only that exact role principal and intentionally does not require a
fresh `aws:MultiFactorAuthPresent` condition on the role-to-role request, because
AWS role chaining does not provide a new MFA request. The exact target-role STS
session ARN is signed and recorded; the release operator cannot sign. Never add
`mfa_serial` to the second-hop profile or substitute another principal.
Before any target-role convergence or checker approval, release preflight reads the
live source-role trust and requires this exact semantic policy. A stale Terraform or
configuration document cannot satisfy the gate; drift stops the cutover before the
target-role trust is changed.

## Local dry run

These commands perform no AWS apply, secret creation, deployment, or production connection:

```sh
npm install --ignore-scripts
npm run rls:full-generate
npm run rls:full-verify
node --test scripts/tests/production-rls-approval.test.mjs scripts/tests/production-full-rls-release.test.mjs
terraform -chdir=infra/aws/terraform init -backend=false
terraform -chdir=infra/aws/terraform fmt -check
terraform -chdir=infra/aws/terraform validate
```

`npm run rls:full-verify` is also a required pull-request quality gate. A source-contract
or generated-output mismatch blocks merge; it is not an ignorable pre-existing failure.
Regenerate only with `npm run rls:full-generate`, then rerun verification and confirm a
second generation produces no diff before release approval.

For the disposable PostgreSQL 18 production-target package proof:

```sh
docker run --name mscqr-production-package-postgres18 --rm \
  -e POSTGRES_USER=mscqr_test_admin \
  -e POSTGRES_DB=mscqr_production_package_disposable \
  -e POSTGRES_HOST_AUTH_METHOD=trust \
  -p 127.0.0.1:55434:5432 -d postgres:18.4

MSCQR_PRODUCTION_PACKAGE_POSTGRES18_TEST=true \
MSCQR_PRODUCTION_PACKAGE_POSTGRES18_ADMIN_URL=postgresql://mscqr_test_admin@127.0.0.1:55434/mscqr_production_package_disposable \
node --test scripts/tests/production-full-rls-package-postgres18.test.mjs
```

The test locally signs only under the explicit test contract, restores the certification package, drops its green database, and proves zero `mscqr_prd_rls_phase2_*` residue. Production generation and execution still require KMS verification.

Run the complete and focused application-path certificates against the same disposable PostgreSQL 18 administrator database:

```sh
export MSCQR_FULL_RLS_CERTIFICATION_CONFIRM=MSCQR_RUN_LOCAL_FULL_RLS_CERTIFICATION
export MSCQR_FULL_RLS_CERTIFICATION_ADMIN_URL=postgresql://mscqr_test_admin@127.0.0.1:55434/mscqr_production_package_disposable

npm run rls:full-certify
for family in b03-durable-outbox c03-authenticated-boundaries public-verification printing-lifecycle; do
  MSCQR_FULL_RLS_CERTIFICATION_FAMILY="$family" npm run rls:full-certify
done
```

The current aggregate certificate proves the required login/session, dashboard, QR, tenant-isolation and catalog paths, while still reporting `clean-room-full-table-enforcement-certified-workflows-pending`: 11 workflows have aggregate application-path evidence and 24 generated contracts do not yet have aggregate application-path certification. The focused B03 outbox, C03, public-verification and printing certificates pass independently. This is an evidence boundary, not permission to claim every registered route is production-certified; the change approvers must either accept that bounded evidence for the activation window or require the remaining workflow certificates before traffic.

## Empty-green first-user onboarding

Initial production activation may use the normal checksum-bound RLS release and backend activation transaction while signing-material rotation remains in authenticated dual-slot overlap. In that case the Release Gate requires `PRODUCTION_INITIAL_ACTIVATION_DURING_AUTHENTICATED_OVERLAP`: exact protected source, rotation state bytes/hash, rotation ID, current ECS task definition/deployment, immutable image digest, current/previous material identities, healthy overlap runtime proof, and the authenticated reviewed grace period of at least 2,592,000 seconds. The persisted `cleanupEligibleAt` must equal the overlap observation plus that exact reviewed grace. The live ECS deployment is re-read and must still match that proof before database mutation.

This permits initial onboarding only after overlap runtime verification. It does not declare `ROTATION_CLOSED`, retire old material, shorten the grace period, or satisfy normal post-rotation freshness. Final cleanup remains a separate governed transaction after `cleanupEligibleAt` and still requires retirement, cleanup deployment/runtime proof, old JWT/QR rejection, and final schema-v2 rotation evidence.

The normal Release Gate reconstructs the redacted rotation state from the authenticated workflow inputs on the production deployment runner. It validates the exact state bytes and hash before publishing same-job bindings, then repeats the overlap validation immediately before the RLS and backend activation mutations. State paths and `$GITHUB_ENV` values from the earlier target-resolution job are never consumed.

An empty green database is a supported launch state. During the brokered `full-rls-admin-ownership` task, after zero-based Prisma migration and before ownership transfer or policy installation, `backend/scripts/production-green-canary-provision.mjs` creates only the marked platform-admin and licensee-admin canary identities plus an isolation-control tenant. It accepts credentials and MFA seeds only through the pre-created secret handles, requires the validated production approval artifact and ownership confirmation, refuses any unrelated user already present, reconciles only its exact marked identities, and records approval ID, ticket ID, and independent-checker attribution without recording credentials. The mandatory canary then proves login, MFA completion, refresh rotation, `/api/auth/me`, dashboard statistics, QR statistics, cross-tenant denial, and logout/session revocation.

After traffic activation, the canary platform administrator creates or invites the first pilot platform and licensee administrators through the normal application governance route. Each recipient consumes the one-time invitation, completes password setup and email verification when required, enrols MFA, and signs in. `backend/scripts/resend-password-setup-link.js` remains the approved operator recovery path; it is dry-run by default, requires an operator, approval, reason, and explicit `--apply`, and never prints setup tokens or credentials. Passwords, MFA seeds, URLs, and setup tokens are never hard-coded or emitted in logs. Staging smoke remains in the workflow and may be marked non-blocking only when it is explicitly targeting the known broken endpoint; it does not replace the green canary gate.

## Operator sequence requiring separate authorization

Nothing in this section is authorized by this repository change.

1. Record blue database identifier, backend task definition `mscqr-backend:47`, worker task definition, current secret version IDs, target-group health, and a read-only blue fingerprint.
2. Stage A is the isolated green-infrastructure root. It has no blue-resource ownership, no image input, no ECS deployment, no runtime secret value, and no traffic switch. AWS root must not plan or apply. An authorised non-root role first creates or approves the dedicated state backend described by `infra/aws/terraform/production-green-stage-a/production-state-backend-prerequisite.json`, then initialises the dedicated root:

```sh
terraform -chdir=infra/aws/terraform/production-green-stage-a init \
  -backend-config='bucket=<approved-production-terraform-state-bucket>' \
  -backend-config='key=mscqr/production/rls-green/stage-a/terraform.tfstate' \
  -backend-config='region=eu-west-2' \
  -backend-config='encrypt=true' \
  -backend-config='use_lockfile=true'
terraform -chdir=infra/aws/terraform/production-green-stage-a plan -out=/secure/operator/rls-green-stage-a.tfplan
terraform -chdir=infra/aws/terraform/production-green-stage-a apply /secure/operator/rls-green-stage-a.tfplan
```

This creates the isolated RDS instance, KMS keys, checker/executor roles, security groups, and empty secret handles. It creates no secret value and does not touch blue.
3. Verify PostgreSQL 18, private networking, encryption, deletion protection, backups, empty public catalog, no package roles, and exact administrator attributes. Confirm the no-required-customer-data precondition or stop for an approved data-transfer plan.
4. Build/publish the backend, worker, and executor images from the release SHA and resolve immutable ECR digests. `publish-ecs-images.sh` reuses an existing immutable release tag on the later activation run:

```sh
  MSCQR_AWS_CREDENTIAL_SOURCE=named-profile MSCQR_AWS_NAMED_PROFILE=mscqr-production-release-deployer AWS_REGION=eu-west-2 IMAGE_TAG='<approved-release-sha>' \
  OUTPUT_FILE=/secure/operator/production-images.jsonl \
  scripts/aws/publish-ecs-images.sh backend
  MSCQR_AWS_CREDENTIAL_SOURCE=named-profile MSCQR_AWS_NAMED_PROFILE=mscqr-production-release-deployer AWS_REGION=eu-west-2 IMAGE_TAG='<approved-release-sha>' \
  OUTPUT_FILE=/secure/operator/production-images.jsonl \
  scripts/aws/publish-ecs-images.sh worker
  MSCQR_AWS_CREDENTIAL_SOURCE=named-profile MSCQR_AWS_NAMED_PROFILE=mscqr-production-release-deployer AWS_REGION=eu-west-2 IMAGE_TAG='<approved-release-sha>' \
  OUTPUT_FILE=/secure/operator/production-images.jsonl \
  scripts/aws/publish-ecs-images.sh rls-executor
```

Generate the source-contract and ordered migration digests locally.
5. The checker uses the MFA-backed source-role session from the authentication
boundary above, then assumes `mscqr-production-rls-independent-checker` through
the exact role chain. It first performs an unsigned local validation, then
explicitly signs the exact v2 input; the input contains every v2 field except
`signatureBase64` and no unknown fields:

```sh
node scripts/aws/create-production-green-stage-b-approval.mjs \
  --credential-source inherited-checker-session \
  --input /secure/operator/production-rls-stage-b-approval-input.json
node scripts/aws/create-production-green-stage-b-approval.mjs --sign \
  --credential-source inherited-checker-session \
  --input /secure/operator/production-rls-stage-b-approval-input.json \
  --output /secure/operator/production-rls-approval.json
```

6. The checker reviews the artifact fields and runs the repository-owned
`scripts/aws/publish-production-green-stage-b-approval.mjs` command. The
publisher uses only the exact Stage B approval secret and exact checker
session, validates before writing, uses the contract-defined deterministic
`ClientRequestToken`, and lets Secrets Manager move `AWSCURRENT` while
retaining the prior version as `AWSPREVIOUS`. Run
`scripts/aws/check-production-green-stage-b-approval-publication.mjs` through
the reviewed broker alias before treating the approval as published. Record
only its approval ID, contract SHA256, payload SHA256, and version ID in the
ticket. Do not expose the signature. The complete publication, idempotency,
rollback, and redaction contract is
`PRODUCTION_GREEN_STAGE_B_APPROVAL_PUBLICATION_CONTRACT-v1.md`.
7. Generate the production package using the KMS-backed artifact:

```sh
node scripts/rls/generate-clean-room-rls-sql.mjs \
  --environment production \
  --deployment-id phase2 \
  --release-sha '<approved-release-sha>' \
  --approval-artifact /secure/operator/production-rls-approval.json \
  --approval-kms-key-arn '<terraform-output-kms-key-arn>'
npm run rls:full-verify
```

8. Stage B is the protected release-activation contract in `infra/aws/terraform/production-green-stage-b/`. It starts only after Stage A outputs, the external protected release role, distinct checker, signed approval, and immutable backend/worker/executor image digests exist. It creates fixed executor/canary tasks and the reviewed broker, then runs mandatory green canaries; it is not part of the Stage A plan.
9. Invoke the protected release workflow with production approval, the exact approval secret ARN/ID, exact broker alias ARN, and `preserve_current_frontend=true`. It invokes only the broker. The broker revalidates the signed approval before every fixed phase.
10. The executor performs capability preflight, creates the exact database, creates restricted roles and generated credentials, writes only the declared secret handles, runs all Prisma migrations from zero, transfers ownership, installs grants/functions/policies, verifies the catalog, and writes redacted receipts.
11. The broker runs the application canary task against green. Required checks are ordinary login, admin login with recent MFA, admin MFA challenge completion, `/auth/me`, refresh-token rotation, dashboard stats, QR stats, catalog verification, and tenant-isolation certification. Any failure triggers pre-traffic green cleanup and leaves backend traffic on blue.
12. Only after independent receipt review, activate the exact Terraform-managed Stage-B backend candidate revision with the exact all-or-nothing secret map. Production currently has no worker ECS service, so preserve the worker image/candidate contract without issuing a worker service update. Do not deploy the frontend. Wait for backend ECS steady state and rerun external canaries.
13. Record task-definition ARNs, secret version IDs (not values), receipt bundle hash, approval ID, checker identity, catalog hash, canary results, and blue fingerprint.

## Database invariants

Before:

- blue identifier/fingerprint unchanged and never named as an executor target;
- green PostgreSQL major is 18 and public catalog contains zero application objects;
- no `mscqr_prd_rls_phase2_*` role exists;
- administrator is `LOGIN NOINHERIT NOSUPERUSER CREATEDB CREATEROLE NOREPLICATION NOBYPASSRLS`;
- approval, release, green database, source digest, migration digest, and KMS key match.

After installation, before traffic:

- all Prisma migrations exist in order with approved checksums;
- 79 inventoried tables and 77 FORCE-RLS targets match the generated report;
- all `app_auth` and `app_rls` routines, policies, grants, owners, default ACLs, and role attributes match;
- `mscqr_rls_install.state` matches the approval and executing administrator;
- the backend has both restricted URLs and the worker has its restricted URL;
- every canary and tenant-isolation proof passes;
- blue fingerprint is unchanged.

After pre-traffic rollback:

- green database is absent;
- zero `mscqr_prd_rls_phase2_*` roles remain;
- no runtime secret is wired to an ECS service;
- backend remains `mscqr-backend:47` on blue;
- blue fingerprint is unchanged.

## Rollback trigger and window

Before accepted green writes, rollback on any checksum/approval mismatch, migration failure, catalog drift, secret partiality, health failure, RLS denial anomaly, cross-tenant result, login/refresh/MFA failure, dashboard/QR failure, or latency/error-budget breach. Stop green consumers, invoke the brokered rollback, verify zero residue, and retain blue traffic.

After any accepted green write, automated blue rollback is prohibited until an approved reconciliation procedure proves write safety.

Maximum recommended temporary activation window: two hours from approval issuance for installation and pre-traffic validation. Do not extend an approval; issue a new independently reviewed artifact. Keep blue available through at least one full production session/token lifetime and the agreed observation window, subject to the no-divergent-writes rule.

## Human/AWS blockers

- Independent checker, change-ticket, protected-environment, Terraform-plan, database-operator, and traffic-switch approvals.
- AWS access to create the isolated resources and populate secret values.
- Verified current production data inventory. Required customer data needs a separate reviewed copy/reconciliation contract before traffic.
- Approved existing canary accounts/data on green; fixture SQL is certification-only and must never seed production.
- Confirmation that worker secret wiring and current worker artifact are included in the same cutover.

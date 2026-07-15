# MSCQR Shared-Table RLS Functional Inventory — 2026-07-15

## Decision

The 222-row compatibility matrix represents 39 unique active application business operations, not 222 independent authorization requirements. `GET /api/qr/batches` reaches two of the matrix's functional groups directly through request authentication/scope hydration. Its complete query graph reads nine RLS-relevant tables. `Organization` is not on that graph; `User` is.

This review changed no application code, policy, SQL, AWS, test, deployment, or blocked-apply file.

## Exhaustive classification

The categories are mutually exclusive and total exactly 222 entries.

| Classification | Entries |
|---|---:|
| `active-unique-business-operation` | 39 |
| `duplicate-caller` | 14 |
| `repository-or-helper-internal` | 61 |
| `test-only` | 45 |
| `legacy-or-dead` | 2 |
| `CLI-or-manual-operations` | 57 |
| `background-or-scheduled` | 2 |
| `generated-or-false-positive` | 2 |
| `unknown-needs-review` | 0 |
| **Raw entries** | **222** |

Classification precedence is: generated rows, tests, proven duplicate implementations, CLI/manual surfaces, proven legacy/dead code, registered background work, helper/internal steps, then the single canonical entry for each active workflow. In an active workflow the first listed database call is the canonical matrix representative; its additional calls are internal workflow steps, not separate business operations.

## Canonical active operations

Each row below is one functional operation. `Internal steps` are additional matrix entries in the same canonical implementation and are classified `repository-or-helper-internal`.

| Canonical implementation | Canonical matrix entry | Internal steps |
|---|---|---:|
| `accountController.ts::updateMyProfile` | `User.UPDATE@56` | 1 |
| `accountController.ts::changeMyPassword` | `User.SELECT@134` | 1 |
| `auditController.ts::getLogs` | `User.SELECT@81` | 1 |
| `auditController.ts::exportLogsCsv` | `User.SELECT@167` | 1 |
| `authAdminSecurityController.ts::beginAdminWebAuthnSetupController` | `User.SELECT@82` | 0 |
| `authAdminSecurityController.ts::disableAdminMfaController` | `User.SELECT@391` | 0 |
| `authController.ts::me` | `User.SELECT@96` | 0 |
| `authSessionController.ts::passwordStepUpController` | `User.SELECT@161` | 0 |
| `irPolicyController.ts::createIrPolicy` | `Licensee.SELECT@94` | 0 |
| `licenseeController.ts::createLicensee` | `Licensee.SELECT@238` | 4 |
| `licenseeController.ts::getLicensees` | `Licensee.SELECT@388` | 0 |
| `licenseeController.ts::getLicensee` | `Licensee.SELECT@471` | 0 |
| `licenseeController.ts::updateLicensee` | `Licensee.UPDATE@528` | 0 |
| `licenseeController.ts::deleteLicensee` | `User.COUNT@556` | 1 |
| `licenseeController.ts::exportLicenseesCsv` | `Licensee.SELECT@591` | 0 |
| `licenseeInviteController.ts::resendLicenseeAdminInvite` | `Licensee.SELECT@47` | 2 |
| `qrController.ts::createBatch` | `Licensee.SELECT@383` | 1 |
| `qrController.ts::assignManufacturer` | `User.SELECT@713` | 0 |
| `userController.ts::createUser` | `Licensee.SELECT@262` | 2 |
| `userController.ts::getUsers` | `User.SELECT@370` | 1 |
| `userController.ts::getManufacturers` | `User.SELECT@432` | 1 |
| `userController.ts::updateUser` | `Licensee.SELECT@526` | 1 |
| `userController.ts::deleteUser` | `User.DELETE@631` | 5 |
| `userController.ts::restoreManufacturer` | `User.UPDATE@764` | 1 |
| `authService.ts::loginWithPassword` | `User.UPDATE@418` | 0 |
| `authService.ts::refreshSession` | `User.SELECT@596` | 0 |
| `emailVerificationService.ts::requestEmailChangeVerification` | `User.SELECT@55` | 2 |
| `emailVerificationService.ts::confirmEmailVerification` | `User.SELECT@218` | 1 |
| `inviteService.ts::createInvite` | `User.SELECT@250` | 1 |
| `inviteService.ts::acceptInvite` | `User.SELECT@586` | 1 |
| `inviteService.ts::getInvitePreview` | `Licensee.SELECT@654` | 0 |
| `passwordResetService.ts::requestPasswordReset` | `User.SELECT@35` | 0 |
| `passwordResetService.ts::resetPasswordWithToken` | `User.UPDATE@122` | 0 |
| `superAdminBootstrapService.ts::bootstrapConfiguredSuperAdmin` | `User.SELECT@123` | 2 |
| `incidentActionsService.ts::applyContainmentAction` | `Licensee.UPDATE@182` | 4 |
| `legacyQrRotationService.ts::getLegacyQrReport` | `Licensee.SELECT@237` | 0 |
| `printValidationEvidenceService.ts::generatePrintValidationEvidenceReport` | `User.SELECT@149` | 0 |
| `qrAllocationService.ts::allocateQrRange` | `Licensee.SELECT@52` | 0 |
| `scanLogReportingService.ts::listScanLogsForReporting` | `Licensee.RAW_SQL@191` | 0 |

Route registration proves the controller operations are active. Service operations above are imported by registered controllers, startup, or the registered worker. The `legacyQrRotationService` name does not make it dead: it is called by both the live legacy-report route and `startLegacyQrRiskReportScheduler` in `src/index.ts` and `src/worker.ts`.

## Helper and internal entries

The 61 helper/internal entries comprise 34 additional calls inside the 39 workflows above and these 27 dedicated helper calls:

| Helper group | Entries | Evidence |
|---|---:|---|
| `irIncidentController.ts::resolveOrgAdminEmail` | 2 | called inside the registered IR incident controller |
| `userController.ts::assertManufacturerTarget` | 1 | local guard used by user lifecycle handlers |
| `middleware/auth.ts::hydrateTenantIfNeeded` | 1 | called by `authenticate` and other auth middleware |
| `auditService.ts::resolveOrgId` | 1 | local audit enrichment helper |
| `authBootstrapRepository.ts::findPreCandidatePasswordUser` | 1 | reachable compatibility fallback |
| `authBootstrapRepository.ts::recordPasswordLoginFailure` fallback | 1 | reachable compatibility fallback at line 97 |
| `authEmailService.ts::getPrimarySuperadminEmail` | 1 | used by `sendAuthEmail` |
| `authService.ts::issueSessionForUser` | 1 | used by login/session issuance |
| `inviteService.ts::inferOrgIdForLicensee` | 1 | local invite helper |
| `inviteService.ts::resolveInviteActorContext` | 1 | local invite helper |
| `inviteService.ts::getOrCreatePlatformOrgId` | 2 | local invite helper |
| `dashboardSnapshotService.ts::computeDashboardSnapshot` | 4 | on-demand dashboard/SSE cache computation; not a scheduler |
| `incidentEmailService.ts::resolveActorUser` | 1 | local incident-email enrichment |
| `incidentEmailService.ts::getSuperadminAlertEmails` | 1 | active alert-recipient helper |
| `policyRuleEngineService.ts::resolveActiveRulesForLicensee` | 1 | local rule-engine helper |
| `manufacturerScopeService.ts::listManufacturerLicenseeLinks` | 1 | shared manufacturer-scope helper |
| `manufacturerScopeService.ts::listManufacturerLinkedLicenseeIds` | 1 | auth and batch-scope helper |
| `manufacturerScopeService.ts::upsertManufacturerLicenseeLink` | 2 | canonical link-mutation helper |
| `notificationService.ts::createRoleNotifications` | 1 | reused notification helper |
| `notificationService.ts::createUserNotification` | 1 | reused notification helper |
| `sensitiveActionApprovalService.ts::batchReleaseReviewBlocker` | 1 | local approval guard |

These entries remain real authorization requirements even though they are not unique business operations.

## Duplicates

Fourteen entries are proven duplicate implementations/callers:

- Six calls in `backend/scripts/cleanup-demo.ts` duplicate the same cleanup workflow in `cleanup-demo.js`; the JS file is the runnable compatibility entry because it loads the backend environment directly.
- Seven calls in `backend/scripts/repair-admin-accounts.ts` duplicate `repair-admin-accounts.js`; `backend/package.json` explicitly registers the JS file as `repair:admin-accounts`.
- `incidentEmailService.ts::getPrimarySuperadminEmail` duplicates the same env-first, earliest-active-platform-admin lookup in `auth/authEmailService.ts::getPrimarySuperadminEmail`. Both are active callers; the auth-email implementation is the canonical functional definition for inventory purposes.

Repeated calls inside one canonical workflow are not counted as duplicate callers: they are implementation steps and are included in the 61 helper/internal entries. Examples are the six calls in `userController.deleteUser`, five calls in `licenseeController.createLicensee`, and five calls in `incidentActionsService.applyContainmentAction`.

## Tests, CLI/manual, background, generated, and legacy

### Test-only — 45

| File | Entries |
|---|---:|
| `backend/tests/helpers/p2SeedFactories.js` | 8 |
| `backend/tests/p2BatchReleaseReadiness.test.js` | 2 |
| `backend/tests/phaseE2RoleTenantIdor.test.js` | 3 |
| `backend/tests/rlsAuthBootstrapP2.test.js` | 30 |
| `backend/tests/rlsPrototypeP2.test.js` | 2 |

### CLI/manual — 57

| Canonical manual surface | Entries |
|---|---:|
| `backend/prisma/seed.ts` | 9 |
| `break-glass-mfa-reset.ts` | 1 |
| `cleanup-demo.js` | 6 |
| `create-super-admin.js` | 3 |
| `repair-admin-accounts.js` | 7 |
| `resend-password-setup-link.js` | 2 |
| `resetSuperAdmin.ts` | 1 |
| `seed-enterprise-e2e.ts` | 4 |
| `seed-launch-smoke-users.js` | 9 |
| `seed-staging-rls-validation-data.js` | 14 |
| `staging-database-role-vpc-executor.mjs` | 1 |

None is imported by `src/index.ts` or `src/worker.ts`. Package scripts explicitly register the break-glass, resend, launch-smoke, staging-validation, repair, E2E-seed, and Prisma-seed commands. The remaining scripts are retained as manual tools; absence from a package script is not evidence of death. The VPC executor is an explicit one-off ECS helper task, not part of the serving backend.

### Background/scheduled — 2

`compliancePackService.ts::startCompliancePackScheduler` contains one `User.SELECT` and one `Licensee.SELECT`. Both `src/index.ts` and `src/worker.ts` explicitly register the scheduler. It is active, not dead.

### Generated/false-positive — 2

`shared-auth-lookup-password-user` and `shared-auth-record-password-failure` are synthetic design rows appended by `generate-shared-table-rls-compatibility-matrix.mjs`; they are not independent direct Prisma/raw-table call sites. The underlying named function calls remain real auth-boundary behavior.

### Legacy/dead — 2

`backend/src/services/userService.ts::createUser` contains `Licensee.SELECT` and `User.INSERT`, but no source, route, startup, worker, script, or test imports `userService`. The registered `POST /users` route uses `controllers/userController.ts::createUser`, which contains its own implementation. This is current-HEAD call-graph evidence, not an inference from low usage.

No other entry is classified dead. `unknown-needs-review` is zero.

## Exact `GET /api/qr/batches` runtime path

```text
backend/src/app.ts:346
  app.use("/api", routes)
    -> backend/src/routes/index.ts:1696
       GET /qr/batches
       -> authenticate
          -> middleware/auth.ts:35-69 hydrateTenantIfNeeded
             -> User SELECT at line 50
             -> for manufacturer: listManufacturerLinkedLicenseeIds
                -> ManufacturerLicenseeLink SELECT at manufacturerScopeService.ts:59
       -> enforceTenantIsolation
          -> only an explicit manufacturer licenseeId may call assertUserCanAccessLicensee
       -> qrController.ts:1251 getBatches
          -> stagingRlsBatchReadService.ts:52 listScopedBatchReadPayload
             -> when the canary flag is true:
                withStagingRlsBatchReadTransaction at stagingRlsBatchReadContext.ts:130
                -> set six transaction-local app.* settings
                -> buildScopedWhere
                   -> resolveScopedLicenseeAccess
                   -> normally reuses linkedLicenseeIds hydrated above
                   -> empty manufacturer claims may repeat the link SELECT
                -> batchAllocationService.ts:313 listBatchOperationalSummaries
                   -> Batch.findMany + Batch.count
                   -> include Licensee and manufacturer User
                   -> InventoryStatusRollup.findMany
                   -> QRCode.groupBy for ranges and missing rollups
                   -> printReservationService.ts:303 raw SELECT
                      QRCode LEFT JOIN PrintItem LEFT JOIN PrintSession LEFT JOIN PrintJob
```

The feature-disabled stable path calls the same `listBatchOperationalSummaries` graph through the versioned cache, but uses the normal Prisma client rather than the read-role transaction. It does not change which tables the uncached computation requires.

## Shared tables required by the route

| Shared table | Operation | Why |
|---|---|---|
| `User` | SELECT | actor hydration before the handler; manufacturer relation included in each Batch payload |
| `ManufacturerLicenseeLink` | SELECT | manufacturer linked-licensee hydration and empty-claim fallback scope resolution |
| `Licensee` | SELECT | Batch payload includes `licensee { id, name, prefix }` |
| `Organization` | none | `orgId` comes from the hydrated User/claims; no Organization query exists on this path |

`User` is therefore genuinely required twice. The direct matrix captures the middleware `User.SELECT`; the Batch relation load is implicit in `Batch.findMany(include.manufacturer)` and is outside the scanner's direct shared-delegate rows.

## Minimum RLS table set for batch list

To preserve the current response and authentication behavior, the minimum complete set is nine tables, all read-only on this route:

1. `Batch`
2. `InventoryStatusRollup`
3. `QRCode`
4. `PrintJob`
5. `PrintSession`
6. `PrintItem`
7. `Licensee`
8. `ManufacturerLicenseeLink`
9. `User`

`Organization` is not required. The earlier ten-table posture is broader than this exact route by one table.

## Recommendation

Keep `User` outside the current FORCE-RLS rollout even though the route reads it. The route cannot be called without authentication hydration, and its response currently needs manufacturer data, so pretending `User` is not a dependency would be incorrect. But enabling FORCE RLS on `User` still affects every revision-7 authentication, account, administrator, and system path. The safe conclusion is:

- narrow the proposed shared phase from four shared tables to the independently safe tables only after separate review;
- do not declare the batch-list route fully RLS-protected while `User` remains unprotected;
- complete the User compatibility slices before adding User to a FORCE-RLS phase;
- leave the blocked shared-table apply unchanged.

The smallest future route-specific alternative would be an explicitly reviewed projection that removes the `User` relation from the batch response and decouples auth hydration from User FORCE RLS. That is a product/API and security decision, not an inventory change, and is not implemented here.

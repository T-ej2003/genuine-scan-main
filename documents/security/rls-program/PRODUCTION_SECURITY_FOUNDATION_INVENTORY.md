# MSCQR production security foundation inventory

Date: 2026-07-22

This is a repository/package inventory, not a production-catalog attestation. It was derived from `tables.json`, `runtime-identities.json`, `public-read-contract.json`, `named-sql-function-inventory.json`, and the generated expected catalogue snapshot. No live database, AWS, staging, or production system was queried.

`Policy count = 0` means the generated package has no permissive path for that table. With RLS enabled and forced, the table fails closed; it does not mean that the application workflow for the table will work.

## 1. Tenant-owned tables

The generated package enables and forces RLS on every table below. Tenant authority is either an explicit row key or an inherited authoritative parent relationship.

### Explicit tenant or actor scope

| Table | Tenant key | ENABLE RLS | FORCE RLS | Policies |
|---|---|---:|---:|---:|
| AllocationEvent | licenseeId | yes | yes | 0 |
| AuditLog | orgId + licenseeId | yes | yes | 11 |
| Batch | licenseeId | yes | yes | 3 |
| CompliancePackJob | licenseeId | yes | yes | 6 |
| EvidenceRetentionJob | licenseeId | yes | yes | 0 |
| EvidenceRetentionPolicy | licenseeId | yes | yes | 2 |
| ForensicEventChain | licenseeId | yes | yes | 0 |
| Incident | licenseeId | yes | yes | 4 |
| InventoryStatusRollup | licenseeId | yes | yes | 1 |
| Invite | orgId + licenseeId | yes | yes | 2 |
| Licensee | orgId | yes | yes | 8 |
| ManufacturerLicenseeLink | licenseeId; manufacturerId narrows actor scope | yes | yes | 5 |
| Notification | orgId + licenseeId; userId narrows actor scope | yes | yes | 0 |
| Organization | id (tenant root) | yes | yes | 8 |
| PolicyAlert | licenseeId | yes | yes | 2 |
| PolicyRule | orgId + licenseeId; manufacturerId narrows actor scope | yes | yes | 2 |
| Printer | orgId + licenseeId; assignedUserId narrows actor scope | yes | yes | 0 |
| PrinterRegistration | orgId + licenseeId; userId narrows actor scope | yes | yes | 0 |
| QrAllocationRequest | licenseeId | yes | yes | 0 |
| QRCode | licenseeId | yes | yes | 3 |
| QRRange | licenseeId | yes | yes | 0 |
| QrScanLog | licenseeId | yes | yes | 2 |
| RouteTransitionMetric | licenseeId | yes | yes | 0 |
| ScanMetricsHourlyRollup | licenseeId | yes | yes | 0 |
| SecurityPolicy | licenseeId | yes | yes | 2 |
| SensitiveActionApproval | orgId + licenseeId; requestedByUserId narrows actor scope | yes | yes | 0 |
| SupportIssueReport | licenseeId; reporterUserId narrows actor scope | yes | yes | 0 |
| TenantFeatureFlag | licenseeId | yes | yes | 0 |
| TraceEvent | licenseeId | yes | yes | 2 |
| User | orgId + licenseeId; id narrows actor scope | yes | yes | 10 |

### Tenant scope inherited through an authoritative parent

| Table | Tenant key derivation | ENABLE RLS | FORCE RLS | Policies |
|---|---|---:|---:|---:|
| AdminMfaCredential | User(userId) → orgId/licenseeId | yes | yes | 1 |
| AdminWebAuthnCredential | User(userId) → orgId/licenseeId | yes | yes | 1 |
| AuthMfaChallenge | User(userId) → orgId/licenseeId | yes | yes | 1 |
| AuthSessionRiskSignal | User(userId) → orgId/licenseeId | yes | yes | 0 |
| AuthWebAuthnChallenge | User(userId) → orgId/licenseeId | yes | yes | 0 |
| CustomerTrustCredential | QRCode(qrCodeId) → licenseeId | yes | yes | 0 |
| EmailVerificationToken | User(userId) → orgId/licenseeId | yes | yes | 2 |
| IncidentCommunication | Incident(incidentId) → licenseeId | yes | yes | 0 |
| IncidentEvent | Incident(incidentId) → licenseeId | yes | yes | 0 |
| IncidentEvidence | Incident(incidentId) → licenseeId | yes | yes | 1 |
| IncidentEvidenceFingerprint | IncidentEvidence → Incident → licenseeId | yes | yes | 0 |
| IncidentHandoff | Incident(incidentId) → licenseeId | yes | yes | 2 |
| MfaLoginChallenge | User(userId) → orgId/licenseeId | yes | yes | 0 |
| Ownership | QRCode(qrCodeId) → licenseeId | yes | yes | 0 |
| OwnershipTransfer | Ownership(ownershipId) → QRCode → licenseeId | yes | yes | 0 |
| PasswordReset | User(userId) → orgId/licenseeId | yes | yes | 3 |
| PrintAuditEvent | Batch(batchId) → licenseeId | yes | yes | 0 |
| PrintItem | PrintSession → PrintJob → Batch → licenseeId | yes | yes | 1 |
| PrintItemEvent | PrintItem(printItemId) → Batch → licenseeId | yes | yes | 0 |
| PrintJob | Batch(batchId) → licenseeId | yes | yes | 1 |
| PrintJobChunk | PrintJob(printJobId) → Batch → licenseeId | yes | yes | 0 |
| PrintReissueRequest | PrintJob(originalPrintJobId) → Batch → licenseeId | yes | yes | 0 |
| PrintSession | PrintJob(printJobId) → Batch → licenseeId | yes | yes | 1 |
| PrinterAgentSession | PrinterRegistration(registrationId) → orgId/licenseeId | yes | yes | 0 |
| PrinterAttestation | PrinterRegistration(printerRegistrationId) → orgId/licenseeId | yes | yes | 0 |
| PrinterProfile | Printer(printerId) → orgId/licenseeId | yes | yes | 0 |
| PrinterProfileSnapshot | PrinterProfile(printerProfileId) → Printer → orgId/licenseeId | yes | yes | 0 |
| RefreshToken | User(userId) → orgId/licenseeId | yes | yes | 6 |
| ReplacementChain | QRCode(originalQrCodeId) → licenseeId | yes | yes | 0 |
| SupportTicket | Incident(incidentId) → licenseeId | yes | yes | 0 |
| SupportTicketMessage | SupportTicket(ticketId) → Incident → licenseeId | yes | yes | 0 |
| UserBackupCode | User(userId) → orgId/licenseeId | yes | yes | 1 |
| UserMfaFactor | User(userId) → orgId/licenseeId | yes | yes | 1 |

Some listed tables permit an explicitly reviewed platform/null-scope row. That exception is command-specific; it is not a tenant wildcard.

## 2. Platform/global tables

There is no generic platform-readable table. These tables or row modes are platform/global because their authoritative subject is the service or a platform actor rather than one tenant:

| Table or row mode | Why platform/global |
|---|---|
| RequestAccess | Platform access intake exists before tenant membership. |
| ScheduledJobCredential | Identifies one scheduled service/job family, not a human tenant actor. |
| VerificationDecision | Records proof-bound product verification decisions that can precede an authenticated tenant/customer relationship. |
| CustomerVerificationSession | Bound to a verification decision and customer proof, not caller-selected tenant context. |
| CustomerTrustIntake | Bound to a verification session; it is not a tenant directory. |
| CustomerWebAuthnChallenge / CustomerWebAuthnCredential | Actor-owned customer authentication material, not tenant-wide data. |
| AuditLog with null orgId/licenseeId | Platform/system audit evidence. |
| CompliancePackJob with null licenseeId | Explicit platform-wide scheduled compliance job only. |
| EvidenceRetentionJob with null licenseeId | Explicit platform retention job only. |
| ForensicEventChain with null licenseeId | Platform forensic evidence. |
| Notification with null orgId/licenseeId | Explicit system broadcast only. |
| PolicyRule with null orgId/licenseeId | Platform policy rule. |
| RouteTransitionMetric with null licenseeId | Anonymous/platform telemetry. |
| SecurityPolicy with null licenseeId | Platform default security policy. |
| SensitiveActionApproval with null orgId/licenseeId | Platform-scoped approval, still actor- and command-bound. |
| User with null orgId/licenseeId | Platform user; role and live session capability remain required. |

## 3. Public tables

Direct public-access tables: **none**. The package grants no table access to PostgreSQL `PUBLIC` and the public contract prohibits generic anonymous reads and lists.

Public and pre-auth product surfaces are intended to use exact `app_public` or `app_auth` SECURITY DEFINER functions through the restricted pre-auth identity. Those functions may consult or mutate a bounded row in QRCode, Licensee, Organization, Batch, ReplacementChain, QrScanLog, VerificationDecision, CustomerVerificationSession, SupportTicket, Incident, SupportIssueReport, RequestAccess, Invite, PasswordReset, EmailVerificationToken, User, RefreshToken, AuditLogOutbox, and ActionIdempotencyKey. This is function access, not public table access; several `app_public` runtime paths remain contract-only in the current inventory.

## 4. System, migration, and service tables

| Table | Classification and authority |
|---|---|
| `_prisma_migrations` | Prisma migration ledger; migration identity only and outside the 78 application models. |
| BatchPrintPackToken | Migration-only compatibility table; not an RLS runtime target. |
| PrintRenderToken | Migration-only compatibility table; not an RLS runtime target. |
| ActionIdempotencyKey | Exact operation/idempotency coordination. |
| AuditLogOutbox | Durable audit delivery boundary. |
| SecurityEventOutbox | Durable SIEM/security-event delivery boundary. |
| SystemCheckpoint | Internal checkpoint coordination. |
| ScheduledJobCredential | Hash-only scheduled identity credential. |
| CompliancePackJob | Tenant/platform scheduled compliance coordination. |
| EvidenceRetentionJob | Tenant/platform retention coordination. |
| ScanMetricsHourlyRollup | Tenant-scoped aggregation maintained by reviewed operations. |
| DegradationEvent | System evidence inheriting QR scope. |
| IncidentEvidenceFingerprint | Internal deduplication inheriting incident-evidence scope. |

## 5. Application identities

All statuses below describe checked-in/generated and locally certified architecture. Production deployment is not verified.

| Requested identity | Implementation | Current runtime status |
|---|---|---|
| Authenticated user | `identity-authenticated-app` LOGIN; opaque `aq_db_session` capability verified by exact `app_auth` boundary; exact function grants. | Implemented for reviewed boundaries; not all production callers/functions are migrated. |
| Platform admin | Same authenticated DB role; platform role and null tenant scope are derived live from User/session rows, not a separate privileged login. | Implemented for reviewed boundaries only. |
| Manufacturer | Same authenticated DB role; manufacturer/licensee scope is derived from live links after capability verification. | Implemented for reviewed boundaries only. |
| Operator | `identity-operator` LOGIN; no direct table privileges; exact `app_ops` procedures/commands only. | Contract and generated role exist; live production status unverified. |
| Worker | `identity-worker` LOGIN; exact durable outbox/job boundaries and command-specific privileges. | Audit/SIEM outbox boundaries implemented; other worker families remain unresolved. |
| Scheduled job | `identity-scheduled-job` LOGIN; hash-only ScheduledJobCredential verified by exact job-family functions. | Implemented for scheduled compliance boundary; other scheduled families require explicit contracts. |
| Pre-auth | `identity-pre-auth-app` LOGIN; no table privileges; exact `app_auth` bearer/token functions only. | Seven B01 pre-auth functions and refresh/session boundaries implemented locally. |
| Migration | `identity-migration` LOGIN; reviewed DDL only, followed by ownership transfer and catalogue verification. | Package role model exists; no production migration/deployment was run. |

The table owner and authentication/function owners are separate NOLOGIN, non-BYPASSRLS roles and are not runtime identities.

## 6. Demonstrated security guarantees

- The generated expected catalogue covers 78 Prisma application tables: 76 are `ENABLE ROW LEVEL SECURITY` plus `FORCE ROW LEVEL SECURITY` targets; the two migration-only tables are excluded from runtime access.
- The generated catalogue contains 114 operation-specific policies across 34 tables. The remaining 42 forced tables have no policy and therefore fail closed.
- Runtime identities are non-owners and are specified as non-superuser/non-BYPASSRLS; function owners are NOLOGIN and do not own protected tables.
- Runtime function grants are exact signatures. Repository/package scans find no production `GRANT EXECUTE ON ALL FUNCTIONS`, no runtime grant for `install_actor_context`, and no protected boundary granted to `PUBLIC`.
- B01 bearer-token consumption/rotation, database-verifiable authenticated sessions, scheduled-job identity, C03 compliance boundaries, and durable outbox workers have local PostgreSQL 18 certification evidence in the checked-in programme.
- The dashboard path verifies the database session capability before scope/data access; forged or missing capability/context fails closed.
- The dashboard fixture performance defect was test statistics, not an RLS relaxation: fixture `ANALYZE` reduced the measured function from 33.045 seconds to 182 milliseconds without policy, grant, index, signature, ownership, or application-query changes.

## 7. Missing production security guarantees

- No production catalogue snapshot proves that the generated owners, grants, policies, and FORCE-RLS flags are deployed.
- The named-function inventory contains 116 production-called functions: 43 reviewed and 73 unresolved. Unresolved functions receive no reviewed runtime boundary.
- Forty-two FORCE-RLS tables currently have no generated policy. They fail closed, but any production API still requiring them through direct access will fail until an exact boundary/policy exists.
- Application callers are not yet fully migrated from direct Prisma/table access to reviewed exact boundaries, so all production APIs are not guaranteed to work after activation.
- Public `app_public` contracts include routes that remain contract-only or explicitly blocked in the public-read review; public verification/support/intake behaviour is not fully runtime-certified.
- The complete local integration gate remains red at the unresolved named-function inventory; there is no full restricted-role backend verification across all production routes.

## 8. Current production guarantees

| Guarantee | Answer | Evidence |
|---|---|---|
| No cross-tenant reads | PARTIAL | Certified B01, authenticated-session, scheduled, C03, dashboard, and outbox boundaries derive scope authoritatively and negative probes fail closed. Seventy-three named functions and unmigrated direct access paths remain unresolved, and production catalogue state is unverified. |
| No cross-tenant writes | PARTIAL | Reviewed mutation boundaries use exact roles, forced RLS, row locks/atomic transactions, and cross-scope denial. Remaining mutation families and direct Prisma paths have not all been placed behind reviewed boundaries. |
| Correct role enforcement | PARTIAL | The identity/owner/grant architecture is implemented and exact for reviewed boundaries, with no blanket/Public execution. Platform/manufacturer/worker/operator coverage is incomplete across unresolved production callers, and no production role catalogue has been verified. |

## Release conclusion

The package is fail-closed for unimplemented access, but it does not yet guarantee both tenant isolation and working production APIs across the complete backend. It is suitable for the next restricted backend-verification phase, not for production activation.

# Database role grant inventory

Status: design and local disposable proof only. This is not a production grant approval.

This inventory is derived from direct Prisma delegate writes in `backend/src`, `backend/scripts`, and `backend/prisma/seed.ts`. The executable guard `npm run check:database-role-grant-inventory` re-extracts `create`, `createMany`, `upsert`, `update`, `updateMany`, `delete`, and `deleteMany` calls and requires the staging template to match exactly. Nested writes are reviewed with their parent service and are covered by the same listed table privilege; new nested write targets require an explicit inventory update.

The app role receives `SELECT` on all current Prisma tables, but never `ALL PRIVILEGES`, `TRUNCATE`, `REFERENCES`, `TRIGGER`, schema `CREATE`, role/database creation, or blanket function execution.

## Direct DML inventory

| Privilege | Tables with a direct backend write path |
| --- | --- |
| INSERT | ActionIdempotencyKey, AdminMfaCredential, AdminWebAuthnCredential, AllocationEvent, AuditLog, AuthMfaChallenge, AuthSessionRiskSignal, AuthWebAuthnChallenge, Batch, CompliancePackJob, EmailVerificationToken, EvidenceRetentionJob, EvidenceRetentionPolicy, ForensicEventChain, Incident, IncidentCommunication, IncidentEvent, IncidentEvidence, IncidentEvidenceFingerprint, IncidentHandoff, InventoryStatusRollup, Invite, Licensee, ManufacturerLicenseeLink, MfaLoginChallenge, Notification, Organization, Ownership, OwnershipTransfer, PasswordReset, PolicyAlert, PolicyRule, PrintAuditEvent, PrintItem, PrintItemEvent, PrintJob, PrintJobChunk, PrintReissueRequest, PrintSession, Printer, PrinterAgentSession, PrinterAttestation, PrinterProfile, PrinterProfileSnapshot, PrinterRegistration, QRCode, QRRange, QrAllocationRequest, QrScanLog, RefreshToken, RequestAccess, RouteTransitionMetric, ScanMetricsHourlyRollup, SecurityEventOutbox, SecurityPolicy, SensitiveActionApproval, SupportIssueReport, SupportTicket, SupportTicketMessage, SystemCheckpoint, TenantFeatureFlag, TraceEvent, User, UserBackupCode, UserMfaFactor |
| UPDATE | ActionIdempotencyKey, AdminMfaCredential, AdminWebAuthnCredential, AuthMfaChallenge, AuthWebAuthnChallenge, Batch, CompliancePackJob, EmailVerificationToken, EvidenceRetentionPolicy, Incident, IncidentEvidenceFingerprint, IncidentHandoff, InventoryStatusRollup, Invite, Licensee, ManufacturerLicenseeLink, MfaLoginChallenge, Notification, Organization, Ownership, OwnershipTransfer, PasswordReset, PolicyAlert, PolicyRule, PrintItem, PrintJob, PrintJobChunk, PrintReissueRequest, PrintSession, Printer, PrinterAgentSession, PrinterProfile, PrinterRegistration, QRCode, QRRange, QrAllocationRequest, RefreshToken, RequestAccess, ScanMetricsHourlyRollup, SecurityEventOutbox, SecurityPolicy, SensitiveActionApproval, SupportIssueReport, SupportTicket, SystemCheckpoint, TenantFeatureFlag, User, UserBackupCode, UserMfaFactor |
| DELETE | ActionIdempotencyKey, AdminWebAuthnCredential, AllocationEvent, AuditLog, Batch, BatchPrintPackToken, IncidentEvidence, IncidentEvidenceFingerprint, Licensee, ManufacturerLicenseeLink, PrintJob, Printer, PrinterAttestation, QRCode, QRRange, QrAllocationRequest, QrScanLog, User, UserBackupCode, UserMfaFactor |

## Sequences and functions

No sequence grants are currently required: the current Prisma schema has no `autoincrement` default and the reviewed migrations create no public sequence. The staging template refuses to proceed if a public sequence is present, forcing a fresh reviewed inventory before any sequence privilege is introduced.

No direct application call requires `EXECUTE` on a user-defined public function. `backend/src/services/hotEventPartitionService.ts` creates the duplicate-guard trigger function as a DDL/partition-maintenance action; it belongs to the controlled migrator-plus-owner workflow, not the normal app role. Candidate `app_rls` helpers are separately schema-qualified and granted only to the dedicated RLS read role by the candidate RLS template.

## Read-only RLS role

The RLS read role is SELECT-only on exactly these 16 route-graph tables: Organization, Licensee, User, ManufacturerLicenseeLink, Batch, InventoryStatusRollup, QRCode, PrintJob, PrintSession, PrintItem, PrinterRegistration, Printer, PrinterAttestation, PrinterAgentSession, PrinterProfile, and PrinterProfileSnapshot. It has no sequence, DML, schema-create, ownership, membership, or elevated role privileges.

## Change control

Any new model, raw SQL write, nested relation write target, sequence, or user-defined function call changes this inventory. Update the template and guard first, then rerun the disposable role-separation harness before a later staging review.

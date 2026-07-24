# MSCQR full-database table ownership review

This is the compact human review of the machine-readable classification in `tables.json`. It changes no policy, database owner, role, runtime behavior, or RLS state. All 78 Prisma tables remain policy-generation candidates owned logically by `identity-table-owner`; implementation and disposable PostgreSQL proof are separate work.

Dependency graph: 79 nodes, 38 directed edges, acyclic=true, recursion risks=0.

## Group A — Security-sensitive and identity

Tables: 23; resolved: 23; unresolved: 0; dependency edges: 15; confidence high/medium/low: 19/4/0; blockers: none.

| Table | Category | Row scope | Parent | FORCE RLS | Readers | Writers | Confidence | Blocker |
|---|---|---|---|---:|---|---|---|---|
| AdminMfaCredential | security-sensitive | Special repository/function boundary with row scope inherited from User through userId=id. | table-user | yes | identity-authenticated-app | identity-authenticated-app | high | none |
| AdminWebAuthnCredential | security-sensitive | Special repository/function boundary with row scope inherited from User through userId=id. | table-user | yes | identity-authenticated-app | identity-authenticated-app | high | none |
| AuthMfaChallenge | security-sensitive | Special repository/function boundary with row scope inherited from User through userId=id. | table-user | yes | identity-authenticated-app | identity-authenticated-app | high | none |
| AuthSessionRiskSignal | security-sensitive | Special repository/function boundary with row scope inherited from User through userId=id. | table-user | yes | none | identity-authenticated-app | high | none |
| AuthWebAuthnChallenge | security-sensitive | Special repository/function boundary with row scope inherited from User through userId=id. | table-user | yes | identity-authenticated-app | identity-authenticated-app | high | none |
| BatchPrintPackToken | migration-only | No production runtime row access; migration identity only. | — | no | none | none | high | none |
| CustomerAuthSession | security-sensitive | Hash-only customer capability sessions are reachable only through exact pre-auth SECURITY DEFINER functions; the raw bearer is never stored. | — | yes | identity-authenticated-app, identity-pre-auth-app | identity-authenticated-app, identity-pre-auth-app | high | none |
| CustomerTrustCredential | security-sensitive | Special repository/function boundary with row scope inherited from QRCode through qrCodeId=id. | table-qrcode | yes | identity-authenticated-app | identity-authenticated-app | high | none |
| CustomerTrustIntake | security-sensitive | Special repository/function boundary with row scope inherited from CustomerVerificationSession through sessionId=id. | table-customer-verification-session | yes | identity-authenticated-app | identity-authenticated-app | high | none |
| CustomerVerificationSession | security-sensitive | Special repository/function boundary with row scope inherited from VerificationDecision through verificationDecisionId=id. | table-verification-decision | yes | identity-authenticated-app, identity-pre-auth-app | identity-authenticated-app, identity-pre-auth-app | high | none |
| CustomerWebAuthnChallenge | security-sensitive | Special actor-owned repository/function boundary using customerUserId; administrator access is command-specific and audited. | — | yes | identity-authenticated-app | identity-authenticated-app | high | none |
| CustomerWebAuthnCredential | security-sensitive | Special actor-owned repository/function boundary using customerUserId; administrator access is command-specific and audited. | — | yes | identity-authenticated-app | identity-authenticated-app | high | none |
| EmailVerificationToken | security-sensitive | Special repository/function boundary with row scope inherited from User through userId=id. | table-user | yes | identity-pre-auth-app | identity-pre-auth-app | high | none |
| Invite | security-sensitive | Special repository/function boundary with row scope inherited from Organization through orgId=id. | table-organization | yes | identity-authenticated-app, identity-pre-auth-app | identity-authenticated-app, identity-pre-auth-app | medium | none |
| MfaLoginChallenge | security-sensitive | Special repository/function boundary with row scope inherited from User through userId=id. | table-user | yes | identity-authenticated-app | identity-authenticated-app | high | none |
| PasswordReset | security-sensitive | Special repository/function boundary with row scope inherited from User through userId=id. | table-user | yes | identity-pre-auth-app | identity-pre-auth-app | high | none |
| PrintRenderToken | migration-only | No production runtime row access; migration identity only. | — | no | none | none | high | none |
| RefreshToken | security-sensitive | Special repository/function boundary with row scope inherited from User through userId=id. | table-user | yes | identity-authenticated-app, identity-pre-auth-app, identity-scheduled-job | identity-authenticated-app, identity-pre-auth-app | high | none |
| ScheduledJobCredential | security-sensitive | Special named function, restricted repository, or operator boundary; ordinary authenticated broad-table access is forbidden. | — | yes | identity-scheduled-job | identity-scheduled-job | medium | none |
| SensitiveActionApproval | security-sensitive | Special actor-owned repository/function boundary using requestedByUserId; administrator access is command-specific and audited. | — | yes | identity-authenticated-app | identity-authenticated-app | medium | none |
| User | security-sensitive | Special actor-owned repository/function boundary using id; administrator access is command-specific and audited. | — | yes | identity-authenticated-app, identity-pre-auth-app, identity-restricted-read, identity-scheduled-job | identity-authenticated-app, identity-pre-auth-app | medium | none |
| UserBackupCode | security-sensitive | Special repository/function boundary with row scope inherited from User through userId=id. | table-user | yes | identity-authenticated-app | identity-authenticated-app | high | none |
| UserMfaFactor | security-sensitive | Special repository/function boundary with row scope inherited from User through userId=id. | table-user | yes | identity-authenticated-app | identity-authenticated-app | high | none |

## Group B — Tenant roots and membership

Tables: 3; resolved: 3; unresolved: 0; dependency edges: 0; confidence high/medium/low: 3/0/0; blockers: none.

| Table | Category | Row scope | Parent | FORCE RLS | Readers | Writers | Confidence | Blocker |
|---|---|---|---|---:|---|---|---|---|
| Licensee | tenant-owned | Direct transaction-context scope using orgId; platform-admin access remains command-specific. | — | yes | identity-authenticated-app, identity-pre-auth-app, identity-restricted-read, identity-scheduled-job | identity-authenticated-app | high | none |
| ManufacturerLicenseeLink | tenant-owned | Direct transaction-context scope using licenseeId; platform-admin access remains command-specific. | — | yes | identity-authenticated-app, identity-restricted-read | identity-authenticated-app | high | none |
| Organization | tenant-root | Organization.id is the canonical tenant identifier; ordinary actors may read only app.organization_id, while create/update/delete require explicit platform-admin commands. | — | yes | identity-authenticated-app, identity-pre-auth-app, identity-restricted-read, identity-scheduled-job | identity-authenticated-app | high | none |

## Group C — Batch and QR lifecycle

Tables: 15; resolved: 15; unresolved: 0; dependency edges: 5; confidence high/medium/low: 14/1/0; blockers: none.

| Table | Category | Row scope | Parent | FORCE RLS | Readers | Writers | Confidence | Blocker |
|---|---|---|---|---:|---|---|---|---|
| AllocationEvent | append-only-audit | Append-only evidence is scoped directly by licenseeId; NULL/platform events require the restricted audit boundary. | — | yes | none | identity-authenticated-app | high | none |
| Batch | tenant-owned | Direct transaction-context scope using licenseeId; platform-admin access remains command-specific. | — | yes | identity-authenticated-app, identity-pre-auth-app, identity-restricted-read | identity-authenticated-app | high | none |
| DegradationEvent | operational-system | Restricted system coordination inherited from QRCode. | table-qrcode | yes | none | none | high | none |
| InventoryStatusRollup | tenant-owned | Direct transaction-context scope using licenseeId; platform-admin access remains command-specific. | — | yes | identity-authenticated-app, identity-restricted-read | identity-authenticated-app | high | none |
| Ownership | parent-inherited | Single-parent authorization inherited from QRCode through qrCodeId=id. | table-qrcode | yes | identity-authenticated-app | identity-authenticated-app | high | none |
| OwnershipTransfer | parent-inherited | Single-parent authorization inherited from Ownership through ownershipId=id. | table-ownership | yes | identity-authenticated-app | identity-authenticated-app | high | none |
| QrAllocationRequest | tenant-owned | Direct transaction-context scope using licenseeId; platform-admin access remains command-specific. | — | yes | identity-authenticated-app | identity-authenticated-app | high | none |
| QRCode | tenant-owned | Direct transaction-context scope using licenseeId; platform-admin access remains command-specific. | — | yes | identity-authenticated-app, identity-pre-auth-app, identity-restricted-read | identity-authenticated-app, identity-pre-auth-app | high | none |
| QRRange | tenant-owned | Direct transaction-context scope using licenseeId; platform-admin access remains command-specific. | — | yes | identity-authenticated-app | identity-authenticated-app | high | none |
| QrScanLog | append-only-audit | Append-only evidence is scoped directly by licenseeId; NULL/platform events require the restricted audit boundary. | — | yes | identity-authenticated-app, identity-pre-auth-app | identity-authenticated-app, identity-pre-auth-app | high | none |
| ReplacementChain | parent-inherited | Single-parent authorization inherited from QRCode through originalQrCodeId=id. | table-qrcode | yes | identity-pre-auth-app | none | high | none |
| ScanMetricsHourlyRollup | operational-system | Restricted worker/scheduled coordination scoped by licenseeId; no platform-global bypass. | — | yes | identity-authenticated-app | identity-authenticated-app | high | none |
| TraceEvent | append-only-audit | Append-only evidence is scoped directly by licenseeId; NULL/platform events require the restricted audit boundary. | — | yes | identity-authenticated-app | identity-authenticated-app | high | none |
| VerificationDecision | security-sensitive | Special named function, restricted repository, or operator boundary; ordinary authenticated broad-table access is forbidden. | — | yes | identity-authenticated-app, identity-pre-auth-app | identity-pre-auth-app | medium | none |
| VerificationEvidenceSnapshot | security-sensitive | Special repository/function boundary with row scope inherited from VerificationDecision through verificationDecisionId=id. | table-verification-decision | yes | identity-authenticated-app, identity-pre-auth-app | identity-authenticated-app, identity-pre-auth-app | high | none |

## Group D — Printing and printers

Tables: 13; resolved: 13; unresolved: 0; dependency edges: 11; confidence high/medium/low: 11/2/0; blockers: none.

| Table | Category | Row scope | Parent | FORCE RLS | Readers | Writers | Confidence | Blocker |
|---|---|---|---|---:|---|---|---|---|
| PrintAuditEvent | append-only-audit | Append-only evidence inherits read scope from Batch through batchId=id; writes use the append boundary. | table-batch | yes | identity-authenticated-app | identity-authenticated-app | high | none |
| Printer | security-sensitive | Special actor-owned repository/function boundary using assignedUserId; administrator access is command-specific and audited. | — | yes | identity-authenticated-app, identity-restricted-read | identity-authenticated-app | medium | none |
| PrinterAgentSession | parent-inherited | Single-parent authorization inherited from PrinterRegistration through registrationId=id. | table-printer-registration | yes | identity-authenticated-app, identity-restricted-read | identity-authenticated-app | high | none |
| PrinterAttestation | parent-inherited | Single-parent authorization inherited from PrinterRegistration through printerRegistrationId=id. | table-printer-registration | yes | identity-restricted-read | identity-authenticated-app | high | none |
| PrinterProfile | parent-inherited | Single-parent authorization inherited from Printer through printerId=id. | table-printer | yes | identity-authenticated-app, identity-restricted-read | identity-authenticated-app | high | none |
| PrinterProfileSnapshot | parent-inherited | Single-parent authorization inherited from PrinterProfile through printerProfileId=id. | table-printer-profile | yes | identity-restricted-read | identity-authenticated-app | high | none |
| PrinterRegistration | actor-owned | Direct actor scope using userId; tenant/platform administration requires an explicit reviewed command boundary. | — | yes | identity-authenticated-app, identity-restricted-read | identity-authenticated-app | medium | none |
| PrintItem | parent-inherited | Single-parent authorization inherited from PrintSession through printSessionId=id. | table-print-session | yes | identity-authenticated-app, identity-restricted-read | identity-authenticated-app | high | none |
| PrintItemEvent | append-only-audit | Append-only evidence inherits read scope from PrintItem through printItemId=id; writes use the append boundary. | table-print-item | yes | none | identity-authenticated-app | high | none |
| PrintJob | parent-inherited | Single-parent authorization inherited from Batch through batchId=id. | table-batch | yes | identity-authenticated-app, identity-restricted-read | identity-authenticated-app | high | none |
| PrintJobChunk | parent-inherited | Single-parent authorization inherited from PrintJob through printJobId=id. | table-print-job | yes | identity-authenticated-app | identity-authenticated-app | high | none |
| PrintReissueRequest | parent-inherited | Single-parent authorization inherited from PrintJob through originalPrintJobId=id. | table-print-job | yes | none | none | high | none |
| PrintSession | parent-inherited | Single-parent authorization inherited from PrintJob through printJobId=id. | table-print-job | yes | identity-authenticated-app, identity-restricted-read | identity-authenticated-app | high | none |

## Group E — Audit, incident and governance

Tables: 18; resolved: 18; unresolved: 0; dependency edges: 7; confidence high/medium/low: 10/8/0; blockers: none.

| Table | Category | Row scope | Parent | FORCE RLS | Readers | Writers | Confidence | Blocker |
|---|---|---|---|---:|---|---|---|---|
| AuditLog | append-only-audit | Append-only evidence is scoped directly by orgId + licenseeId; NULL/platform events require the restricted audit boundary. | — | yes | identity-authenticated-app, identity-operator, identity-scheduled-job | identity-authenticated-app, identity-pre-auth-app, identity-worker | medium | none |
| EvidenceRetentionPolicy | tenant-owned | Direct transaction-context scope using licenseeId; platform-admin access remains command-specific. | — | yes | identity-authenticated-app, identity-scheduled-job | identity-authenticated-app | high | none |
| ForensicEventChain | append-only-audit | Append-only evidence is scoped directly by licenseeId; NULL/platform events require the restricted audit boundary. | — | yes | identity-authenticated-app | identity-authenticated-app | medium | none |
| Incident | security-sensitive | Special security repository using explicit licenseeId scope and command-specific platform administration. | — | yes | identity-authenticated-app, identity-scheduled-job | identity-authenticated-app, identity-pre-auth-app | medium | none |
| IncidentCommunication | append-only-audit | Append-only evidence inherits read scope from Incident through incidentId=id; writes use the append boundary. | table-incident | yes | identity-authenticated-app | identity-authenticated-app | high | none |
| IncidentEvent | append-only-audit | Append-only evidence inherits read scope from Incident through incidentId=id; writes use the append boundary. | table-incident | yes | identity-authenticated-app | identity-authenticated-app, identity-pre-auth-app | high | none |
| IncidentEvidence | append-only-audit | Append-only evidence inherits read scope from Incident through incidentId=id; writes use the append boundary. | table-incident | yes | identity-authenticated-app | identity-authenticated-app, identity-pre-auth-app | high | none |
| IncidentEvidenceFingerprint | operational-system | Restricted system coordination inherited from IncidentEvidence. | table-incident-evidence | yes | none | none | high | none |
| IncidentHandoff | parent-inherited | Single-parent authorization inherited from Incident through incidentId=id. | table-incident | yes | identity-authenticated-app, identity-scheduled-job | identity-authenticated-app | high | none |
| Notification | actor-owned | Direct actor scope using userId; tenant/platform administration requires an explicit reviewed command boundary. | — | yes | identity-authenticated-app | identity-authenticated-app | medium | none |
| PolicyAlert | tenant-owned | Direct transaction-context scope using licenseeId; platform-admin access remains command-specific. | — | yes | identity-authenticated-app | identity-authenticated-app | high | none |
| PolicyRule | security-sensitive | Special actor-owned repository/function boundary using manufacturerId; administrator access is command-specific and audited. | — | yes | identity-authenticated-app | identity-authenticated-app | medium | none |
| RequestAccess | security-sensitive | Special named function, restricted repository, or operator boundary; ordinary authenticated broad-table access is forbidden. | — | yes | identity-authenticated-app | identity-authenticated-app, identity-pre-auth-app | medium | none |
| SecurityPolicy | security-sensitive | Special security repository using explicit licenseeId scope and command-specific platform administration. | — | yes | identity-authenticated-app | identity-authenticated-app | medium | none |
| SupportIssueReport | security-sensitive | Special actor-owned repository/function boundary using reporterUserId; administrator access is command-specific and audited. | — | yes | identity-authenticated-app | identity-authenticated-app, identity-pre-auth-app | medium | none |
| SupportTicket | parent-inherited | Single-parent authorization inherited from Incident through incidentId=id. | table-incident | yes | identity-authenticated-app | identity-authenticated-app, identity-pre-auth-app | high | none |
| SupportTicketMessage | parent-inherited | Single-parent authorization inherited from SupportTicket through ticketId=id. | table-support-ticket | yes | none | identity-authenticated-app | high | none |
| TenantFeatureFlag | tenant-owned | Direct transaction-context scope using licenseeId; platform-admin access remains command-specific. | — | yes | identity-authenticated-app, identity-pre-auth-app | identity-authenticated-app | high | none |

## Group F — Operational/system

Tables: 7; resolved: 7; unresolved: 0; dependency edges: 0; confidence high/medium/low: 0/7/0; blockers: none.

| Table | Category | Row scope | Parent | FORCE RLS | Readers | Writers | Confidence | Blocker |
|---|---|---|---|---:|---|---|---|---|
| ActionIdempotencyKey | operational-system | Restricted system coordination boundary with no human broad-table access. | — | yes | identity-authenticated-app, identity-pre-auth-app, identity-scheduled-job | identity-authenticated-app, identity-pre-auth-app, identity-scheduled-job | medium | none |
| AuditLogOutbox | operational-system | Restricted system coordination boundary with no human broad-table access. | — | yes | identity-authenticated-app, identity-worker | identity-authenticated-app, identity-pre-auth-app, identity-scheduled-job, identity-worker | medium | none |
| CompliancePackJob | operational-system | Restricted worker/scheduled coordination scoped by licenseeId; no platform-global bypass. | — | yes | identity-authenticated-app, identity-scheduled-job | identity-scheduled-job | medium | none |
| EvidenceRetentionJob | operational-system | Restricted worker/scheduled coordination scoped by licenseeId; no platform-global bypass. | — | yes | none | identity-authenticated-app | medium | none |
| RouteTransitionMetric | append-only-audit | Append-only evidence is scoped directly by licenseeId; NULL/platform events require the restricted audit boundary. | — | yes | identity-authenticated-app | identity-authenticated-app | medium | none |
| SecurityEventOutbox | operational-system | Restricted system coordination boundary with no human broad-table access. | — | yes | identity-authenticated-app, identity-worker | identity-authenticated-app, identity-pre-auth-app, identity-worker | medium | none |
| SystemCheckpoint | operational-system | Restricted system coordination boundary with no human broad-table access. | — | yes | identity-authenticated-app | identity-authenticated-app | medium | none |

## Group G — Reference and remaining

Tables: 0; resolved: 0; unresolved: 0; dependency edges: 0; confidence high/medium/low: 0/0/0; blockers: none.

| Table | Category | Row scope | Parent | FORCE RLS | Readers | Writers | Confidence | Blocker |
|---|---|---|---|---:|---|---|---|---|


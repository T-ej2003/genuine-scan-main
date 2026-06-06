# MSCQR Incident/SLA Launch Scope

Date: 2026-06-06
Status: Green for launch MVP foundation; Yellow for operational SLA drill evidence.

## Launch MVP Scope

Implemented and tested foundation includes:

- public incident report intake
- incident rate limiting
- customer contact consent normalization
- incident severity/status fields
- incident timeline events
- tenant-scoped incident list/read/update/export APIs
- platform IR routes
- incident PDF export
- incident evidence handling
- customer incident update email path
- support ticket handoff foundation
- `IncidentHandoff` and support ticket SLA fields
- governance metrics referencing incident SLA status

Relevant tests:

- `backend/tests/incidentMvp.test.js`
- `backend/tests/incidentPdfExport.test.js`
- `backend/tests/phaseE2RoleTenantIdor.test.js`
- `backend/tests/p2DbAuthorization.test.js`
- `backend/tests/governanceComplianceDownloadResilience.test.js`

## What Is Not Claimed

Do not claim full operational SLA automation unless separately implemented, tested, and drilled. This launch scope does not claim:

- automated escalation paging
- guaranteed human response within SLA
- complete on-call rotation integration
- external ticketing integration
- customer-facing live SLA portal
- post-incident review automation

## Launch Sign-off Checklist

- [ ] Incident creation smoke passes in staging.
- [ ] Platform admin can view incident queue.
- [ ] Licensee admin cannot access another tenant incident.
- [ ] Incident PDF export works for an authorized incident.
- [ ] Customer notification uses staging-owned SMTP and does not expose SMTP internals.
- [ ] Support handoff/ticket record is created where workflow requires it.
- [ ] SLA fields are visible to operators.
- [ ] Manual escalation owner is named for launch week.

## Current Sign-off

- Code foundation: Green.
- Tenant/IDOR proof: Green subject to DB-backed gate passing in CI.
- Staging operational drill: Yellow until evidence is attached.

CTO recommendation: launch with explicit manual incident owner and daily SLA review until automated paging/escalation is tested in a separate post-launch hardening phase.

# Prioritized Action Plan

## Phase 0: Immediate Discovery

### Goals

- close remaining unknowns that block legal, ops, and launch signoff

### Tasks

- confirm production cookie/runtime inventory in browser
- confirm AWS backup, restore, alerting, SSL, and bucket controls with evidence
- confirm connector packaging/signing target platforms and release flow
- confirm whether any remaining clients depend on legacy auth compatibility

### Dependencies

- access to production/staging environment and AWS console evidence

### Owners

- DevOps
- Frontend
- Backend
- Legal/Privacy

### Estimated effort

- 1 to 2 days

### Go / no-go criteria

- all critical unknowns converted into evidence or explicit blockers

## Phase 1: Critical Blockers

### Goals

- remove blockers that make launch commercially unsafe

### Tasks

- repair Prisma migration chain
- publish Privacy Policy, Terms, and Cookie Notice
- decide and implement consent posture if required
- disable verify-customer bearer compatibility in production
- disable legacy admin token response in production
- finalize connector signing/notarization workflow

### Dependencies

- phase 0 evidence
- lawyer review

### Owners

- Backend
- Frontend
- Legal/Privacy
- DevOps

### Estimated effort

- 3 to 5 days

### Go / no-go criteria

- clean deploy proven
- legal docs published
- auth compatibility posture locked
- connector trust path approved

## Phase 2: Production Hardening

### Goals

- reduce avoidable security and professionalism debt before real customer traffic

### Tasks

- standardize structured logging
- remove mock data residue
- replace branded 404 and other dev-like surfaces
- add support evidence privacy notice
- verify permission matrix across roles and tenants

### Dependencies

- phase 1 completed or near-complete

### Owners

- Backend
- Frontend
- QA
- Support Ops

### Estimated effort

- 1 to 2 days

### Go / no-go criteria

- no obvious developer garbage remains in customer-facing flows
- logging and permission posture is clean enough for launch-week operations

## Phase 3: Legal / Privacy Completion

### Goals

- close privacy/compliance gaps beyond the minimum document set

### Tasks

- finalize retention/deletion policy
- prepare DPA
- confirm subprocessor/hosting disclosure
- complete runtime cookie audit against deployed stack

### Dependencies

- phase 0 evidence
- legal review

### Owners

- Legal/Privacy
- Founder
- Frontend
- Ops

### Estimated effort

- 2 to 3 days

### Go / no-go criteria

- legal package is internally approved and customer-facing links are live

## Phase 4: Role UAT and Data Onboarding

### Goals

- prove that real roles can use MSCQR with real-ish data and no trust-breaking issues

### Tasks

- execute UAT for super admin
- execute UAT for licensee admin
- execute UAT for manufacturer including connector install
- execute public verification UAT on desktop and mobile
- validate master data and QR allocation rules
- finalize onboarding packet and import templates

### Dependencies

- phases 1 and 2

### Owners

- QA
- Product Ops
- Customer Success
- Backend
- Frontend

### Estimated effort

- 3 to 5 days

### Go / no-go criteria

- all launch-blocking UAT issues are closed or explicitly waived by leadership
- signoff sheets are complete

## Phase 5: Go-Live Prep

### Goals

- make launch operationally controlled rather than hopeful

### Tasks

- publish operator deployment checklist
- rehearse rollback
- assign support and incident owners
- approve launch-day and incident communications
- confirm synthetic checks and dashboards

### Dependencies

- prior phases completed

### Owners

- DevOps
- Ops Lead
- Founder
- QA

### Estimated effort

- 1 to 2 days

### Go / no-go criteria

- rollback rehearsal complete
- support rota approved
- monitoring visible

## Phase 6: Launch Day

### Goals

- execute a controlled release with rapid detection and response capability

### Tasks

- confirm gate pass and approved release candidate
- deploy with named incident commander and communications lead
- run smoke tests
- monitor auth, verify, support, and connector download paths
- capture launch evidence artifact

### Dependencies

- all launch blockers closed

### Owners

- DevOps
- Engineering lead
- Ops lead
- Support lead

### Estimated effort

- same day

### Go / no-go criteria

- smoke tests pass
- no SEV-1 or SEV-2 regressions detected

## Phase 7: First 7 Days After Launch

### Goals

- stabilize early customer usage and catch operational weak points fast

### Tasks

- daily review of auth and verify failures
- daily review of support and incident queue
- daily review of connector install/printer issues
- collect first-customer friction points
- prioritize week-1 fixes
- hold 7-day retrospective

### Dependencies

- launch completed

### Owners

- Engineering
- Ops
- Support
- Product

### Estimated effort

- 1 week of hypercare

### Go / no-go criteria

- no unresolved severe incidents
- support backlog under control
- first-customer onboarding issues understood and owned

## CTO recommendations beyond this launch plan

1. Build a customer/tenant onboarding control center instead of relying on docs and manual ops forever.
2. Invest early in connector fleet visibility and printer health telemetry if manufacturers are core to the business model.
3. Add enterprise readiness features next: SSO/SAML, SCIM, tenant-level retention controls, customer-facing audit export, and admin approval workflows.
4. Add deeper product analytics around scan success, suspicious-result rate, invite acceptance, connector install failure, and support time-to-resolution so scale decisions are data-driven.

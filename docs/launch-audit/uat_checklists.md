# Role Flow Audit

This file covers:

- primary journeys by role
- missing states and edge cases
- permission and trust issues
- onboarding readiness
- UAT checklist per role
- signoff sheet template per role

Repo evidence used included `src/App.tsx`, `backend/src/routes/index.ts`, role guides under `docs/`, public verification components, support flows, and route guards.

## Super Admin

### Primary journeys

- Log in securely and complete MFA cycle
- View dashboard and operational overview
- Manage licensees and manufacturers
- Review code requests, QR requests, batches, and tracking
- Access audit logs, governance, support, incident response, and incidents
- Review operational/support escalations

### Missing or weak states

- Final launch/legal/trust links are not surfaced consistently in the app shell
- Operational ownership for support and incident queues is not clearly embedded in the product experience
- No final signoff artifact proves the super admin can execute a complete launch-day control cycle

### Permission observations

- Super admin-only routing is present for high-risk surfaces including `licensees`, `ir`, `incidents`, `support`, and `governance`
- Final verification task: confirm no hidden deep links or API calls allow non-super-admin access

### Workflow blockers

- Clean deployment blocker can affect any admin environment recreation
- Missing formal privacy/legal surface affects customer-facing confidence and enterprise procurement
- Ops evidence gap affects super admin confidence in incident handling and recovery

### Onboarding readiness

- Strong internal guides exist
- Still needs named launch-day command owner, backup owner, and support duty owner

### UAT checklist

- [ ] Super admin can log in with production auth settings and complete MFA
- [ ] Dashboard loads without console errors or broken empty states
- [ ] Licensee create/edit/deactivate flow works and audit trail is visible
- [ ] Manufacturer create/edit/access assignment flow works
- [ ] QR request approval/rejection flow works end to end
- [ ] Batch listing, filtering, and detail view work with production-like data
- [ ] Audit logs load with correct scope and role restrictions
- [ ] Governance, IR, and incident screens load and respect permissions
- [ ] Support queue can be viewed, triaged, and assigned according to SOP
- [ ] Legal/footer/support/trust links are present in final build
- [ ] No technical stack traces, raw IDs, or unprofessional wording appear during normal use

### Signoff template

| Field | Value |
| --- | --- |
| Role | Super Admin |
| Tester name |  |
| Environment |  |
| Test date |  |
| Blocking issues found |  |
| Non-blocking issues found |  |
| Data set used |  |
| Signoff status | Pass / Conditional / Fail |
| Approver |  |

## Licensee Admin

### Primary journeys

- Log in and access organization-specific dashboard
- Request or manage QR/code allocations
- Review batches and tracking
- Manage manufacturers within allowed scope
- Review audit-relevant activity and submit support issues when needed

### Missing or weak states

- No formalized launch kit proving what data licensees must provide before activation
- Need clearer first-login expectations and support/contact signposting
- Import/master-data validation process is not surfaced as a launch-ready workflow package

### Permission observations

- Licensee admin has access to batches, code requests, QR requests, tracking, manufacturers, and audit logs in the frontend route model
- Final verification task: test tenant isolation across all list/detail endpoints with cross-tenant IDs

### Workflow blockers

- Role-based UAT not yet signed off
- Legal/privacy/commercial documents not yet surfaced
- Data onboarding dependencies are not formalized enough for first customer activation

### Onboarding readiness

- Guide content exists
- Needs customer-facing onboarding packet and support expectations

### UAT checklist

- [ ] Licensee admin can log in and only see allowed organization data
- [ ] QR/code request creation works and validation messages are clear
- [ ] Request approval dependencies are understandable from UI copy
- [ ] Batches and tracking views load with realistic data volume
- [ ] Manufacturer relationship and visibility rules behave correctly
- [ ] Audit log visibility is scoped correctly
- [ ] Support issue submission works and expected response path is stated
- [ ] Empty states, error states, and success messages feel customer-safe
- [ ] Privacy, terms, cookie, and support links are accessible
- [ ] No cross-tenant leakage is observed in UI or API responses

### Signoff template

| Field | Value |
| --- | --- |
| Role | Licensee Admin |
| Tester name |  |
| Customer org |  |
| Environment |  |
| Test date |  |
| Blocking issues found |  |
| Non-blocking issues found |  |
| Signoff status | Pass / Conditional / Fail |
| Approver |  |

## Manufacturer

### Primary journeys

- Log in and access batch/print capabilities
- Complete printer setup and diagnostics
- Install and connect the local print connector
- Use print workflow and calibration state
- Review tracking and audit logs relevant to manufacturing operations
- Raise support issues when connector/printer issues occur

### Missing or weak states

- Connector installer trust and signing/notarization is not yet a closed launch item
- Manufacturer onboarding depends on device, OS, network, and local install realities that are not proven solely by repo tests
- Privacy wording around support screenshots and diagnostics needs clearer end-user explanation

### Permission observations

- Frontend explicitly exposes `printer-setup` to manufacturer role
- Session and local storage are used for printer onboarding and dialog state
- Final verification task: validate manufacturer cannot reach super admin/support/governance surfaces

### Workflow blockers

- Unsigned or weakly trusted connector packages will hurt adoption immediately
- UAT must include Windows and macOS installer experience, not just web routing

### Onboarding readiness

- Manufacturer guide exists
- Needs install prerequisites, signed-download confirmation, printer compatibility matrix, and named support escalation path

### UAT checklist

- [ ] Manufacturer login works with correct role restrictions
- [ ] Printer setup page loads cleanly and diagnostics are understandable
- [ ] Connector download is trusted and integrity information is visible
- [ ] Installation succeeds on target OS versions used by launch customers
- [ ] Printer discovery/handshake works in target customer environments
- [ ] Calibration state persists correctly and can be reset safely
- [ ] Batch print flow handles success, failure, retry, and offline states cleanly
- [ ] Manufacturer audit logs and tracking are correctly scoped
- [ ] Support capture flow explains screenshots/log collection clearly
- [ ] Error copy is user-safe and not overly technical

### Signoff template

| Field | Value |
| --- | --- |
| Role | Manufacturer |
| Tester name |  |
| Device / OS |  |
| Printer model |  |
| Environment |  |
| Test date |  |
| Blocking issues found |  |
| Non-blocking issues found |  |
| Signoff status | Pass / Conditional / Fail |
| Approver |  |

## Public Customer / Consumer

### Primary journeys

- Land on public trust pages
- Scan or enter a code
- Complete verification session flow
- Receive or use OTP/customer verification linkage if required
- Review authenticity results, ownership, and incident/reporting options

### Missing or weak states

- Privacy/cookie/legal trust information is not yet surfaced like a premium consumer product
- Final runtime cookie/storage inventory still needs browser confirmation
- Empty/error/help states should be reviewed against real customer confusion scenarios

### Permission observations

- Public routes are clearly separated from operator routes
- Verification session uses a distinct cookie/session model and browser continuity state
- Final verification task: verify no authenticated operator cookies or data leak into public flow

### Workflow blockers

- Public legal disclosures and cookie explanations are missing
- Support/incident/report privacy wording needs formalization

### Onboarding readiness

- No formal onboarding needed, but trust must be instant and low-friction
- Public footer, privacy links, support links, and verification help need to be always visible

### UAT checklist

- [ ] Public landing and trust pages load quickly and feel professional
- [ ] Code scan/manual verify flow works on mobile and desktop
- [ ] Success state clearly explains what was verified and what the user should do next
- [ ] Failure/suspicious state gives safe guidance without panic or technical jargon
- [ ] OTP or verification continuity flows work without confusing storage/session behavior
- [ ] Privacy, cookie, and terms links are present and readable before data submission
- [ ] Consent behavior matches the final legal decision
- [ ] No raw internal identifiers, stack traces, or developer wording are exposed
- [ ] Help/support escalation path is obvious
- [ ] Session recovery and refresh behavior feel stable rather than brittle

### Signoff template

| Field | Value |
| --- | --- |
| Role | Public Customer / Consumer |
| Tester name |  |
| Device / Browser |  |
| Environment |  |
| Test date |  |
| Blocking issues found |  |
| Non-blocking issues found |  |
| Signoff status | Pass / Conditional / Fail |
| Approver |  |

## Cross-role must-verify scenarios

- [ ] Expired session behavior is clear and secure for each role
- [ ] Unauthorized route attempts redirect cleanly and do not leak data
- [ ] Empty-state copy is actionable and non-technical
- [ ] Error logging is structured server-side and not noisy client-side
- [ ] Support issue submission is available where expected and hidden where not appropriate
- [ ] Role changes take effect immediately after re-authentication
- [ ] Audit trail reflects key actions taken by each role
- [ ] Production legal links remain accessible in all shells, including error states

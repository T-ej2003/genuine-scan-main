# 1. PLAN

MSCQR was audited as a production SaaS launch candidate using repo evidence only: application code, route definitions, auth/session logic, storage usage, operational docs, release workflows, security guardrails, and non-mutating validation commands. Unknowns were not treated as complete; they were converted into explicit verification tasks.

Audit workstreams executed:

| Workstream | What was verified |
| --- | --- |
| Architecture and roles | Frontend, backend, shared contracts, local print connector, route surfaces, role mapping |
| Privacy and storage | Cookies, localStorage, sessionStorage, auth/session tokens, Sentry, absence of marketing analytics |
| Security and hardening | RBAC, tenant isolation, CSRF, rate limiting, headers, upload validation, env/startup guards |
| AWS and operations | Deployment workflows, backup/restore docs, rollback docs, release gates, monitoring config validation |
| Product and role flows | Public verify flow, super admin, licensee admin, manufacturer, customer journeys and edge states |
| Quality validation | Frontend build, frontend typecheck, backend typecheck, representative frontend/backend tests, hardening scripts |
| Legal and compliance | Privacy/cookie/legal document gaps based on actual implementation and UK-facing compliance cues |
| Premium polish | Developer residue, trust gaps, empty/error/legal footer gaps, launch feel and professionalism |

# 2. EXECUTIVE SUMMARY

## Readiness score

**64 / 100**

## Launch verdict

**Not Ready**

## Why the verdict is this strict

MSCQR is technically much stronger than a typical pre-launch startup app. The codebase shows real production intent: RBAC, tenant isolation, CSRF, rate limiting, upload controls, security startup guards, release workflows, backup/incident runbooks, Playwright/Vitest coverage, and a meaningful trust/public verification experience. That said, paying-customer launch readiness is not only about whether the app works. It is also about whether a clean deployment succeeds, whether privacy/legal obligations are visibly met, whether operator/customer storage behavior is disclosed, whether rollback and restore are proven in the real environment, and whether distributed connector artifacts are trusted on end-user machines.

Today, MSCQR still has material launch blockers in those areas.

## Top blockers

| Blocker | Severity | Why it blocks launch |
| --- | --- | --- |
| Clean-environment Prisma migration chain is broken | Critical | `backend/README.md` documents that `backend/prisma/migrations/20260213120000_add_incident_response/migration.sql` alters `QrScanLog` before that table exists in a clean deployment path. A greenfield production restore or environment recreation can fail. |
| No formal Privacy Policy / Terms / Cookie Notice in product surface | Critical | Real users are onboarded and personal data is processed. Repo searches did not find formal public legal docs or visible legal links in the app. |
| No consent/banner implementation despite non-essential or borderline storage | High | Even though there is no evidence of GA/GTM/Hotjar-style marketing tracking, MSCQR uses several browser-side identifiers and optional Sentry telemetry. Cookie/storage disclosures are not surfaced in-product. |
| AWS ops evidence is documented but not proven | High | Backup, restore, monitoring, secret rotation, S3/versioning, SSL, alert routing, and restore drill evidence are described in docs but not provable from repo alone. |
| Customer auth legacy compatibility still present | High | Verify-customer bearer compatibility remains available when enabled; `scripts/check-customer-auth-cutover.mjs` currently skips because `ENFORCE_BEARER_COMPAT_DISABLE` is false. |
| Connector signing/notarization must be confirmed before manufacturer rollout | High | Browser app signing is not required, but local print connector installers should be signed and, on macOS, notarized to avoid trust and install friction. |

## Top risks after launch if blockers are ignored

| Risk | Impact |
| --- | --- |
| Failed clean recovery or fresh environment provisioning | Operational outage or inability to restore/scale environments quickly |
| Privacy complaint or customer trust loss | Legal exposure, slowed enterprise sales, onboarding friction |
| End-user distrust of connector download | Manufacturers may refuse installation or trigger OS trust warnings |
| Weak proof of backup/restore readiness | High-severity operational risk if data corruption or account compromise occurs |
| Mixed legacy/new auth behaviors | Harder support burden, inconsistent token/session posture, audit noise |

## Must fix before launch

1. Repair and validate the Prisma migration chain on a clean database.
2. Publish Privacy Policy, Terms of Use, Cookie Notice, and visible legal footer links.
3. Decide and implement cookie/storage consent posture based on the final runtime stack, including Sentry and browser identifiers.
4. Confirm real AWS backup, restore, alerting, secret rotation, SSL, and storage controls with evidence.
5. Complete connector signing/notarization decision and release procedure.
6. Complete role-based UAT and onboarding signoff for super admin, licensee admin, manufacturer, and public verification.

## Can wait until post-launch

1. Bundle-size optimization of larger frontend chunks.
2. Additional premium UX refinement of empty/error states beyond blocker surfaces.
3. Longer-term analytics maturity, product instrumentation, and customer success dashboards.
4. Extended security improvements such as centralized audit dashboards and automated evidence export.

## Estimated effort by gap cluster

| Gap cluster | Effort |
| --- | --- |
| Migration chain repair and clean deploy proof | 1 to 2 days |
| Legal/privacy docs and in-app surfacing | 3 to 5 days plus lawyer review |
| Cookie/storage disclosure and consent implementation | 1 to 3 days plus legal review |
| AWS evidence collection and restore verification | 2 to 4 days |
| Connector signing/notarization workflow | 1 to 3 days |
| Role UAT, data onboarding, and launch signoff | 3 to 5 days |
| Premium polish blockers and copy cleanup | 1 to 2 days |

## Recommended launch sequence

1. Fix clean deployment blocker.
2. Lock privacy/legal surface and consent approach.
3. Verify AWS operational controls with evidence.
4. Run role-based UAT with production-like data.
5. Sign connector artifacts and validate installer trust.
6. Execute go-live checklist and staffed hypercare window.

# 3. ARCHITECTURE / PRODUCT UNDERSTANDING

## What MSCQR is

MSCQR is not a simple marketing site or demo. It is a production-style QR trust and operational platform with:

- A Vite/React frontend under `src/`
- An Express/TypeScript backend under `backend/src/`
- Prisma/Postgres persistence under `backend/prisma/`
- Shared contracts and validation utilities
- Public verification flows for scanned codes
- Admin/operator flows for super admin, licensee admin, and manufacturer users
- A local print connector/agent for manufacturer-side printing workflows
- Release, deployment, DR, and incident documentation under `docs/` and `.github/workflows/`

## Role model observed in code

Repo evidence shows these launch-relevant roles:

- Super admin / platform admin
- Licensee admin / org admin
- Manufacturer admin / manufacturer user
- Public customer / consumer verification user

The frontend route surface in `src/App.tsx` and backend route registration in `backend/src/routes/index.ts` support those journeys directly.

## Auth and session model observed

- Operator auth is cookie-backed with:
  - `aq_access`
  - `aq_refresh`
  - `aq_csrf`
- Public/customer verification uses a separate session model with:
  - `mscqr_verify_session`
  - `gs_device_claim`
  - browser identifiers and local/session storage continuity
- CSRF protection and role/tenant checks exist.
- Compatibility paths for legacy token/bearer behavior still exist and should be closed before premium launch.

## Storage and tracking model observed

- No evidence of Google Analytics, GTM, Mixpanel, Hotjar, Clarity, Segment, or similar marketing analytics.
- Sentry exists on frontend and backend but appears conditional on DSN configuration.
- Browser-side storage is actively used for verification continuity, help drafts, printer onboarding state, calibration state, and session proof caching.

## Package signing decision

**Package signing is not relevant to the browser-only web deployment.**

It **is relevant** for any distributed installer, desktop helper, local print connector, or native binary shipped to manufacturers or operators. For MSCQR, that means Windows code signing and macOS signing/notarization should be treated as launch requirements for the connector distribution path.

# 4. GAP ANALYSIS BY CATEGORY

The full finding inventory is in:

- [gap_analysis.csv](/Users/abhiramteja/Downloads/genuine-scan-main/docs/launch-audit/gap_analysis.csv)
- [gap_analysis.json](/Users/abhiramteja/Downloads/genuine-scan-main/docs/launch-audit/gap_analysis.json)

## Category summary

| Category | Current state | Launch posture |
| --- | --- | --- |
| Product readiness | Core workflows exist and feel intentionally designed | Needs role UAT, clean deploy proof, and onboarding readiness |
| UX/UI polish | Strong base, especially public trust pages | Missing legal/footer/trust completion and a few dev-like surfaces |
| Role-based workflows | Good coverage in routes and docs | Needs end-to-end signoff and permissions edge-case validation |
| Functional completeness | Broad feature surface | Some operational/legal completion work still missing |
| Data integrity | Strong schema intent, auditability, QR workflows | Migration chain blocker is a major risk |
| Security | Better-than-average startup hardening | Still needs final auth cleanup, log cleanup, artifact trust, and evidence |
| Privacy and cookies | Storage/session use is understandable | Disclosure and consent posture incomplete |
| Legal/compliance | Guides reference compliance | Formal customer-facing legal documents are missing |
| AWS/infra/ops | Strong documentation and workflow posture | Real environment evidence still needed |
| Monitoring/incident handling | Good runbooks and CloudWatch validation | Need proof of configured alerts and on-call ownership |
| Backup/restore/DR | Documents exist | Restore drill proof required |
| Support/onboarding/comms | Support launcher and docs exist | Launch-day support process and templates need finalization |
| Release management | Release gate and audit workflows exist | Final go-live checklist and rollback rehearsal required |
| Performance/scalability | Build passes; chunking is acceptable for now | Bundle optimization and capacity evidence can follow post-launch |
| Premium SaaS feel | Strong trust/product direction | Legal trust surface and customer reassurance still incomplete |

# 5. ROLE FLOW AUDIT

Detailed role journeys, UAT checklists, workflow blockers, and signoff templates are in:

- [uat_checklists.md](/Users/abhiramteja/Downloads/genuine-scan-main/docs/launch-audit/uat_checklists.md)

## Current role-flow verdict

| Role | Verdict | Notes |
| --- | --- | --- |
| Super admin | Conditionally strong | Broadest control surface exists, but go-live depends on clean migration, ops proof, and support/legal completion |
| Licensee admin | Risky until UAT | Core allocation and request flows appear present, but onboarding, data import, and support expectations need signoff |
| Manufacturer | Risky until connector trust is proven | Printer flows exist, but connector distribution and install trust are launch-critical |
| Public customer | Functionally credible | Privacy disclosures, consent posture, and edge-case copy still need hardening |

# 6. COOKIES / PRIVACY / LEGAL AUDIT

Detailed findings and inventories are in:

- [cookies_audit.md](/Users/abhiramteja/Downloads/genuine-scan-main/docs/launch-audit/cookies_audit.md)
- [legal_requirements_brief.md](/Users/abhiramteja/Downloads/genuine-scan-main/docs/launch-audit/legal_requirements_brief.md)

## Short conclusion

MSCQR does not appear to be running ad-tech or broad marketing tracking from repo evidence. That is good. However, the app still uses multiple cookies and browser storage keys tied to authentication, security, device continuity, support, and workflow persistence. Those behaviors need to be documented in a Privacy Policy and Cookie Notice, and the final consent requirement must be decided against the actual deployed runtime configuration and geography.

For a UK/EU-facing launch, lawyer review is strongly recommended before go-live.

# 7. SECURITY / HARDENING AUDIT

Detailed findings and checklists are in:

- [security_hardening_checklist.md](/Users/abhiramteja/Downloads/genuine-scan-main/docs/launch-audit/security_hardening_checklist.md)

## What is already good

- Production startup refuses several insecure configurations.
- RBAC and tenant isolation exist.
- CSRF protections are implemented for cookie-auth flows.
- Public rate limiting exists.
- Upload validation and MIME restrictions exist.
- Nginx hardening and public metadata guardrails are validated by scripts.
- Representative security-related tests passed.

## What still blocks a premium launch

- Broken migration chain
- Legacy auth compatibility not fully retired
- No proof of least-privilege AWS/IAM posture from repo alone
- No formalized retention/deletion surface for uploads and support evidence
- Local connector artifact trust path not proven

# 8. AWS / OPS / RELIABILITY AUDIT

Detailed readiness and runbooks are in:

- [ops_runbooks.md](/Users/abhiramteja/Downloads/genuine-scan-main/docs/launch-audit/ops_runbooks.md)

## Short conclusion

MSCQR is unusually well-documented for a pre-launch product. The issue is not absence of intent. The issue is that AWS-console-level proof is outside the repo, so launch readiness still depends on collecting evidence for backups, restores, alerts, rotations, S3/versioning, SSL, and production environment separation.

# 9. DATA / ONBOARDING / SUPPORT AUDIT

Detailed onboarding and support readiness checklists are in:

- [onboarding_checklists.md](/Users/abhiramteja/Downloads/genuine-scan-main/docs/launch-audit/onboarding_checklists.md)

## Short conclusion

MSCQR needs a disciplined first-customer onboarding motion, not just working screens. The platform should not grant access to licensees or manufacturers until master data, QR numbering rules, support contacts, connector readiness, and escalation ownership are confirmed.

# 10. PREMIUM POLISH AUDIT

Detailed polish issues and backlog are in:

- [premium_polish_backlog.md](/Users/abhiramteja/Downloads/genuine-scan-main/docs/launch-audit/premium_polish_backlog.md)

## Short conclusion

MSCQR already looks more serious than a demo, especially on the trust/public side. The main premium gaps are not flashy design work. They are trust-surface completeness: legal footer links, customer reassurance, removal of developer residue, consistent empty/error/support wording, and clearly trusted connector distribution.

# 11. MASTER LAUNCH CHECKLIST

Primary execution checklist:

- [master_launch_checklist.csv](/Users/abhiramteja/Downloads/genuine-scan-main/docs/launch-audit/master_launch_checklist.csv)
- [master_launch_checklist.json](/Users/abhiramteja/Downloads/genuine-scan-main/docs/launch-audit/master_launch_checklist.json)

# 12. PRIORITIZED PHASE PLAN

Practical launch plan:

- [prioritized_action_plan.md](/Users/abhiramteja/Downloads/genuine-scan-main/docs/launch-audit/prioritized_action_plan.md)

# 13. FILES GENERATED

- [launch_readiness_report.md](/Users/abhiramteja/Downloads/genuine-scan-main/docs/launch-audit/launch_readiness_report.md)
- [launch_readiness_report.json](/Users/abhiramteja/Downloads/genuine-scan-main/docs/launch-audit/launch_readiness_report.json)
- [gap_analysis.csv](/Users/abhiramteja/Downloads/genuine-scan-main/docs/launch-audit/gap_analysis.csv)
- [gap_analysis.json](/Users/abhiramteja/Downloads/genuine-scan-main/docs/launch-audit/gap_analysis.json)
- [uat_checklists.md](/Users/abhiramteja/Downloads/genuine-scan-main/docs/launch-audit/uat_checklists.md)
- [cookies_audit.md](/Users/abhiramteja/Downloads/genuine-scan-main/docs/launch-audit/cookies_audit.md)
- [legal_requirements_brief.md](/Users/abhiramteja/Downloads/genuine-scan-main/docs/launch-audit/legal_requirements_brief.md)
- [security_hardening_checklist.md](/Users/abhiramteja/Downloads/genuine-scan-main/docs/launch-audit/security_hardening_checklist.md)
- [ops_runbooks.md](/Users/abhiramteja/Downloads/genuine-scan-main/docs/launch-audit/ops_runbooks.md)
- [onboarding_checklists.md](/Users/abhiramteja/Downloads/genuine-scan-main/docs/launch-audit/onboarding_checklists.md)
- [premium_polish_backlog.md](/Users/abhiramteja/Downloads/genuine-scan-main/docs/launch-audit/premium_polish_backlog.md)
- [master_launch_checklist.csv](/Users/abhiramteja/Downloads/genuine-scan-main/docs/launch-audit/master_launch_checklist.csv)
- [master_launch_checklist.json](/Users/abhiramteja/Downloads/genuine-scan-main/docs/launch-audit/master_launch_checklist.json)
- [prioritized_action_plan.md](/Users/abhiramteja/Downloads/genuine-scan-main/docs/launch-audit/prioritized_action_plan.md)

# 14. FINAL GO/NO-GO RECOMMENDATION

**Recommendation: NO-GO until Critical and High blockers are closed.**

MSCQR is closer than many products ever get before first revenue, and that is worth recognizing. The engineering base is credible. The launch discipline is the missing piece. If you close the migration-chain issue, formalize privacy/legal trust surfaces, prove AWS recovery controls, lock connector artifact trust, and run role-based signoff, MSCQR can move from `Not Ready` to `Conditionally Ready` quickly.

## Validation evidence used

Successful non-mutating checks during this audit included:

- Frontend typecheck: `./node_modules/.bin/tsc --noEmit -p tsconfig.app.json`
- Frontend build: `./node_modules/.bin/vite build`
- Backend Prisma client generation and typecheck: `./backend/node_modules/.bin/prisma generate --schema backend/prisma/schema.prisma` and `./backend/node_modules/.bin/tsc -p backend/tsconfig.json`
- Frontend targeted tests: verify/login/connector/printer diagnostics suites passed
- Backend targeted tests: customer auth cookie mode, public verify rate limit, security hardening, admin MFA cycle passed
- Guardrail scripts passed for security hardening, nginx hardening, public metadata surface, trust observability, and CloudWatch config validation

## CTO recommendations beyond launch blockers

1. Add a proper trust/legal footer and a lightweight trust center entry point from every public and authenticated shell.
2. Centralize structured logging and eliminate stray `console.*` usage before scale makes incident forensics harder.
3. Build a first-class tenant onboarding console with import templates, validation reports, and signoff capture.
4. Add post-launch operational analytics around verification conversion, failed scans, printer health, invite acceptance, and support SLA compliance.
5. Plan for stronger enterprise controls next: SSO/SAML, SCIM, configurable retention, customer-facing audit exports, and admin approval workflows.

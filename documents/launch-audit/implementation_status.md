# MSCQR Closing Sprint Implementation Status

## Traffic-light summary

| Phase | Status | Light | Summary |
| --- | --- | --- | --- |
| Phase 0: Immediate Discovery | Waiting on user | Amber | Repo-first discovery is complete. External runtime and AWS evidence still required. |
| Phase 1: Critical Blockers | In progress | Amber | Migration fix, legal/trust routes, support privacy notice, consent plumbing, and auth-default hardening are implemented. External legal/signing evidence still pending. |
| Phase 2: Production Hardening | In progress | Amber | 404 recovery, support privacy copy, mock-data cleanup, and trust footer work are implemented. Permission-matrix automation still open. |
| Phase 3: Legal / Privacy Completion | In progress | Amber | Product legal pages exist and consent plumbing is staged. Lawyer approval and runtime proof still pending. |
| Phase 4: Role UAT and Data Onboarding | In progress | Amber | Execution-ready UAT and onboarding artifacts are created. Customer-specific data and human signoff still required. |
| Phase 5: Go-Live Prep | In progress | Amber | Operator runbooks, checklist templates, and evidence pack templates are created. AWS-side proof still pending. |
| Phase 6: Launch Day | In progress | Amber | Launch-day runbook and go/no-go materials are prepared. Release execution still depends on closed blockers. |
| Phase 7: First 7 Days After Launch | In progress | Amber | Hypercare and daily-review templates are prepared. Live telemetry/support evidence still pending. |

## Phase-by-phase task log

| Phase | Task | Status | What changed | Evidence | Next step | Owner |
| --- | --- | --- | --- | --- | --- | --- |
| Phase 0 | Reconfirm cookie/storage and auth posture | Done | Reconfirmed cookie/storage usage, operator auth production posture, and verify-customer compat behavior. | `cookies_audit.md`, `backend/src/services/customerVerifyCookieService.ts`, `backend/src/index.ts` | Capture runtime browser evidence. | Codex |
| Phase 0 | Build manual verification operating system | Done | Created manual verification tracker with click-by-click tasks and evidence requirements. | `manual_verification_tracker.md` | User collects evidence and pastes it back. | Codex / User |
| Phase 1 | Repair migration chain | Done | Added safe historical bootstrap for `QrScanLog` inside the incident-response migration. | `backend/prisma/migrations/20260213120000_add_incident_response/migration.sql` | Validate on a clean non-production DB. | Codex / User |
| Phase 1 | Add public legal/trust routes | Done | Added `/privacy`, `/terms`, and `/cookies` pages plus shared layout. | `src/App.tsx`, new legal page components | Lawyer review and copy approval. | Codex / User |
| Phase 1 | Add legal/footer surface | Done | Added shared legal footer across public/help/dashboard/verify shells. | `src/components/trust/LegalFooter.tsx` and linked shells | Visual QA in browser. | Codex / User |
| Phase 1 | Add support evidence privacy notice | Done | Added clear privacy notice to support issue reporting dialog. | `src/components/support/SupportIssueLauncher.tsx` | Confirm UX in browser. | Codex / User |
| Phase 1 | Stage consent plumbing | Done | Added feature-flagged consent banner plumbing. Default remains off. | `src/components/trust/CookieConsentBanner.tsx` | Decide whether to activate after legal review. | Codex / User |
| Phase 1 | Harden auth compatibility defaults | Done | Operator legacy token response now hard-fails in production if enabled; verify bearer compat defaults away from production. | `backend/src/index.ts`, `backend/.env.example`, `scripts/check-customer-auth-cutover.mjs` | Confirm no emergency rollback path is currently needed. | Codex / User |
| Phase 1 | Tighten connector trust surface | In progress | Connector UI still needs final browser QA against live manifest/signing evidence. | `src/pages/ConnectorDownload.tsx` | Bring back signing/account evidence. | Codex / User |
| Phase 2 | Remove launch-visible dev residue | Done | Deleted unused mock-data file and replaced dev-like 404 experience. | `src/lib/mock-data.ts` removed, `src/pages/NotFound.tsx` updated | Run UI regression tests. | Codex |
| Phase 2 | Clean support and trust wording | Done | Strengthened trust/legal/support guidance in live UI. | public pages, support launcher, footers | Browser QA. | Codex / User |
| Phase 2 | Fix worker archive bootstrap SQL | Done | Split trigger drop/create into separate raw SQL executions so Prisma/Postgres no longer reject the archive bootstrap with a multi-command prepared statement error. Added runtime regression coverage. | `backend/src/services/hotEventPartitionService.ts`, `backend/tests/hotEventPartitionRuntimeSql.test.js` | Redeploy backend and worker, then confirm logs stay clean. | Codex / User |
| Phase 2 | Permission-sensitive route verification | Not started | No new permission test matrix has been automated yet. | Audit artifacts | Convert role checks into executable validation next. | Codex |
| Phase 3 | Align legal/privacy UI with implementation | Done | Legal pages reflect actual cookies, sessions, support diagnostics, Sentry, and AWS-hosting posture. | new public legal pages | Lawyer review. | Codex / User |
| Phase 3 | Add retention and DPA handoff artifacts | Done | Added engineering retention notes and DPA handoff brief. | `retention_deletion_implementation_notes.md`, `dpa_handoff_brief.md` | Counsel completes final text. | Codex / User |
| Phase 4 | Create execution-ready UAT pack | Done | Added role-based UAT session plans. | `uat_session_plans.md` | Run UAT with real users/data. | Codex / User |
| Phase 4 | Create onboarding templates | Done | Added onboarding intake, master data request, QR worksheet, and contact matrix templates. | new onboarding template files | Fill with customer-specific data. | Codex / User |
| Phase 5 | Create go-live prep materials | Done | Added operator-friendly launch, owner, and release-evidence templates. | runbook/checklist/template files | Populate with real owners and live evidence. | Codex / User |
| Phase 6 | Create launch-day operator pack | Done | Added launch-day runbook and go/no-go checklist. | `launch_day_runbook.md`, `go_no_go_checklist.md` | Use during release. | Codex / User |
| Phase 7 | Create hypercare pack | Done | Added hypercare tracker, daily review checklist, issue triage template, and retrospective template. | hypercare files | Use in first 7 days after launch. | Codex / User |

## Validation run in this implementation pass

- Frontend typecheck: passed
- Backend Prisma client generation: passed
- Backend TypeScript compile: passed
- Frontend build: passed
- Targeted frontend tests: passed
  - `legal-surface.test.tsx`
  - `support-issue-launcher.test.tsx`
  - `connector-download.test.tsx`
  - `login-basic-flow.test.tsx`
  - `printer-diagnostics-page.test.tsx`
- Backend targeted tests: passed
  - `customerVerifyAuthCookieMode.test.js`
  - `securityHardening.test.js`
  - `authAdminLoginMfaCycle.test.js`
  - `hotEventPartitionPlan.test.js`
  - `hotEventPartitionRuntimeSql.test.js`

## What Abhiram must do next

1. Complete every task in `manual_verification_tracker.md` and bring the evidence back.
2. Run a clean non-production Prisma migration replay to prove the migration-chain fix.
3. Review the new `/privacy`, `/terms`, and `/cookies` pages in-browser and mark any wording that needs lawyer rewrite.
4. Confirm whether connector signing credentials and publisher details already exist.
5. After evidence comes back, I can close or reopen the remaining blockers with proof instead of assumptions.

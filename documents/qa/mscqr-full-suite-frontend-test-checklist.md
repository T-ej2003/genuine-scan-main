# MSCQR Full-Suite Frontend Test Checklist

## 1. Scope

This checklist covers the MSCQR frontend surface discovered in the current `genuine-scan-main` codebase: public marketing and trust pages, product verification and scan flows, authentication/session flows, role-protected platform workspaces, shared platform shell behavior, frontend-observable security behavior, accessibility, responsive behavior, and technical quality gates.

The checklist is intended for QA, engineering, and release readiness. It is written as manual test coverage first, then proposes automated coverage that matches the actual stack in this repository.

## 2. Discovery Summary From The Codebase

### Framework and frontend structure

- Vite + React 18 + TypeScript application.
- Routing uses `react-router-dom` in `src/App.tsx` with lazy-loaded pages and route guards.
- Server state and async UI use `@tanstack/react-query`.
- UI primitives are local shadcn/Radix-style components under `src/components/ui`.
- Styling uses Tailwind CSS with MSCQR-specific design tokens in `src/index.css`.
- Frontend entrypoint is `src/main.tsx`, which initializes theme, browser storage cleanup, consent cleanup, and frontend monitoring before rendering `<App />`.
- API access is centralized through `src/lib/api-client.ts`, composed from auth, QR/licensee, printing, admin ops, and verify/support client modules.
- Default API base URL is `import.meta.env.VITE_API_URL || "/api"`.
- Sentry frontend monitoring is consent-gated by analytics consent and uses release metadata from `src/lib/observability/release`.

### Public routes/pages discovered

- `/` home/landing page.
- `/trust` trust center.
- `/privacy` privacy policy.
- `/terms` terms of use.
- `/cookies` cookie notice.
- `/platform` platform marketing page.
- `/solutions/brands` brand marketing page.
- `/solutions/garment-manufacturers` garment manufacturer marketing page.
- `/solutions/apparel-authenticity` apparel authenticity page.
- `/how-scanning-works` public scanning explainer.
- `/about` company/about page.
- `/contact` company/contact page.
- `/request-access` request access page with client-side form validation and `mailto` handoff.
- `/blog` placeholder/insights page.
- `/verify` public verify landing/manual entry/camera-assisted entry page.
- `/verify/:code` public verification result/session flow.
- `/scan` public scan alias; without `?t=` it renders the verify landing.
- `/connector-download` public connector download page with invite-token preview behavior.
- `/help` help hub.
- Public/auth-optional help pages: `/help/auth-overview`, `/help/getting-access`, `/help/setting-password`, `/help/roles-permissions`, `/help/licensee-admin`, `/help/manufacturer`, `/help/customer`, `/help/support`.
- Public redirects: `/solutions/manufacturers`, `/solutions/licensees`, `/industries`, `/industries/industrial-components`, `/industries/spare-parts`, `/industries/regulated-supply-chains`.
- Catch-all `*` renders `NotFound`.

### Authentication routes/pages discovered

- `/login` with password login, MFA bootstrap/setup, MFA challenge, backup code challenge, and admin WebAuthn challenge.
- `/accept-invite?token=...` with invite preview, password setup, optional name, and connector-download link.
- `/verify-email?token=...` with loading, success, missing token, invalid/expired token states.
- `/forgot-password` with email submission.
- `/reset-password?token=...` with new password and confirm password.

### Platform/authenticated routes/pages discovered

- `/dashboard` available to all admin roles.
- `/licensees` super admin only.
- `/code-requests` super admin and licensee admin.
- `/qr-requests` redirects to `/code-requests`.
- `/batches` super admin, licensee admin, manufacturer.
- `/product-batches` redirects to `/batches`.
- `/printer-setup` manufacturer only.
- `/scan-activity` super admin, licensee admin, manufacturer.
- `/qr-tracking` redirects to `/scan-activity`.
- `/qr-codes` redirects to `/scan-activity`.
- `/manufacturers` super admin and licensee admin.
- `/audit-history` super admin, licensee admin, manufacturer.
- `/audit-logs` redirects to `/audit-history`.
- `/incident-response` super admin only.
- `/ir` and `/incidents` redirect to `/incident-response`.
- `/incident-response/incidents/:id` super admin only.
- `/ir/incidents/:id` super admin only.
- `/support` super admin only.
- `/release-readiness` super admin only.
- `/governance` super admin only.
- `/settings` all admin roles.
- `/account` all admin roles.

### Role-specific areas discovered

- `super_admin` / Platform Admin: dashboard, brands/licensees, QR requests, batches, manufacturers, scan activity, audit history, support, release readiness, governance, incident response, settings, account.
- `licensee_admin` / Brand Admin: dashboard, QR requests, batches, manufacturers, scan activity, audit history, settings, account.
- `manufacturer` / Manufacturer Admin: dashboard, batches, printer setup, scan activity, audit history, settings, account.
- Public customer/user flow: verify landing, verification result/session, customer OTP/social/passkey auth, product claim, ownership transfer, fraud report.

### Important shared components

- Public shell/header/footer: `PublicShell`, `PublicHeader`, `LegalFooter`, `CookieConsentBanner`.
- Platform shell: `DashboardLayout`, `DashboardLayoutShell`, sidebar, breadcrumbs, command palette, activity panel, notifications dropdown, theme toggle, support issue launcher, printer onboarding/status dialogs.
- Feedback and loading components: `LoadingState`, `ErrorState`, `EmptyState`, skeletons, toasts, operation progress dialogs.
- Data and workflow patterns: `DashboardPagePattern`, `DataTablePagePattern`, `DetailPagePattern`, `SettingsPagePattern`, `WorkflowModalPattern`.
- MSCQR domain components: status badges, lifecycle rail, audit timeline, verification confidence/stamp components, tracking insights panel.

### Important forms and workflows

- Login, MFA setup/challenge, WebAuthn challenge.
- Accept invite and connector onboarding handoff.
- Forgot/reset password and email verification.
- Public verify: manual QR code entry, image/camera QR capture, signed scan token, verification session bootstrap, customer email OTP, OAuth handoff, customer passkeys, intake/reveal, product claim, ownership transfer accept, concern/fraud report.
- Request access form with client-side validation and mailto handoff.
- Brands/licensees: create/edit/deactivate/hard delete guard, admin invite resend/copy, create user, allocate QR range.
- QR requests: licensee creates QR allocation request; super admin approves/rejects.
- Batches: search/filter, assign manufacturer, rename/delete, allocation map, audit package download, print job dialog, reissue flow.
- Printing: connector download, local helper status, printer inventory, network printer setup, live test label, diagnostics, managed printer profiles.
- Scan activity: filters, analytics, batch summary, scan logs, allocation map.
- Manufacturers: invite/link, details, deactivate/restore/delete, navigate to batch views.
- Audit history: audit log filters, fraud report queue, fraud response.
- Incident response: incidents, alerts, policies, incident detail actions, notes, email, evidence uploads/downloads, PDF/bundle export, customer trust review.
- Support center: support tickets, reports, assignment, status updates, internal/public messages, reporter responses.
- Governance: verify feature flags, evidence retention, compliance reports/packs, route telemetry, incident evidence bundle export.
- Account: profile, password, admin MFA, backup codes, WebAuthn credentials, active sessions, browser storage risk summary.

### API/client integration points

- Auth/session: `/auth/login`, `/auth/me`, `/auth/logout`, `/auth/forgot-password`, `/auth/reset-password`, `/auth/verify-email`, `/auth/invite`, `/auth/mfa/*`, `/auth/sessions`.
- Public verify/customer trust: `/verify/:code`, `/scan`, `/verify/session/*`, `/verify/auth/*`, `/fraud-report`, `/verify/feedback`, ownership transfer endpoints.
- QR/licensee/batches: `/licensees`, `/qr/ranges/allocate`, `/qr/generate`, `/qr/codes`, `/qr/batches`, `/qr/requests`, `/admin/qr/scan-logs`, `/admin/qr/analytics`.
- Printing/manufacturer: `/manufacturer/print-jobs`, `/manufacturer/printers`, `/manufacturer/printer-agent/*`, local connector `http://127.0.0.1:17866/*`.
- Admin ops: `/users`, `/audit/logs`, `/audit/fraud-reports`, `/trace/timeline`, `/analytics/*`, `/policy/*`, `/notifications`, `/governance/*`, `/telemetry/route-transition`, `/security/abuse/rate-limits`.
- Incidents/support: `/incidents/*`, `/ir/*`, `/support/tickets`, `/support/reports`.

### Existing test framework

- Unit/component tests: Vitest + jsdom + Testing Library, configured in `vitest.config.ts`, setup in `src/test/setup.ts`.
- Existing frontend tests include verify page, public verify entry route, login basic flow, MFA challenge, dashboard nav visibility, dashboard rate limit, dashboard manufacturer scope, batches, QR tracking, governance, IR, support center, support issue launcher, connector download, printer setup/diagnostics, legal surface, cookie preferences, frontend monitoring consent, browser storage cleanup, action button, API clients, and UI action inventory.
- E2E tests: Playwright configured by `playwright.enterprise.config.ts`.
- Existing E2E includes enterprise smoke tests and visual specs for client pages/platform shell using mocked or seeded roles.
- Current Playwright config only defines Chromium desktop project.

### Gaps or unknowns

- No dedicated Safari/WebKit, Firefox, Edge, iOS Safari, or Android Chrome Playwright projects are configured.
- No explicit axe/accessibility automation was discovered.
- No visual regression coverage was discovered for public marketing pages, verify result states, auth/MFA states, governance, incident detail, support center, printer setup, or mobile layouts beyond current visual snapshots.
- No direct route exists for pricing or billing/subscription pages.
- No dedicated 500 route was discovered; API/server errors are handled in-page through error states/toasts.
- Verify geolocation caching is currently stubbed in the frontend model (`readCachedGeo` returns `{}`), so location persistence expectations should be validated against backend behavior and product intent.
- Source map production behavior was not verified from code inspection.

## 3. Assumptions And Unknowns

- [ ] Treat `super_admin`, `licensee_admin`, and `manufacturer` as the only authenticated frontend roles unless backend fixtures expose more raw roles.
- [ ] Treat public verification customers as unauthenticated by default, with optional customer auth via email OTP, OAuth, passkey, and session proof token flows.
- [ ] Treat pricing and billing/subscription as not present until product adds routes or UI.
- [ ] Treat product management as batch/QR/licensee/manufacturer-oriented; no separate `/products` route was discovered.
- [ ] Treat `/connector-download` as public but security-sensitive because it exposes signed installer metadata/checksums.
- [ ] Validate all route redirects with query-string preservation where `RedirectWithQuery` is used.
- [ ] Confirm backend seed data exists for every P0 manual role-flow before QA execution.
- [ ] Confirm production build configuration for source maps, CDN caching, and security headers outside frontend code.

## 4. P0 Critical Test Checklist

### Public verification and customer trust

- [ ] `/verify` loads without calling `/auth/me`.
- [ ] `/scan` without `?t=` renders the verify landing.
- [ ] Manual code entry on `/verify` redirects to `/verify/:code` with URL-encoded code.
- [ ] Empty manual code disables the submit button.
- [ ] Camera/image QR capture works on browsers with `BarcodeDetector`.
- [ ] Camera/image QR capture shows safe fallback copy when `BarcodeDetector` is unavailable.
- [ ] Valid signed scan token `GET /scan?t=...` loads verification without exposing raw token in UI.
- [ ] Valid code shows genuine result with brand/licensee details, print check, scan history, and last checked time.
- [ ] Invalid/not-found code shows plain-language not-found result without stack traces.
- [ ] Blocked code shows blocked result and does not describe internal policy internals.
- [ ] Not-ready label shows not-ready/pending messaging and does not claim authenticity.
- [ ] Suspicious duplicate/repeat scan shows review-needed messaging and safe next steps.
- [ ] Network failure during verification shows a recoverable error and retry path.
- [ ] Verification challenge-required state blocks reveal until customer auth/quick check is completed.
- [ ] Customer email OTP request validates email, masks email in UI, and handles resend/failure safely.
- [ ] Customer OTP verify handles invalid, expired, and successful codes.
- [ ] Customer OAuth return hash is cleared after exchange.
- [ ] Customer passkey register/assert/delete handles unsupported browser and failed ceremonies safely.
- [ ] Product claim button appears only when allowed by `verifyUxPolicy` and ownership state.
- [ ] Ownership transfer accept handles invalid/expired token safely.
- [ ] Report concern validates reason/notes and displays only safe support ticket reference.
- [ ] Public verification result pages are `noindex,nofollow`.

### Authentication and session

- [ ] `/login` loads without private content flash.
- [ ] Valid login redirects to `/dashboard`.
- [ ] Invalid login shows a generic, safe error without account enumeration.
- [ ] Temporarily locked/rate-limited login shows safe waiting guidance.
- [ ] Email-unverified login shows verification guidance.
- [ ] MFA bootstrap setup starts when backend returns `MFA_BOOTSTRAP` with unenrolled admin.
- [ ] MFA setup QR and backup codes render without layout overflow.
- [ ] MFA setup confirmation handles invalid code and success.
- [ ] MFA challenge handles authenticator code, backup code, expired ticket, invalid code, and success.
- [ ] Admin WebAuthn challenge handles unsupported browser, canceled prompt, failed assertion, and success.
- [ ] Auth pages redirect authenticated users to `/dashboard`.
- [ ] Protected pages redirect unauthenticated users to `/login` without rendering sensitive content.
- [ ] Forbidden role access redirects to `/dashboard`.
- [ ] Logout clears auth state and returns to `/login`.
- [ ] Expired session clears user and returns to `/login`.
- [ ] `/accept-invite` handles missing token, preview, connector requirement, password mismatch, weak password, expired token, and success.
- [ ] `/verify-email` handles loading, missing token, invalid/expired token, normal verification, and email-change verification.
- [ ] `/forgot-password` does not reveal whether an account exists.
- [ ] `/reset-password` handles missing token, weak password, mismatch, expired token, and success redirect.

### Role-based shell and route protection

- [ ] `super_admin` sidebar shows Overview, Brands, QR Requests, Batches, Manufacturers, Scans, Support, History, Issues, Release Readiness, Settings.
- [ ] `licensee_admin` sidebar shows Overview, QR Requests, Batches, Manufacturers, Scans, History, Settings.
- [ ] `manufacturer` sidebar shows Overview, Batches, Printing, Scans, History, Settings.
- [ ] Manufacturer sees printer status/onboarding controls in shell.
- [ ] Non-manufacturer roles do not see manufacturer printer controls.
- [ ] Command palette only exposes role-allowed destinations.
- [ ] Notifications dropdown loads empty, unread, clear-all, and click-through states.
- [ ] Activity panel opens/closes and contains only role-safe content.
- [ ] Breadcrumbs match current route metadata.
- [ ] Direct URL access to super-admin routes by brand/manufacturer redirects safely.
- [ ] Direct URL access to brand routes by manufacturer redirects safely.

### Platform P0 pages

- [ ] `/dashboard` loads for every admin role.
- [ ] Dashboard handles loading, API error, no stats, live SSE connected/disconnected, polling fallback, and rate-limited recent activity.
- [ ] `/licensees` is accessible only to super admin.
- [ ] Licensee create/edit/deactivate/hard-delete guard flows handle success and failure.
- [ ] Licensee QR allocation guards prevent invalid ranges and large operations show progress.
- [ ] `/code-requests` is accessible only to super admin and licensee admin.
- [ ] Licensee admin can create QR request with valid quantity and batch name.
- [ ] Licensee admin cannot approve/reject QR requests.
- [ ] Super admin can approve/reject QR requests with decision notes.
- [ ] Large QR request approval shows progress and handles busy/conflict retry.
- [ ] `/batches` loads for all admin roles and enforces role-specific actions.
- [ ] Manufacturer can open print pack and print workflow only for assignable/printable batches.
- [ ] Licensee admin can assign manufacturer, rename, delete, view allocation map, and download audit package where permitted.
- [ ] Super admin/brand admin controlled print reissue requires reason.
- [ ] `/scan-activity` loads analytics, filters, logs, empty state, API error, and allocation map.
- [ ] `/manufacturers` is accessible to super admin and licensee admin only.
- [ ] Manufacturer invite/link/deactivate/restore/delete flows handle success, email delivery degraded state, and failure.
- [ ] `/audit-history` loads audit logs for all admin roles with correct scoped data.
- [ ] Super admin fraud report queue can respond with safe customer messaging.
- [ ] `/incident-response` and incident detail are super admin only.
- [ ] Incident response incidents/alerts/policies tabs load, filter, create/edit, and show safe errors.
- [ ] Incident detail supports status assignment, notes, communications, evidence upload/download, action dialogs, and trust review.
- [ ] `/support` is super admin only and supports ticket filtering, assignment, messages, and issue report replies.
- [ ] `/governance` is super admin only and supports flags, retention, compliance, telemetry, and exports.
- [ ] `/release-readiness` is super admin only and summarizes release metadata, compliance, telemetry, and rate-limit alerts.
- [ ] `/settings` and `/account` load for all admin roles and show role-appropriate cards.
- [ ] Account settings profile/password/MFA/WebAuthn/session controls handle validation and step-up required states.

### Security-facing P0

- [ ] No raw JWT, refresh token, session proof token, OTP, invite token, reset token, or signed scan token is displayed in UI.
- [ ] Protected routes never flash private data before redirect.
- [ ] Error states never render backend stack traces, raw Prisma/SQL errors, HTML error pages, or internal JSON objects.
- [ ] Frontend bundle does not expose secrets beyond intended public `VITE_*` values.
- [ ] Browser console is free of sensitive logs in normal login, verify, print, incident, and governance flows.
- [ ] Logout clears sensitive auth state, private query cache, and route access.
- [ ] Customer verify logout clears customer verification session state.
- [ ] Local/session storage contains no sensitive admin token material after login/logout.
- [ ] User-entered org, brand, manufacturer, product, batch, incident, support, and notes fields render XSS-safe.
- [ ] External and dynamic URLs do not allow unsafe redirects or `javascript:` execution.

## 5. P1 Important Test Checklist

### Public pages

- [ ] Home page hero CTAs go to `/request-access`, `/how-scanning-works`, and `/verify`.
- [ ] Public header brand link returns home.
- [ ] Public desktop nav links are correct.
- [ ] Public mobile header actions are visible and usable.
- [ ] Public footer legal links are correct.
- [ ] Trust center content loads and matches security positioning.
- [ ] Privacy, terms, and cookies pages load with legal footer.
- [ ] About and contact pages load; email link uses `mailto:administration@mscqr.com`.
- [ ] Request access form validates required full name, work email, company, role, volume, country, and message.
- [ ] Request access form rejects invalid email and insufficient message.
- [ ] Request access form success/handoff does not submit private data to unintended endpoint.
- [ ] Blog placeholder does not look broken or unfinished.
- [ ] Legacy/alias public routes redirect to canonical solution pages.
- [ ] Unknown route renders 404 with trusted recovery links.

### SEO and metadata

- [ ] Public pages set route-specific title and description.
- [ ] Public pages set canonical URL to `https://www.mscqr.com`.
- [ ] Home page structured data includes Organization and WebSite.
- [ ] Public pages include Open Graph and Twitter metadata.
- [ ] Auth/private/help detail/verify result pages are noindexed as configured.
- [ ] Redirect aliases do not produce duplicate indexable canonical pages.
- [ ] `robots.txt`, `sitemap.xml`, favicon, webmanifest, and brand assets load in production build.

### Platform shell

- [ ] Sidebar opens/closes on mobile and overlay click closes it.
- [ ] Sticky header remains visible during page scroll.
- [ ] User dropdown opens, links to settings, and logs out.
- [ ] Theme toggle persists expected theme without layout shift.
- [ ] Support issue launcher captures screenshot when allowed and handles upload/failure.
- [ ] Help assistant opens, role context is correct, search works, and no private data appears on public pages.
- [ ] Cookie consent banner appears where expected and persists preferences.
- [ ] Analytics consent initializes Sentry only after analytics consent.

### Tables, lists, dashboards, and data views

- [ ] Tables render empty, small, and large data sets.
- [ ] Search fields debounce or update without excessive UI jank.
- [ ] Filters combine correctly and can be cleared.
- [ ] Sorting/pagination is tested where available or explicitly absent.
- [ ] Row actions are visible only when permitted.
- [ ] Bulk actions, if present, handle no selection, partial failure, and success.
- [ ] Loading skeletons/spinners are visible and accessible.
- [ ] Refresh buttons handle success, failure, and in-flight disabled state.
- [ ] Export/download actions generate correct filenames and handle failed blob responses.
- [ ] Long names, emails, IDs, support refs, and QR codes wrap/truncate without overlap.
- [ ] Mobile table views remain usable through horizontal scroll, stacked rows, or alternate layout.

### Printing and connector

- [ ] Connector download page detects macOS, Windows, and unknown platform.
- [ ] Connector download page shows latest version, platform cards, signatures/trust labels, checksums, and release diagnostics.
- [ ] Connector download links normalize `/public/connector/download` to `/api/public/connector/download`.
- [ ] Invite-token preview on connector page handles valid, invalid, and network failure.
- [ ] Local connector status handles reachable, unreachable, outdated, protocol mismatch, and no printer.
- [ ] Printer setup inventory refresh does not thrash the UI.
- [ ] Printer setup auto-detect recommends local-only, network IPP, or network direct correctly.
- [ ] Printer setup blocks save when required host/IP/port/path/language is invalid.
- [ ] Printer setup warns against `local`, `localhost`, and `dnssd://` saved shared-printer addresses.
- [ ] Live test label success and needs-attention states are clear.
- [ ] Printer diagnostics can create/edit/delete managed printer profile and rotate gateway secret where supported.

## 6. P2 Nice-To-Have/Completeness Checklist

- [ ] Add visual regression snapshots for all public marketing pages.
- [ ] Add visual regression snapshots for every verification result category.
- [ ] Add visual regression snapshots for auth MFA setup/challenge and invite activation.
- [ ] Add visual regression snapshots for governance, release readiness, support, and incident detail.
- [ ] Add mobile visual snapshots for public verify, dashboard shell, batches, scan activity, and account settings.
- [ ] Add automated keyboard-only journey tests for public verify, login/MFA, and platform shell.
- [ ] Add axe accessibility checks to smoke routes.
- [ ] Add production build source-map and bundle disclosure checks.
- [ ] Add performance budget smoke for home, verify, dashboard, batches, and scan activity.
- [ ] Add network offline/slow 3G browser simulations for verify and connector pages.
- [ ] Add customer privacy copy assertions for geolocation/device metadata capture.
- [ ] Add synthetic monitoring checks for `/verify`, `/scan?t=...`, `/login`, `/dashboard`, and `/health/ready` handoff.

## 7. Page-By-Page Checklist

### `/` home

- [ ] Page loads with public shell/header/footer.
- [ ] Hero heading identifies MSCQR as garment authentication platform.
- [ ] Request Access CTA navigates to `/request-access`.
- [ ] See how scanning works CTA navigates to `/how-scanning-works`.
- [ ] Verify Product CTA navigates to `/verify`.
- [ ] QR label visual has accessible `role="img"`/label.
- [ ] Sections render without overlap on mobile/tablet/desktop.
- [ ] SEO title/description/canonical/OG/Twitter metadata are correct.

### `/platform`, `/solutions/brands`, `/solutions/garment-manufacturers`, `/solutions/apparel-authenticity`, `/how-scanning-works`, `/blog`

- [ ] Page loads through `PublicShell`.
- [ ] Page title and intro match route intent.
- [ ] Feature cards render icons and copy without overflow.
- [ ] Primary CTA routes are correct.
- [ ] Redirect aliases land on the canonical page.
- [ ] Metadata matches route-specific SEO map.
- [ ] Mobile layout stacks cards cleanly.
- [ ] Keyboard focus reaches every CTA in logical order.

### `/about` and `/contact`

- [ ] Page loads through `PublicShell`.
- [ ] About page describes garment-first product focus.
- [ ] Contact page email CTA uses `mailto:administration@mscqr.com`.
- [ ] Access request CTA goes to `/request-access`.
- [ ] No inactive/placeholder contact methods appear.
- [ ] Metadata matches SEO map.

### `/trust`, `/privacy`, `/terms`, `/cookies`

- [ ] Legal/trust page loads with correct title.
- [ ] Legal footer links do not loop incorrectly.
- [ ] Cookie notice page matches consent banner categories.
- [ ] Trust page does not over-disclose internal controls or secrets.
- [ ] Metadata matches SEO map.

### `/request-access`

- [ ] All fields render with labels and required-state cues.
- [ ] Missing required fields show field-specific errors.
- [ ] Invalid email shows field-specific error.
- [ ] Long company/message values do not break layout.
- [ ] Special characters render safely.
- [ ] Submit/check form disabled/loading/success states are clear.
- [ ] Mailto handoff includes safe, encoded content.
- [ ] Form remains usable on mobile.

### `/verify`

- [ ] Manual code input accepts common QR code formats.
- [ ] Manual code preserves exact value until redirect but normalizes where result requires.
- [ ] Enter key submits when code is present.
- [ ] Scan QR label button opens file/camera chooser.
- [ ] No QR detected shows helpful camera error.
- [ ] Unsupported browser shows manual-entry guidance.
- [ ] Redirect overlay displays both checking and opening stages.
- [ ] Telemetry capture failure does not block verification.

### `/verify/:code` and `/scan?t=...`

- [ ] Loading state is visible during session bootstrap.
- [ ] URL session proof flow reloads existing session using sessionStorage proof token.
- [ ] Result categories render correct title, badge, explanation, and icon.
- [ ] Brand, manufacturer, label status, proof tier, risk, replacement, and timeline cards render only when data exists/policy allows.
- [ ] Intake form validates source/context/concern/intent steps.
- [ ] Skip optional questions path reveals where allowed.
- [ ] Customer sign-in section supports email OTP, social provider links, and passkeys.
- [ ] Product claim, transfer accept, report concern, and help sections respect policy and auth state.
- [ ] Customer verify logout clears customer session and updates UI.

### `/connector-download`

- [ ] Page loads publicly without admin auth bootstrap.
- [ ] Latest release loading/error/success states render.
- [ ] Platform cards show correct filename, size, architecture, SHA-256, trust/signature status, notes, and CTA.
- [ ] Detected platform card is marked recommended.
- [ ] Unknown platform still shows available downloads.
- [ ] Local connector status handles reachable/unreachable.
- [ ] Invite token preview shows intended user/role without leaking token.
- [ ] Download link is safe and does not allow arbitrary external URLs.

### `/login`

- [ ] Email and password fields have labels and autocomplete.
- [ ] Show/hide password works and preserves value.
- [ ] Submit disabled/loading state prevents duplicate login.
- [ ] Humanized errors are safe and specific enough.
- [ ] Forgot password link works.
- [ ] Successful active session navigates to `/dashboard`.
- [ ] MFA setup/challenge/WebAuthn paths work as P0.

### `/accept-invite`

- [ ] Missing token error renders immediately.
- [ ] Invite preview renders email, role, licensee, expiration, and connector requirement.
- [ ] Name optional field accepts long and special-character names safely.
- [ ] Password minimum length and confirmation match enforced.
- [ ] Connector link includes invite token only in URL, not page copy.
- [ ] Success redirects to `/dashboard`.

### `/verify-email`, `/forgot-password`, `/reset-password`

- [ ] Loading/success/error states render.
- [ ] Missing/invalid/expired token states are safe.
- [ ] Password reset validates length and confirmation.
- [ ] Forgot password always shows non-enumerating success copy.
- [ ] Back-to-sign-in links work.

### `/dashboard`

- [ ] Cards show total QR codes, brands/licensees, manufacturers, and batches where role permits.
- [ ] QR status chart filters status rows.
- [ ] Live updates toggle starts/stops SSE/polling behavior.
- [ ] SSE snapshot and audit delta update UI.
- [ ] Rate-limited audit feed shows paused/unavailable copy.
- [ ] Quick actions reflect role.
- [ ] Dashboard empty/error/loading states work.

### `/licensees`

- [ ] Search and status filter update rows.
- [ ] Export CSV succeeds and handles failure.
- [ ] Create licensee validates name, prefix, admin email, and QR range fields.
- [ ] Invite email accepted and degraded mail states show correct copy.
- [ ] Copy invite link handles clipboard success/failure.
- [ ] Edit licensee validates name and optional brand/contact fields.
- [ ] Deactivate/reactivate updates row state.
- [ ] Hard delete is blocked when linked users/batches/QR codes/ranges exist.
- [ ] Create user validates role/email/name.
- [ ] Allocate QR range validates start/end and busy errors.

### `/code-requests`

- [ ] Status and licensee filters work.
- [ ] Licensee admin request form validates positive quantity and batch name length.
- [ ] Super admin sees approve/reject actions.
- [ ] Approval and rejection dialogs require/accept decision notes.
- [ ] Pending/approved/rejected badges and dates are clear.
- [ ] Large approval progress dialog completes or closes on failure.

### `/batches`

- [ ] Search, assignment filter, and print filter work.
- [ ] Stable batch rows display parent/child/allocation information correctly.
- [ ] Empty state explains next action by role.
- [ ] API error state offers refresh.
- [ ] Batch workspace opens and closes.
- [ ] Assign manufacturer validates manufacturer and quantity.
- [ ] Rename dialog validates non-empty name.
- [ ] Delete dialog requires confirmation and updates list.
- [ ] Allocation map dialog loads, empty, error, and success states.
- [ ] Audit package download handles blob failure.
- [ ] Print job dialog validates print quantity and selected printer.
- [ ] Print progress dialog updates total/printed/remaining/current code.
- [ ] Printer recovery actions handle relink, abandon, diagnostic test label, and retry.
- [ ] Reissue flow requires authorization reason and refreshes audit history.

### `/printer-setup` and `/printer-diagnostics`

- [ ] Manufacturer-only access enforced.
- [ ] Helper status, installed version, latest version, and printer count render.
- [ ] Inventory refresh button works and disables while fetching.
- [ ] Recommended path card updates when printer selection changes.
- [ ] Advanced fields toggle works.
- [ ] Network direct/IP address, IPP host/port/path/URI, TLS, command language, and delivery mode inputs validate.
- [ ] Save printer runs discovery and live test label.
- [ ] Existing registered printer test label works.
- [ ] Diagnostics route handles local agent unreachable, remote status stale, compatibility mode, blocked state, and trusted state.
- [ ] Managed profiles dialog supports edit/delete and gateway secret visibility safely.

### `/scan-activity`

- [ ] Totals, trend, event summary, batch summary, and logs render.
- [ ] Filters work for code, batch query, status, first scan, date range, licensee, outcome, risk band, replacement status, and customer trust review state.
- [ ] Super admin licensee selector loads and scopes data.
- [ ] Manufacturer/brand users do not see cross-tenant selector.
- [ ] Friendly error copy appears for 500/network/offline cases.
- [ ] Allocation map opens from a batch and handles loading/error/success.
- [ ] Long QR codes and locations do not overflow.

### `/manufacturers`

- [ ] Super admin licensee selector loads.
- [ ] Brand admin is scoped to own licensee.
- [ ] Search and show inactive filter work.
- [ ] Summary cards match filtered rows.
- [ ] Invite dialog validates email/name/licensee.
- [ ] Existing manufacturer link path shows linked/already linked messages.
- [ ] Invite email failure gives copyable link fallback.
- [ ] Details dialog opens and links to relevant batches.
- [ ] Deactivate, restore, and hard delete confirmation states work.

### `/audit-history`

- [ ] Audit log list loads and filters by search/activity/licensee.
- [ ] Live refresh toggle works.
- [ ] Row expansion shows readable details.
- [ ] Sensitive details are sanitized/masked, especially email and printer errors.
- [ ] Fraud report queue filters by status.
- [ ] Fraud report response validates message/status and notify-customer toggle.
- [ ] Fraud response delivery state is clear.

### `/incident-response` and `/incident-response/incidents/:id`

- [ ] Incidents tab filters status/severity/priority/licensee/search.
- [ ] Create incident validates QR code/description/type/severity/priority.
- [ ] Alerts tab filters acknowledgement/severity/type/licensee.
- [ ] Acknowledge alert updates list.
- [ ] Policies tab lists, creates, edits, activates/deactivates rules.
- [ ] Policy threshold/window validation prevents invalid values.
- [ ] Incident detail loads valid ID and handles invalid/not-found.
- [ ] Incident detail save validates status/severity/priority/assignee/tags/resolution.
- [ ] Notes require content and append to timeline.
- [ ] Email requires subject/message and shows delivery result.
- [ ] Attachment upload handles file selection, upload failure, and success.
- [ ] Evidence download and PDF export work and handle errors.
- [ ] Action dialogs require reason for suspend/reinstate/flag/unflag actions.
- [ ] Customer trust review validates credential selection and review note.

### `/support`

- [ ] Ticket filters search/status/priority and refresh work.
- [ ] Empty ticket list shows helpful empty state.
- [ ] Selecting ticket loads details and messages.
- [ ] Status/assignee save works for super admin.
- [ ] Internal/public message toggle is respected.
- [ ] Empty message is blocked.
- [ ] Issue reports list loads and can be responded to.
- [ ] Reporter notification success/failure is clear.
- [ ] `reference`, `incidentId`, and `ticketId` query params seed selection/search.

### `/governance`

- [ ] Super admin licensee selector loads and scopes data.
- [ ] Verify feature flags toggle and persist.
- [ ] Retention policy validates retention days and legal hold tags.
- [ ] Retention preview and apply modes show evaluated/exported/purged counts.
- [ ] Compliance report loads and handles failure.
- [ ] Compliance pack run starts and jobs list refreshes.
- [ ] Compliance pack download works and handles failure.
- [ ] Route telemetry loads and shows verify funnel data.
- [ ] Incident evidence bundle export requires real incident ID and rejects compliance job ID confusion.

### `/release-readiness`

- [ ] Loading state renders.
- [ ] Refresh re-fetches all readiness sources.
- [ ] Partial failure shows missing source names.
- [ ] Release metadata shows name/version/git SHA/environment/release/signing details without leaking key secrets.
- [ ] Compliance, compliance pack, route telemetry, rate-limit analytics, and alerts render.
- [ ] Healthy/warning/critical badges match data.
- [ ] Links to governance/dashboard are correct.

### `/settings` and `/account`

- [ ] Settings shows personal card to all roles.
- [ ] Settings shows printer cards only to manufacturer.
- [ ] Settings shows governance card only to super admin.
- [ ] Profile save validates name/email and handles pending email verification.
- [ ] Password change validates current/new/confirm fields.
- [ ] Admin MFA card appears for super admin and licensee admin where `isAdminUser` is true.
- [ ] MFA setup/disable/rotate backup codes handle validation and sensitive display.
- [ ] WebAuthn setup/assert/delete handles unsupported/cancel/failure/success.
- [ ] Active sessions load, revoke one, and revoke all.
- [ ] Browser storage risk summary updates after cleanup.

### `*` 404

- [ ] Unknown public route shows 404 recovery page.
- [ ] Requested path is displayed safely as text.
- [ ] Verify, Trust Center, and Help links work.
- [ ] 404 page is noindexed.

## 8. Flow-By-Flow Checklist

### Public QR and anti-counterfeit flow

- [ ] Customer scans valid QR and sees genuine result.
- [ ] Customer scans invalid QR and sees not-found result.
- [ ] Customer scans expired/revoked/blocked QR and sees blocked or unavailable result.
- [ ] Customer scans duplicate/repeated QR and sees review-needed/suspicious warning.
- [ ] Customer scans not-ready label and sees not-ready result.
- [ ] Customer signs in with email OTP and re-checks challenge-required result.
- [ ] Customer reports counterfeit/tampered/wrong-product concern.
- [ ] Admin later sees scan in `/scan-activity`.
- [ ] Admin later sees fraud report in `/audit-history` or incident/support queues where applicable.
- [ ] Public copy remains privacy-safe and does not reveal internal fraud thresholds.

### Brand/licensee QR request to batch flow

- [ ] Brand admin requests QR allocation.
- [ ] Super admin approves request.
- [ ] Approved request creates/updates batch inventory.
- [ ] Brand admin sees batch in `/batches`.
- [ ] Brand admin assigns manufacturer allocation.
- [ ] Manufacturer sees assigned batch.
- [ ] Audit history records request, approval, and allocation.

### Manufacturer print flow

- [ ] Manufacturer opens settings and printer setup.
- [ ] Manufacturer installs or updates connector from `/connector-download`.
- [ ] Helper reports printer inventory.
- [ ] Manufacturer saves/test printer route if needed.
- [ ] Manufacturer opens batch print pack.
- [ ] Print job starts with correct quantity.
- [ ] Progress dialog reflects printed/remaining counts.
- [ ] Print confirmation/retry/recovery paths update batch state.
- [ ] Scan activity and audit history reflect print completion.

### Incident response flow

- [ ] Customer concern or policy alert leads to incident.
- [ ] Super admin opens incident response.
- [ ] Super admin filters incident list.
- [ ] Super admin opens detail, assigns owner, changes status/priority/severity.
- [ ] Super admin adds note and uploads evidence.
- [ ] Super admin sends customer/org communication.
- [ ] Super admin applies QR/batch/org/manufacturer action with reason.
- [ ] Super admin exports PDF/evidence bundle.
- [ ] Audit history reflects incident actions.

### Support flow

- [ ] User opens support issue launcher from platform shell.
- [ ] Screenshot capture attaches where allowed.
- [ ] Support report creates a support ticket/report.
- [ ] Super admin filters and opens support center item.
- [ ] Super admin updates status/assignee and adds message.
- [ ] Reporter response succeeds or safely reports delivery failure.

## 9. Role-By-Role Checklist

### Super admin

- [ ] Can access `/dashboard`, `/licensees`, `/code-requests`, `/batches`, `/manufacturers`, `/scan-activity`, `/audit-history`, `/incident-response`, `/support`, `/release-readiness`, `/governance`, `/settings`, `/account`.
- [ ] Cannot access manufacturer-only printer setup.
- [ ] Sees cross-licensee selectors where implemented.
- [ ] Can approve/reject QR requests.
- [ ] Can manage licensees/brands.
- [ ] Can manage manufacturers across selected licensee.
- [ ] Can view/respond to fraud reports.
- [ ] Can operate incident response, governance, support, and release readiness.
- [ ] Does not see raw debug panels, seed labels, stack traces, or internal garbage in production-facing screens.

### Licensee admin / Brand admin

- [ ] Can access `/dashboard`, `/code-requests`, `/batches`, `/manufacturers`, `/scan-activity`, `/audit-history`, `/settings`, `/account`.
- [ ] Cannot access `/licensees`, `/incident-response`, `/support`, `/release-readiness`, `/governance`, `/printer-setup`.
- [ ] Can create QR requests but cannot approve/reject them.
- [ ] Can assign manufacturers and manage brand-scoped batches where permitted.
- [ ] Can invite/link/manage manufacturers within scope.
- [ ] Sees only own brand/licensee data.
- [ ] Direct URL to super-admin pages redirects without content flash.
- [ ] Button/action visibility matches permissions.

### Manufacturer admin

- [ ] Can access `/dashboard`, `/batches`, `/printer-setup`, `/scan-activity`, `/audit-history`, `/settings`, `/account`.
- [ ] Cannot access `/licensees`, `/code-requests`, `/manufacturers`, `/incident-response`, `/support`, `/release-readiness`, `/governance`.
- [ ] Sees printer status controls in shell.
- [ ] Can install connector, select/save/test printer, and print assigned batch labels.
- [ ] Cannot assign other manufacturers, approve QR requests, or access cross-tenant selectors.
- [ ] Sees only assigned/allowed batch and scan data.
- [ ] Direct URL to brand/super-admin pages redirects without content flash.

### Public/customer

- [ ] Can access public marketing, legal, help, connector download, verify, and scan pages without admin auth bootstrap.
- [ ] Cannot access protected pages.
- [ ] Can verify QR code, optionally authenticate customer session, claim product where allowed, and report concern.
- [ ] Sees no admin sidebar, platform command palette, internal logs, or raw backend details.

## 10. Technical Frontend Quality Checklist

- [ ] `npm run typecheck` passes.
- [ ] `npm run lint` passes or known debt is documented.
- [ ] `npm test` passes.
- [ ] `npm run build` passes.
- [ ] `npm run check:budgets` passes.
- [ ] `npm run verify:seo` passes.
- [ ] `npm run verify:ci:frontend` passes before release.
- [ ] `npm run test:e2e` passes when enterprise E2E env/seed data is available.
- [ ] No broken imports or unresolved aliases.
- [ ] No React hydration or StrictMode side-effect warnings in normal flows.
- [ ] No duplicate key warnings in lists/tables.
- [ ] No console errors/warnings during public verify, login, dashboard, batches, scan activity, and account flows.
- [ ] React Query cache invalidation occurs after mutations that change lists.
- [ ] Suspense loading fallback appears for lazy routes.
- [ ] Error boundaries or equivalent safe error states cover route/page failures.
- [ ] Environment variable behavior works with default `/api` and explicit `VITE_API_URL`.
- [ ] Production build smoke test covers static assets, routing fallback, and API base behavior.
- [ ] Images/icons/assets load in production build.
- [ ] Bundle size and chunk count remain within budget.
- [ ] Lazy-loaded route chunks do not block first public page unnecessarily.
- [ ] Local connector calls fail gracefully when `127.0.0.1:17866` is unreachable.
- [ ] Request timeout/offline states show recoverable UI.
- [ ] Date/time formatting handles invalid/null values.
- [ ] File downloads use safe filenames and blob error handling.

## 11. Accessibility Checklist

- [ ] All pages have one logical `h1`.
- [ ] Heading hierarchy is semantic and not skipped for visual size only.
- [ ] Keyboard-only navigation reaches all links, buttons, inputs, selects, dialogs, tabs, and menus.
- [ ] Focus states are visible in public and platform shells.
- [ ] Sidebar, dropdowns, dialogs, sheets, popovers, command palette, and support launcher trap/restore focus correctly.
- [ ] Escape closes modal/dialog/dropdown/sheet where expected.
- [ ] Form fields have associated labels.
- [ ] Form errors are programmatically associated or announced.
- [ ] Toast/status updates are screen-reader friendly enough for critical actions.
- [ ] Icon-only buttons have accessible names.
- [ ] Public QR label visual has meaningful role/label or is hidden if decorative.
- [ ] Tables have headers and row action names that make sense with screen readers.
- [ ] Charts have adjacent textual summaries.
- [ ] Color contrast meets WCAG AA for normal text and controls.
- [ ] Error/warning/success states do not rely on color alone.
- [ ] Reduced motion is respected where framer-motion animations are used.
- [ ] Mobile touch targets are at least 44px where practical.
- [ ] Long focus outlines are not clipped by overflow containers.
- [ ] File inputs and camera capture controls are operable with keyboard and screen reader.

## 12. Security-Facing Frontend Checklist

- [ ] No secrets, private keys, signing secrets, SMTP credentials, database URLs, or backend-only config appear in built JS.
- [ ] No raw JWT/access/refresh token is stored in localStorage/sessionStorage.
- [ ] Session proof tokens for verification are stored only in sessionStorage and never displayed.
- [ ] Invite/reset/email verification tokens are never copied into visible page text.
- [ ] OAuth exchange hash is cleared from URL after processing.
- [ ] Unsafe redirect parameters are not honored by auth or verify flows.
- [ ] `mailto`, download, and external URLs are encoded and constrained.
- [ ] Backend HTML error pages are stripped/sanitized before display.
- [ ] User-generated text renders as text, not HTML.
- [ ] Local connector errors are sanitized before user display.
- [ ] Emails and support/customer references are masked or friendly-labeled where required.
- [ ] Browser storage cleanup removes legacy dangerous keys on startup.
- [ ] Cookie consent cleanup removes non-essential browser state when consent is absent.
- [ ] Sentry initializes only after analytics consent and redacts as configured.
- [ ] Admin private pages are marked `noindex,nofollow`.
- [ ] Verify result/session pages are marked `noindex,nofollow`.
- [ ] Private pages do not remain visible after logout via browser back navigation where practical.
- [ ] API `403`/forbidden states do not reveal hidden actions or internal role names beyond friendly copy.
- [ ] Console logs do not expose tokens, OTPs, QR signing data, full support internals, or PII.
- [ ] Production source maps policy is reviewed and intentional.

## 13. Suggested Automated Test Plan

### Tools matched to current stack

- Unit/component: Vitest + Testing Library + jsdom.
- Integration/page tests: Vitest with mocked `apiClient`, React Router, React Query provider.
- E2E: Playwright using `playwright.enterprise.config.ts`.
- Visual regression: Playwright screenshots using existing snapshot conventions.
- Accessibility: add `@axe-core/playwright` for E2E and/or `jest-axe` for component checks.
- Bundle/performance: existing `scripts/check-code-size.mjs`, plus Lighthouse/Playwright trace smoke for P1.

### Recommended test file/folder structure

- `src/test/public/` for public pages, SEO, public shell, request access.
- `src/test/auth/` for login, MFA, invite, email verification, reset.
- `src/test/verify/` for QR verification model, result categories, customer auth, concern reporting.
- `src/test/platform/` for route guards, nav visibility, shell widgets.
- `src/test/batches/`, `src/test/printing/`, `src/test/incidents/`, `src/test/support/`, `src/test/governance/` for domain areas.
- `src/test/security/` for storage cleanup, token display guards, URL/download sanitization, safe error rendering.
- `e2e/smoke/` for P0 authenticated and public smoke flows.
- `e2e/visual/` for public, platform, verify, auth, and mobile screenshots.
- `e2e/accessibility/` for axe scans and keyboard journeys.

### P0 automation priority

- [ ] Add route access matrix tests for all protected routes and all three roles.
- [ ] Add public auth-optional bootstrap tests proving public pages do not call `/auth/me`.
- [ ] Add verify result category tests: genuine, suspicious duplicate, blocked, not ready, not found, network failure.
- [ ] Add auth tests for login success/failure, MFA setup/challenge, expired session, logout.
- [ ] Add dashboard role nav visibility tests for all sidebar/menu/action states.
- [ ] Add batches flow tests for brand/admin/manufacturer permission differences.
- [ ] Add QR request create/approve/reject tests.
- [ ] Add scan activity filter/error tests.
- [ ] Add account security tests for MFA/WebAuthn/session revoke visible behavior.
- [ ] Add security test that rendered errors strip HTML/stack/internal JSON.
- [ ] Add Playwright smoke for public verify, login, dashboard, batches, scan activity, and account.

### P1 automation priority

- [ ] Add Playwright visual snapshots for public pages and auth pages.
- [ ] Add Playwright visual snapshots for verify result categories.
- [ ] Add Playwright visual snapshots for governance, support, IR, release readiness, and printer setup.
- [ ] Add axe scans for public shell, verify, login, dashboard, batches, account, and incident detail.
- [ ] Add keyboard-only E2E for public verify, login/MFA, sidebar, command palette, and dialogs.
- [ ] Add connector download tests for platform detection, checksum display, URL normalization, invite preview, and local connector unavailable.
- [ ] Add support launcher/report tests with screenshot capture success/failure.
- [ ] Add fraud report queue and incident evidence upload/download tests with mocked blobs.

### P2 automation priority

- [ ] Add WebKit and Firefox Playwright projects.
- [ ] Add mobile projects for iPhone Safari-like WebKit and Android Chrome-like Chromium.
- [ ] Add Lighthouse CI or Playwright performance budgets for core routes.
- [ ] Add synthetic monitoring script for production smoke.
- [ ] Add production source-map exposure check.
- [ ] Add automated screenshot diff coverage for dark/light theme if dark theme becomes production-supported.

## 14. Recommended Next Implementation Steps

- [ ] First, build the P0 role-route access matrix test. This gives the fastest confidence that private surfaces cannot leak across roles.
- [ ] Second, expand verify-flow automated coverage. MSCQR's business value lives in trust decisions, so valid/invalid/blocked/suspicious/not-ready states should be locked down with fixtures.
- [ ] Third, add Playwright mobile and browser projects. Current E2E is Chromium desktop only, which is not enough for a QR scanning product.
- [ ] Fourth, add accessibility automation with axe plus keyboard journey tests for verify, login/MFA, and platform shell.
- [ ] Fifth, create reusable API fixture builders for brands, manufacturers, batches, scan logs, incidents, support tickets, and printer states so future tests stay concise and deterministic.
- [ ] Sixth, add a production-facing security UI test pack: no token display, no raw backend errors, safe URL handling, no private content flash, storage cleanup after logout.
- [ ] Seventh, add visual baselines for public and verification pages before major design changes.
- [ ] CTO recommendation: define a release-blocking "MSCQR frontend trust gate" that runs typecheck, build, unit tests, P0 Playwright smoke, route-access matrix, verify category tests, and security UI checks before every production promotion.
- [ ] CTO recommendation: invest next in mobile QR UX hardening, cross-browser scan support, and customer privacy copy. The strongest product improvement is making the public scan flow feel instant, trustworthy, and safe even under poor camera/network conditions.
- [ ] CTO recommendation: build a small QA fixture control panel or script for generating valid, suspicious, blocked, not-ready, and expired QR scenarios. That will reduce manual QA time and prevent trust-regression mistakes.

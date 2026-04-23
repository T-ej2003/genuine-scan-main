# Cookies, Storage, Privacy, and Tracking Audit

## Executive conclusion

MSCQR does **not** show evidence of typical marketing analytics or ad-tech trackers such as Google Analytics, GTM, Mixpanel, Hotjar, Clarity, Segment, FullStory, or Intercom from the audited repo. That is a positive finding.

MSCQR **does** use:

- authentication cookies for operators
- verification cookies for public/customer flows
- browser identifiers and workflow persistence keys
- optional Sentry observability if DSNs are configured
- support and printer-related storage keys

That means MSCQR still needs a clear privacy and cookie disclosure package before launch.

## Implementation update

The product now includes:

- public routes for `/privacy`, `/terms`, and `/cookies`
- shared legal/footer links across public and authenticated shells
- feature-flagged consent-banner plumbing behind `VITE_ENABLE_COOKIE_CONSENT_UI`

The consent UI remains disabled by default until legal review confirms the final live requirement.

## Package signing answer

**Package signing is not required for the browser-only web application.**

It **is** relevant for any downloadable local connector, installer, or distributed binary. For MSCQR, the local print connector should be treated as a signed-distribution artifact:

- Windows: code signing is strongly recommended
- macOS: signing and notarization are effectively required for a premium commercial rollout

## Inventory table

| Name / key | Source / provider | Purpose | Expiry if known | Essential? | Where set | Compliance implication |
| --- | --- | --- | --- | --- | --- | --- |
| `aq_access` | MSCQR backend auth | Primary operator access session cookie | JWT expiry based | Essential | `backend/src/services/auth/tokenService.ts` via auth controller | Must be disclosed in privacy/cookie materials as authentication storage |
| `aq_refresh` | MSCQR backend auth | Refresh token cookie for operator session continuity | JWT expiry based | Essential | `backend/src/services/auth/tokenService.ts` | Must be disclosed; secure cookie/session handling should be described at high level |
| `aq_csrf` | MSCQR backend auth | Double-submit CSRF protection token | Session/short-lived | Essential | `backend/src/services/auth/tokenService.ts`; read by frontend client | Must be disclosed as security cookie |
| `mscqr_verify_session` | MSCQR verify auth | Customer/public verification session | Controlled by verify auth config | Essential | `backend/src/services/customerVerifyCookieService.ts` | Must be disclosed as verification/session cookie |
| `gs_device_claim` | MSCQR verify flow | Device claim continuity for verification and ownership-related flow support | 1 year | Likely essential to verification flow | `backend/src/controllers/verify/verifySchemas.ts` | Long-lived identifier on user device; needs plain-English explanation |
| `aq_vid` | MSCQR frontend | Anonymous device ID for verification continuity | 1 year | Borderline; likely functional | `src/lib/anon-device.ts` | Device identifier stored client-side; legal review needed on essential classification |
| `sidebar:state` | MSCQR frontend | Remembers sidebar open/closed state | 7 days | Functional but non-essential to core service | `src/components/ui/sidebar.tsx` | Needs disclosure; likely falls under preference storage |
| `mscqr_verify_customer_token` | MSCQR frontend | Local storage continuity for verify-customer token | Not explicit | Essential or transitional depending on final cutover | `src/features/verify/verify-model.ts` | Needs disclosure; should be minimized once cookie-only posture is final |
| `authenticqr_verify_customer_token` | MSCQR frontend legacy key | Legacy verify token key | Not explicit | Transitional/legacy | `src/features/verify/verify-model.ts` | Legacy storage should be cleaned up and documented until removed |
| `mscqr_verify_customer_email` | MSCQR frontend | Remembers customer email during verification flow | Until cleared | Functional | `src/features/verify/verify-model.ts`, `VerifyExperience.tsx` | Personal data in local storage must be disclosed and retained minimally |
| `authenticqr_verify_customer_email` | MSCQR frontend legacy key | Legacy customer email key | Until cleared | Transitional/legacy | `src/features/verify/verify-model.ts` | Same as above; clean up post-cutover |
| `mscqr_verify_last_geo` | MSCQR frontend | Stores recent geolocation cache for verify experience | 10 minutes max intended | Functional / borderline sensitive context | `src/features/verify/verify-model.ts` | Location-related state needs careful privacy wording |
| `mscqr_verify_session_proof:<sessionId>` | MSCQR frontend | Session proof cached in session storage | Session | Essential to active flow | `VerifyExperience.tsx` | Dynamic session key; disclose as verification-session data |
| `aq_missing_help_requests` | MSCQR frontend help widget | Stores unsent help requests | Until cleared | Functional | `src/components/help/HelpAssistantWidget.tsx` | Can contain user-entered support content; disclose and document retention behavior |
| `manufacturer-printer-dialog-opened:v1:<userId>` | MSCQR frontend manufacturer flow | Tracks whether onboarding dialog has been shown | Session | Functional | `src/features/layout/useManufacturerPrinterConnection.ts` | User-specific UI state; disclose in cookie/storage notice |
| `manufacturer-printer-onboarding:v1:<userId>` | MSCQR frontend manufacturer flow | Tracks onboarding completion/progress | Persistent until cleared | Functional | `src/features/layout/useManufacturerPrinterConnection.ts` | User-specific workflow persistence; disclose |
| `printer-calibration:<printerId>` | MSCQR frontend printer flow | Stores printer calibration state | Persistent until cleared | Functional | `src/features/batches/batch-print-operations.ts` | Operational device state stored locally; disclose to operator users |

## Plain-English explanation of why each item exists

- `aq_access`, `aq_refresh`, `aq_csrf`: these keep admins and operators logged in securely and help stop request forgery.
- `mscqr_verify_session`: this lets a customer continue a verification session without re-entering everything on every request.
- `gs_device_claim`: this helps MSCQR remember the device during verification or ownership-related interactions.
- `aq_vid`: this gives the public verification flow a stable anonymous device reference.
- `sidebar:state`: this simply remembers whether the navigation sidebar was collapsed.
- `mscqr_verify_customer_token` and legacy token keys: these bridge verification/customer session continuity in the frontend.
- `mscqr_verify_customer_email` and legacy email keys: these prevent users from retyping their email during verification flow steps.
- `mscqr_verify_last_geo`: this caches recent location context briefly so the verify experience does not repeatedly request or recalculate it.
- `mscqr_verify_session_proof:<sessionId>`: this holds proof tied to the current verification session until the browser tab/session ends.
- `aq_missing_help_requests`: this avoids losing drafted help requests if the user closes or refreshes the page.
- `manufacturer-printer-*` keys: these remember that the manufacturer has already seen certain onboarding prompts.
- `printer-calibration:<printerId>`: this keeps printer calibration information available locally for smoother operator workflow.

## Third-party scripts and SDKs

### Found

- **Sentry** on frontend and backend, conditionally initialized if DSNs are configured

### Not found in repo evidence

- Google Analytics
- Google Tag Manager
- Mixpanel
- Hotjar
- Microsoft Clarity
- Segment
- FullStory
- Meta Pixel
- Intercom

## Analytics conclusion

MSCQR appears to rely primarily on internal product and trust analytics plus optional Sentry, rather than third-party marketing analytics. That reduces privacy exposure. It does **not** remove the need for:

- a Privacy Policy
- a Cookie Notice
- a storage/cookie inventory
- a decision on consent for any non-essential storage or telemetry

## Is a consent banner required?

### Engineering answer

- If MSCQR only uses strictly necessary authentication, security, and core service storage, a consent banner may not be required for those items.
- If MSCQR enables non-essential storage, preference storage, optional diagnostics, or third-party telemetry that is not strictly necessary, consent may be required for UK/EU users before setting those items.

### Legal caution

ICO guidance covers cookies **and similar technologies**, including local storage and other access/storage on user devices. This means the final answer is not just about browser cookies. It must include localStorage/sessionStorage behavior too.

## Is a Cookie Policy required?

**Yes, recommended at minimum and effectively required for a professional launch.**

Even if a banner ends up not being needed for essential-only storage, MSCQR still needs a clear cookie/storage notice because it stores information on user devices and accesses it during product flows.

## Does the Privacy Policy need specific wording based on actual implementation?

**Yes.** It should explicitly cover:

- operator authentication cookies
- customer verification session cookies
- anonymous/public device identifiers
- local/session storage used during verification and support flows
- support screenshot/log uploads
- optional Sentry/error telemetry if enabled
- AWS hosting and storage
- retention and deletion expectations
- role-based access to operational data

## Runtime verification tasks still required

1. Run a browser HAR/devtools audit in staging and production to capture any cookies added by CDN, reverse proxy, auth edge, or infra.
2. Confirm actual cookie flags in deployed environments:
   - `Secure`
   - `HttpOnly`
   - `SameSite`
   - domain/path scoping
3. Confirm whether Sentry is enabled in production and whether it captures identifiers or payload fields that need extra disclosure.
4. Confirm whether any reverse-proxy health or session cookies are added outside the application code.

## Lawyer review sources

- [ICO: Cookies and similar technologies](https://ico.org.uk/for-organisations/direct-marketing-and-privacy-and-electronic-communications/guide-to-pecr/cookies-and-similar-technologies/)
- [ICO: What are storage and access technologies?](https://ico.org.uk/for-organisations/direct-marketing-and-privacy-and-electronic-communications/guidance-on-the-use-of-storage-and-access-technologies/what-are-storage-and-access-technologies/)

These are regulatory guidance sources, not a substitute for legal advice.

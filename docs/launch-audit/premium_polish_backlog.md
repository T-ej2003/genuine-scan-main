# Premium Product Polish Audit

## Polish issues list

| ID | Issue | Severity | Why it matters | Fast fix |
| --- | --- | --- | --- | --- |
| UX-001 | No visible legal/privacy/cookie footer across product experience | High | Trust is incomplete without obvious policy access | Add persistent footer links |
| UX-002 | 404 page is plain and logs a console error | Medium | Feels dev-like and reduces confidence | Replace with branded recovery experience |
| UX-003 | Support screenshot/log collection needs clearer customer-safe explanation | High | Users need to know what is captured and why | Add concise notice and policy links |
| UX-004 | Connector download trust messaging is not yet premium | High | Install trust is make-or-break for manufacturers | Show signing status, checksum, support path |
| UX-005 | Internal docs are stronger than public/app trust surfaces | Medium | Customers judge the product, not repo docs | Surface trust and support signals in UI |
| UX-006 | Mock data residue remains in source tree | Medium | Signals unfinished/developer residue | Remove or isolate |
| UX-007 | Some client-side console logging remains | Medium | Adds dev feel and noise | Remove or route through proper logging |
| UX-008 | Bundle size could hurt perceived responsiveness in some routes | Medium | Slow routes reduce premium feel | Lazy-load heavy modules |

## Must-fix before launch list

1. Add visible Privacy, Terms, Cookies, Support, and Trust links.
2. Add privacy-safe wording to support evidence capture surfaces.
3. Finalize premium connector-download trust presentation after signing/notarization decision.
4. Review public verification success/failure/help copy against real customer trust expectations.

## Fast wins list

1. Replace `NotFound` with a branded recovery page and useful navigation.
2. Remove client-side `console.error` on 404.
3. Remove or quarantine `src/lib/mock-data.ts`.
4. Add consistent support CTA language to empty/error states in high-traffic screens.
5. Add a compact trust/legal footer to public and authenticated layouts.

## Premium UX improvement backlog

### Public/customer experience

- Improve suspicious-result guidance so it feels calm, authoritative, and action-oriented
- Add clearer trust signals around what MSCQR verifies and what it does not
- Add lightweight contact/support reassurance on verify and trust pages

### Operator/admin experience

- Standardize empty-state language across dashboard, requests, tracking, and audit views
- Standardize success toasts and save-confirmation copy
- Add more visible role context so users understand what they can control

### Manufacturer experience

- Turn connector download into a polished install center
- Show OS support, version history, checksums, and support expectations
- Surface printer readiness and calibration health more explicitly

## Professionalism risks to remove

- developer console residue
- mock/demo residue
- plain fallback/error experiences
- legal/compliance trust gaps
- any wording that sounds internal rather than customer-safe

## CTO recommendations for taking MSCQR beyond “good enough”

1. Build a unified trust center with uptime, security commitments, legal docs, subprocessors, and support expectations.
2. Build a premium install center for manufacturers with signed downloads, release notes, environment checks, and diagnostics upload.
3. Add a customer-facing verification history or case support flow that feels enterprise-grade without exposing internals.
4. Add design-system level content standards so every empty/error/success state reads like one product, not several modules.

# MSCQR SEO and Indexing Runbook

Last reviewed: 2026-04-28  
Production domain: `https://www.mscqr.com`  
Production baseline after SEO polish: `9148e06`

## Purpose

This runbook records the production SEO, indexing, and public verification safeguards for MSCQR. Treat these rules as operational controls. Do not change them during normal copy, UI, or dashboard work unless there is a concrete indexing defect and the relevant guardrails are updated in the same change.

## Current Indexing Policy

Indexable public entry pages include:

- `https://www.mscqr.com/`
- `https://www.mscqr.com/verify`
- `https://www.mscqr.com/platform`
- `https://www.mscqr.com/solutions/manufacturers`
- `https://www.mscqr.com/solutions/licensees`
- `https://www.mscqr.com/industries`
- `https://www.mscqr.com/trust`
- `https://www.mscqr.com/request-access`
- `https://www.mscqr.com/blog`

The public verification entry page has special handling:

- `/verify` must render for logged-out visitors.
- `/verify` must remain crawlable and indexable.
- `/verify/` must canonicalize in the browser to `/verify`.
- `/api/auth/me` returning 401 for logged-out visitors must not blank the page.

Routes that must not be indexed:

- `/verify/:code` and deeper verification result paths
- `/scan`
- Auth routes such as `/login`, `/accept-invite`, `/verify-email`, `/forgot-password`, and `/reset-password`
- Dashboard/private routes such as `/dashboard`, `/licensees`, `/code-requests`, `/batches`, `/printer-setup`, `/scan-activity`, `/manufacturers`, `/audit-history`, `/incident-response`, `/support`, `/release-readiness`, `/governance`, `/settings`, and `/account`
- Legacy private redirects such as `/qr-codes`, `/qr-requests`, `/product-batches`, `/qr-tracking`, `/audit-logs`, `/ir`, and `/incidents`
- `/api`

## Robots Policy

`public/robots.txt` must explicitly allow the public verification entry route:

```txt
User-agent: *
Allow: /
Allow: /verify
Allow: /verify/
```

It must keep private, auth, API, scanner, and dashboard routes disallowed. It must not contain:

```txt
Disallow: /verify
Disallow: /verify/
```

`/verify-email` remains blocked separately:

```txt
Disallow: /verify-email
```

## Sitemap Policy

`public/sitemap.xml` must contain only indexable public pages. It must include `https://www.mscqr.com/verify` and must never include:

- `/verify/`
- `/verify/<code>` or any result-like verification path
- `/scan`
- Auth pages
- Dashboard/private pages
- `/api`
- Incident, support, governance, audit, account, settings, or legacy private paths

## Search Console Workflow

Google Search Console is verified for the `mscqr.com` domain property. The submitted sitemap is:

```text
https://www.mscqr.com/sitemap.xml
```

Use URL Inspection after deploys that affect public SEO surfaces. Recommended inspection set:

- `https://www.mscqr.com/`
- `https://www.mscqr.com/verify`
- `https://www.mscqr.com/platform`
- `https://www.mscqr.com/solutions/manufacturers`
- `https://www.mscqr.com/industries`
- `https://www.mscqr.com/trust`

For negative checks, inspect one representative result/private URL:

- `https://www.mscqr.com/verify/TESTCODE123` should be excluded by `noindex`.
- `https://www.mscqr.com/scan` should remain blocked/noindexed under the current policy.
- `https://www.mscqr.com/dashboard` should remain blocked/protected/private.

Do not repeatedly request indexing for the same URL after Search Console quota is reached.

## Validation Commands

Run these before shipping SEO or public-route changes:

```bash
npm test -- src/test/index-page-navigation.test.tsx src/test/legal-surface.test.tsx src/test/public-verify-entry-route.test.tsx src/test/connector-download.test.tsx
npm run verify:seo
npm run typecheck
npm run build
npm run verify:guardrails
npm run verify:ci:frontend
npm run verify:release
```

Run the production browser smoke after deployment, or against a staging URL using `VERIFY_BROWSER_SMOKE_BASE_URL`:

```bash
npm run smoke:verify-browser
VERIFY_BROWSER_SMOKE_BASE_URL=https://staging.example.com npm run smoke:verify-browser
```

The browser smoke verifies:

- `/verify` returns a successful HTML document.
- `/verify` renders a visible public verification heading.
- `/verify` is not blank.
- `/verify` does not render `noindex`.
- `/verify` has the expected canonical URL.
- `/verify/` canonicalizes in-browser to `/verify`.
- Logged-out guest auth probes do not fail the public render.

## Do Not Regress

- Do not auth-gate `/verify`.
- Do not put result-like verification URLs in the sitemap.
- Do not use robots rules that make `/verify` ambiguous.
- Do not canonicalize `/verify/:code` or `/scan` to the indexable `/verify` entry page.
- Do not weaken dashboard/private route protection.
- Do not change QR verification business logic, API contracts, auth permissions, database schema, object storage, or deployment security gates as part of SEO work.
- Do not add fake customer, compliance, security, uptime, certification, or anti-counterfeit guarantee claims.

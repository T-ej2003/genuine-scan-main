# Manufacturer Printing History and Dashboard UX Evidence

Date: 2026-06-09

## Root Cause

Physical Zebra ZT410 validation showed that the backend print flow could work while the manufacturer workspace still felt noisy and technical. The dashboard overview rendered freshness/status badges that competed with the shell printer readiness indicator. The History page rendered audit actions directly through generic audit-label fallbacks, so manufacturer users could see backend-style action names and weak summaries such as generic workspace activity copy. Print-job data existed, but it was not presented as a manufacturer-facing print history.

## Changed Files

- `src/pages/Dashboard.tsx`
- `src/pages/AuditLogs.tsx`
- `src/lib/manufacturer-activity-display.ts`
- `src/test/manufacturer-activity-display.test.ts`
- `src/test/manufacturer-history-page.test.tsx`
- `src/test/dashboard-rate-limit.test.tsx`
- `src/test/dashboard-nav-visibility.test.tsx`
- `documents/qa/evidence/manufacturer-printing-history-dashboard-ux-20260609.md`

## Dashboard Status Cleanup

Before: the overview header showed a green live/freshness badge such as `Updated just now` plus another updated badge, while the shell/header already showed printer readiness.

After: the overview uses quiet freshness text beside the Refresh control. The shell/header remains the primary printer/system readiness indicator. Refresh is disabled and labeled `Refreshing...` while data is in flight.

## Manufacturer-Facing Activity Mapping

Manufacturer activity now uses a frontend display layer that maps raw audit actions to safe product language:

- `LOCAL_AGENT_PRINT_ITEM_ACKED` -> `Print job received by printer connector`
- `LOCAL_AGENT_PRINT_ITEM_CONFIRMED` -> `Label print confirmed`
- `PRINTER_CONNECTION_COMPAT_MODE_ONLINE` -> `Printer connected while setup was still being verified`
- `AUTH_LOGIN_SUCCESS` -> `User signed in`
- `AUTH_LOGOUT` -> `User signed out`

Unknown manufacturer-visible actions fall back to `Workspace activity` with a safe explanation. Raw unknown action codes, tokens, render URLs, cookies, passwords, secrets, and stack-style backend messages are not displayed to manufacturer users.

## Print History Visibility

The manufacturer History page now includes a `Print history` section sourced from the existing tenant-scoped `/api/manufacturer/print-jobs` endpoint. It shows:

- batch
- print run
- labels printed/requested
- labels remaining
- printer
- status
- operator field when available
- timestamp

Backend gap: current print-job list DTOs do not consistently include the operator/actor who started the job. The UI renders `Operator not included` rather than inventing a user. Recommended backend follow-up: add a safe `createdBy`/`operator` DTO field scoped to the same tenant/manufacturer constraints.

## Rate-Limit and Repeated-Click UX

History Refresh is single-flight in the page. A repeated click while the first refresh is in progress reuses/ignores the in-flight work because the button is disabled and the in-flight promise is tracked. If audit or print-history reads return 429, manufacturer users see:

`Too many refresh attempts. Waiting a few seconds before trying again.`

Raw backend error text is not displayed.

## Physical Printer Validation Status

This change does not alter print dispatch, confirmation, tenant scoping, auth, idempotency, or lifecycle semantics. It only presents existing print-job and audit data safely in the manufacturer workspace. Zebra ZT410 Windows validation should be repeated to confirm:

1. Header shows one clear printer readiness signal.
2. Overview no longer shows duplicate green freshness/status badges.
3. History shows product language for connector accepted/confirmed events.
4. Print history shows the latest ZT410 print run with batch, counts, printer, status, and timestamp.
5. Double-clicking Refresh does not create duplicate requests or duplicate visible errors.

## Test Evidence

Targeted frontend tests added/updated:

- manufacturer activity mapping hides raw/internal names
- unknown activity uses safe fallback
- print-history row formatting
- rendered manufacturer History hides raw connector/internal event names
- rendered manufacturer History shows print history fields
- empty states are clean
- 429 copy is user-safe
- Refresh disables and stays single-flight while loading
- dashboard overview no longer renders duplicate freshness labels
- shell still exposes printer readiness for manufacturers


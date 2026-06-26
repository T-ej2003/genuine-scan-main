# Auth Refresh 401 Reload Race - 2026-06-26

## Symptom

After the printer WebSocket recovery, printing remained stable, but a separate frontend auth issue appeared after several browser refreshes/reloads.

Protected frontend pages called APIs and received `401 Unauthorized` / `No token provided`.

Observed affected endpoints:

- `/api/auth/me`
- `/api/notifications`
- `/api/dashboard/attention-queue`
- `/api/qr/batches`
- `/api/manufacturer/printer-agent/status`
- `/api/manufacturer/printers`
- `/api/manufacturer/printer-agent/events`

## Browser Evidence

Network request headers showed cookies were sent, including:

- `aq_vid`
- `aq_refresh`
- `aq_csrf`

The failing protected API requests did not include `Authorization: Bearer <access token>`.

`document.cookie` only exposed `aq_vid` and `aq_csrf`, which is expected because `aq_refresh` is HttpOnly.

## Backend Evidence

Backend logs showed:

- `status=401`
- `actorUserId=null`
- `authAssurance=null`
- `release=mscqr-backend@1.0.0+a5b1036fd417`

## Root Cause

Protected frontend routes bootstrapped session state with `/api/auth/me`. After a hard reload, the JavaScript in-memory bearer token is empty by design, while the refresh token remains in the HttpOnly `aq_refresh` cookie. Because HttpOnly cookies are not visible to `document.cookie`, the API client could incorrectly decide there was no cookie-backed session and return the original `401 No token provided` response instead of first exchanging the refresh cookie for a renewed access session.

This let protected TanStack queries and polling surface raw authentication failures after reload, even though the browser still had a valid refresh cookie.

## Files Changed

- `src/contexts/AuthContext.tsx`
  - Added explicit auth bootstrap readiness fields.
  - Restores a session with `/api/auth/refresh` first when no in-memory token exists, then falls back to `/api/auth/me`.
  - Keeps protected routes loading until the restore attempt completes.
- `src/lib/api/internal-client-core.ts`
  - Retries protected `401` responses through `/api/auth/refresh` without relying on JS-visible cookies.
  - Clears stale bearer state before refresh retry so stale `Authorization` cannot shadow renewed HttpOnly cookies.
  - Converts raw `No token provided` style messages into session-expired copy for frontend callers.
- `src/test/auth-bootstrap-reload.test.tsx`
  - Covers reload restore before `/api/qr/batches` and printer-status reads fire.
  - Covers clean redirect when restore fails, without raw token errors.
- `src/test/internal-client-core.test.ts`
  - Covers HttpOnly refresh-cookie recovery.
  - Covers stale bearer clearing and optional restored bearer use when a backend response provides one.

## Validation

- `npm run test -- src/test/auth-bootstrap-reload.test.tsx src/test/internal-client-core.test.ts src/test/public-verify-entry-route.test.tsx`
- `npm run test -- src/test/auth-bootstrap-reload.test.tsx src/test/internal-client-core.test.ts src/test/public-verify-entry-route.test.tsx src/test/login-basic-flow.test.tsx src/test/login-mfa-challenge-regression.test.tsx src/test/dashboard-manufacturer-scope.test.tsx src/test/dashboard-layout-printer.test.tsx src/test/active-print-session-suppression.test.tsx src/test/internal-client-printing.test.ts src/test/active-print-job-polling.test.tsx src/test/printer-user-facing.test.ts`
- `npm run typecheck`
- `npm run build`
- `git diff --check`

## Manual Validation Steps

1. Sign in with MFA and open a protected page such as `/batches`.
2. Hard refresh after the access session has expired but while the refresh session is still valid.
3. Confirm the first protected reads wait until auth bootstrap finishes.
4. Confirm `/api/auth/refresh` succeeds and protected reads no longer show `No token provided`.
5. Confirm expired sessions redirect to `/login` with clean sign-in copy.

## Security Notes

- Refresh tokens remain HttpOnly and are not copied into localStorage or JavaScript state.
- Backend authorization remains unchanged.
- Printer WebSocket/session/trust logic is unchanged.

# PR99 Integration Shutdown Fix - 2026-07-05

## Root Cause

The disposable system integration harness proved the backend worker boot path by launching the compiled worker in `INTEGRATION_WORKER_BOOT_ONLY` mode, but that mode still started a keepalive interval and waited for external termination. In CI, GitHub Actions began tearing down the PostgreSQL service while worker/reconciler code could still hold active Prisma clients or schedule lease-backed loops, producing PostgreSQL `E57P01` shutdown errors from `AuditLogOutbox`, `PrintItem`, distributed leases, and print reconciliation.

The frontend smoke test also asserted the seeded fixture brand text `P2 Brand A`. The public verification UI contract guarantees a customer-safe valid result, but it does not guarantee that exact fixture brand string is always rendered in the first public summary surface.

## Implemented Shutdown Order

The system integration runner now:

1. Starts the backend HTTP process with background workers disabled.
2. Exports explicit integration loop-disable flags for DB-backed recurring services.
3. Starts the worker only as a Redis-backed boot proof when `REDIS_URL` is present.
4. Requires the worker boot proof to exit with code 0 before the test body continues.
5. Runs Playwright system tests with test-only frontend telemetry/auth/session polling disabled.
6. Requires each Playwright test to close its isolated browser context after assertions.
7. Waits for a frontend/browser traffic drain window after Playwright returns.
8. Marks integration shutdown as started in `finally`.
9. Waits for a final traffic drain before backend termination.
10. Stops any remaining worker process with SIGTERM, then SIGKILL if needed, and waits for exit.
11. Calls the backend-owned `POST /__integration/shutdown` endpoint with the per-run shutdown token.
12. Requires the backend child process to exit with code 0 after the graceful shutdown request.
13. Uses SIGTERM/SIGKILL for the backend only as a fallback after the graceful shutdown endpoint fails or times out.
14. Disconnects the runner Prisma client.
15. Drops the disposable database only after child process exits are confirmed.

## Hardening Notes

- Redis shutdown is idempotent, so repeated process shutdown paths can safely call the same close function.
- Distributed leases refuse new work after shutdown begins.
- The integration harness disables audit outbox, SIEM outbox, print reconciliation, analytics rollups, compliance pack scheduling, legacy QR risk reports, hot event partition maintenance, and distributed-lease work before the backend process starts.
- The integration harness disables non-essential frontend telemetry, auth bootstrap polling, customer verification session bootstrap, and printer polling with `VITE_E2E_*` flags so public verification pages cannot keep sending background requests after assertions finish.
- Audit outbox and print confirmation reconciliation loops check shutdown state before DB work.
- The worker boot-only path connects to Redis for readiness proof, skips recurring jobs, closes Redis and Prisma, and exits by itself.
- Backend SIGTERM handling tracks active HTTP requests and sockets, closes idle connections, waits briefly for in-flight requests, then force-closes remaining sockets before disconnecting Redis and Prisma.
- The backend integration shutdown endpoint is registered only when `NODE_ENV=test` and `INTEGRATION_TEST_SHUTDOWN_TOKEN` are both set. It returns 404 for missing or incorrect tokens and is not registered in production.
- Successful integration teardown is backend-owned: the endpoint responds 202, emits an internal shutdown request, closes HTTP traffic, disconnects Redis and Prisma, and exits with code 0.

## Frontend Smoke Contract

The Playwright smoke now asserts stable public verification semantics:

- Verification summary is visible for the seeded valid QR.
- The valid result includes customer-visible valid-verification language inside the visible main result area.
- The valid result does not show visible not-found/could-not-match text inside that main result area.
- The invalid result is checked in a fresh page so valid and invalid state cannot bleed between assertions.
- Valid, invalid, and protected dashboard checks each run in isolated browser contexts and close those contexts before the runner starts backend teardown.
- The page does not leak `P2 Brand B`.
- The page does not leak secrets, stack traces, Prisma internals, bearer tokens, or token/hash fields.

## CTO Recommendations

- Add a small integration harness unit test around `stopProcess` and boot-proof worker behavior so this lifecycle contract is guarded without waiting for full Playwright.
- Add a backend shutdown registry for all interval/timeout-based services so future workers register one standard stop hook.
- Expose a lightweight `/health/shutdown` or process metric in non-production test mode to confirm Redis and Prisma clients are closed before disposable infrastructure cleanup.

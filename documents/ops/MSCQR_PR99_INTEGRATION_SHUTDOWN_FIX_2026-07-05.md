# PR99 Integration Shutdown Fix - 2026-07-05

## Root Cause

The disposable system integration harness proved the backend worker boot path by launching the compiled worker in `INTEGRATION_WORKER_BOOT_ONLY` mode, but that mode still started a keepalive interval and waited for external termination. In CI, GitHub Actions began tearing down the PostgreSQL service while worker/reconciler code could still hold active Prisma clients or schedule lease-backed loops, producing PostgreSQL `E57P01` shutdown errors from `AuditLogOutbox`, `PrintItem`, distributed leases, and print reconciliation.

The frontend smoke test also asserted the seeded fixture brand text `P2 Brand A`. The public verification UI contract guarantees a customer-safe valid result, but it does not guarantee that exact fixture brand string is always rendered in the first public summary surface.

## Implemented Shutdown Order

The system integration runner now:

1. Starts the backend HTTP process with background workers disabled.
2. Starts the worker only as a Redis-backed boot proof when `REDIS_URL` is present.
3. Requires the worker boot proof to exit with code 0 before the test body continues.
4. Marks integration shutdown as started in `finally`.
5. Stops any remaining worker process with SIGTERM, then SIGKILL if needed, and waits for exit.
6. Stops the backend HTTP process with SIGTERM, then SIGKILL if needed, and waits for exit.
7. Disconnects the runner Prisma client.
8. Drops the disposable database only after child process exits are confirmed.

## Hardening Notes

- Redis shutdown is idempotent, so repeated process shutdown paths can safely call the same close function.
- Distributed leases refuse new work after shutdown begins.
- Audit outbox and print confirmation reconciliation loops check shutdown state before DB work and suppress PostgreSQL administrator-termination errors only when shutdown is already active.
- The worker boot-only path connects to Redis for readiness proof, skips recurring jobs, closes Redis and Prisma, and exits by itself.

## Frontend Smoke Contract

The Playwright smoke now asserts stable public verification semantics:

- Verification summary is visible for the seeded valid QR.
- The valid result includes customer-visible valid-verification language.
- The valid result does not show not-found/could-not-match text.
- The page does not leak `P2 Brand B`.
- The page does not leak secrets, stack traces, Prisma internals, bearer tokens, or token/hash fields.

## CTO Recommendations

- Add a small integration harness unit test around `stopProcess` and boot-proof worker behavior so this lifecycle contract is guarded without waiting for full Playwright.
- Add a backend shutdown registry for all interval/timeout-based services so future workers register one standard stop hook.
- Expose a lightweight `/health/shutdown` or process metric in non-production test mode to confirm Redis and Prisma clients are closed before disposable infrastructure cleanup.

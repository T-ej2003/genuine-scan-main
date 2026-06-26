# Printer Session Launch-Freeze Fix - 2026-06-26

## Scope

This note documents the Windows connector and backend persistent printer session hardening performed during launch-freeze for MSCQR / Genuine Scan.

## Root Cause

Heartbeat trust and WebSocket session admission did not resolve trusted printer registrations the same way. Heartbeat could validate a current trusted registration while WebSocket admission selected only one candidate and could stop on an older revoked or invalid duplicate before evaluating the trusted registration.

A second hardening issue existed in connector URL handling: saved backend URLs ending in `/api` could produce doubled paths such as `/api/api/printer-agent/session`. The backend now tolerates that path, and the connector normalizes backend origins before building HTTP and WebSocket URLs.

## Trust Invariants Kept

- Revoked and untrusted registrations remain rejected.
- Ed25519 signature verification remains required.
- mTLS remains optional unless `PRINT_AGENT_REQUIRE_MTLS=true`.
- Production printing still requires persistent WebSocket session mode and connector build `2026.6.25` or newer.
- Browser/frontend code still cannot mark jobs printed.
- Print completion still depends on backend/connector physical confirmation paths.
- Logs use hashes or short identifiers only; raw keys, signatures, tokens, cookies, CSRF values, payloads, and signed URLs are not logged.

## Implementation Summary

- WebSocket admission now enumerates all same `agentId + deviceFingerprint` registration candidates, skips revoked/untrusted/null-key candidates, and accepts only a trusted signed candidate whose selected printer matches an active local-agent printer.
- Duplicate connected sessions for the same trusted registration and selected printer are superseded cleanly.
- WebSocket rejection and connection logs now emit structured safe fields including reason code, candidate counts, signature result, build acceptance, and persistent-session capability.
- Heartbeat emits the same safe resolver summary fields for production diagnostics.
- Backend status selection no longer picks rows with `trustStatus=REVOKED` even if `revokedAt` is missing.
- Connector runtime normalizes backend base URLs, logs safe WebSocket upgrade rejection details, and exposes `lastRejectReasonCode` in local `/status`.
- UI readiness now blocks production readiness when the persistent session is disconnected, even if the local helper can see the printer.
- Windows installer post-install verification now treats a single process as a one-item array and logs success when exactly one canonical connector process is running.

## Validation

- `npm --prefix backend run build`
- `npm --prefix backend test`
- `npm --prefix backend run connector:smoke`
- `npm run test -- src/test/internal-client-printing.test.ts src/test/active-print-job-polling.test.tsx src/test/printer-user-facing.test.ts src/test/secure-printer-readiness.test.ts`
- `npm run check:architecture-guardrails`
- `npm run check:branch-secret-diff`
- `npm run check:print-qr-identity`
- `npm run check:route-rate-limit-contracts`
- `git diff --check`

## Deployment Note

Backend-only deployment fixes the trusted duplicate resolver, safe logs, route alias handling, and production readiness behavior. Because connector runtime and Windows installer source files also changed, publishing those improvements to customers requires rebuilding/signing a new Windows connector artifact through the signed connector release workflow.

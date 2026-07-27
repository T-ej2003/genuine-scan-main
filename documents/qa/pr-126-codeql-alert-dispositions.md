# PR #126 CodeQL Alert Dispositions

## Scope

This record covers only the twelve CodeQL alerts reviewed on PR #126: eleven
`js/missing-rate-limiting` results and one
`js/insufficient-password-hash` result.

## Production route findings

The application mounts `backend/src/routes/index.ts` at `/api`. The nine
production findings were real middleware-ordering gaps: authentication and
sensitive-auth checks ran before the route-family limiter. Each route now
starts with the existing `printMutationPreAuthRouteLimiter`; the authenticated
route, IP, actor, tenant, MFA and CSRF controls remain unchanged.

| Alert | Method and mounted path | Effective limiter |
| --- | --- | --- |
| 574 | `POST /api/manufacturer/print-jobs` | `printMutationPreAuthRouteLimiter`, then authenticated print route/IP/actor limiters |
| 575 | `POST /api/manufacturer/printers` | `printMutationPreAuthRouteLimiter`, then authenticated print route/IP/actor limiters |
| 576 | `PATCH /api/manufacturer/printers/:id` | `printMutationPreAuthRouteLimiter`, then authenticated print route/IP/actor limiters |
| 577 | `DELETE /api/manufacturer/printers/:id` | `printMutationPreAuthRouteLimiter`, then authenticated print route/IP/actor limiters |
| 578 | `POST /api/manufacturer/printers/:id/test` | `printMutationPreAuthRouteLimiter`, then authenticated print route/IP/actor limiters |
| 579 | `POST /api/manufacturer/printers/:id/test-label` | `printMutationPreAuthRouteLimiter`, then authenticated print route/IP/actor limiters |
| 580 | `POST /api/manufacturer/printers/:id/discover` | `printMutationPreAuthRouteLimiter`, then authenticated print route/IP/actor limiters |
| 581 | `POST /api/manufacturer/print-jobs/:id/direct-print/tokens` | `printMutationPreAuthRouteLimiter`, then authenticated print route/IP/actor limiters |
| 582 | `POST /api/manufacturer/print-jobs/:id/confirm` | `printMutationPreAuthRouteLimiter`, then authenticated print route/IP/actor limiters |

The pre-auth limiter is keyed by protected actor context and the reviewed
resource fields (`id`, `batchId`, or `printerId`). Its five-minute limit is
forty requests. Tests prove the forty-first matching request receives the
standard `429 RATE_LIMITED` response while a different printer resource
retains its own bucket.

## Unmounted legacy router findings

Alerts 556 and 557 refer to `backend/src/routes/publicRoutes.ts`. Repository
import and application-mount inspection found no production caller for that
module, so neither declared path has a mounted HTTP path. The active
`GET /api/verify/:code` route is declared in `routes/index.ts` and is protected
by `verifyLookupRouteLimiter`, `verifyCodeIpLimiter`, and
`verifyCodeActorLimiter`. These two alerts are false-positive production
dataflow classifications and are dismissed individually with this mount
evidence; no duplicate limiter is added to the quarantined router.

## Keyed-fingerprint finding

Alert 566 points to `hmacSha256Hex`, the keyed fingerprint primitive used for
opaque tokens and operational metadata. It is not a password-storage path.
User passwords use the dedicated approved password hash service. New MFA
backup codes use the dedicated scrypt service; its versioned HMAC check is
retained only for previously stored compatibility records. The invitation
test value previously named `preexistingPasswordRaw` was an invitation token
used to prove that accepting an invite does not overwrite an existing account
password, and is now named accordingly.

The primitive and its parameters now explicitly describe keyed fingerprints,
and the focused security regression proves deterministic token lookup,
input separation and key binding. Alert 566 is therefore dismissed only as a
false-positive password classification; authentication hashing behavior is
unchanged.

# MSCQR Public-Read Contract Review

This review resolves `decision-context-public-read-contract`. It defines workflow authorization only. It creates no runtime handler, SQL, function, role, grant, policy, RLS state, database mutation, infrastructure action or deployment.

## Decision

`public-read-contract-v1` is the sole public database-access authority. There is no generic anonymous read and no public list. Protected data is reachable only through one exact proof-bound named-function contract executed by `identity-pre-auth-app`; the runtime has no direct table privilege and installs no human or tenant context. Static health/content and connector artifacts avoid the database.

The thirteen exhaustive classes are: static public content, raw public QR verification, signed scan verification, proof-bound public status, one-time token consumption, email-link verification, public support tracking, public feedback submission, public download, pre-auth security function, authenticated-only, operator-only and prohibited public access. An unclassified route is prohibited.

## Current registered public routes

| Surface | Approved class | Proof | Database ceiling |
|---|---|---|---|
| Health and readiness | static-public-content | none | no row payload or internal dependency detail |
| `/verify/:code`, `/scan`, legacy verify aliases without `t` | public-qr-verification | canonical legacy code while compatibility gate remains | one QR-derived result |
| `/verify/:code?t=...`, `/scan?t=...` | signed-scan-verification | verified Ed25519 token and stored digest/nonce/epoch/parent binding | one QR-derived result |
| Verification session start/status | proof-bound-public-status | opaque hashed decision/session proof; optional later customer binding | one session |
| Invite/reset/email link routes | one-time-token-consumption or email-link-verification | existing hashed one-time token | one exact pre-auth function |
| Support ticket tracking | public-support-tracking | signed support-status proof | one ticket status |
| Feedback, fraud/incident, access and support intake | public-feedback-submission | validated artifact routing where tenant routing is needed; CAPTCHA/honeypot/idempotency as applicable | one created intake/result |
| Connector manifest/download | public-download | exact signed allowlisted manifest entry | no database |
| Customer ownership, session reveal/intake and credential operations | authenticated-only | verified customer actor plus continuity/CSRF | actor-bound only |
| Catalog/RLS/role/grant diagnostics | operator-only | exact operator procedure | no application route |
| Every broad public list or unknown public route | prohibited-public-access | none can authorize it | zero rows |

## Unsafe or ambiguous current behavior

- The inventory currently labels public QR, signed verification, feedback and ticket tracking as authenticated application workflows even though their registered roots are unauthenticated or optional-auth. That false human context is removed by the contract overlay; runtime remains pending.
- Ticket tracking accepts a reference alone when `customerEmail` is absent and returns distinct not-found/email-mismatch errors. `SupportTicket` has no proof version or dedicated proof row, so this route stays blocked until a signed, expiring, revocable proof exists.
- Raw QR verification is enumerable at the route surface, reads rich nested licensee/manufacturer/print fields, exposes more lifecycle and scan detail than the minimum public result, and performs protected reads/writes through global Prisma.
- Signed-token failures currently return detailed failure variants. The approved contract collapses them and forbids raw lookup after any signature, expiry, digest, nonce, epoch or parent-binding failure.
- Tenant feature-flag `config`, replacement-chain IDs, internal risk inputs, scan locations and device/IP evidence are used inside the flow. They may influence the customer state but cannot cross serialization.
- Product feedback uses a raw code to derive tenant and manufacturer routing and writes rich audit details. Only a server-verified QR artifact may route it; caller tenant IDs, observed state and page data never create authority.
- Fraud/incident intake spans helpers, evidence, incident, ticket, mail and audit behavior without one transaction-client-only proof boundary. It remains blocked pending full call-chain, idempotency and concurrency implementation.
- Verification-session status currently exposes resource-specific not-found and internal identifiers in parts of the service model. Session ID alone is no longer sufficient; the exact public status projection is proof-bound.

## QR verification model

The temporary raw path accepts only one canonical uppercase ASCII code matching `^[A-Z0-9][A-Z0-9_-]{7,127}$`, at most 128 characters. Validation happens before a protected read. The code is a lookup artifact, not tenant authority. The authoritative chain is one `QRCode`, its active Licensee and Organization, and its released, unsuspended Batch. Every parent must agree; NULL, orphaned, suspended, unreleased or inconsistent state fails closed.

Only `authentic`, `review-required`, `blocked` and `unavailable` are customer states. The response is limited to a safe message/action, masked code, approved brand/manufacturer presentation, printed/verification timestamps, claim availability and an opaque session-start token. It omits internal IDs, raw code, lifecycle enums, risk scores/factors, scan count/location, device/IP evidence, rules, audit data, private metadata and diagnostics.

Proof validation, the bounded read, scan counter/evidence update, immutable verification decision, idempotency record and hashed request attribution must share one transaction. A retry with the same request ID, QR/token epoch and bounded time bucket returns the same public decision rather than duplicating a scan.

Raw compatibility is removed after signed-label coverage reaches 99.9%, no unexpired legacy inventory remains and 90 consecutive days show no valid legacy-only scans. Progress is reviewed by 2026-10-31; the criteria, not the date alone, control removal.

## Signed-token model

Signed scans are a different class. The application first validates canonical token encoding, Ed25519 signature, allowlisted key version, issue/expiry time and required claims. `JWT_SECRET` fallback is prohibited. The exact function then rebinds the verified token digest, QR ID, licensee, batch, optional manufacturer, nonce and replay epoch to the stored row and current parents. No unsigned field creates authority.

Validation order is fixed: syntax/length, signature/key, expiry/purpose, claims, stored QR, digest/nonce/epoch, parents, readiness and atomic attribution. Every failure returns the same signed-proof-rejected response and stops. There is no raw-code fallback.

## Proof-bound public status

Verification sessions use a random token with at least 192 bits of entropy, store only its hash, expire within 30 minutes and bind one decision/session and replay epoch. A session ID is only a locator. Once a customer authenticates, the session binds to that customer and subsequent access requires both the same actor and fresh continuity proof.

Support tracking requires a server-signed proof with at least 128 bits of entropy binding reference, `support-status` purpose, version and a maximum seven-day expiry. Reference, ticket ID and email—alone or combined—are not proof. A proof-version column or dedicated proof record is needed for revocation, so the current handler is not implementation-ready.

## Existing pre-auth token model

The decision preserves the seven contracts in `pre-auth-functions.json`: password lookup, password-failure recording, password-reset request, password-reset consumption, invitation preview, invitation consumption and email-verification consumption. Invitation/reset/email consumption locks one hashed token, checks expiry and unused state, handles ambiguous matches as denial and consumes atomically. Password reset and account lookup retain constant/generic external responses. No generic new auth function is introduced.

The four historically pre-auth workflows already moved behind actor resolution—password login completion, email-change verification request, MFA challenge creation and MFA challenge completion—were also inspected. They remain `authenticated-only` under the existing actor-bootstrap decision, do not execute as anonymous/pre-auth database readers and are therefore not reassigned to `identity-pre-auth-app`.

## Public feedback and intake

All payloads are strict and length-bounded. Product feedback is limited to a 128-character code, rating 1–5, fixed satisfaction enum, 1,000-character notes and 1,000-character URL. Fraud/incident text is at most 2,000 characters; reply email is at most 160; attachments are at most five files, 10 MiB each, and PNG/JPEG/WebP/PDF only after signature validation. Access/support forms retain their existing smaller field ceilings and honeypots.

Only a verified QR/signed artifact or server routing map may derive a tenant. Body/query licensee, organization, manufacturer, batch or role fields are rejected. CAPTCHA protects fraud/incident reports; IP and privacy-preserving actor/resource buckets protect every intake; a stable digest enforces one logical creation. PII is minimized, separately protected and excluded from broad audit details. The response contains only accepted, an opaque public reference where required and a generic message.

## Public downloads and public policy content

Connector routes read the version-controlled release manifest and filesystem only. Version and platform must match an allowlisted manifest entry; resolved paths remain below the release root; SHA-256, signed production status, filename and content type come from the manifest. `windowsUnsignedTest`, internal/test artifacts and private channels are never public.

Marketing, help, trust and published policy text is static/version-controlled. No registered public protected-table policy projection exists. `TenantFeatureFlag`, `SecurityPolicy`, `PolicyRule`, governance state, compliance state and security configuration are authenticated-only. Policy alerts remain prohibited publicly under `policy-alert-actor-ceiling-v1`.

## Enumeration resistance, limits and failures

Every protected public operation yields at most one resource; there is no public count/list. Syntax and token validation precede protected access. Rate limits are exact per class and combine IP with a privacy-preserving actor/resource key. Raw email, token, QR or reference values are never rate-limit keys or logs.

Malformed/proof failures return “Request could not be verified.” Unknown, inactive, foreign, inconsistent and unavailable resources return “Requested information is unavailable.” Consumed/expired one-time links return “Link is invalid or expired.” Account/invitation requests use a constant accepted response. Rate limiting and dependency failures are generic. Detailed reason codes remain server-side with request ID and hashed attribution, never returned payloads.

## Implementation requirements

The ten `app_public` function contracts in `public-read-contract.json` have exact signatures, projections, fixed `pg_catalog` search paths, a dedicated NOLOGIN owner, no dynamic SQL, no generic predicates and no PUBLIC execution. `identity-pre-auth-app` receives EXECUTE only and no table privileges. The existing seven `app_auth` functions remain separate.

Runtime work must replace global Prisma with the exact function/repository call chain, preserve a single transaction, validate proof before access, enforce deterministic one-row cardinality, recursively redact nested content, make attribution/idempotency atomic and serialize only the class projection. No runtime workflow is implemented by this decision.

Required tests include malformed-before-read, unknown/inactive/foreign/ambiguous denial, invalid-signature-no-fallback, expiry/replay/epoch rotation, unreleased denial, exact projection and recursive redaction, one-row ceiling, tenant-routing rejection, support proof/version revocation, one-time token concurrency, same-transaction attribution/idempotency, path containment, signed artifact checksum and all generic response equivalence classes.

## Workflows potentially unlocked

The contract gives exact semantics to 26 workflows. Nineteen formerly blocked workflows move to these eleven contract-only public families; this is semantic eligibility, not runtime implementation:

- `family-split-governanceservice-public-verification-policy-80f0c95935`
- `family-contract-public-fn-read-verification-session`
- `family-contract-public-fn-record-qr-verification`
- `family-contract-public-fn-start-verification-session`
- `family-contract-public-fn-verify-raw-qr`
- `family-contract-public-fn-verify-signed-qr`
- `family-contract-public-fn-submit-public-incident`
- `family-contract-public-fn-submit-public-support`
- `family-contract-public-fn-submit-request-access`
- `family-contract-public-fn-submit-product-feedback`
- `family-contract-public-fn-track-support-status`

The other seven affected workflows remain in the existing exact invitation/reset/email pre-auth families. The first implementation candidates are the isolated QR raw lookup, signed lookup, duplicate-risk/UX-policy reads, replacement-status read, feedback QR routing and proof-bound verification-session reads. Support tracking additionally requires proof-version schema support. Fraud/incident intake requires a full atomic call-chain split.

Nested ownership, scan-insight, customer-trust, mail, audit/outbox and notification helpers were inspected as runtime dependencies but are not silently authorized by this decision. They retain query-trace, transaction, concurrency, projection or special-boundary blockers until the full-system runtime pass maps each call to the owning function/transaction.

The frozen counts are 316 families: three implemented families/four workflows, 31 contract-only families/59 workflows and 282 blocked families/365 workflows. The public decision changed the prior 321-family plan only through deterministic proof/function regrouping; workflow coverage remains exactly 428.

## Architecture freeze

All workflow-level context authorization decisions are now resolved. The architecture is frozen: future blockers are runtime, SQL, schema, concurrency or test blockers. A new broad product-decision category is prohibited unless a concrete code/schema contradiction to an approved boundary is demonstrated and reviewed.

The next stage is `full-system-runtime-implementation`, governed by `FULL_SYSTEM_RUNTIME_IMPLEMENTATION_PLAN.md`. The current four implemented workflows remain pending certification, and their partial disposable proof must not be treated as full-system RLS certification.

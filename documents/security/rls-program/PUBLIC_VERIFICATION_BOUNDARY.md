# Release Fix 6: public verification boundary

## Runtime call paths

| Entry point | Authority | PostgreSQL boundary |
|---|---|---|
| `GET /api/verify/:code` and `GET /api/verify` | anonymous immutable-code possession | `app_public.verify_raw_qr` |
| Signed label scan routes | backend-verified, QR/purpose/version/expiry-bound token | `app_public.verify_signed_qr` |
| `POST /api/verify/session/start` | one-use proof returned by verification | `app_public.start_verification_session` |
| `GET /api/verify/session/:id` | session ID plus proof | `app_public.read_verification_session` |
| Session intake and reveal | session proof plus optional live customer session | `app_public.write_verification_session` |
| Product feedback | exact immutable code plus bounded idempotency proof | `app_public.submit_product_feedback` |
| Fraud/concern report | live verification session proof plus bounded report inputs | `app_public.submit_public_incident` |
| Ownership claim | verification-session proof and optional customer session | `app_public.claim_customer_ownership` |
| Ownership transfer create/cancel/accept | live customer session; acceptance also needs the hashed transfer proof | `app_public.create_customer_ownership_transfer`, `cancel_customer_ownership_transfer`, `accept_customer_ownership_transfer` |
| Customer OTP/OAuth/passkey completion | RF1 challenge proof followed by a durable customer session | `app_public.issue_customer_auth_session` |
| Customer session status/logout | durable capability revalidation or exact idempotent revocation | `app_public.read_customer_auth_session`, `revoke_customer_auth_session` |
| Customer passkeys | live customer session plus server-verified WebAuthn challenge/assertion | `app_public.begin_customer_passkey`, `load_customer_passkey`, `finish_customer_passkey`, `list_customer_passkeys`, `delete_customer_passkey` |
| Public request-access and support forms | anonymous bounded inputs plus idempotency digest | `app_public.submit_request_access`, `submit_public_support`, then exact delivery completion functions |
| Scan rollups | dedicated worker database identity | existing RF4 `app_rls.refresh_scan_metrics_hourly_rollups` |

The HTTP process does not start the analytics scheduler. Printing, tenant
administration, authenticated incident response, and connector workflows
remain owned by earlier release boundaries.

Legacy Prisma implementations in `verifyOwnership.ts`,
`verifyFraudSnapshot.ts`, `verificationSignedTokenResolver.ts`, and
`authenticatedRepositories.ts` have no active RF6 route caller. They remain
quarantined compatibility code; active controllers call
`publicBoundaryRepository.ts`. The test-only intake fallback is enabled only
when `NODE_ENV=test` and the B02 boundary flag is disabled.

## Identity and capability model

- `QRCode.code` remains the case-sensitive immutable server identity.
- Raw verification accepts only the existing surrounding-whitespace trim; it
  does not fall back to `displayCode`.
- Signed labels are verified by the existing backend signer. PostgreSQL
  rebinds the verified QR, tenant, batch, nonce, replay epoch, purpose,
  issuance, and expiry claims to the locked database row.
- After a signed scan creates its verification session, the frontend replaces
  the bearer-token URL with the opaque session URL. Ownership and concern
  actions use that session proof; the masked presentation code is never
  reused as database authority.
- Customer sessions are opaque 32-byte capabilities. Only SHA-256 hashes are
  stored in `CustomerAuthSession`; expiry, revocation, and the database-bound
  customer identity are checked on every authenticated customer call. The
  current customer model is a cryptographically derived email identity and
  has no separate enabled/disabled account state.
- The session-status route revalidates the durable database row instead of
  treating the signed cookie alone as authority. Logout cannot report success
  after silently skipping database revocation; repeated revocation is
  idempotent.
- WebAuthn cryptography remains in the existing server library. PostgreSQL
  owns challenge/ticket binding, expiry, single use, credential ownership,
  signature-counter replay protection, and atomic credential mutation.
- The restricted pre-auth role receives exact `EXECUTE` grants only. It has no
  direct protected-table privilege. `PUBLIC`, the authenticated application
  role, worker roles, connector roles, and restricted-read roles receive no
  implicit RF6 execution.

## Authoritative verification transaction

`public_verify_execute` locks the exact QR row and, in one transaction:

1. resolves immutable identity;
2. validates signed claims when present;
3. derives tenant, batch, manufacturer, replacement, and lifecycle state;
4. classifies the scan from committed scan history and server-derived hashes;
5. inserts consumer scan history only for `FIRST_SCAN`, `LEGIT_REPEAT`, or
   `SUSPICIOUS_DUPLICATE`, while every resolved denial still records its
   decision, evidence snapshot, audit, and security-outbox evidence;
6. returns an explicit public projection.

The row lock ensures concurrent first scans produce one `FIRST_SCAN`. A
follower observes committed history and becomes a deterministic repeat.
Failure before commit leaves none of the scan/evidence/audit/outbox state.

## Lifecycle and public decisions

| Database condition | Internal decision | Customer-safe result |
|---|---|---|
| no exact immutable-code row | not found | generic unregistered result |
| blocked QR or active replacement makes label obsolete | `BLOCKED_BY_SECURITY` | safe blocked guidance |
| QR/batch is not customer-ready | `NOT_READY_FOR_CUSTOMER_USE` | safe not-ready guidance |
| first eligible committed scan | `FIRST_SCAN` | authentic first verification |
| eligible repeat in the same server-derived context | `LEGIT_REPEAT` | authentic repeat with copyable-code caveat |
| eligible repeat in changed context | `SUSPICIOUS_DUPLICATE` | review guidance without asserting counterfeit certainty |

Customer readiness requires a real released, unsuspended batch, an active
organization, an active and unsuspended licensee, and the established
QR/printing evidence. Missing-batch, failed, voided, unreleased, obsolete, or
blocked inventory cannot become an authentic result through browser input.
`LEGIT_REPEAT` additionally requires both server-derived IP and device
purpose hashes to match; one caller-influenced signal is insufficient.
Blocked, replaced, recalled, failed, voided, and not-ready outcomes never
increment `QRCode.scanCount` or create `QrScanLog` history, so a label's first
eligible post-release scan remains `FIRST_SCAN`.

## Public projection and privacy

The output allowlist is: public decision/message/next-action keys, masked
code, public brand/manufacturer names and validated HTTP(S) websites, safe
printing/verification timestamps, ownership availability, and the one-use
session-start proof.

It excludes database IDs, tenant keys, internal lifecycle fields, scores,
thresholds, device/IP hashes, raw IP or location, audit metadata, signing
metadata, incidents, private contacts, session capability hashes, and raw
tokens.

| Collected value | Source and purpose | Stored form |
|---|---|---|
| immutable code | label input; exact lookup | protected QR row; masked in public output |
| IP/device context | server derived; repeat/abuse classification | purpose-specific hash only |
| user agent | server derived; customer-session/passkey binding | bounded hash only |
| email | customer identity, transfer, or opted-in support | normalized email only in the relevant protected record |
| concern text | customer-submitted support evidence | bounded validated text; never echoed with internal metadata |
| signed label token | bearer proof | digest/verified claims only; raw token is not persisted or audited |

Route-specific rate limiters, input-size limits, CAPTCHA where already
configured, high-entropy immutable codes, exact lookup, and generic malformed
responses provide enumeration and abuse resistance. Complete codes and bearer
tokens are not written to RF6 audit or outbox metadata. HTTP completion,
exception, and legacy-bearer telemetry replace public codes, customer session
IDs, credential IDs, and query strings with stable route templates before
logging.

Unknown manual-code lookups receive 15–25 ms of database-side random padding
after bounded input validation and before the generic not-found response. The
padding is not constant-time, does not apply to signed-token verification, and
occurs before any QR row lock or verification evidence mutation.

## Ownership, concern, email, and support

- Ownership claims resolve QR scope from the verification proof; supplied
  customer, tenant, batch, or QR database IDs are never authority.
- Report-session eligibility is independent of ownership eligibility.
  Reportable authentic, review, blocked, and not-ready results receive the
  same short-lived QR-bound session-start proof; PostgreSQL separately denies
  ownership when the evidence snapshot says the label is not claimable.
- Transfer creation/cancellation requires the current database customer;
  acceptance consumes one exact hashed transfer token. Competing pending
  transfers are cancelled atomically.
- Concern creation resolves the exact QR and writes Incident, IncidentEvent,
  IncidentEvidence, SupportTicket, idempotency, and security-outbox evidence
  atomically. The browser supplies only the live verification-session proof;
  PostgreSQL derives the QR from that session. Delivery failure cannot erase
  the committed concern.
- RF1 OTP/OAuth/passkey proof issues the RF6 customer database session; email
  alone never grants saved-verification or ownership access.
- Public support resolves brand/licensee scope from the immutable code and
  stores that canonical code on the protected support record. The caller
  cannot provide a tenant, brand, or QR database identifier.
- Request-access and support rows commit before the existing mail adapters run.
  The exact delivery-completion functions persist bounded delivery outcomes;
  content-based idempotency returns `deliveryRequired=false` on retry so mail
  is not resent. Support mail contains only a masked code, never the complete
  immutable QR value.

## RLS, owners, grants, analytics, and rollback

RF6 functions use fixed `pg_catalog,public` search paths and a controlled
`NOLOGIN`, `NOBYPASSRLS` owner that owns no protected application table.
Operation-local GUC values are installed only by verified functions and are
row-bound in generated policies. Runtime roles cannot call internal helpers.
The pre-auth runtime has 23 exact public-function grants; the five shared
helpers have no runtime execution grant.

Public-verification analytics reuse the RF4 worker-only rollup functions.
Those functions paginate their reviewed source and checkpoint writes, run
only in the worker process, and give the HTTP/pre-auth roles no analytics
table access.

The RF6 rollback drops only the RF6 policies, exact functions, helpers, and
grants without `CASCADE`. It preserves application data, RF1–5 functions,
roles, policies, and runtime behaviour. Disposable PostgreSQL certification
proved the exact rollback and zero database/role residue.

## Certification

The final package was generated twice with byte-identical aggregate SHA-256
`c0d2e319a8e6f06fad5cb30c801ef66572329d592da2585e9ec20336426a85a8`.
Its source-contract SHA-256 is
`99a6d9100b277d06a8fb99efacccd14b0d4f5f2ac4856c971ae6eb6b800a02a9`.

Fresh PostgreSQL 18.4 certification installed the real migration history and
the exact generated package, certified 77 FORCE-RLS tables, 285 generated
policies, 74 column-privilege cells, the RF6 application path, concurrent
first-scan classification, exact runtime grants, direct-access denial,
session-bound claims and concerns, atomic delivery evidence, and the exact
rollback. The run left zero disposable databases and zero disposable roles.

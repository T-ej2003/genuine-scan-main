# Worker audit producer/consumer compatibility

Base source: b7e0f171c716d5ba6d5a13da096bd87d9b638867. Production is untouched by this PR.

## Complete SQL producer map (before correction)

| Producer | Source | Digest | Idempotency identity | Can be incomplete |
|---|---|---|---|---|
| app_rls.c03_queue_audit | backend/src/rls-waves/session-c/c03/c03AuthenticatedBoundaries.sql | False | False | True |
| app_rls.enqueue_audit_log_outbox | backend/src/rls-waves/session-b/b03/b03OutboxFunctions.sql | True | True | False |
| app_rls.scheduled_job_queue_audit | backend/src/rls-waves/session-b/b03/scheduledJobIdentityFunctions.sql | False | False | True |
| app_auth.b01_preauth_audit | backend/src/rls-waves/session-b/b01/b01PreAuthSecurityFunctions.sql | False | False | True |
| app_rls.load_authenticated_manufacturer_scope | backend/src/rls-waves/session-b/b01/b01AuthenticationClosureFunctions.sql | False | False | True |
| app_rls.record_auth_session_risk_signal | backend/src/rls-waves/session-b/b01/b01AuthenticationClosureFunctions.sql | False | False | True |
| app_rls.create_refresh_token | backend/src/rls-waves/session-b/b01/b01AuthenticationClosureFunctions.sql | False | False | True |
| app_rls.update_authenticated_profile | backend/src/rls-waves/session-b/b01/b01AuthenticationClosureFunctions.sql | False | False | True |
| app_rls.change_authenticated_password | backend/src/rls-waves/session-b/b01/b01AuthenticationClosureFunctions.sql | False | False | True |
| app_rls.complete_admin_totp_enrollment | backend/src/rls-waves/session-b/b01/b01AuthenticationClosureFunctions.sql | False | False | True |
| app_rls.disable_admin_mfa | backend/src/rls-waves/session-b/b01/b01AuthenticationClosureFunctions.sql | False | False | True |
| app_rls.create_admin_mfa_challenge | backend/src/rls-waves/session-b/b01/b01AuthenticationClosureFunctions.sql | False | False | True |
| app_rls.record_admin_mfa_challenge_failure | backend/src/rls-waves/session-b/b01/b01AuthenticationClosureFunctions.sql | False | False | True |
| app_rls.complete_admin_mfa_challenge | backend/src/rls-waves/session-b/b01/b01AuthenticationClosureFunctions.sql | False | False | True |
| app_rls.complete_admin_webauthn_registration | backend/src/rls-waves/session-b/b01/b01AuthenticationClosureFunctions.sql | False | False | True |
| app_rls.delete_admin_webauthn_credential | backend/src/rls-waves/session-b/b01/b01AuthenticationClosureFunctions.sql | False | False | True |
| app_auth.b01_audit | backend/src/rls-waves/session-b/b01/b01RefreshRotationFunctions.sql | False | False | True |

The TypeScript queueAuditLogOutbox → enqueue_audit_log_outbox path supplies both fields. Shared persistence enforcement covers all SQL producers rather than changing business/activation function bodies. Consumers are claimAuditLogOutboxSlice → validateClaim → withB03AuditWorkerContext → consumeAuditLogOutbox/failAuditLogOutbox. SQL consume projects AuditLog and SecurityEventOutbox atomically; SENT replay returns the existing audit ID.

ALL_PRODUCERS_MAPPED=true
ALL_CONSUMERS_MAPPED=true

## Canonical contract

Required field: `payloadDigest`. Algorithm: SHA-256, UTF-8. SQL producers use PostgreSQL JSONB text; the existing TypeScript producer uses recursively sorted JSON after normalising through the same JSON serializer used for persistence. Both existing formats remain explicit, verified formats; no new identity scheme is introduced. Identity: the existing SHA-256 AUDIT_LOG_RECOVERY:<requestId>:<payloadDigest> tuple, with the existing unique idempotencyKey index. Request is a UUID; attribution is established by the original SECURITY DEFINER/RLS producer, not caller JSON as standalone authority. Original producer payload and authorisation predicates remain unchanged. Runtime roles gain no privileges.

The SQL producer map contains 17 functions and 19 INSERT sites: risk-signal recording and challenge completion each have two sites. The risk-block branch already supplied a JSONB-text digest and identity; its other branch could omit them. The TypeScript enqueue is the additional public producer path. Every insert reaches the shared BEFORE INSERT trigger; every original authorisation and RLS predicate stays intact.

`idempotencyKey` is the existing SHA-256 of `AUDIT_LOG_RECOVERY:<requestId>:<payloadDigest>`, enforced by the existing unique index. UUID request identities are retained. Where a **new** event has no UUID request, its existing immutable UUID record ID supplies the durable identity, and provenance explicitly identifies that choice. This is not a claim that a client supplied a historical request ID. Separate failed-login attempts remain separate audit events. Retrying the canonical enqueue with the same request/payload returns the same durable record; incompatible attribution is rejected.

Supplied digests are never silently rewritten. Source-selected new producer provenance distinguishes `stable-json-v1` from `jsonb-text-v1`. Legacy complete records are verified against those two established encodings; an invalid supplied digest cannot enter the missing-digest recovery branch.

## Legacy classification and recovery

The retained production proof establishes a baseline of 193 queued audit records, of which 156 lack digest/identity. It does **not** establish per-record request identity, attribution, expiry, or tamper status. Therefore neither 156 recoverable nor zero failures is claimed. Production is untouched; exact production classification counts are obtained when the corrected claim boundary is installed and consumed after merge.

| Classification | Exact treatment |
|---|---|
| Authentically reconstructable | Existing persisted UUID request, attributed payload/columns agreeing, original unexpired expiry, absent digest **and** identity, zero prior attempts and no completed projection. Derive digest and identity from those protected stored inputs, retaining the same row. |
| Not reconstructable / invalid | Missing authority, partial identity, mismatched supplied digest/scope, expired authority or ambiguous prior attempt: retain the row and stamp `B03_AUDIT_RECORD_UNRECONSTRUCTABLE`. No SENT status, deletion, historical request invention, or expiry extension. |
| Duplicate identity | Retain the additional row as `B03_AUDIT_RECORD_DUPLICATE`; do not create another projection or claim successful processing. |
| Already processed | SENT rows remain unchanged. Existing successful consume replay returns the original audit ID while the original validity window permits. |

Recovery provenance has its own exact version-1 shape: `origin=legacy-recovery`, `originalDigestPresent=false`, `recoveryDigestDerived=true`, `originalIdentityPresent=false`, source record ID and recovery timestamp. It remains in the queue row and is copied into the resulting audit details. It cannot be supplied by a new producer. Payload, request, tenant/user scope and original expiry are never rewritten to manufacture recovery authority.

## Concurrency and security

Row locks with SKIP LOCKED preserve the existing five-minute claim lease, ten-attempt bound and retry/backoff. Recovery additionally takes a transaction-scoped, non-blocking lock on the existing idempotency identity; its unique index remains the final arbiter against concurrent new producer delivery. A lock hash collision can defer a retry, never merge identities. Digest/identity derivation and claim commit together. A rollback leaves the pre-correction row intact; a process crash after claim retains its lease and provenance for retry.

Audit projection, security-event enqueue and SENT completion remain one transaction. The row lock plus SENT replay makes database projection idempotent. External SIEM delivery semantics are unchanged; this document does not claim globally exactly-once external delivery.

No app, worker, preauth or scheduled-role table/DDL privileges are added. RLS expressions, membership isolation, owner NOLOGIN/NOBYPASSRLS attributes and PUBLIC revocation remain intact. The existing NOLOGIN function owner receives only the extra metadata column privileges necessary for the fixed recovery implementation, not broader runtime access. The trigger-install EXECUTE grant to the table owner is revoked in the same installation transaction.

## Upgrade and verification

Migration `20261001150000_audit_record_provenance` adds one nullable JSONB provenance column and preserves existing rows. The canonical RLS generator installs the private helpers and trigger. Generated SQL/reports are generator output, not handwritten synchronisations. This PR does not install anything in production or use a clean-room installer on the active database.

The local PostgreSQL 18 proof loads actual nullable old-shape fixtures **before** installing the trigger, then runs current producer/worker code. It covers all 19 canonical write shapes, stable JSON Unicode/numeric encoding, new digest tampering, forged provenance, current TypeScript enqueue, rollback, two concurrent workers, duplicate legacy identity, non-reconstructable retention, already-SENT retention, partial completion rollback, replay and mixed populations. The existing retry tests exercise failure/backoff. Repository unit tests cover persisted JSON normalisation, deterministic hashes and request/context validation.

Mandatory CI: `rls:full-verify` includes `b03-outbox-contract.test.mjs`; the existing Quality Gate PostgreSQL job runs the B03 audit application proof and worker boundary unit tests. No standalone workflow is added.

## After merge only

1. Synchronise protected main and classify affected image components using the existing classifier.
2. Apply the additive column/private routine/trigger delta through the authorised active-database route; preserve onboarding and existing privilege boundaries.
3. Publish/deploy only required immutable components. Keep the worker's already-corrected startup flags and existing worker credential.
4. Run corrected claims and report actual recovered, failed-closed, duplicate, invalid, processed and remaining counts. Do not reset the queue or mislabel failed-closed records as processed.
5. Verify intended worker jobs and fresh permission/DDL logs; run a small health/login/refresh/onboarding regression. Stop at worker closure.

Recommendation: use the durable failure classifications as the operational backlog; add alerting only when the observed volume requires it. Do not grant direct table access to resolve malformed audit records.

## Local verification checkpoint

The focused worker/audit/security unit run passed 9 tests; the canonical full RLS verification passed 24 tests. The dedicated PostgreSQL 18 application proof passed, including old-shape fixtures and transaction failure injection. The local Codex diff review reported no actionable defects. Exact-head GitHub CI and review remain required before the merge decision. Production queue classification and recovery have not been executed: the retained aggregate evidence establishes 156 incomplete records, not their individual recoverability. No production changes are part of this PR preparation.

CI harness isolation: the B03 proof uses the existing docker-compose.rls-certification.yml cluster. The P2 harness deliberately pre-creates certification-administrator, so it cannot satisfy the independent clean-room provenance guard. The guard remains unchanged; the workflow regression checks the separate harness and URL.

Bare SQL INSERT producers use their immutable event-row UUID for identity even when a client request UUID is reused; the original request remains explicit provenance. Existing replay-aware producers with supplied digest/identity preserve their original canonical request tuple. PostgreSQL coverage proves two equal payloads under one client request persist and complete as distinct events.

Replay-aware requests are normalised by the existing repository UUID validator before deriving the key; uppercase/lowercase representations converge. Replay and legacy duplicate checks also compare the original actor-role snapshot in addition to user and tenant scope. Regression coverage rejects changed-role substitution.

# Database-verifiable authenticated session capability

## Purpose

Authenticated PostgreSQL boundaries must not trust `app.*` values supplied by
Node.  A successful authentication event now creates an opaque capability
bound to the current `RefreshToken` session lineage. PostgreSQL verifies the
capability before it derives any actor, assurance or tenant scope.

## Durable state

The existing `RefreshToken` row is the durable authenticated-session lineage.
It stores a `sha256-v1` SHA-256 digest of a 32-byte base64url capability,
assurance, expiry, revocation state and last-use time. It never stores the raw
capability, tenant membership or role claims. Those are derived from current
authoritative rows during verification.

The capability is delivered only in the encrypted, HTTP-only `aq_db_session`
cookie. Existing access-token and refresh-token JSON/cookie contracts remain
unchanged. The raw value is opened only by the trusted Node authentication
middleware and is passed to exact reviewed PostgreSQL boundaries; it is not
logged, returned in API JSON or put in a general `app.*` setting.

## Lifecycle

* Password login or completed MFA creates one capability with an expiry no
  later than its active refresh-token expiry.
* Refresh rotation revokes the predecessor capability and creates a successor
  capability inside the same transaction as the replacement refresh token.
* Logout, logout-all, password reset/change and user disablement revoke the
  applicable rows. Live user, membership, organisation and licensee checks
  also reject stale sessions before protected access.
* A rollback removes capability creation/revocation with its enclosing auth
  operation. A committed predecessor or revoked session cannot be replayed.

## Database boundary

The reviewed `app_auth` functions use fixed `pg_catalog,public` search
paths and a dedicated NOLOGIN, non-BYPASSRLS function owner. They accept the
raw capability only as an exact argument, hash it in PostgreSQL using
PostgreSQL 18's built-in `pg_catalog.sha256(bytea)`, require exactly one active row and install
owner-only transaction-local context. Runtime roles receive no direct session
table access and cannot execute internal context installers.

Issuance additionally requires the exact existing refresh-token hash for the
candidate row. A refresh-row ID is therefore only a selector: it cannot be
used by a pre-auth caller to mint a capability for another active session.

## Migration and rollback

The migration is additive and nullable only where lifecycle state requires it;
existing `RefreshToken` rows are not invalidated. Rolling back this source
contract first stops capability issuance and verification, then drops the
`RefreshToken` capability columns and indexes only after no application version
references them. Production rollout must use the generated
package and its catalog checks; this document is not an activation procedure.

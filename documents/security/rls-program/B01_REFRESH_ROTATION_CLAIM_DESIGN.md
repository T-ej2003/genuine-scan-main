# B01 refresh rotation claim

## Deficiency

The production `RefreshToken` record had replacement-hash lineage but no durable request claim. Concurrent refresh requests could therefore race before the old token was revoked.

## Selected model

Three nullable fields are added to `RefreshToken`: `rotationRequestId`, `rotationClaimedAt`, and `rotationCompletedAt`. Existing rows remain valid. `replacedByTokenHash` remains the durable replacement linkage; no raw replacement token is stored.

## State and concurrency

`ACTIVE -> CLAIMED -> ROTATED` is protected by `SELECT ... FOR UPDATE` in one transaction. The first request records its request ID and claim time. A different request is denied while the claim is uncommitted. Completion and revocation both receive that request ID explicitly and rebind it to the locked predecessor; they do not rely on inherited connection state. Completion inserts the successor and atomically revokes the original, records the replacement hash and completion time. Transaction rollback removes the claim and every partial write.

## Replay and compatibility

Transactional atomicity is not HTTP replayability. After commit, the raw replacement token cannot be replayed from storage and every later use of the old bearer, including the same request ID, is rejected as reuse. This preserves token secrecy and the existing cookie response contract. Expired, revoked, disabled, or stale-membership tokens are revoked or denied as before. Existing tokens with NULL claim fields remain eligible.

## Rejected alternatives

A separate claim table adds another RLS-protected object and does not improve the single-token lock. Redis/process locks are not durable across instances. Persisting the raw successor would create an unacceptable credential-retention surface.

## FORCE RLS execution model

The existing `identity-auth-function-owner` NOLOGIN role owns the five `app_auth` signatures, but not production tables and never has `BYPASSRLS`. Each SECURITY DEFINER function first clears all B01 derived settings, then installs transaction-local bearer-hash and request scope. The first `RefreshToken` read is constrained to the presented bearer hash; after locking it, functions derive and overwrite predecessor, user, organization, manufacturer membership, MFA and audit scope from database rows. User-wide refresh-token access is available only for exact derived revocation operations; claim, load, MFA and completion paths remain predecessor-scoped. FORCE RLS policies require both the auth-function-owner identity and that derived scope. A pre-auth runtime role may set arbitrary custom GUCs but cannot become the function owner or access protected tables directly, so caller-provided GUCs never authorize data access. PostgreSQL clears the local settings on commit, rollback and error.

## Rollout and grants

Apply the nullable migration first, then install `app_auth` functions owned by the controlled NOLOGIN auth owner, revoke PUBLIC execution, and grant only the pre-auth runtime exact signatures. Rollback removes functions/grants before dropping the three nullable columns and index; do not drop columns while a function package still references them.

# Production Green Stage B Approval Publication Contract v1

This contract defines how the independently signed Stage B approval becomes
the broker's current approval. It is a publication step, not a new signing
step.

## Authority and target

- Publisher: `arn:aws:iam::368992683803:role/mscqr-production-rls-independent-checker`.
- Human authentication remains at the checker-user-to-Role-A MFA boundary;
  the publisher is usable only from the exact assumed Role-B session.
- Secret: `arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase2/approval-e0shho`.
- The release-deployer never receives approval-secret read or write access.
- The broker role remains read-only for this secret.

## Allowed operation

The publisher may use exactly `secretsmanager:PutSecretValue` on the exact
secret ARN above. It may not use `GetSecretValue`, `UpdateSecret`,
`UpdateSecretVersionStage`, `DeleteSecret`, `CreateSecret`, or
`secretsmanager:*`. No arbitrary secret identifier is accepted by the
publisher.

The publisher loads the exact signed approval file bytes, validates the
schema-v2 contract and KMS signature, and submits those same UTF-8 bytes as
`SecretString`. It never parses and reserializes the payload for publication.

The artifact must have approval ID `APR-STAGE-B-<releaseSha>`, where the
suffix is the complete lowercase 40-character release SHA. This ID is
deterministically derived from `releaseSha` and is not caller-selected. Its
`releaseSha` must equal the clean checkout `HEAD`, and its `checkerIdentity`
must equal the current exact assumed Role-B caller. The signature, account, region, expiry,
not-before, images, task maps, broker identity, and all other schema-v2
bindings are validated before the write.

## Version and idempotency semantics

The publisher supplies a 64-character lowercase hexadecimal
`ClientRequestToken` equal to:

```text
sha256(approvalId + "\n" + releaseSha)
```

This is the stable logical publication identity for one approval ID and
source release. The request omits `VersionStages`. Secrets Manager therefore
assigns `AWSCURRENT` to the new version and moves the previous current version
to `AWSPREVIOUS`.

The broker replay key remains `approvalId#mode`; because the approval ID
contains the complete release SHA, the same mode is independent across
releases while duplicate execution within one release remains blocked.
Retrying the same approval ID/source with identical bytes is idempotent.
Reusing that identity with different bytes fails because Secrets Manager does
not permit changing an existing version. A different source SHA necessarily
produces a different approval ID and publication identity. Malformed, unsigned,
expired, future-dated, wrong-source, or
wrong-caller artifacts fail before `PutSecretValue`.

The publisher reports only the secret ARN, version ID/stages, approval ID,
source SHA, and SHA-256 of the exact local file bytes. Secret content,
signature material, credentials, and KMS messages are never logged.

## Readback and broker proof

The broker role reads only `AWSCURRENT` and verifies the exact schema-v2
approval and KMS signature before every operation. The repository-owned
publication check invokes the reviewed broker alias in validation-only mode;
that mode reads and verifies `AWSCURRENT` but does not claim replay state,
launch ECS tasks, write receipts, or mutate production resources.

The validation result is redacted and includes only the approval ID, source
SHA, approval contract hash, exact payload SHA-256, and validation status.

## Rollback and failure behavior

Publication is append-only. There is no automatic fallback to a stale
approval. Existing versions remain available under Secrets Manager version
history. Restoring a prior version is a separate emergency procedure that
requires explicit operator approval, selection of a previously validated
version, and a fresh broker validation; it is not part of normal publication
or retry behavior.

Any validation failure, identity mismatch, AWS write failure, or broker
validation failure leaves the cutover blocked. No deployment phase may treat a
local signed file as published until the broker validation proof passes.

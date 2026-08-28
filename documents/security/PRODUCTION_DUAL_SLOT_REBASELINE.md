# Production dual-slot rebaseline

`PRODUCTION_DUAL_SLOT_REBASELINE` is a one-time, operation-specific recovery path for
authenticated pre-cutover dual-slot state with zero live consumers. It does not alter
the ordinary stale-rotation classifier or its `UNKNOWN` rejection.

The preparation step records an `ABANDONED_PRE_CUTOVER` evidence hash, including the
exact current version, stages, schema, historical metadata, and safe payload identity
of every historical slot. The retained historical Secrets Manager VersionId is the
immutable payload authority; the newly observed safe payload hash/fingerprint must
match the corresponding schema and metadata before the version can be abandoned. It
authenticates the complete live ECS task/deployment reference set and the legacy runtime
baseline, then creates one private material journal. The audit retains a raw observation
hash for forensics, but authorization binds the stable security topology: service and
task-definition identities, every secret-reference audit, legacy authority, and zero
dual-slot/database/external consumers. A replacement task on the same audited definition
is safe to resume; a different definition requires a new authorization even when it has
no dual-slot reference. The journal is
the only resumable copy of newly generated signing material; it is never published,
logged, or included in authorization/completion evidence.

The seven writes use domain-separated SHA-256 client request tokens derived from the
operation, protected source, rotation, slot, ARN, and baseline identity. A retry may
reuse only the exact authenticated deterministic version. At every resume point each
slot must be either the immutable abandonment snapshot or that exact prepared version;
any third state fails closed. Any mismatch fails closed.

`BASELINE_COMPLETE` is emitted only after a fresh read authenticates all seven exact
versions and `AWSCURRENT` stages. Completion and canonical rotation bindings are
durable private outputs; a retry after a persistence interruption reuses the exact
seven deterministic versions and emits the same artifacts without another write.
Runtime preparation accepts only the declared rebaseline binding producer and requires
an independently resolved protected-environment authorization artifact whose digest
matches the completion. The operation performs no `DeleteSecret`, Terraform, ECS, database,
IAM, KMS, or image action.

The existing release-deployer seven-secret `secretsmanager:PutSecretValue` allowlist
is reused; no steady-state permission is broadened. Production execution still
requires the dedicated protected-environment authorization artifact.

Production execution requires the exact prepared rotation ID plus the private
preparation and material-journal paths. Execution never generates material: a missing
or mismatched journal fails before a write. Fresh ECS reference enumeration occurs before
each write and before completion; incomplete task/deployment/task-definition reads also
fail closed.

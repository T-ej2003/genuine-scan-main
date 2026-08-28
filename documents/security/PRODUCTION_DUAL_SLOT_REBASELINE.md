# Production dual-slot rebaseline

`PRODUCTION_DUAL_SLOT_REBASELINE` is a one-time, operation-specific recovery path for
authenticated pre-cutover dual-slot state with zero live consumers. It does not alter
the ordinary stale-rotation classifier or its `UNKNOWN` rejection.

The preparation step records an `ABANDONED_PRE_CUTOVER` evidence hash, authenticates
the legacy runtime baseline, and creates one private material journal. The journal is
the only resumable copy of newly generated signing material; it is never published,
logged, or included in authorization/completion evidence.

The seven writes use domain-separated SHA-256 client request tokens derived from the
operation, protected source, rotation, slot, ARN, and baseline identity. A retry may
reuse only the exact authenticated deterministic version. Any mismatch fails closed.

`BASELINE_COMPLETE` is emitted only after a fresh read authenticates all seven exact
versions and `AWSCURRENT` stages. Runtime preparation accepts a rebaseline binding
only when that completion artifact, source, rotation, resources, and authorization
hash all match. The operation performs no `DeleteSecret`, Terraform, ECS, database,
IAM, KMS, or image action.

The existing release-deployer seven-secret `secretsmanager:PutSecretValue` allowlist
is reused; no steady-state permission is broadened. Production execution still
requires the dedicated protected-environment authorization artifact.

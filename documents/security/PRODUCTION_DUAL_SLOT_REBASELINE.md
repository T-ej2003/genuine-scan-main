# Production dual-slot rebaseline

`PRODUCTION_DUAL_SLOT_REBASELINE` is a one-time, operation-specific recovery path for
authenticated pre-cutover dual-slot state with zero live consumers. It does not alter
the ordinary stale-rotation classifier or its `UNKNOWN` rejection.

The preparation step records an `ABANDONED_PRE_CUTOVER` evidence hash, including the
exact current version, stages, schema, historical metadata, and safe payload identity
of every historical slot. The retained historical Secrets Manager VersionId is the
immutable payload authority; the newly observed safe payload hash/fingerprint must
match the corresponding schema and metadata before the version can be abandoned. It
authenticates the complete paginated live ECS task/deployment reference set and the legacy runtime
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

The baseline identity also authenticates the complete legacy/current runtime manifest.
The three legacy signing-secret ARNs and active QR version are compared against the
independently authorized baseline identity before rebaseline bindings are emitted or
consumed. This check runs even when the binding source SHA is unchanged; source
equality never substitutes for live baseline authentication.

`BASELINE_COMPLETE` is emitted only after a fresh read authenticates all seven exact
versions and `AWSCURRENT` stages. Completion and canonical rotation bindings are
durable private outputs; a retry after a persistence interruption reuses the exact
seven deterministic versions and emits the same artifacts without another write. They
are published through a same-directory private temporary file, complete-write
verification, file and directory synchronization, and atomic no-replace publication.
The no-replace step uses POSIX hard-link publication followed by temporary-name
cleanup; plain rename could replace a concurrently-created immutable final. A crash can
leave an orphan temporary file or a complete final, and retries ignore orphan names,
authenticate exact finals, and never overwrite them. The material journal uses the same
primitive before any secret write is reachable. If preparation stops after abandonment
publication, the next run authenticates and reuses that exact immutable evidence rather
than regenerating its timestamp or historical snapshot; a divergent existing artifact is
rejected.

If a process stops after the private preparation is published but before it can report
success, rerunning preparation authenticates and reuses the same source, abandonment,
baseline, and seven safe write descriptors. It never regenerates material or replaces
the immutable preparation file; a divergent preparation fails closed.

The abandoned production snapshot also has an authenticated
`AUTHENTICATED_PRE_CUTOVER_COORDINATOR_TRANSITION` variant. It is accepted only when
the retained supersession evidence, protected coordinator writer semantics, predecessor
identities, deterministic post-transition VersionIds, both transitioned slot payload
fingerprints, historical authorization/state evidence, and the zero-consumer/single
legacy-baseline audit all agree. It is not a general source-less or `previous`-slot
compatibility exception. Preparation supplies this retained private evidence with
`--historical-transition-evidence`; missing, divergent, or locally altered evidence
remains a fail-closed error.

The transition envelope is additionally compared with the reviewed protected-source
anchor for this exact seven-resource historical transition. The anchor binds each
predecessor and post-transition VersionId plus its non-secret payload identity: canonical
payload SHA, family/slot/schema, source-presence semantics, rotation identity, and every
applicable fingerprint or key-version. This includes all five unchanged slots, not only
the two coordinator writes. Its embedded SHA proves only internal integrity; the
protected-source anchor establishes historical authority. The authoritative validator
also requires fresh observed VersionIds and slot identities, so the anchor never
substitutes for live Secrets Manager agreement.

Security-critical transition fields have two independent checks: protected source fixes
the accepted resources, predecessor/post VersionIds, payload identities, writer,
supersession, authorization, and rotation-state provenance; fresh Secrets Manager reads
must then match the protected post-transition identities. The transition file's hashes,
including `transitionSha256`, are integrity checks only. ECS audit and coherent legacy
baseline values are fresh safety predicates bound into abandonment/preparation and are
not historical authority. No supplied field selects a weaker validator or supplies its
own expected value.

The protected authorization says that the seven deterministic writes may occur; it is
not proof that they did. Runtime preparation therefore re-resolves the protected
environment authorization artifact and performs fresh `DescribeSecret` plus
`GetSecretValue` reads for every exact authorized resource. It accepts a baseline only
when each `AWSCURRENT` VersionId, staging label, non-secret canonical payload identity,
and operation/source/rotation/slot metadata matches both the authorization and the
prepared material. A locally constructed completion or binding file cannot substitute
for this post-write observation. The later cutover control plane repeats the same
authorization resolution and seven-slot read immediately before rotation preparation.
That coordinator intentionally advances the baseline slots; immediately before overlap
task-definition registration, its read-only `--status` path re-authenticates the
persisted prepared-rotation state against the live ten-slot topology instead of
incorrectly requiring the superseded baseline versions.

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
each write and before completion; desired RUNNING or STOPPED is only a census filter, while
every described task whose lastStatus is not STOPPED remains live. Every live service
task-definition must expose the same canonical legacy JWT/QR baseline; zero or multiple
live baselines fail closed. Incomplete
task/deployment/task-definition reads also
fail closed.

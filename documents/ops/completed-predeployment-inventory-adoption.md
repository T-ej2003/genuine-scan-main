# Completed pre-deployment inventory adoption

The ccf3013 rotation inventory completed before the operator discovered that its
CLI-selected runtime config (`b7badc52…`) pointed `rotationConfigFile` at the
original bootstrap config (`498fbc19…`). The original DynamoDB claim is
`succeeded`; inventory task revision `:9` exited zero. The rotation state and
overlap readiness evidence were never written. Running the broker again would
attempt a second inventory operation and is prohibited.

The operator now compares the selected config path, its actual SHA-256, the
embedded `rotationConfigFile`, and the preparation manifest before asking for
MFA. Regenerate a **new** private runtime directory with the existing bootstrap
inputs, the authenticated Stage-A endpoint and runtime security-group IDs, and
`--adopt-completed-inventory true`. The bootstrap must report
`readyToConsumeMfa: true`; preserve the old directory and its signed evidence.
The new config carries `completedInventoryAdoptionRequired: true`, which makes
both operator preflight and the inventory adapter stop if the adoption proof is
missing. Never hand-edit the generated config or its hash.

Before MFA, run `scripts/aws/prepare-completed-inventory-adoption.mjs` with the
exact paths and SHA-256 values for `--original-config`,
`--original-config-sha256`, `--continuation-config`,
`--continuation-config-sha256`, `--original-recovery-evidence`,
`--original-recovery-evidence-sha256`, `--original-approval`, and
`--original-approval-sha256`. The original config is the b7badc52… file used
by the completed inventory request. This producer reads the live claim, ECS
task and definition, and bounded inventory log using the existing root reader;
it verifies the historical KMS approval and absent-claim recovery proof at
the original execution time. The independent checker signs a short-lived
adoption proof in the **new** runtime directory. Repeating the producer while
the proof is valid authenticates and reuses it. It never resets the claim or
invokes the inventory broker.

Only after the new runtime manifest and adoption proof are authenticated
should the emitted `stage-b:run-cutover-operator -- --mode prepare-overlap`
command be used. The adapter re-verifies the proof signature and exact task
definition and returns the original inventory to the existing rotation
preparation and readiness producers with zero inventory mutations. Any missing,
expired, cross-source, cross-rotation, or conflicting proof fails closed.
Protected-main source and separate production approvals still apply. If the
live claim has disappeared under DynamoDB TTL before it can be authenticated,
stop; the private readback snapshot is investigative evidence, not a substitute
authorization or a replay permit.

Restart checks: a crash before the adoption proof is written leaves the marker
without proof, so operator preflight blocks before MFA. A crash after the
exclusive proof write permits the producer to authenticate and reuse that exact
proof; it does not sign a replacement in the same directory. A restart after
inventory adoption reads the same proof and performs no registration, broker
invoke, or inventory RunTask. The existing rotation coordinator's crash-safe
state/fixture handling takes over once preparation begins. A proof that has
expired requires a new private runtime preparation and independent check; the
old proof is never overwritten.

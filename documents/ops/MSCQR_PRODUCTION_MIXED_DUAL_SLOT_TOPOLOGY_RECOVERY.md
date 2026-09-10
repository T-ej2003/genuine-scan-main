# Production mixed dual-slot topology recovery

This is a one-time recovery bridge for the immutable seven-slot predecessor
identified by `PRODUCTION_MIXED_DUAL_SLOT_TOPOLOGY_RECOVERY`. It is not a
rotation, adoption, rebaseline, or a general migration interface.

The bridge admits each reviewed `AWSCURRENT` identity and its one exact retained
`AWSPREVIOUS` identity across all seven secret ARNs. Version, stage,
envelope-hash, schema, source-presence, rotation, slot, fingerprint, and
key-version differences fail before mutation; arbitrary retained history is
not accepted.

Recovery removes `AWSCURRENT` from those seven unused rotation-slot versions
only. It does not write, delete, or expose secret values; it does not touch
the legacy secrets selected by `mscqr-backend:52`; and it never promotes the
historical pending material. The seven reviewed versions become unlabelled;
the seven older authenticated versions retain `AWSPREVIOUS` unchanged.

The resulting state is the existing initial bootstrap's admissible predecessor.
The bootstrap then creates its ordinary source-bound seven fresh
values. Recovery retries may continue only from an exact contiguous prefix of
the seven authenticated label removals; any other partial topology fails
closed. Preparation, authorization, and execution remain separate operations.

Preparation is read-only and writes one private preparation file. Authorization
is produced only by `authorize-production-mixed-dual-slot-topology-recovery.yml`
after the protected `production` environment reviewer approves the exact file
hash. Before that approval is requested, preparation requires an administrator
IAM simulation proving that `mscqr-production-release-deployer` can perform
`UpdateSecretVersionStage` on all seven exact ARNs, and readback proving each
exact secret has no resource policy that could override that identity result.
The administrator signs that exact preflight with the root-attestation KMS key;
the preparation command emits the signature as a separate private sidecar. An
unprotected workflow job verifies the signature with the protected-source-pinned
public key and authenticates the fresh, source-bound seven-result preflight before
the protected
authorization job becomes eligible; deny, indeterminate, wrong-principal,
permissions-boundary, missing, or substituted results fail closed. Execution is available only through
`execute-production-mixed-dual-slot-topology-recovery.yml` on protected main;
that job reauthenticates the authorization artifact, source, :52 predecessor,
all fourteen payload identities, and the exact contiguous prefix before and
after
every `UpdateSecretVersionStage` call. Its inline AWS session policy allows
only readback plus that mutation against the seven exact ARNs—never create,
delete, or value-write APIs.

The base capability is owned by the existing
`MSCQRProductionInitialActivationLifecycle` managed policy and remains attached
only to the release-deployer role. Its exact source statement and the execution
workflow's inline session policy must both allow the action; the session policy
is a restriction and cannot grant a missing base-role capability.

A fresh approval is required to start at 0/7. If execution is interrupted, the
same exact authorization may resume an authenticated 1/7 through 6/7 prefix.
If protected main advances, a new preparation and approval bind the observed
exact prefix and maximum remaining mutations; execution cannot regress behind
that prepared prefix. Non-contiguous or altered state is rejected. At 7/7,
replay is classified as complete and performs no mutation. The bootstrap
accepts T1 because no slot has an `AWSCURRENT` value and every retained
`AWSPREVIOUS` identity is the exact reviewed one. It still generates and writes
all fresh source-bound T2 material itself, and its live-origin verification
requires those same retained identities beside the new `AWSCURRENT` versions.
The recovery neither creates nor promotes cryptographic
material and is not a general migration API.

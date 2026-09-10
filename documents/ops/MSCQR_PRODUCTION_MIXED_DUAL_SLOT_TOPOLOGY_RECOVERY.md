# Production mixed dual-slot topology recovery

This is a one-time recovery bridge for the immutable seven-slot predecessor
identified by `PRODUCTION_MIXED_DUAL_SLOT_TOPOLOGY_RECOVERY`. It is not a
rotation, adoption, rebaseline, or a general migration interface.

The bridge admits all seven exact secret ARN, version, stage, envelope-hash,
schema, source-presence, rotation, slot, fingerprint, and key-version
identities. Any difference fails before mutation.

Recovery removes `AWSCURRENT` from those seven unused rotation-slot versions
only. It does not write, delete, or expose secret values; it does not touch
the legacy secrets selected by `mscqr-backend:52`; and it never promotes the
historical pending material. All seven historical versions remain available
without staging labels.

The resulting state is the existing initial bootstrap's admissible predecessor.
The unmodified bootstrap then creates its ordinary source-bound seven fresh
values. Recovery retries may continue only from an exact contiguous prefix of
the seven authenticated label removals; any other partial topology fails
closed. Preparation, authorization, and execution remain separate operations.

Preparation is read-only and writes one private preparation file. Authorization
is produced only by `authorize-production-mixed-dual-slot-topology-recovery.yml`
after the protected `production` environment reviewer approves the exact file
hash. Execution is available only through
`execute-production-mixed-dual-slot-topology-recovery.yml` on protected main;
that job reauthenticates the authorization artifact, source, :52 predecessor,
all seven payload identities, and the exact contiguous prefix before and after
every `UpdateSecretVersionStage` call. Its inline AWS session policy allows
only readback plus that mutation against the seven exact ARNs—never create,
delete, or value-write APIs.

A fresh approval is required to start at 0/7. If execution is interrupted, the
same exact authorization may resume an authenticated 1/7 through 6/7 prefix.
If protected main advances, a new preparation and approval bind the observed
exact prefix and maximum remaining mutations; execution cannot regress behind
that prepared prefix. Non-contiguous or altered state is rejected. At 7/7,
replay is classified as complete and performs no mutation. The bootstrap
accepts T1 because no slot has an `AWSCURRENT` value; it still generates and
writes all fresh source-bound T2
material itself. The recovery neither creates nor promotes cryptographic
material and is not a general migration API.

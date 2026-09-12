# Production mixed dual-slot topology recovery

This is a one-time recovery bridge for the immutable seven-slot predecessor
identified by `PRODUCTION_MIXED_DUAL_SLOT_TOPOLOGY_RECOVERY`. It is not a
rotation, adoption, rebaseline, or a general migration interface.

The bridge admits each reviewed `AWSCURRENT` identity and its one exact retained
`AWSPREVIOUS` identity across all seven secret ARNs. Version, stage,
envelope-hash, schema, source-presence, rotation, slot, fingerprint, and
key-version differences fail before mutation; arbitrary retained history is
not accepted.

AWS cannot leave a secret without `AWSCURRENT`. Recovery therefore performs
one exact `UpdateSecretVersionStage` move per slot: it moves `AWSCURRENT` from
the reviewed current version to the one reviewed retained version. AWS then
automatically moves `AWSPREVIOUS` to the former current version. The exact
from/to identities and both before/after stage sets are preparation- and
authorization-bound for every slot. It does not write, delete, or expose
secret values and does not touch the legacy secrets selected by
`mscqr-backend:52`.

The resulting state is the existing initial bootstrap's admissible predecessor.
The bootstrap then creates its ordinary source-bound seven fresh
values. Recovery retries may continue only from an exact contiguous prefix of
the seven authenticated AWS label swaps; any other partial topology fails
closed. Preparation, authorization, and execution remain separate operations.

Preparation is read-only and writes one private preparation file. Authorization
is produced only by `authorize-production-mixed-dual-slot-topology-recovery.yml`
after the protected `production` environment reviewer approves the exact file
hash. Before that approval is requested, preparation requires an administrator
IAM simulation proving that the dedicated
`mscqr-production-mixed-dual-slot-recovery-executor` has its exact source trust,
the live GitHub OIDC provider retains the exact URL and STS audience, and the
live `production-mixed-dual-slot-recovery` environment exists with no protection
rules and exactly one custom deployment branch policy for `main`. The same
environment check runs before the Terraform installation plan and again before
its apply, so an absent, auto-created, tag-enabled, or otherwise broadened
environment cannot install or satisfy the role trust. The preflight also proves
the role can perform its STS identity read, both ECS predecessor reads, and all
`DescribeSecret`, `GetSecretValue`, and `UpdateSecretVersionStage` calls on the
seven exact ARNs. Readback also proves each exact secret has no resource policy
that could override those identity results and still uses the AWS-managed
Secrets Manager encryption key; a customer-managed key fails closed because
the executor has no reviewed `kms:Decrypt` grant. An independent Organizations
read proves the production account has no applicable SCP layer. An account in
an Organization, an unreadable Organizations state, or any SCP ambiguity fails
before protected approval because role policy simulation cannot prove SCPs.
The administrator signs that exact preflight with the root-attestation KMS key;
the preparation command emits the signature as a separate private sidecar. An
unprotected workflow job verifies the signature with the protected-source-pinned
public key and authenticates the fresh, source-bound 24-result preflight plus
the seven exact encryption guards before
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

The base capability is owned by the Terraform-managed
`MSCQRProductionMixedDualSlotRecoveryExecutor` policy, attached only to the
dedicated executor role. The shared release-deployer lifecycle policy explicitly
denies this mutation. The dedicated base policy and the execution workflow's
inline session policy must both allow the exact seven-resource action; the
session policy remains a restriction and cannot grant a missing base-role
capability. The existing protected reconciler installation transaction creates
and verifies the dedicated role, policy, and attachment before recovery approval.

A fresh approval is required to start at 0/7. If execution is interrupted, the
same exact authorization may resume an authenticated 1/7 through 6/7 prefix.
If protected main advances, a new preparation and approval bind the observed
exact prefix and maximum remaining mutations; execution cannot regress behind
that prepared prefix. Non-contiguous or altered state is rejected. At 7/7,
replay is classified as complete and performs no mutation. The bootstrap
accepts T1 only when each slot has the exact AWS-legal swap: the retained
reviewed version is `AWSCURRENT` and the former current version is
`AWSPREVIOUS`. It then writes all fresh source-bound T2 material itself; AWS
moves `AWSPREVIOUS` to the T1 current version as part of those ordinary writes.
Its live-origin verification binds both the recovery handoff and the retained
history. The recovery neither creates nor alters cryptographic material and is
not a general migration API.

# MSCQR Stage-A root-drop orphan recovery

This contract covers both the external-orphan `0/0` topology and the
partial-recovery `1/0` topology where Terraform already owns the exact
`aws_kms_key.root_drop`, its alias is absent, and provider-computed ARN fields
may still be unset before a successful refresh.

## Read-only census (schema version 4; Stage-A identity version 2)

`npm run stage-a:root-drop:census` is the only producer. It paginates the
current KMS key, alias, and CloudTrail result sets, then reads the exact
production key metadata, tags, key policy, public-key identity, aliases, and
the CloudTrail `CreateKey` event. It is hard-bound to `eu-west-2`; any other
region is rejected before an AWS query. Current KMS state determines the
candidate universe; the failed-apply window authenticates provenance but never
filters an older potentially relevant key out of the census. Such a key, or a
candidate with missing history, is ambiguous and blocks creation. The result
binds to the fresh Stage-A state identity, source SHA, transition ID, failed-
plan SHA, creator session, observation time, and census digest. Tags alone
never authenticate a candidate.

Current Stage-A state identity uses semantic canonicalization, not raw JSON
serialization bytes. Object keys are serialized deterministically; only the
top-level `check_results` collection is canonicalized as unordered, using the
unique `(object_kind, config_addr)` key for each entry. Resource, instance,
attribute, dependency, output, and nested-array order remains significant.
An absent `check_results`, `check_results: null`, and `check_results: []` are
preserved as three distinct states; only array entries are sorted. Malformed
types and malformed or duplicate check-result keys fail closed. The identity
version is bound into prerequisite, census, and downstream evidence artifacts, so older
raw-byte identities are not silently reinterpreted. The historical failed-
apply state hash in `ROOT_DROP_LEGACY_POLICY_BINDING` remains immutable
provenance evidence and is not converted to the current identity format.

Authenticated Stage-A state bytes are decoded with fatal UTF-8 before any
numeric precision check or JSON parsing; malformed byte sequences fail closed.
A numeric literal is accepted only when its normalized decimal
value round-trips through the runtime number representation; literals that
would collapse to a different value (for example `9007199254740993` after
rounding to `9007199254740992`) fail closed. Equivalent spellings such as
`1`, `1.0`, and `1e0` share one identity, as do `0` and `-0`. Every
Stage-A state identity producer and consumer uses this parser; no ordinary
lossy JSON parse is valid at the authenticated state boundary.

For the single historical legacy-policy recovery, the census command also
requires `--failed-apply-state-identity` pointing to the private, independently
captured pre-apply Stage-A state identity. That lineage, serial, and state hash
must exactly match the historical binding; the current live state identity is
validated separately and cannot substitute for it.

The census uses the approved split-actor boundary: administrator/root performs
account-wide `kms:ListKeys` and coarse `kms:DescribeKey` discovery plus
`cloudtrail:LookupEvents` provenance reads; `mscqr-production-release-deployer`
performs only the scoped tags, key-policy, public-key, and alias reads for
metadata that is not provably irrelevant, followed by Terraform operations.
The census records these actor-domain bindings; neither identity is
substituted for the other. Existing STS preflight evidence authenticates the
selected profiles; the census digest does not claim to be a digital signature.

Coarse metadata may exclude a key only when it proves that the key cannot be
the exact customer-managed, single-region RSA_3072/SIGN_VERIFY AWS_KMS
root-drop key (for example an AWS-managed key, a different key spec/usage, or
an explicit account/region/origin mismatch). A release read failure on any
remaining key fails closed; it is never converted into `NO_CANDIDATE`.

The census is valid only as one of:

- `NO_CANDIDATE`: the fresh 0/0 Terraform state may use the normal exact
  two-create plan;
- `AUTHENTICATED_ORPHAN`: exactly one key passes every identity and event
  check and is eligible for adoption or exact key-only continuation. In the
  `1/0` topology, Terraform ownership is bound by the exact state resource ID;
  a missing computed ARN is not treated as a different key, while any present
  non-matching ARN still fails closed;
- `AMBIGUOUS`: creation is blocked.

The census captures each potentially relevant key's complete security snapshot
twice, including metadata, tags, policy, public-key identity, aliases, and
provenance. Any snapshot change fails closed as `CENSUS_UNSTABLE`; key-ID
universe equality alone is insufficient. The two universe enumerations and
the two candidate snapshots are bounded consistency checks, not a claim that
AWS eventual consistency is transactional.

The temporary-capability authorization command must receive the fresh census.
At the authorization boundary it performs a new read-only census through the
same producer and compares the candidate result with the supplied artifact.
Thus a replayed `NO_CANDIDATE` census cannot authorize after a key appears;
newly created candidates are included even when they fall outside the old
failed-apply window. An authenticated or ambiguous candidate makes `CreateKey`
fail closed before Terraform apply. For the exact authenticated historical
`1/0` topology, authorization occurs before provider refresh and installs the
exact-key `kms:GetKeyRotationStatus` capability required by the locked
provider; no steady-state IAM permission is broadened. Any other partial
Terraform state fails closed.

## Adoption

`npm run stage-a:root-drop:adopt` with explicit `--execute` authorization
performs a fresh read-only census through the same producer immediately before
any import. The supplied census and fresh observation must match on candidate,
state, source, transition, region, and policy/tag/alias identity; the fresh
observation is also bounded in age. Only then does it import exactly
`aws_kms_key.root_drop` using the locked AWS provider's documented key-ID
identifier. Without `--execute`, an absent Terraform key is not imported.
The adoption command consumes the same reviewed Stage-A variable environment as
the normal production plan: only the nine required `TF_VAR_*` inputs declared
by `infra/aws/terraform/production-green-stage-a/variables.tf` are accepted;
all other `TF_VAR_*` and Terraform redirect variables are rejected or removed.
For the normal 0/0 path, the refresh-enabled, non-mutating Terraform plan is
saved, shown as JSON, and classified before import; only the exact root-drop
key and alias create envelope is accepted. For the authenticated historical
1/0 path, the provider boundary is different and explicit: after temporary
authorization, an exact already-refreshed key instance marked `tainted` is
first reconciled with `terraform untaint -lock=true aws_kms_key.root_drop`.
That state-only command is allowed only for the authenticated 1/0 key/provider
identity; its post-state must advance the serial once and differ only by
removal of that marker. It performs no AWS resource write and is recorded as
one Terraform state write. Then `terraform plan -refresh-only -out <refresh-only-plan>` is
saved, shown as JSON, classified as the exact root-drop computed-identity
transition plus, when present, only the exact provider-computed forward
`aws_db_instance.green.latest_restorable_time` UTC timestamp transition,
byte-revalidated immediately before `terraform apply` of that
saved refresh-only plan, and then `terraform state pull` must observe the
persisted result. This is `AWS_RESOURCE_MUTATIONS=0` but an expected
`TERRAFORM_STATE_WRITES=1`; it is not an ordinary infrastructure apply.
The refreshed state lineage, backend, workspace, exact key properties, 1/0
topology, and unrelated state values are revalidated against the pre-refresh
identity. The RDS exception is valid only for the exact managed green database,
an update with no replacement or unknown values, strict forward RFC3339 UTC
timestamps, and no other attribute difference; it never authorizes a
configuration-driven `resource_changes` entry. The authenticated historical
pre-refresh instance has `identity_schema_version = 0` and `identity = null`;
the refreshed instance must retain schema version zero and replace only that
null identity with the exact provider identity below. The provider may advance
serial/state bytes only while populating the exact root-drop ARN/key ID, the
AWS provider v6.56.0 instance identity
`{ account_id: "368992683803", id: <authenticated-key-id>, region: "eu-west-2" }`,
and, when observed, that exact RDS computed timestamp. Missing, substituted,
or extended root-drop identity metadata fails closed. The resulting
post-refresh state identity is then bound to the new recovery plan and all
subsequent checks.

The same saved refresh-only boundary handles one completed `1/1` post-apply
representation: after Terraform already owns
`aws_vpc_security_group_ingress_rule.runtime_endpoints_https[<runtime-sg>]`,
the AWS provider may add its exact TCP/443 SG-source representation to the
computed `ingress` set on `aws_security_group.executor_endpoints`. The operator
must supply `--endpoint-security-group-id` and `--runtime-security-group-id`.
Terraform 1.15.8 omits `resource_changes` from this refresh-only JSON when
there are zero configuration actions; an explicit array is therefore not
required, but `null`, malformed, incomplete, errored, or non-applyable plans
remain rejected.
The classifier authenticates those IDs against the raw Stage-A state, the
standalone rule ID/provider identity, account, region, and the parent SG's
pre-refresh attributes. It then permits only the single matching ingress-set
addition, with no CIDR, IPv6, prefix-list, self, egress, tag, description,
VPC, replacement, resource action, or unrelated drift. The saved resource
plan is never replayed; only the separately generated and byte-revalidated
refresh-only plan can advance the state serial once.

Auto-loaded `terraform.tfvars` and `*.auto.tfvars` files are rejected so the reviewed inputs remain authoritative. The executing
checkout must have a clean execution-relevant tree and its exact `HEAD` must
equal the census `sourceSha`; for the exact historical legacy-policy binding,
the command additionally requires `--execution-source-sha` and binds the
clean execution checkout to that current source while retaining the historical
census source binding. The pre-import classifier also proves that the
alias expression targets `aws_kms_key.root_drop.key_id`. Any failure after a
mutation is emitted at the CLI boundary with deterministic recovery accounting.
After an authorized import it refreshes state, proves the imported key
ARN/spec/usage, and requires a plan containing only:

```text
+ aws_kms_alias.root_drop
```

The one historically authenticated Stage-A failed apply bound to the merged
source, transition, recorded plan SHA, CreateKey event, key ARN, and pre-apply
state identity may contain the predecessor root-drop policy that lacks only
`kms:GetKeyRotationStatus`. That exact legacy policy is not accepted as a
steady-state result: the adoption plan must contain only its update to the
current canonical policy plus the exact root-drop alias create, and the
post-apply state must contain the canonical policy before recovery is
reported complete. Any other policy difference, binding, address, or action
fails closed. The historical two-create binary plan is stale, non-executable,
and never applied; its recorded SHA is provenance only. Historical plan JSON
is not required for this exact legacy 1/0 authorization because the current
candidate, state, policy, metadata, stable census, CloudTrail, and failed-apply
bindings authenticate the existing partial mutation independently. The fresh
post-authorization recovery plan is the only plan eligible for classification
or apply. Its `resource_drift` is independently classified and may contain only
the same exact forward green-database timestamp transition; any other provider
drift blocks apply and zero-drift completion. The existing temporary Stage-A capability
grants only `kms:GetKeyRotationStatus`, `kms:PutKeyPolicy`, and
`kms:CreateAlias` for the exact authenticated orphan key (plus the exact alias
resource), and is the only approved mutation path for this convergence.

The alias is created only by the exact saved Terraform plan and must target the
authenticated key. Key creation, replacement, destroy, unrelated actions,
alias retargeting, ambiguous import/apply outcomes, and non-zero drift fail
closed. The command requires `--execute` before the alias-only apply; this
repair never runs that command against production.

Import replay reads current state first and never retries an ambiguous import.
Recovery accounting records Terraform imports, ordinary Terraform applies,
refresh-only Terraform applies, exact untaint/state writes, KMS writes, IAM writes, unknown
mutations, and unclassified mutations. The refresh-only state write is not an
AWS resource mutation and is never counted as a KMS/IAM write. No destructive
KMS action, permanent release-role administration, lockout bypass, or manual
alias operation is part of recovery.

The provider contract was verified against AWS provider v6.56.0: the key import
identifier is the KMS key ID, and the alias import identifier would be
`alias/mscqr-production-root-drop`; the recovery path does not import the
absent alias.

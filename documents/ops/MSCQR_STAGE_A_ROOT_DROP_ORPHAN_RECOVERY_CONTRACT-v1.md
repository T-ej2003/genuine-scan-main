# MSCQR Stage-A root-drop orphan recovery

This contract covers the partial apply where `aws_kms_key.root_drop` exists in
AWS but Terraform does not own it and `aws_kms_alias.root_drop` is absent.

## Read-only census

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

The census is valid only as one of:

- `NO_CANDIDATE`: the fresh 0/0 Terraform state may use the normal exact
  two-create plan;
- `AUTHENTICATED_ORPHAN`: exactly one key passes every identity and event
  check and is eligible for adoption;
- `AMBIGUOUS`: creation is blocked.

The temporary-capability authorization command must receive the fresh census.
At the authorization boundary it performs a new read-only census through the
same producer and compares the candidate result with the supplied artifact.
Thus a replayed `NO_CANDIDATE` census cannot authorize after a key appears;
newly created candidates are included even when they fall outside the old
failed-apply window. An authenticated or ambiguous candidate makes `CreateKey`
fail closed before Terraform apply. A partial Terraform state also fails
closed.

## Adoption

`npm run stage-a:root-drop:adopt` with explicit `--execute` authorization
performs a fresh read-only census through the same producer immediately before
any import. The supplied census and fresh observation must match on candidate,
state, source, transition, region, and policy/tag/alias identity; the fresh
observation is also bounded in age. Only then does it import exactly
`aws_kms_key.root_drop` using the locked AWS provider's documented key-ID
identifier. Without `--execute`, an absent Terraform key is not imported.
After an authorized import it refreshes state, proves the imported key
ARN/spec/usage, and requires a plan containing only:

```text
+ aws_kms_alias.root_drop
```

The alias is created only by the exact saved Terraform plan and must target the
authenticated key. Key creation, replacement, destroy, unrelated actions,
alias retargeting, ambiguous import/apply outcomes, and non-zero drift fail
closed. The command requires `--execute` before the alias-only apply; this
repair never runs that command against production.

Import replay reads current state first and never retries an ambiguous import.
Recovery accounting records Terraform imports, Terraform applies, KMS writes,
IAM writes, unknown mutations, and unclassified mutations. No destructive KMS
action, permanent release-role administration, lockout bypass, or manual alias
operation is part of recovery.

The provider contract was verified against AWS provider v6.56.0: the key import
identifier is the KMS key ID, and the alias import identifier would be
`alias/mscqr-production-root-drop`; the recovery path does not import the
absent alias.

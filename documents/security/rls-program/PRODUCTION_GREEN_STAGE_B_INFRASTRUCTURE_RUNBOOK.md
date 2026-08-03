# Production Green Stage B infrastructure runbook

1. Obtain an MFA-backed non-root production release-deployer session and generate one private backend config with `npm run stage-b:generate-backend-config -- --output <absolute-private-path>`. Initialise the dedicated encrypted S3 backend with that exact direct production-state key, `use_lockfile=true`, and `TF_WORKSPACE=default`; do not list workspaces or access the legacy base key. The Terraform `deployment_environment` variable remains `production`. Signed immutable image provenance is valid for 24 hours after administrator observation/signing when its release, workflow, artifact, authoritative per-repository `DescribeRepositories` immutability evidence, digest, account/region, KMS, and `time-bounded-no-supersession-registry` capability joins remain exact. Immediate revocation is not supported until a separately authenticated supersession registry exists. Permission preflight and the plan-bound reference audit retain independent 15-minute live-evidence windows.
2. Confirm Stage A owns and has applied the executor/database security groups, exact database/interface-endpoint/S3/DNS rules, executor/broker log groups, executor/broker roles, approval resources, and runtime-secret ARNs. Write one explicit reviewed prerequisite file matching `infra/aws/terraform/production-green-stage-b/stage-a-prerequisites.schema.json`; do not copy values into tfvars by hand.
3. Build the reviewed broker package with `node scripts/aws/package-production-green-stage-b-broker.mjs`, then run only `npm run stage-b:generate-tfvars -- ...` with the signed image evidence, state backup, prerequisite file, broker ZIP, exact tooling/image identities, and private output paths. The generator derives package/source/migration checksums and retained definitions, verifies every image digest byte-for-byte, emits the binding report, and commits tfvars/report as one mode-0600 pair. Plan, closure, verify-only, and apply require the complete canonical tfvars provenance; each binding gate rereads the current broker ZIP bytes, and the apply path repeats that check immediately before Terraform.
4. Run the plan wrapper. Approve only create/update operations for Stage B task definitions, roles/policies, candidate log groups, replay table, broker/numbered version/reviewed alias, and the alias-qualified Lambda permission. Reject all destroys and all service, traffic, database, secret-value, security-group, or tagged-image changes.
5. After explicit change approval, apply the reviewed saved plan. Verify task-definition revisions, role ARNs, Stage A log/SG bindings, replay table, numeric broker version and `reviewed` alias, secret references by ARN only, and exact image digests. Do not run a task or update a service.
6. Infrastructure rollback is limited to a separately reviewed Terraform change that removes only unused Stage B control-plane resources; never destroy a live task definition, secret, database, or service as rollback.

## Plan-bound reference audit

Generate the audit only from the exact `terraform show -json` output for the plan
being validated. The generator performs read-only ECS and Lambda calls, enforces the
exact twelve source-controlled task-definition families, and fails closed on missing
families, unknown families, old service/task/broker references, malformed responses,
or package and plan-hash mismatches. Audits expire after 15 minutes; timestamps more
than 60 seconds in the future are rejected. Generate the audit immediately after the
final plan and never reuse it after expiry. ECS service descriptions run in batches of
10 and task descriptions in batches of 100. Every describe response must contain valid
`services`/`tasks` and `failures` arrays, with no failures and an exact ARN set match
to the preceding list response. Never reuse an audit from another plan or release.
The plan classifies task definitions with an existing `before.arn` as rollover or no-op
families; create-only families are recorded explicitly and are not sent to
`DescribeTaskDefinition`. No-op families are observed but are not treated as replacements.
Any unexpected prior ARN or live service, task, or broker reference for a create-only
family fails closed; rollover-family reference checks remain unchanged.

Retained history is validated per immutable generation key. Before the first successful
read-only-canary creation, every retained generation contains exactly the eleven existing
families; multiple complete eleven-family generations are valid. After read-only-canary
exists, each newly rotated generation contains all twelve families, while older
eleven-family generations remain preserved and valid.

An initial broker Lambda create is validated entirely from the plan and Terraform
configuration; it has no live reference audit requirement. Every non-no-op broker
Lambda update requires a fresh, plan-bound reference audit. The
full-RLS release checksum is `var.package_checksum_sha256`, which must flow through
`local.broker_approval_expected.packageChecksumSha256` into the broker environment.
The independently built ZIP is `var.broker_package_path`; its raw SHA-256 and
base64 `source_code_hash` are proved separately. These two artifact digests are
different contract values and must not be equal. If the live release checksum is
older, the audit records `plannedAtomicPackageChecksumTransition` only when the same
exact plan updates it from the broker plan `before` value to the release checksum,
replaces the ZIP, and binds all evidence to the exact plan SHA. Missing, stale,
incomplete, or mismatched broker evidence fails closed.

```sh
node scripts/aws/generate-production-green-stage-b-reference-audit.mjs \
  --plan-json /absolute/private/production-green-stage-b.plan.json \
  --plan-sha256 "$PLAN_JSON_SHA256" \
  --output /absolute/private/production-green-stage-b-reference-audit.json \
  --region eu-west-2 \
  --cluster-arn arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main \
  --expected-package-checksum-sha256 "$PACKAGE_CHECKSUM_SHA256"
```

The reference-audit generator derives the broker identity from the shared
`STAGE_B.brokerAliasArn` contract. Do not pass or reconstruct a broker ARN in
the operator command; the required identity is the qualified `reviewed` alias.
This is a permanent invariant: executable Stage B consumers import the shared
contract, and no wrapper, helper, validator, or test may construct, strip, or
accept an alternate broker function or alias ARN.

When `GetFunctionConfiguration` is queried through `reviewed`, AWS may return the
canonical alias-qualified `FunctionArn`. The audit records the base function ARN,
stable alias ARN, and resolved numeric version ARN separately. It accepts the
unqualified base ARN, a matching numeric version ARN, or the exact reviewed alias
ARN only when an independent `GetAlias` read proves `AliasArn`, alias name, and
`FunctionVersion` match the configuration version. Other qualifiers remain
invalid.

Bind both SHA-256 values when invoking `scripts/plan-production-green-stage-b.mjs`.
The generator and validator accept only these families: backend candidate, worker
candidate, application canary, read-only canary, and the eight fixed full-RLS
executor families (`admin-bootstrap`, `admin-ownership`, `capability-preflight`,
`role-provision`, `role-verify`, `rollback`, `runtime-policy`, and `verification`).

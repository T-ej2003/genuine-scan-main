# Production Green Stage B infrastructure runbook

1. Obtain an MFA-backed non-root production release-deployer session and initialise the dedicated encrypted S3 backend with `use_lockfile=true`; select workspace `production`.
2. Confirm Stage A owns and has applied the executor/database security groups, exact database/interface-endpoint/S3/DNS rules, executor/broker log groups, executor/broker roles, approval resources, and runtime-secret ARNs. Copy only its `stage_b_prerequisites` names/ARNs/IDs into the untracked tfvars file; Stage B must not recreate or import them.
3. Build the reviewed broker package with `node scripts/aws/package-production-green-stage-b-broker.mjs`. Put its absolute path plus the Stage A bindings, release/package digests, and approved image digests in the private tfvars file. Set `stage_a_executor_networking_ready=true` only from reviewed Stage A evidence.
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
  --broker-function arn:aws:lambda:eu-west-2:368992683803:function:mscqr-production-rls-approval-broker:reviewed \
  --expected-package-checksum-sha256 "$PACKAGE_CHECKSUM_SHA256"
```

Bind both SHA-256 values when invoking `scripts/plan-production-green-stage-b.mjs`.
The generator and validator accept only these families: backend candidate, worker
candidate, application canary, read-only canary, and the eight fixed full-RLS
executor families (`admin-bootstrap`, `admin-ownership`, `capability-preflight`,
`role-provision`, `role-verify`, `rollback`, `runtime-policy`, and `verification`).

# Production Green Stage B infrastructure runbook

## Credential and evidence timing contract

The bootstrap MFA session is requested with `aws sts get-session-token --duration-seconds 129600` (36 hours). The bootstrap operator then requests the release session with `aws sts assume-role --duration-seconds 3600` (one hour). A fresh release session is required at each final release boundary. The root administrator `aws login --profile default` session is externally controlled; never assume its lifetime, and run `aws sts get-caller-identity --output json --no-cli-pager` immediately before each administrator phase. `ExpiredToken` and any caller mismatch stop the phase. Codex child processes inherit only the verified parent shell environment and must not persist credentials or session-token values.

Deployment-bound evidence remains valid only while its exact bindings remain unchanged and its age is below `3600` seconds. Evidence freshness does not extend AWS credentials, and valid AWS credentials do not replace evidence freshness. Image evidence retains its separate 24-hour contract; normal application-user sessions and MFA/browser challenges are unchanged. Saved-plan validity remains binding-based rather than time-only.

## Administrator preflight producer lifecycle

Start exactly one administrator producer through the reviewed lifecycle launcher:

```bash
npm run stage-b:administrator-preflight -- \
  --output <absolute-private-report> \
  --signature-output <absolute-private-signature> \
  --lifecycle-directory <new-private-lifecycle-directory>
```

The launcher wraps `scripts/aws/run-production-green-stage-b-preflight.mjs`, captures
the exact PID, and persists private lifecycle metadata as `RUNNING`. It waits for that
PID before inspecting the report or signature. The producer timeout is `1200` seconds,
independent of the `3600`-second evidence TTL. A process that is active before the
deadline remains `RUNNING`; exit code zero plus a complete mode-0600 transactional pair
becomes `SUCCEEDED`; non-zero exit becomes `FAILED`; an active process at the deadline
is terminated through the reviewed shutdown path and becomes `TIMED_OUT`.

An empty output directory while lifecycle state is `RUNNING` is not a failure. A second
invocation while the recorded PID is active is rejected. Retry is permitted only after
the prior PID is terminal and requires an explicit retry request. Lifecycle metadata,
stdout, and stderr are private, atomic, and redacted; they never contain AWS
credentials, session tokens, policy bodies, or sensitive artifact contents. Lifecycle
state and evidence freshness are independent controls.

1. Obtain an MFA-backed non-root production release-deployer session and generate one private backend config with `npm run stage-b:generate-backend-config -- --output <absolute-private-path>`. Initialise the dedicated encrypted S3 backend with that exact direct production-state key, `use_lockfile=true`, and `TF_WORKSPACE=default`; this environment variable is the only workspace selector, so production commands may assert `terraform workspace show` but must never run `terraform workspace select`. Do not list workspaces or access the legacy base key. The Terraform `deployment_environment` variable remains `production`. Signed immutable image provenance is valid for 24 hours after administrator observation/signing when its release, workflow, artifact, authoritative per-repository `DescribeRepositories` immutability evidence, digest, account/region, KMS, and `time-bounded-no-supersession-registry` capability joins remain exact. Immediate revocation is not supported until a separately authenticated supersession registry exists. Administrator capability evidence, release-preflight capability evidence, and the plan-bound reference audit use a 60-minute live-evidence window (`3600` seconds) to cover the reviewed sequence. Hash, caller, policy, state-serial, workspace, reference, and plan bindings still invalidate evidence immediately; saved-plan validity is binding-based, not time-only. Move directly from permission signing to closure/apply rather than pausing for the full window.
2. Confirm Stage A owns and has applied the executor/database security groups, exact database/interface-endpoint/S3/DNS rules, executor/broker log groups, executor/broker roles, approval resources, and runtime-secret ARNs. Write one explicit reviewed prerequisite file matching `infra/aws/terraform/production-green-stage-b/stage-a-prerequisites.schema.json`; do not copy values into tfvars by hand.
3. Build the reviewed broker package with `node scripts/aws/package-production-green-stage-b-broker.mjs /absolute/private/broker.zip --tooling-sha "$TOOLING_SHA" --tooling-tree-sha256 "$TOOLING_TREE_SHA256"`. The packager performs locked production installation, emits the deterministic ZIP and adjacent `broker.zip.manifest.json` as one mode-0600 transaction, and fixes entry order, timestamps, modes, compression, lockfile/source/contract identities, and raw/base64 ZIP hashes. `base64Sha256` means `SHA256(Buffer.from(zipBytes.toString("base64")))` rendered as lowercase hex; it is distinct from the raw ZIP digest and from the tfvars binding report's existing base64-rendered raw digest. The shared validator applies the source-controlled schema, recomputes provenance, and checks every ZIP entry's path, order, timestamp, mode, compression, size, and extracted bytes before any binding is trusted. Then run only `npm run stage-b:generate-tfvars -- ...` with the signed image evidence, state backup, prerequisite file, broker ZIP, exact tooling/image identities, and private output paths. The canonical tfvars output must be HCL at a filename ending exactly in `.tfvars`; `.json` and `.tfvars.json` are rejected. The generator derives package/source/migration checksums and retained definitions, verifies every image digest byte-for-byte, records the canonical broker manifest path/SHA, records format/filename/extension in the binding report, and commits tfvars/report as one mode-0600 pair. Plan, refresh-only, closure, verify-only, and apply require the complete canonical tfvars provenance; each binding gate rereads the current broker ZIP and manifest bytes, and the apply path repeats that check immediately before Terraform.
4. Run the single reviewed refresh boundary with `npm run stage-b:refresh-only -- --closure-mode production ...`. It validates the canonical tfvars filename/content contract before Terraform and never writes a deployable plan. `--terraform-data-dir` is the sole Terraform data-directory authority; it is an external mode-0700 directory and its exact `<terraform-data-dir>/terraform.tfstate` metadata file is normalized by preflight to mode 0600 before `ready-for-plan`. Refresh, plan, closure, verify-only, and apply revalidate that same path, mode, and content binding; `--backend-metadata` must be exactly `<terraform-data-dir>/terraform.tfstate`, and the same private directory is passed as `TF_DATA_DIR` to workspace observation and refresh execution. Do not chmod failed artifacts or assemble raw `terraform plan -refresh-only` commands.
5. Capture exactly one deployment plan with `scripts/plan-production-green-stage-b.mjs` and write the binary plan, plan JSON, canonical plan JSON, and a private capture report with `state=PLAN_CAPTURED`. Capture validates the complete classification (`58` no-op, `12` create, `3` update, `0` destroy, `0` unclassified) but is not deployable.
6. Generate the reference audit from that exact plan JSON. Then run the planner's explicit approval phase with `--approval-only`; it performs no Terraform plan, re-hashes every captured artifact, validates the broker references, and writes `state=PLAN_APPROVED` with the logical canonical-plan hash. Only this approval state may proceed to plan-bound permission evidence, closure, verify-only, or apply.
7. Apply the reviewed saved plan only after explicit change approval. Verify task-definition revisions, role ARNs, Stage A log/SG bindings, replay table, numeric broker version and `reviewed` alias, secret references by ARN only, and exact image digests. Do not run a task or update a service.
8. Infrastructure rollback is limited to a separately reviewed Terraform change that removes only unused Stage B control-plane resources; never destroy a live task definition, secret, database, or service as rollback.

## Plan-bound reference audit

Generate the audit only from the exact `terraform show -json` output for the plan
being validated. The generator performs read-only ECS and Lambda calls, enforces the
exact twelve source-controlled task-definition families, and fails closed on missing
families, unknown families, old service/task/broker references, malformed responses,
or package and plan-hash mismatches. Audits expire after 60 minutes; timestamps more
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

Bind the saved-plan SHA, plan JSON SHA, canonical-plan file SHA, and logical canonical
JSON SHA in the capture and approval reports. Bind all four again when invoking
`scripts/plan-production-green-stage-b.mjs --approval-only`; the approval report is the
only planner evidence accepted by permission, closure, verify-only, and apply.
The generator and validator accept only these families: backend candidate, worker
candidate, application canary, read-only canary, and the eight fixed full-RLS
executor families (`admin-bootstrap`, `admin-ownership`, `capability-preflight`,
`role-provision`, `role-verify`, `rollback`, `runtime-policy`, and `verification`).

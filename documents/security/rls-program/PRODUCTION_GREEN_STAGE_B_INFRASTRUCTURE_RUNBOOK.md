# Production Green Stage B infrastructure runbook

## Credential and evidence timing contract

The bootstrap MFA session is requested with `aws sts get-session-token --duration-seconds 129600` (36 hours). The bootstrap operator then requests the release session with `aws sts assume-role --duration-seconds 3600` (one hour). A fresh release session is required at each final release boundary. The root administrator `aws login --profile default` session is externally controlled; never assume its lifetime, and run `aws sts get-caller-identity --output json --no-cli-pager` immediately before each administrator phase. `ExpiredToken` and any caller mismatch stop the phase. Codex child processes inherit only the verified parent shell environment and must not persist credentials or session-token values.

Deployment-bound evidence remains valid only while its exact bindings remain unchanged and its age is below `3600` seconds. Evidence freshness does not extend AWS credentials, and valid AWS credentials do not replace evidence freshness. Image evidence retains its separate 24-hour contract; normal application-user sessions and MFA/browser challenges are unchanged. Saved-plan validity remains binding-based rather than time-only.

## Administrator preflight producer lifecycle

Start exactly one initial administrator capability producer through the reviewed lifecycle launcher:

```bash
npm run stage-b:administrator-capability-preflight -- \
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

The initial report uses `evidenceKind=INITIAL_ADMIN_CAPABILITY` and `phase=initial`.
It proves baseline release-role authority only; it cannot authorize closure, verify-only,
or apply. After refresh, plan capture, reference audit, and `PLAN_APPROVED`, run the
separate plan-bound permission producer:

```bash
npm run stage-b:plan-bound-permission-preflight -- \
  --report-generator-caller-arn <root-caller> \
  --simulated-role-arn <release-role> \
  --plan-json <plan-json> \
  --canonical-plan-json <canonical-plan-json> \
  --saved-plan <saved-plan> \
  --plan-approval-report <approval-report> \
  --plan-approval-report-sha256 <approval-report-sha256> \
  --reference-audit <reference-audit> \
  --manifest <permission-manifest> \
  --expected-account 368992683803 \
  --expected-region eu-west-2 \
  --policy-published-at <iso-timestamp> \
  --cloudtrail-session-name <session-name> \
  --output <absolute-private-report> \
  --signature-output <absolute-private-signature> \
  --lifecycle-directory <new-private-lifecycle-directory>
```

This report uses `evidenceKind=PLAN_BOUND_PERMISSION` and `phase=plan-bound`; BASELINE
requires `--reference-audit`, and `PLAN_BOUND_PERMISSION` binds the exact reference-audit
artifact used by approval and completeness validation. It always requires `PLAN_APPROVED`
and binds the exact plan, refresh, audit, state, and identity artifacts. The two reports are
not substitutable. The base launcher requires an explicit
`--phase` and rejects ambiguous invocations.

Permission evidence has four distinct hash domains. `canonicalPayloadSha256` is the
immutable canonical JSON payload digest. `reportFileSha256` is the digest of the exact
mode-0600 report bytes. `signedBindingSha256` is the digest of the canonical,
domain-separated `MSCQR_STAGE_B_PERMISSION_EVIDENCE_V2` binding payload signed by KMS;
that payload contains signature schema/binding versions, evidence kind, phase, purpose,
both report hashes, protected account/region, key ARN, and signing algorithm.
`signatureFileSha256` is the digest of the exact published mode-0600 signature-envelope
bytes and is external lifecycle metadata, not part of the KMS message. The report never
embeds its own raw-file digest, the signature envelope is not signed, and legacy or
unknown signature schemas are rejected. The producer constructs and validates both files
in memory, publishes them only through the reviewed atomic pair writer, and lifecycle
recomputes `canonicalPayloadSha256`, `reportFileSha256`, `signedBindingSha256`, and
`signatureFileSha256` from the final files before `SUCCEEDED`.

The lifecycle launcher resolves and validates absolute output paths outside the
repository, rejects pre-existing or symlink outputs before spawning, and runs the
producer inside a new mode-0700 invocation-owned staging directory. Failure cleanup can
remove only that directory, identified by its private ownership token; it never unlinks
operator-owned final report or signature paths. A retry is permitted only after the
prior lifecycle is terminal and its owned staging paths are clear. Any report/signature
substitution, whitespace rewrite, partial pair, or temporary-file residue fails closed.

## Simulator context registry

The administrator permission producer keeps a complete, source-controlled simulator
context-key registry whose keys are the union of condition keys found in the reviewed
Stage B policy sources. The registry may contain reviewed candidate values for a key used
by several resource families, but a scalar candidate is never serialized as a multi-value
request entry. Operation-specific manifest context supplies the exact scalar for the
request when one exists; otherwise a multi-candidate scalar remains unbound and AWS
MissingContextValues is enforced rather than guessed. Forbidden evaluations use their
manifest context unchanged and retain the captured policy-wide FULL-14/PASSROLE-13
MissingContextValues sets. Unknown keys, wildcard values, missing registry entries,
duplicate entries, and invalid scalar cardinality fail before `SimulatePrincipalPolicy`
is called.

`iam:GetContextKeysForPrincipalPolicy` is an optional discovery-only completeness check.
It may return required key names, but it never supplies or synthesizes values. The
producer compares those names with the reviewed registry and fails closed on any
unrepresented key. AWS `MissingContextValues` responses remain enforcement failures;
they are not ignored or converted into defaults.

1. Obtain an MFA-backed non-root production release-deployer session and generate one private backend config with `npm run stage-b:generate-backend-config -- --output <absolute-private-path>`. Initialise the dedicated encrypted S3 backend with that exact direct production-state key, `use_lockfile=true`, and `TF_WORKSPACE=default`; this environment variable is the only workspace selector, so production commands may assert `terraform workspace show` but must never run `terraform workspace select`. Do not list workspaces or access the legacy base key. The Terraform `deployment_environment` variable remains `production`. Signed immutable image provenance is valid for 24 hours after administrator observation/signing when its release, workflow, artifact, authoritative per-repository `DescribeRepositories` immutability evidence, digest, account/region, KMS, and `time-bounded-no-supersession-registry` capability joins remain exact. Immediate revocation is not supported until a separately authenticated supersession registry exists. Administrator capability evidence, release-preflight capability evidence, and the plan-bound reference audit use a 60-minute live-evidence window (`3600` seconds) to cover the reviewed sequence. Hash, caller, policy, state-serial, workspace, reference, and plan bindings still invalidate evidence immediately; saved-plan validity is binding-based, not time-only. Move directly from permission signing to closure/apply rather than pausing for the full window.
2. Confirm Stage A owns and has applied the executor/database security groups, exact database/interface-endpoint/S3/DNS rules, executor/broker log groups, executor/broker roles, approval resources, and runtime-secret ARNs. Write one explicit reviewed prerequisite file matching `infra/aws/terraform/production-green-stage-b/stage-a-prerequisites.schema.json`; do not copy values into tfvars by hand.
3. Build the reviewed broker package with `node scripts/aws/package-production-green-stage-b-broker.mjs /absolute/private/broker.zip --tooling-sha "$TOOLING_SHA" --tooling-tree-sha256 "$TOOLING_TREE_SHA256"`. The packager performs locked production installation, emits the deterministic ZIP and adjacent `broker.zip.manifest.json` as one mode-0600 transaction, and fixes entry order, timestamps, modes, compression, lockfile/source/contract identities, and raw/base64 ZIP hashes. `base64Sha256` means `SHA256(Buffer.from(zipBytes.toString("base64")))` rendered as lowercase hex; it is distinct from the raw ZIP digest and from the tfvars binding report's existing base64-rendered raw digest. The shared validator applies the source-controlled schema, recomputes provenance, and checks every ZIP entry's path, order, timestamp, mode, compression, size, and extracted bytes before any binding is trusted. Then run only `npm run stage-b:generate-tfvars -- ...` with the signed image evidence, state backup, prerequisite file, broker ZIP, exact tooling/image identities, and private output paths. The canonical tfvars output must be HCL at a filename ending exactly in `.tfvars`; `.json` and `.tfvars.json` are rejected. The generator derives package/source/migration checksums and retained definitions, verifies every image digest byte-for-byte, records the canonical broker manifest path/SHA, records format/filename/extension in the binding report, and commits tfvars/report as one mode-0600 pair. Plan, refresh-only, closure, verify-only, and apply require the complete canonical tfvars provenance; each binding gate rereads the current broker ZIP and manifest bytes, and the apply path repeats that check immediately before Terraform.
4. Run the single reviewed refresh boundary with `npm run stage-b:refresh-only -- --closure-mode production ...`. It validates the canonical tfvars filename/content contract before Terraform and never writes a deployable plan. `--terraform-data-dir` is the sole Terraform data-directory authority; it is an external mode-0700 directory and its exact `<terraform-data-dir>/terraform.tfstate` metadata file is normalized by preflight to mode 0600 before `ready-for-plan`. Refresh, plan, closure, verify-only, and apply revalidate that same path, mode, and content binding; `--backend-metadata` must be exactly `<terraform-data-dir>/terraform.tfstate`, and the same private directory is passed as `TF_DATA_DIR` to workspace observation and refresh execution. Do not chmod failed artifacts or assemble raw `terraform plan -refresh-only` commands.
5. Capture exactly one deployment plan with `scripts/plan-production-green-stage-b.mjs` and write the binary plan, plan JSON, canonical plan JSON, and a private capture report with `state=PLAN_CAPTURED`. The baseline profile validates the reviewed create/update/destroy classification and requires every remaining canonical managed address to be no-op. Structurally validated append-only retained ECS generations may increase the no-op set; arbitrary or unrecognized no-op resources remain rejected. A task-definition rotation uses the separate exact address/action/field contract documented below; it is not authorized by changing aggregate counts. Capture records broker reference validation as pending and is not deployable. Preserved artifacts may use the planner's recovery phase to emit `PLAN_CAPTURED` without another Terraform plan.
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

After a partial apply, current source-declared `candidate` and `executor` task-definition
addresses may already be present in state. Recovery first validates the raw Terraform
resource identity: only `mode = "managed"` root resources (with no `module` field or a
null root-module value) may enter current or retained task-definition validation. Data
resources, child-module resources, malformed identity fields, unknown collections,
addresses, families, or duplicate mappings fail closed. Valid current addresses are
excluded from retained history before the mandatory fresh refresh and plan; current
state is never reused as saved-plan evidence.

Terraform state serials are canonical non-negative safe-integer JSON numbers throughout
the Stage B evidence chain. CLI text is parsed exactly once at the CLI boundary using the
strict decimal-integer contract; leading whitespace/zeroes, fractions, exponents, partial
values, negative values, and unsafe integers fail closed. Persisted attestation,
classification, tfvars, refresh, plan, approval, closure, verify-only, and apply evidence
must already contain the numeric JSON representation; artifact validators never coerce
strings. All bindings compare numeric values without coercive equality.

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

## Readiness closure and task-definition rotation

The production cutover uses two distinct runtime-verification boundaries. Before
rotation preparation, the release path registers the fixed
`mscqr-production-rls-green-predeployment-inventory` task definition and invokes
the reviewed broker operation `production-predeployment-rotation-inventory`.
The broker launches exactly one terminating Fargate task in the reviewed private
subnets/security group, with the approved backend digest, injected `DATABASE_URL`,
and the fixed `node /app/scripts/production-rotation-state-inventory.mjs`
command. The task emits one aggregate JSON record to its exact CloudWatch Logs
stream; the broker reads only that stream, validates the bounded inventory
schema, and stops/cleans up the task. No caller supplies a command, image, role,
network, database URL, or log group, and the verifier is never granted
`ecs:RunTask` or `iam:PassRole`.

The sequence is therefore: one MFA-backed in-memory verifier session, bounded
pre-deployment inventory, rotation preparation, overlap task registration,
readiness, one governed `UpdateService`, stabilization, and only then the
post-deployment exact-task ECS Exec selector. The selector still requires the
authorized digest, `MSCQRExecTarget=production-backend`, connected
`ExecuteCommandAgent`, exact task identity, and immediate ARN revalidation.

Before generating administrator evidence, run the source-controlled local readiness
check with the exact protected SHA and private output paths:

```sh
npm run stage-b:readiness:check -- \
  --protected-sha <full-origin-main-sha> \
  --artifact-parent <absolute-mode-0700-parent> \
  --backend-config <absolute-non-existing-backend-output>
```

This check performs no AWS API call and no Terraform refresh, plan, or apply. It proves
the local runtime, Terraform child-process spawn, dependencies, region, KMS contract,
clean protected checkout, disk, and producer-owned backend-output preconditions before
the evidence clock starts.

The current task-definition collection is versioned ECS infrastructure, not a generic
delete allowance. A fresh generation may replace only the exact four candidate and
eight executor families when the plan has `create,delete` or `delete,create`, exactly
`[["container_definitions"]]` as `replace_paths`, unchanged family/roles/CPU/memory/
network/runtime/secrets/logging fields, unchanged container identity, and immutable
current image digests bound to the plan evidence. Delete-only actions, unknown
families, family/module/address migration, and `ecs:DeregisterTaskDefinition` remain
forbidden. The plan, reference audit, permission manifest, closure, verify-only, and
apply wrapper all consume this same explicit rotation profile; aggregate counts are
diagnostics rather than authorization.

Partial-apply recovery remains orthogonal. A present-time administrator-signed
`STAGE_B_PARTIAL_APPLY_RECOVERY_ATTESTATION` can classify only the exact root-managed
`aws_lambda_alias.reviewed` update after independent verification. It cannot authorize
ECS rotations, arbitrary deletes, or any other drift. The historical refresh report
remains immutable, and a fresh authoritative plan is mandatory.

The complete source-readiness state machine, identity/TTL boundaries, requirements
matrix, historical failure coverage, and post-apply success definition are maintained
in `documents/ops/iam/MSCQRProductionGreenStageBReadinessClosure-v1.md` and its JSON
matrix companion.

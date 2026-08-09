# MSCQR Production Green Stage B readiness closure

This document is the source-readiness contract for the next production attempt. It
does not authorize AWS mutation, Terraform refresh, plan, or apply. The companion
[`MSCQRProductionGreenStageBReadinessMatrix-v1.json`](./MSCQRProductionGreenStageBReadinessMatrix-v1.json)
is the machine-readable requirements matrix.

## Protected-source rule

The operator resolves `git rev-parse origin/main` after fetching `origin/main`, then
creates a new clean, non-shallow detached worktree at that exact full SHA. Every
deployment artifact binds that SHA. A new source SHA invalidates all administrator,
image, state, refresh, recovery, plan, audit, permission, approval, closure, validator,
verify-only, and saved-plan evidence from the prior chain.

The merged PR #232 file-backed Terraform JSON capture is present in the protected
source. Its child process uses explicit argv, streams stdout to a private mode-0600
file in a mode-0700 directory, bounds stderr, validates status/signal/spawn errors,
parses JSON before publication, and cleans only invocation-owned artifacts.

## Canonical state machine

```text
SOURCE
  -> frozen clean protected worktree
  -> deterministic dependencies/toolchain/readiness check
  -> image impact classification
  -> one immutable image publication or contractually valid reuse
  -> new protected-SHA image evidence
  -> ROOT identity
  -> INITIAL_ADMIN_CAPABILITY (one producer)
  -> RELEASE_DEPLOYER identity
  -> release preflight and producer-owned backend config
  -> state lineage/serial/tfvars binding
  -> exactly one refresh-only observation
  -> CLEAN_REFRESH or immutable RESOURCE_DRIFT result
  -> ROOT identity only when exact recovery residue is present
  -> signed present-time recovery attestation
  -> RELEASE_DEPLOYER identity
  -> independently verified recovery classification
  -> exactly one authoritative Terraform plan
  -> file-backed terraform show JSON and exact address/action classification
  -> one read-only reference audit
  -> ROOT identity and one PLAN_BOUND_PERMISSION producer
  -> RELEASE_DEPLOYER identity
  -> PLAN_APPROVED, closure, validator, verify-only, final apply precheck
  -> explicit human apply authorization
  -> exactly one canonical saved-plan apply
  -> immediate post-apply state/ECS/Lambda/IAM/RLS/runtime verification
  -> final closure
```

There is no hidden retry or generic recovery mode. A failed one-shot producer is
terminal until an operator explicitly starts a new valid lifecycle. The credential
transitions are deliberate boundaries: the repository does not persist credentials or
pretend that one process can safely own ROOT and MFA-backed release-deployer sessions.

## Identity and freshness boundaries

| Boundary | Required identity | Evidence | Freshness / transition rule |
| --- | --- | --- | --- |
| GitHub image workflow | repository-approved GitHub workflow/OIDC | workflow run, publication identity, immutable digests | bound to exact protected SHA; no old image evidence is rebound |
| Initial administrator | `arn:aws:iam::368992683803:root` | `INITIAL_ADMIN_CAPABILITY` signed pair | live evidence TTL is 3600 seconds; caller mismatch stops |
| Release execution | `arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/<SESSION>` | release preflight/backend/state bindings | session lifetime and evidence TTL are independent |
| Recovery attestation | exact administrator boundary | `STAGE_B_PARTIAL_APPLY_RECOVERY_ATTESTATION` signed pair | 3600 seconds plus exact source/lineage/serial/refresh/resource bindings |
| Plan-bound permission | exact administrator boundary | `PLAN_BOUND_PERMISSION` signed pair | generated after plan/audit/approval and consumed immediately |
| KMS signer | existing Stage B asymmetric key | domain-separated signature verification | signer identity is verified; no release-deployer self-attestation |
| Terraform/AWS execution | release-deployer session | approved saved plan and complete evidence chain | canonical wrapper independently revalidates before apply |

Evidence survives a credential transition only when its own signatures, exact byte
hashes, source/state/plan bindings, and freshness remain valid. A transition never
refreshes or extends evidence.

## Plan/action contract

Authorization is derived from exact root-managed Terraform address, type, action, and
field delta. Aggregate counts are diagnostics only.

Before any plan evidence can enter the approval chain, `assertStageBPlanSemanticCompleteness`
walks every non-no-op resource recursively. It records changed leaves, every true
`after_unknown` and sensitive marker, replacement paths, and structured configuration
references. Each item must be one of the explicit semantic classes in
`scripts/aws/stage-b-plan-semantic-contract.mjs`; any unclassified path fails closed with
its address and path. This is PLAN-SEM-01 and is required for `ONE_SHOT_DEPLOYMENT_READY`.
The contract covers both supported twelve-address ECS profiles: `ECS_INITIAL_CREATE`
(`actions=["create"]`) for a baseline deployment and `ECS_REVIEWED_ROLLOVER`
(`actions=["create","delete"]` or `["delete","create"]`) for an approved immutable
task-definition rotation. The baseline and recovery-shaped fixtures must each produce
zero unclassified resource actions, changed paths, unknown paths, replacement paths, and
configuration references.
The baseline profile also requires an atomic broker policy/function/alias create shape;
the rollover profile requires the corresponding exact all-update shape. Partial or mixed
broker action shapes fail closed, while the no-change/append-only retry profile permits
only the canonical broker no-op shape.
The semantic census still records a computed alias reference diagnostically, but recovery
authorization does not accept an unknown alias target: Terraform cannot prove that a new
published broker version equals the attested desired version. Recovery therefore requires
a concrete `aws_lambda_alias.reviewed.function_version` equal to the attested configured
version; unknown values elsewhere are not accepted.

PLAN-SEM-01 also requires provider-fidelity proof for every baseline-created resource.
The independent Stage B security snapshot in
`scripts/aws/stage-b-provider-semantic-snapshot.mjs` is derived from the locked
`hashicorp/aws` 6.56.0 `terraform providers schema -json` output. Provider-computed
identifiers and metadata are recognized only at explicitly recorded paths; they never
authorize IAM content. Baseline fixtures must preserve Terraform's exact
`after_unknown` and structural-placeholder representation. The provider-fidelity
counters `unrepresentedSupportedProfiles`, `unfaithfulSupportedProfileFixtures`, and
`unfaithfulProviderComputedFields` must all be zero.
Typed shape recognition uses the separate complete four-resource universe in
`scripts/aws/stage-b-provider-resource-shape-universe.mjs`, with extracted evidence
captured in `scripts/tests/fixtures/stage-b-provider-6.56.0-resource-shape.json`.
That universe is exhaustive for provider field/block names and nesting metadata, while
the security snapshot and validators remain the authorization boundary. A schema-known
field therefore passes representation only when its exact reviewed null/default/empty
shape is present; a non-null or non-empty value still requires an independent security
rule. The completeness test fails closed on missing or extra provider attributes/blocks.
Provider nested-block shape is part of the same fidelity gate: the locked AWS 6.56.0
`runtime_platform` block is a one-element list, so baseline ECS paths are explicitly
indexed as `runtime_platform[0].operating_system_family` and
`runtime_platform[0].cpu_architecture`; object-shaped or unindexed substitutes fail closed.
The broker policy and Lambda environment are configuration-dependent values rather than
provider-owned outputs: a fresh create may carry their exact unknown shape, while a
partial-initial-apply retry may carry concrete values only after exact policy, variable,
task-definition ARN, and structured-reference validation. Provider-owned identifiers remain
mandatory unknowns in both cases.

For the baseline broker Lambda create, the source-controlled representation contract also
requires the provider's reviewed defaults `memory_size=128` and `package_type="Zip"`, the
configured region and `tags_all` value, a concrete `source_code_hash`, and the exact
optional-computed unknown `code_sha256`. These are separate categories: defaults and the
package digest are not interchangeable with provider diagnostics, and no unlisted optional
or optional-computed field is admitted.

The semantic engine evaluates a typed Terraform representation envelope before security
authorization. The envelope admits only the recorded categories in
`STAGE_B_TYPED_REPRESENTATION_MANIFEST`: configured concrete values, dependency-computed
unknown/resolved values, provider-computed unknowns, provider defaults/normalization, typed
nulls, false markers, and exact empty structures. A false `after_unknown` marker is known
and is never counted as an unknown path; a true leaf is the only unknown authorization
input. Nulls and empty blocks are representation-valid only at their exact reviewed paths
and grant no authority to a non-null or non-empty value. The counters
`unmodeledTypedAfterFields`, `unmodeledAfterUnknownMarkers`, and `unmodeledEmptyStructures`
are required to remain zero alongside the PLAN-SEM-01 counters, so provider or Terraform
typed-shape drift identifies the exact resource/path and fails closed.

The manifest is exhaustive over the locked provider shape universe for the four Stage B
resource types. Every top-level attribute or block has exactly one reviewed representation
disposition, including `NOT_EMITTED_IN_SUPPORTED_PROFILE`; an omitted disposition is a
completeness failure, while a field marked not emitted is still rejected if it appears in a
plan. Provider shape recognition does not authorize meaningful values. Broker publish
metadata is limited to `code_sha256`, `source_code_size`, `last_modified`, `qualified_arn`,
`qualified_invoke_arn`, and `version`; `source_code_hash` remains the package-identity input.

### Normal profiles

- Clean/no-change: each allowlisted resource has its exact `[]`/`["no-op"]` equivalent;
  no resource outside the matrix is accepted.
- Baseline initial release: the existing reviewed classification remains `58` no-op,
  `12` create, `3` update, `0` destroy, `0` unclassified. These counts are a regression
  assertion, not a generalized allowance.
- Image/Lambda rotation: the current source-controlled resource matrix permits only
  the exact resource-level create/update/no-op actions and the independently validated
  immutable image/package deltas. A broker publish update may change
  `source_code_hash` with the exact `var.broker_package_path` reference and the existing
  package-bytes/source-hash artifact proof; this does not permit other Lambda fields.
- ECS rotation: the exact twelve root-managed `aws_ecs_task_definition` addresses
  (four candidate and eight executor families) may use `create,delete` or
  `delete,create` only when all of these are true:
  - `mode=managed`, root module, exact address/type/family, and no duplicate family;
  - before ARN is the expected account/region/family with a valid positive revision;
  - after family is unchanged and, when present, after ARN is valid;
  - `replace_paths` is exactly `[["container_definitions"]]`;
  - family, network mode, compatibility, CPU, memory, roles, runtime platform,
    volumes, and tags are unchanged;
  - container names and count are unchanged, images are immutable digests bound to the
    plan/image evidence, and only reviewed provenance environment values change;
  - secret sources, logging, network, role, CPU/memory, and task identity fields do
    not change; no family/module/address migration is present;
  - no delete-only resource is accepted and no `ecs:DeregisterTaskDefinition` permission
    is introduced.

### Recovery profile

Recovery is additive and orthogonal:

```text
NORMAL_STAGE_B_ACTION_CONTRACT
  + exactly aws_lambda_alias.reviewed ["update"]
    from attested live version to attested configured version
```

The signed attestation never authorizes ECS rotation, arbitrary updates, deletes,
replacements, another Lambda resource, or an unknown address. The original refresh
`RESOURCE_DRIFT` report is immutable. A separately verified
`REVIEWED_PARTIAL_APPLY_RESIDUE` result is accepted only after the canonical KMS
recovery verifier rechecks raw bytes, hashes, signature, source, lineage, serial,
refresh SHA, resource identity, versions, and freshness at each security-sensitive
consumer.

For the recovery plan delta, the reviewed alias target must be concrete and equal the
attested configured version. A computed `aws_lambda_function.broker.version` reference
is insufficient because the plan cannot prove whether the publish produces the attested
version or a later one. Post-apply verification must still read the actual broker
configuration and reviewed alias and prove that the alias resolves to the published
broker version.

## Historical failure coverage

The following previously encountered blockers are now guarded by source and tests:

| Failure class | Current guard | CI path | Can regress undetected? |
| --- | --- | --- | --- |
| Terraform ENOENT / wrong runtime | readiness command and release gate | Stage B control-plane | false |
| stale administrator evidence | 3600-second freshness and lifecycle tests | Stage B control-plane | false |
| ROOT/deployer transition and MFA | exact caller contracts and phase split | Stage B control-plane | false; live credential availability remains operator-only |
| pre-created backend output | producer-owned atomic path contract | backend/release tests | false |
| UpdateAlias IAM resource mismatch | administrator permission and base-function policy contracts | identity/capability tests | false |
| MissingContextValues/scalar cardinality | context registry and simulator contract | identity capability tests | false |
| partial-apply task-definition state | root-managed/current/retained identity parser | reference-audit tests | false |
| data-source/child-module confusion | exact root managed identity checks | reference-audit tests | false |
| alias partial-apply drift | signed attestation and immutable refresh classification | recovery tests | false |
| unsigned recovery classification | `assertVerifiedStageBRecovery` at consumers | recovery/closure/apply tests | false |
| apply wrapper drift propagation | `trustedRecovery !== null` only | apply recovery tests | false |
| PR-mode approval dereference | mode-safe closure logic | closure tests | false |
| synchronous recovery CLI | synchronous executable entrypoint regression | control-plane aggregation | false |
| serial string/negative mismatch | strict CLI parse and numeric persisted evidence | serial/recovery tests | false |
| Stage A stale vs malformed taxonomy | canonical validation before freshness | Stage A prerequisite test | false |
| Terraform show ENOBUFS | file-backed stdout capture and bounded stderr | capture tests | false |
| ECS task-definition replacement gap | exact twelve-address rotation profile | ECS rotation/control-plane tests | false |
| CI registration gaps | package aggregator reached by quality gate | `quality-gate.yml` closure job | false |
| protected-SHA evidence reuse | checkout and every artifact source binding | deployment identity tests | false |
| stale saved plan reuse | saved-plan/hash/approval bindings | approval/apply tests | false |
| lineage/serial preservation | canonical state bindings | refresh/tfvars/approval tests | false |

The historical failed plan SHA
`01f3d4fa0c717db0d0e35c4e23b168a3647201a16421eb9c067130e05d54881f` is not available
as plan JSON in this readiness checkout. Its reported `12/3/12` preview therefore
remains forensic context, not a source of authorization. The next real plan must be
captured from the new protected SHA and pass the exact rotation contract.

## Tooling and TTL operator sequence

Run `npm run stage-b:readiness:check -- --protected-sha <SHA> --artifact-parent
<0700-parent> --backend-config <non-existing-output>` before the administrator
evidence clock. It checks local tools, Terraform child-process spawn, dependencies,
region, KMS configuration, source cleanliness, disk, and producer-owned backend output.

Then publish/reuse image evidence, authenticate ROOT, generate exactly one initial
administrator lifecycle, immediately transition to the release-deployer, and run
release preflight. Keep local package/tfvars prerequisites, private paths, and
Terraform runtime ready before ROOT evidence is generated. After the single refresh,
return to ROOT only for a required recovery attestation or plan-bound permission.
Move directly from permission signing through closure and verify-only to the final
apply decision; do not pause near the 3600-second TTL.

If the single refresh-only Terraform command fails, the producer retains a private
`terraform-plan-diagnostic.json` beside the refresh report. It contains only bounded,
redacted excerpts plus hashes of the complete command streams; it is forensic evidence
and never permits a retry or deployment.

## Post-apply success contract

`STAGE_B_INFRASTRUCTURE_APPLIED_AND_VERIFIED=true` is permitted only after the
canonical saved-plan apply exits successfully and post-apply verification proves:

- lineage is unchanged and serial advances as expected;
- no unclassified or unexpected resource action remains;
- the reviewed alias targets the configured Lambda version and function configuration
  is correct;
- all twelve expected ECS task-definition families have exact new revisions and
  immutable current image digests;
- ECS services/tasks, Lambda resources, IAM policy version/content, RLS infrastructure,
  health checks, and runtime/security invariants are correct;
- closure, validator, verify-only, signatures, hashes, and freshness remain valid.

No production post-apply claim is made by this source-readiness exercise.

## Forward-looking hardening

Future apply executions should publish a signed machine-readable
`STAGE_B_APPLY_FAILURE` artifact immediately on failure containing source/plan/state
identity, operation/target, provider error class, stdout/stderr hashes, and completed
resource observations. That artifact must be produced at failure time; it must never be
retrofit onto historical unsigned logs.

The repository intentionally does not add a hidden all-in-one credential orchestrator:
ROOT and MFA-backed release-deployer sessions are human authentication boundaries.
The readiness command and this deterministic state machine remove local/tooling
surprises without weakening those boundaries.

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
The computed alias exception remains field-specific: only
`aws_lambda_alias.reviewed.function_version` may be unknown, and only with the exact
structured reference to `aws_lambda_function.broker.version` plus the same-plan published
broker update. Unknown values elsewhere are not accepted.

PLAN-SEM-01 also requires provider-fidelity proof for every baseline-created resource.
The independent Stage B snapshot in
`scripts/aws/stage-b-provider-semantic-snapshot.mjs` is derived from the locked
`hashicorp/aws` 6.56.0 `terraform providers schema -json` output. Provider-computed
identifiers and metadata are recognized only at explicitly recorded paths; they never
authorize IAM content. Baseline fixtures must preserve Terraform's exact
`after_unknown` and structural-placeholder representation. The provider-fidelity
counters `unrepresentedSupportedProfiles`, `unfaithfulSupportedProfileFixtures`, and
`unfaithfulProviderComputedFields` must all be zero.
Provider nested-block shape is part of the same fidelity gate: the locked AWS 6.56.0
`runtime_platform` block is a one-element list, so baseline ECS paths are explicitly
indexed as `runtime_platform[0].operating_system_family` and
`runtime_platform[0].cpu_architecture`; object-shaped or unindexed substitutes fail closed.

### Normal profiles

- Clean/no-change: each allowlisted resource has its exact `[]`/`["no-op"]` equivalent;
  no resource outside the matrix is accepted.
- Baseline initial release: the existing reviewed classification remains `58` no-op,
  `12` create, `3` update, `0` destroy, `0` unclassified. These counts are a regression
  assertion, not a generalized allowance.
- Image/Lambda rotation: the current source-controlled resource matrix permits only
  the exact resource-level create/update/no-op actions and the independently validated
  immutable image/package deltas.
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

For the recovery plan delta, the reviewed alias target may be concrete only when it
equals the attested configured version, or computed when Terraform marks only
`aws_lambda_alias.reviewed.function_version` unknown. The computed form is accepted
only when structured Terraform configuration metadata binds that expression exactly to
`aws_lambda_function.broker.version`, the same plan contains the exact publishing
broker update, and no conflicting concrete target or other unknown alias field exists.
Post-apply verification must read the actual broker configuration and reviewed alias
and prove that the alias resolves to the published broker version.

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

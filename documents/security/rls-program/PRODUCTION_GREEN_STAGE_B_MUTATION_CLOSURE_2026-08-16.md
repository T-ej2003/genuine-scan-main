# Production Green Stage B mutation closure

This closure describes the production path at protected base
`a7e9fde5a9cc2ad9f1c397ec51c0de727e92f115`. It is a source contract, not
production execution evidence. No Terraform, AWS, ECS, IAM, or MFA mutation was
performed while producing it.

## Barrier 1

The production call chain is refresh, saved plan, semantic census, reference
audit, plan approval, approved binding, permission simulation, registration
census, image binding, saved-plan re-read, and apply. The signed permission
report now carries `MSCQRProductionGreenStageBMutationManifest`; apply derives
the same manifest from the selected plan and rejects any canonical difference.

The imported-backend profile is exact: one create, eleven ECS task-definition
replacements, four updates, no standalone destroy, and no unclassified action.
Every replacement is one reviewed current task-definition address with exact
actions `create,delete`. The imported backend candidate remains an update from
`skip_destroy=null` to `true`, retains canonical revision `:9`, requires no AWS
action, and is not a registration.

Each manifest resource records address, type, ordered actions, semantic or
permission classification, before/after identity, required AWS actions, and a
canonical after-value digest. Output changes are recorded separately. Exact
address/action equality—not counts—defines completeness.

Immediately before apply the wrapper revalidates the protected checkout,
canonical backend, default workspace, canonical tfvars, and the hashes of the
saved plan, plan JSON, approval, permission evidence, and mutation manifest.
Ambient `TF_CLI_ARGS` and every `TF_CLI_ARGS_*` key are rejected. Apply consumes
only the approved saved plan; no target, replace, refresh-only, or re-plan path
is accepted. Fresh approval and permission evidence remain mandatory and are
revalidated, but their renewable artifact hashes do not mint another mutation
right. The apply-attempt identity is the canonical hash of the stable saved-plan,
protected-source, normalized backend identity, and workspace bindings. Canonical
tfvars remain mandatory authenticated evidence but are not consumed by
`terraform apply <saved-plan>`, so reserialization cannot mint another key.
The normalized backend identity contains only the validated S3 type, bucket,
state key, region, encryption, and lockfile coordinates; Terraform's metadata
hash and default-valued optional serialization do not mint another key. The mutation manifest
and all authorization artifacts are still authenticated against that saved plan
immediately before reservation, but their renewable artifact bytes cannot select
a new reservation key.
Immediately before Terraform starts, the wrapper resolves the
canonical S3 reservation key
`env:/production/mscqr/production/rls-green/stage-b/apply-attempts/<artifact-set-sha256>.json`
in the existing production Terraform backend bucket. It uses one conditional
`PutObject` with `If-None-Match: *`, then reads back and verifies the exact
identity-bound bytes before Terraform can start. `412`, `409`, unavailable
storage, or mismatched readback all fail closed without retry. The release
deployer can read and conditionally create this exact prefix, but explicit
denies prevent unconditional overwrite, `DeleteObject`, and
`DeleteObjectVersion`.

The effective OS account marker at
`<effective-operator-home>/.mscqr/production-green-stage-b/apply-attempts/<artifact-set-sha256>.json`
remains local defense-in-depth only. Losing it cannot restore mutation
authority because the shared S3 reservation is authoritative across hosts,
users, runners, and local filesystem loss. Without `s3:ListBucket`, a
missing-object `GetObject` is not an authoritative absence test. Readiness
therefore reports the reservation as not authoritatively readable and does not
consume it. Only conditional `PutObject` at the final mutation boundary decides
whether the mutation right is available.

### Apply-attempt result and reconciliation contract

New reservations use schema version 3 and are append-only. The initial
`RESERVED` object records the exact source, approved plan and saved-plan
identities, state lineage/serial/digest, workspace, backend identity, execution
principal, and the structured conditional-create/readback result. The wrapper
publishes a separately keyed, conditionally-created transition record before
Terraform is spawned. Transition records are read-only evidence; they never
replace the immutable reservation object and are never overwritten or deleted.

The allowed state machine is:

```text
RESERVED -> APPLYING -> APPLIED
                    \-> FAILED
                    \-> UNKNOWN -> ABORTED_BEFORE_APPLY
RESERVED -> ABORTED_BEFORE_APPLY
```

`UNKNOWN`, `APPLIED`, `FAILED`, and `ABORTED_BEFORE_APPLY` are terminal for
automatic execution. A process or storage failure after the reachability marker
is written remains `UNKNOWN` unless a separate, independently reviewed
reconciliation artifact proves Terraform was not reached. A failed or uncertain
apply is never retried from age, an unchanged state serial, a missing local
marker, or an operator assertion.

The one historical schema-v2 bridge is literal and non-reusable: it accepts only
the authenticated incident reservation, source, plan, saved plan, state
lineage/serial/digest, workspace, backend identity, and creation timestamp
recorded in the incident review. A fresh reconciliation artifact must include
independently authenticated evidence that the apply entrypoint and Terraform
process were not reached, provider-side mutation is absent, infrastructure is
unchanged, and the local marker was not created. The artifact is still not
execution authority. A protected production-environment approval must bind the
exact artifact, historical reservation, successor source, successor attempt
identity, and a maximum of one successor Terraform apply. The original
reservation is retained as historical evidence; the successor has a new
identity and predecessor link.

The reconciliation workflow publishes the canonical `authorization.json`
member only after the production environment's independent required-reviewer
approval. It grants no AWS or Terraform capability itself. A future successor
execution must re-read the reservation, state, plan, and provider/reference
safety evidence before any apply. Missing or contradictory evidence fails
closed. No secret values, credentials, signed request contents, or private
material are present in reservation, transition, reconciliation, or
authorization evidence.

The global mutation identity field audit is:

| Field | Classification | Reservation-key effect |
|---|---|---|
| saved binary plan SHA-256 | executable mutation | included |
| protected source SHA | immutable execution binding | included |
| normalized backend identity | external state target | included |
| canonical workspace | external state target | included |
| tfvars and binding report | freshly validated evidence; not an apply input | excluded |
| approval, permission, manifest, signatures, timestamps | renewable authorization evidence | excluded |

Excluded evidence is still validated against the saved plan immediately before
conditional reservation; exclusion changes no freshness or authorization gate.

## Barrier 2 expected operations

| Planned class | Exact count | AWS operation family | Postcondition |
|---|---:|---|---|
| backend ECS Exec inline policy create | 1 | `iam:PutRolePolicy` | exact reviewed inline policy exists |
| current task-definition rollover | 11 | `ecs:RegisterTaskDefinition`, `ecs:TagResource`, `iam:PassRole` | one new exact family revision per address; immutable image and task contract match the plan |
| imported backend metadata normalization | 1 | none | state still owns canonical backend `:9`; no backend registration |
| broker managed-policy update | 1 | `iam:CreatePolicyVersion`, conditional oldest-version `iam:DeletePolicyVersion` | reviewed policy is default; no unrelated policy changes |
| broker Lambda update | 1 | `lambda:UpdateFunctionCode`, `lambda:UpdateFunctionConfiguration`, `lambda:PublishVersion` | code/config identity matches the approved plan |
| reviewed Lambda alias update | 1 | `lambda:UpdateAlias` | alias targets the approved published version |
| `task_definition_arns` output | 1 | none | output maps each current address to its resulting ARN |

Terraform state lineage must remain unchanged. Serial must advance from the
authenticated pre-apply serial but is not assigned an invented increment.
Post-apply readback must prove all manifest addresses are owned, backend remains
`:9`, eleven and only eleven reviewed registrations exist, no unexpected
resource or output changed, and a fresh convergence plan has zero resource
change, drift, unknown action, and output change with all checks passing. A
partial or non-converged apply stops; the immutable attempt marker forbids an
automatic second apply.

## Downstream release boundary

Downstream cutover is a separate mutation boundary. Runtime bootstrap binds the
protected source, image authorization, Stage-B tfvars, inventory approval,
rotation state, and exact task-definition ARN. The governed cutover targets only
cluster `mscqr-prod-euw2-main`, service `mscqr-backend-servi-euw2`, with one
`UpdateService`, `propagateTags=TASK_DEFINITION`, and an explicit approved ARN;
`latest` is never accepted. The current task definition captured by runtime
bootstrap is the rollback identity. The deploy script does not mutate service
deployment configuration, but it also does not authenticate deployment-circuit-
breaker settings. Circuit-breaker presence therefore remains an explicit
pre-cutover evidence gap; it is not silently repaired or authorized by this PR.

The verifier MFA boundary remains after readiness and before service mutation.
Post-cutover requires service stability, exact task definition, exact immutable
digest, execution marker, ECS Exec runtime proof, and strict onboarding evidence.

## Onboarding success

`DEPLOYED=true` means the governed service cutover converged to the exact
approved task definition and digest. `READY_FOR_ONBOARDING=true` additionally
requires every `STRICT_ONBOARDING_CHECKS` probe.

- Read-only or authentication probes: deployed release/digest, service and task
  identity, health, database/Redis/object-storage readiness, login, MFA,
  `authMe`, refresh, dashboard/QR statistics, tenant isolation, RBAC, audit,
  printer trust, public QR verification/anti-cloning, rotation state, and all
  JWT/QR/artifact current/historical verification and rejection checks.
- Safe synthetic writes: only the canonical QR fixture used by the strict HTTP
  adapter, with its cleanup and evidence-leak guards.
- Real business mutations: manufacturer onboarding, licensee onboarding,
  production allocations, and customer print jobs are not readiness probes and
  remain operator/business actions after readiness.

Any missing probe, sensitive evidence leak, source/digest/task mismatch, unknown
change, unexpected AWS mutation, or non-converged post-apply plan fails closed.

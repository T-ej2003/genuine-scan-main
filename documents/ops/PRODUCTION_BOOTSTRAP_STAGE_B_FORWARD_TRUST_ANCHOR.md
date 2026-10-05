# Bootstrap to Stage B forward trust anchor

## Purpose

This protocol bridges one authenticated `BOOTSTRAP` component-state snapshot into the existing Stage B release transaction. It never claims how the bootstrapped task definitions were originally deployed. It asserts only that Stage B started from the exact bootstrapped live identities, classified each component's independent accumulated protected-main range, deployed an approved immutable Stage B plan, verified the result, and committed the existing `SECURITY_INFRASTRUCTURE` terminal state.

No new deployment engine, provenance lane, approval system, or historical adoption is introduced.

## Release classification closure

| Path | Semantics | Correct class |
|---|---|---|
| `backend/src/services/auditLogOutboxService.ts` | B03 durable security-audit outbox attribution, request normalization, idempotency, and RLS worker boundary | `SECURITY_INFRASTRUCTURE` |
| `scripts/plan-production-green-stage-b.mjs` | Stage B plan and release control plane | `EMERGENCY_RECOVERY` |
| `e2e/enterprise-smoke.spec.ts` | Non-runtime validation | ignored by release ownership classification |

The bridge fails closed if either component range contains any path the canonical classifier cannot classify.

## Security invariant

Stage B does not fundamentally require `NORMAL_APPLICATION` ancestry. It requires every live predecessor outside the Terraform plan to be authenticated by a source-owned provenance contract, bound to exact live service/task/image/source identities and the approved plan. The existing B01 predecessor contract already establishes this model.

The bootstrap bridge is admissible only when all of these are true:

1. Component state is schema v2, generation 1, `BOOTSTRAP`, from the canonical protected workflow and a numeric GitHub run.
2. It has no normal-deployment receipt; backend and frontend are present; database and security remain explicitly unproven (`null`).
3. Both component provenances are the exact bootstrap provenance.
4. Backend and frontend service and immutable task-definition image digest exactly match the source/digest identity already authenticated and conditionally persisted by bootstrap.
5. Each component has its own `establishedThroughSha..toolingSha` file list and classification. Neither baseline can substitute for the other.
6. Every range has zero unknown paths, and at least one component range is a stronger lane (`SECURITY_INFRASTRUCTURE` or `EMERGENCY_RECOVERY`). A normal or already-current sibling component remains independently bound and verified.
7. The complete reference is hashed into the Stage B plan approval and revalidated by apply from protected source.
8. The normal `production-deploy` concurrency group serializes bootstrap, normal deployment, and Release Gate.
9. Stage B terminal evidence commits existing `SECURITY_INFRASTRUCTURE` provenance with CAS; it never rewrites the historical bootstrap as normal.

## State machine

| State | Durable authority and transition |
|---|---|
| F0 absent | No component state. Stage B bridge forbidden. |
| F1 bootstrap committed | Generation 1 records exact backend and frontend live identities with `BOOTSTRAP` provenance. Conditional create is the only transition from F0. |
| F2 reference captured | Read-only live evidence and independent source ranges match F1. Any mismatch fails before mutation. |
| F3 plan approved | Existing Stage B plan approval hashes the reference audit, plan, source, images, state lineage, and serial. Approval expiry and operator controls remain unchanged. |
| F4 apply reserved | Existing single-use Stage B apply-attempt reservation owns the approved artifact set. Replay or competing ownership fails closed. |
| F5 task definitions registered | Existing Terraform/Stage B plan registers only approved immutable definitions. Unknown outcomes reconcile through existing apply-attempt and Terraform state contracts. |
| F6 service/RLS mutation started | Existing Stage B transaction applies the checksum-bound plan. No bridge-specific AWS mutation exists. |
| F7 candidates live | Existing ECS and database verification observes exact approved candidates. Partial component progress remains an incomplete Stage B apply. |
| F8 complete set verified | Backend, frontend when required, RLS, health, and release receipts satisfy existing terminal contracts. |
| F9 terminal state committed | CAS advances component state and writes truthful `SECURITY_INFRASTRUCTURE` provenance. Bootstrap history is preserved in the prior generation/evidence, not relabelled. |
| F10 closed | Existing Stage B closure and durable evidence complete; reruns reconcile/idempotently observe the terminal state. |
| F11 Stage-B-compatible predecessor | Subsequent Stage B or normal work consumes the committed component-scoped provenance under existing rules. |

### Transition bindings

Every F1-F3 transition binds repository, protected-main tooling SHA, component-state generation/hash, independent component baselines and file lists, release classifications, service/environment/account/region, task-definition ARNs, immutable image digests, and live source identities. F3-F10 additionally use the existing Stage B plan/image/task-definition/approval/nonces, state lineage, Terraform serial, apply-attempt reservation, receipts, and component-state CAS.

No operation continues after changed generation, predecessor, source range, classification, image, task definition, service, environment, account, region, plan, or authorization. Unknown mutation outcomes remain inside existing Stage B reconciliation; they are never converted into a new bridge attempt.

## Component ranges

Backend starts at its own `establishedThroughSha`; frontend starts at its own `establishedThroughSha`. Both end at the protected Stage B tooling SHA. The bridge records and hashes both exact file lists separately. Candidate image publication and the Stage B plan remain authoritative for which immutable artifacts are deployed. A component never inherits the other component's baseline.

## Authorization and concurrency

The existing Stage B approval is reused. Its approved plan report binds the complete reference-audit bytes and hash, protected tooling SHA/tree, image evidence, plan hashes, state lineage/serial, caller, and freshness. Existing Stage B runtime approval supplies nonce, expiry, exact images/task definitions, account, region, environment, and operator/checker identities. No new approval payload is added.

The GitHub `production-deploy` concurrency group serializes canonical bootstrap, normal deployment, and Release Gate. DynamoDB generation CAS and the Stage B apply-attempt reservation protect durable writers. Any out-of-band ECS change is rejected by exact live-reference validation or by existing plan/apply/terminal verification; ECS cannot authorize itself.

## Hostile model

Every case has one permitted outcome: `SAFE_AUTOMATIC_RECOVERY` through an existing idempotent/reconciliation contract, or `FAIL_CLOSED_EXPLICITLY` before new authority is created.

| # | Attack/interruption | Outcome |
|---:|---|---|
| 1 | Missing component state | FAIL_CLOSED_EXPLICITLY |
| 2 | State generation other than 1 | FAIL_CLOSED_EXPLICITLY |
| 3 | Schema v1 state | FAIL_CLOSED_EXPLICITLY |
| 4 | Wrong aggregate provenance | FAIL_CLOSED_EXPLICITLY |
| 5 | Wrong backend provenance | FAIL_CLOSED_EXPLICITLY |
| 6 | Wrong frontend provenance | FAIL_CLOSED_EXPLICITLY |
| 7 | Wrong bootstrap workflow | FAIL_CLOSED_EXPLICITLY |
| 8 | Non-numeric bootstrap run | FAIL_CLOSED_EXPLICITLY |
| 9 | Pending normal receipt | FAIL_CLOSED_EXPLICITLY |
| 10 | Database/security already asserted | FAIL_CLOSED_EXPLICITLY |
| 11 | Authorization replay | FAIL_CLOSED_EXPLICITLY |
| 12 | Authorization for wrong SHA | FAIL_CLOSED_EXPLICITLY |
| 13 | Wrong starting generation/hash | FAIL_CLOSED_EXPLICITLY |
| 14 | Wrong predecessor ARN | FAIL_CLOSED_EXPLICITLY |
| 15 | Wrong source range start | FAIL_CLOSED_EXPLICITLY |
| 16 | Wrong source range end | FAIL_CLOSED_EXPLICITLY |
| 17 | Missing range file | FAIL_CLOSED_EXPLICITLY |
| 18 | Added range file | FAIL_CLOSED_EXPLICITLY |
| 19 | Duplicate/unsorted range | FAIL_CLOSED_EXPLICITLY |
| 20 | Wrong release classification | FAIL_CLOSED_EXPLICITLY |
| 21 | Unclassified path | FAIL_CLOSED_EXPLICITLY |
| 22 | Normal-only range presented to bridge | FAIL_CLOSED_EXPLICITLY |
| 23 | Inactive task definition | FAIL_CLOSED_EXPLICITLY |
| 24 | Image digest substitution | FAIL_CLOSED_EXPLICITLY |
| 25 | Required container missing | FAIL_CLOSED_EXPLICITLY |
| 26 | Backend source environment disagrees with bootstrapped source | FAIL_CLOSED_EXPLICITLY |
| 27 | Wrong task-definition family | FAIL_CLOSED_EXPLICITLY |
| 28 | Wrong task-definition ARN | FAIL_CLOSED_EXPLICITLY |
| 29 | Backend/frontend candidate swap | FAIL_CLOSED_EXPLICITLY |
| 30 | Wrong service/environment/account/region | FAIL_CLOSED_EXPLICITLY |
| 31 | Service not stable | FAIL_CLOSED_EXPLICITLY |
| 32 | Multiple primary deployments | FAIL_CLOSED_EXPLICITLY |
| 33 | Backend source env mismatch | FAIL_CLOSED_EXPLICITLY |
| 34 | Only backend advances | existing Stage B partial-apply reconciliation or FAIL_CLOSED_EXPLICITLY |
| 35 | Only frontend advances | existing Stage B partial-apply reconciliation or FAIL_CLOSED_EXPLICITLY |
| 36 | Backend succeeds/frontend fails | existing Stage B partial-apply reconciliation or FAIL_CLOSED_EXPLICITLY |
| 37 | Frontend succeeds/backend fails | existing Stage B partial-apply reconciliation or FAIL_CLOSED_EXPLICITLY |
| 38 | Task registration succeeds, response lost | SAFE_AUTOMATIC_RECOVERY through Terraform/apply-attempt reconciliation |
| 39 | Service mutation succeeds, response lost | SAFE_AUTOMATIC_RECOVERY through existing live verification/reconciliation |
| 40 | ECS rollback/circuit breaker | FAIL_CLOSED_EXPLICITLY with existing rollback evidence |
| 41 | Health verification fails | FAIL_CLOSED_EXPLICITLY |
| 42 | Durable receipt write fails | FAIL_CLOSED_EXPLICITLY; rerun reconciles existing Stage B attempt |
| 43 | DynamoDB timeout, unknown outcome | SAFE_AUTOMATIC_RECOVERY by consistent read/CAS or explicit conditional failure |
| 44 | Stale CAS generation | FAIL_CLOSED_EXPLICITLY or retry only if changed components are identical |
| 45 | Cancellation before any mutation | SAFE_AUTOMATIC_RECOVERY |
| 46 | Cancellation after reservation | SAFE_AUTOMATIC_RECOVERY through same apply-attempt identity |
| 47 | Cancellation after any AWS mutation | SAFE_AUTOMATIC_RECOVERY through existing Stage B reconciliation |
| 48 | Same-SHA rerun | SAFE_AUTOMATIC_RECOVERY/idempotent closure |
| 49 | Newer-SHA rerun using old approval | FAIL_CLOSED_EXPLICITLY |
| 50 | Protected main advances after authorization | FAIL_CLOSED_EXPLICITLY |
| 51 | Bootstrap races bridge | serialized; stale generation fails closed |
| 52 | Normal deployment races bridge | serialized; stale generation fails closed |
| 53 | Release Gate races bridge | same operation/concurrency boundary; duplicate reservation fails closed |
| 54 | Two bridge runs race | one concurrency owner; duplicate approval/reservation fails closed |
| 55 | Manual ECS drift before reference | FAIL_CLOSED_EXPLICITLY |
| 56 | Manual ECS drift after reference | existing Stage B plan/apply/terminal identity checks fail closed |
| 57 | Stale candidate image | FAIL_CLOSED_EXPLICITLY through image evidence/freshness |
| 58 | Stale task definition | FAIL_CLOSED_EXPLICITLY through plan/reference binding |
| 59 | Malicious/tampered reference | FAIL_CLOSED_EXPLICITLY through reference hash and contract |
| 60 | Wrong AWS account/region | FAIL_CLOSED_EXPLICITLY |
| 61 | Future component added to state schema | FAIL_CLOSED_EXPLICITLY until the canonical component set and bridge are reviewed together |
| 62 | Component removed from schema | FAIL_CLOSED_EXPLICITLY through exact key coverage |
| 63 | Stage B starts before bootstrap closes | FAIL_CLOSED_EXPLICITLY |
| 64 | Normal deployment starts mid-transition | serialized; state/receipt blocks it |
| 65 | Approval expires mid-transition | existing Stage B expiry/apply-attempt contract decides; no new bridge authority |
| 66 | Receipt belongs to another plan/source/image | FAIL_CLOSED_EXPLICITLY |
| 67 | Cross-component baseline contamination | FAIL_CLOSED_EXPLICITLY through independent range starts/hashes |
| 68 | Bootstrap-only state offered to later Stage B without fresh reference | FAIL_CLOSED_EXPLICITLY |
| 69 | Stage B terminal succeeds but runner dies | SAFE_AUTOMATIC_RECOVERY through terminal evidence/state idempotency |
| 70 | Stage B component state committed but ECS later disagrees | subsequent complete live verification fails closed |

## Recovery DAG

After merge, the source-owned sequence is:

`IAM convergence` -> `canonical complete-component BOOTSTRAP` -> `fresh Stage B preparation with bootstrap-forward reference` -> `existing human Stage B approval` -> `existing Stage B apply/reconciliation` -> `complete live/RLS verification` -> `SECURITY_INFRASTRUCTURE component-state commit` -> `closure`.

There is no artificial normal-application deployment between the forward Stage B transition and its terminal state.

## Post-implementation attacker pass

These counterexamples were generated after the implementation was complete. `production-bootstrap-stage-b-predecessor.test.mjs` covers the reference cases; the existing reference-audit, permission-preflight, component-state, and reconciliation suites cover Stage B authorization, replay, interruption, and terminal behavior.

| # | Category | Attack | Blocked by code | Blocked by test |
|---:|---|---|---|---|
| 1 | concurrency | Change backend after plan approval | mutation-boundary full revalidation | bootstrap mutation-boundary test |
| 2 | concurrency | Change frontend after plan approval | mutation-boundary full revalidation | bootstrap mutation-boundary test and frontend live mutations |
| 3 | concurrency | Advance component-state generation | state hash/generation equality | generation substitution attack |
| 4 | concurrency | Add a normal receipt while approval waits | bootstrap state contract | pending receipt attack |
| 5 | concurrency | Run bootstrap twice | conditional generation-1 initialization | component-state bootstrap tests |
| 6 | concurrency | Start normal deployment during Stage B | shared `production-deploy` group plus receipt/CAS | normal reconciliation suite |
| 7 | concurrency | Start two Stage B applies | global apply-attempt reservation | permission-preflight replay tests |
| 8 | concurrency | Lose task-registration response | existing Terraform/apply-attempt reconciliation | apply-attempt interruption tests |
| 9 | concurrency | Lose service-update response | existing Stage B reconciliation | apply-attempt interruption tests |
| 10 | concurrency | Terminal CAS loses an unrelated race | component-scoped retry with unchanged predecessor | component-state CAS tests |
| 11 | provenance | Relabel bootstrap backend as normal | exact per-component bootstrap provenance | backend provenance lane substitution |
| 12 | provenance | Relabel only aggregate writer | exact aggregate bootstrap provenance | aggregate lane substitution |
| 13 | provenance | Substitute bootstrap workflow | fixed protected workflow | aggregate workflow substitution |
| 14 | provenance | Supply non-GitHub run identity | numeric run requirement | non-run bootstrap identity |
| 15 | provenance | Assert database/security history in bootstrap | generation-1 bootstrap shape | database/security authority attacks |
| 16 | classification | Omit audit outbox service from range | canonical Git diff at generation and apply | real accumulated-range zero-unknown check |
| 17 | classification | Mark audit outbox service normal | security-first classifier rule | release-classification test |
| 18 | classification | Mark Stage B planner normal | emergency classifier rule | release-classification test |
| 19 | classification | Insert unknown runtime input | classifier fails closed | unclassified bridge-path attack |
| 20 | classification | Present normal-only range to bridge | stronger-lane assertion | normal-only bridge-range attack |
| 21 | cross-component | Use frontend baseline for backend | range start equals named component state | cross-component range-start attack |
| 22 | cross-component | Swap backend/frontend task definitions | exact service/family/container contracts | family/task substitution attacks |
| 23 | cross-component | Omit frontend from state | exact canonical component set | missing frontend component attack |
| 24 | cross-component | Omit frontend range | exact range-key set | missing frontend range attack |
| 25 | cross-component | Drift unaffected frontend | complete-set mutation-boundary revalidation | frontend service/task/image attacks |
| 26 | authorization | Replay approved plan | single global apply-attempt identity | apply marker/shared reservation tests |
| 27 | authorization | Change protected SHA | deployment identity and reference audit hash | checkout/source-binding tests |
| 28 | authorization | Change reference after approval | approval report binds reference bytes/hash | removal/substitution integration test |
| 29 | authorization | Substitute image digest | state, task-definition, and Stage B image-evidence bindings | backend/frontend image attacks |
| 30 | authorization | Use expired evidence | existing Stage B freshness contract | stale audit/permission evidence tests |

All 30 are blocked; none requires a bridge-specific rollback, deployment engine, or approval mechanism.

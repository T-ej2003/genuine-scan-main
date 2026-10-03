# Historical runtime retention through release closure

The release train could not authenticate a required standalone worker predating its deployment-receipt authority. Replacing that worker is outside this correction. This change authenticates its exact current runtime identity while recording that its historical launch was **not** governed by the release system.

There is no family, revision, image-only or root-actor exception. The initial reference is available only from the exact generation-1 BOOTSTRAP snapshot, with no outstanding normal transaction. The task must predate bootstrap. Initial preparation independently reads ECS, its immutable task definition and ECR image, the ENI configuration, and the associated root/MFA CloudTrail registration and launch. The initial CloudTrail reader uses the existing administrator profile; normal deployments have no CloudTrail or worker ECR authority. Initial image/repository attribution also uses the existing administrator reader.

## One reference and authority chain

`production-historical-runtime-contract.mjs` defines the sole canonical reference and `referenceSha256`. It binds repository, recovery source and tooling tree, bootstrap workflow/run/generation/state hash, account/region/cluster, exact task and definition ARNs, definition content hash, protected image/source, roles, effective container/override configuration hash, secret references through that hash, ENI/subnet/private IP/security groups, and the two exact CloudTrail event associations. Environment/secret values are not published in the reference; secret values are never retrieved.

1. The canonical Stage B reference-audit generator prepares this reference or authenticates an already retained reference. Only the exact matching RUNNING standalone worker may be excluded from the unknown-reference check. Another worker still fails.
2. The existing saved-plan approval binds the complete audit checksum. The existing root-attestation signature over the plan-bound permission-report binding explicitly carries the reference hash, recovery SHA, plan-approval checksum, audit checksum and approval time.
3. The emitted `.historical-runtime.json` is a compact projection of that existing signed binding, the reference and signature. It is not a launch receipt or a new evidence/signing system. Initial authority must be current-source and fresh under the existing evidence-age contract.
4. The existing checker Stage B approval input/signature includes `historicalRuntimeReferenceSha256`. Omitting/substituting a required hash fails validation.
5. Before Terraform mutation, Stage B apply independently verifies the reference against current state and live immutable identity. It performs no worker registration, launch, stop or modification.
6. Release Train transports the exact proof bytes and checksum. Release Gate's existing image-authorization JSON input carries a transport envelope only when necessary, preserving GitHub's 25-input limit. Both signed inner artifacts retain their original bytes and checksums; envelope unpacking confers no authority.
7. Release Gate carries the same canonical hash in each existing full-RLS broker request. The broker compares it to the signed checker approval before consuming authorization or launching an executor, rejecting omission/substitution in either direction. Release Gate independently verifies the pinned root signature and the complete worker inventory before deployment work. Its existing rotation terminal and final security terminal revalidate the same proof and live object, then persist retention in the existing component-state CAS. Both re-read live identity after CAS before reporting success.
8. Subsequent audits and normal reconciliation verify the stored signed binding using the existing pinned public key and re-read the exact live runtime. They never need the original large IAM report or logs to reconstruct authority.

Plain image authorization remains supported when no historical worker exists. Dropping the optional transport is not a bypass: the live worker census and component state require the missing proof/retention and fail closed.

## State and interruption semantics

| State | Authority | Permitted result |
|---|---|---|
| Generation 1 BOOTSTRAP; no retention | Exact bootstrap hash/run plus fresh signed Stage B reference | Initial retention may accompany an authenticated existing Release Gate terminal CAS |
| Reference prepared/signed; no terminal CAS | Proof does not attest historical governance or completed deployment | Existing Stage B/gate checks and human controls still required |
| Pre-CAS read/signature/identity failure | No verified closure | No retention write; no worker mutation |
| Conditional write loses generation race | Starting bootstrap is no longer authoritative | Fail; do not retry initial retention against another generation |
| Write fails before mutation | Bootstrap remains intact | Fresh read and authentication before retry |
| Write commits but response is lost | Exact reference already persisted | Authenticate the durable state/live object; identical rerun is idempotent |
| Worker changes/disappears during closure | Runtime no longer matches authority | Fail before reporting closure; never transfer trust to another task |
| Retention committed | Original consumed signed reference plus authenticated component-state CAS | Preserve unchanged through unrelated backend/frontend/database/security writes |
| Unsupported successor/retirement evidence | No governed worker-successor closure type exists | Reject; retain unchanged |

The retention record stores the reference, compact signed authority and originating terminal workflow/run/generation. It does not duplicate the IAM simulation bundle. Backend/frontend normal transactions clone/preserve it, including intermediate durable receipts, reconciliation and rollback. Their canonical live-verification adapter authenticates retention before and after normal smoke verification. Removing the record while the worker is live fails closed.

Production deployments share the existing `production-deploy` workflow serialization and generation CAS. ECS observations are not an atomic distributed lock: an out-of-band task change can occur after a read. The terminal performs pre/post-CAS readback; later consumers always revalidate live identity and reject drift. The signed initial source/digest proof remains authoritative; mutable ECR tags cannot replace it or invalidate its authenticated source history. A lost response or post-CAS drift never triggers a worker launch, stop, trust transfer or blind extra CAS.

## Retention and supersession

Generation advancement is not supersession. A changed/missing historical task is a failed identity check, not successor proof. Inventory receipts, RLS receipts, task-definition registration, CloudTrail launch and a newly RUNNING worker cannot retire or substitute this record.

No governed worker-successor evidence contract exists today. This correction intentionally introduces neither one nor worker deployment automation. Unsupported `SUPERSEDED` records and deletion/replacement of retention are rejected by schema/CAS. A future separately reviewed governed successor contract must establish its own authenticated closure and irreversible retirement; it is not required for current recovery or ordinary backend/frontend deployment.

## Current recovery walkthrough and remaining gates

No production step was executed by this implementation.

| Node and existing owner | Classification | Required outcome |
|---|---|---|
| Exact-head CI/review and merge | NORMAL_RELEASE_GATE | New protected-main authority; no reuse of old SHA-bound preparation |
| Normal-deployer read-policy convergence (`converge-production-normal-deployer-policy.mjs`) | OPERATIONAL_EXECUTION | Add region-restricted ENI reads only; no worker mutation authority. Independently verify policy hash |
| Fresh state, full live predecessor and CloudTrail readback | MISSING_PRODUCTION_EVIDENCE | Generation-1 bootstrap/hash/run and exact historical task unchanged, no receipt, healthy services. No bootstrap rerun |
| Stage B audit/plan/package (`generate-production-green-stage-b-reference-audit.mjs`, plan/preflight/approval contracts) | MISSING_PRODUCTION_EVIDENCE | Fresh exact-main source/images/task definitions, no unclassified paths, correct stronger-lane classification, exact reference and checksums |
| Saved-plan/checker approval, broker publication/convergence/authorization | HUMAN_APPROVAL | Existing protected environment/MFA/signature/expiry/replay checks, current release/image/reference hash; no prior authorization reuse |
| Signing-key initial overlap, predeployment inventory and readiness (`production-cutover-control-plane.mjs` and canonical coordinator/adapters) | OPERATIONAL_EXECUTION | Existing independently authenticated key lifecycle, inventory, task-definition/RLS/source/runtime bindings. Inventory/RLS receipts remain their original receipt types |
| Stage B infrastructure/RLS, receipts and application activation | OPERATIONAL_EXECUTION | Existing apply single-use reservation, broker/RLS authorization, database/runtime/readiness/rollback contracts; worker remains untouched |
| Rotation/final Gate terminal, complete verification and CAS | OPERATIONAL_EXECUTION | Same signed historical reference, exact live runtime, authenticated activation/receipts and current CAS generation; persist retention on the first component terminal |
| Accumulated-range closure and next eligible normal deployment | NORMAL_RELEASE_GATE | Existing completed-emergency-range receipts and per-component establishedThroughSha; normal history classification is not weakened |

Initial reference authority uses the existing bounded evidence freshness window. Complete prerequisite CI/gates before final fresh plan approval and do not activate production against expired authority. Once retention is committed, unrelated generations use the consumed durable proof rather than requiring a new historical approval. Reconciliation of an interrupted initial release must authenticate the persisted state first.

The implementation/tests remove the missing-reference and evidence-handoff source blockers. They do not establish current production IAM, broker version/configuration, fresh key/rotation/inventory/RLS receipts, candidate publication, protected-main freshness, or human approvals. These are ordinary release gates requiring fresh evidence after merge, not claims that execution is presently authorized. Existing signing-key/rotation and emergency-range completion gates must all pass before declaring release COMPLETE.

The next ordinary **eligible backend/frontend** commit uses existing PR/CI/merge, committed-baseline classification, normal component transaction, health verification, durable receipt and CAS. Retention stays unchanged through backend generation N+1 and frontend generation N+2. No new bootstrap, historical exception, manual AWS investigation or ChatGPT step is required. A worker-affecting/stronger-lane change remains subject to its existing stronger-lane controls; this PR does not automate worker lifecycle.

## Verification and bounded recommendation

Tests cover live identity substitutions, signed-handoff/body/hash/source/bootstrap/CloudTrail tampering, missing/deleted retention, extra workers, unsupported successor receipts, expiry and unknown write outcomes, CAS races, exact generator/plan acceptance, checker hash binding, both terminal writers, transport byte preservation, and real backend then frontend component transactions. Existing bootstrap/Stage B/normal/release/security contracts remain mandatory.

Recommendation: finish these existing fresh-evidence and approval gates first. Keep worker successor automation and the separately recorded printing/shutdown findings outside this recovery; add a successor contract only when a real governed worker deployment operation is separately authorized.

## Local verification ledger

Baseline: `a32d2cc8cf56914425ce49ac867569e7470dfd7a`. Production was not used to establish readiness; all runtime transition tests use injected readers and state clients.

- Focused historical-runtime, terminal, generator, approval-input and component-state suite: 384 passing tests, including 68 historical-runtime identity, authority, failure and lifecycle cases. Four additional broker rejection cases use real RSA-signed checker approvals and prove rejection before nonce consumption/task launch; matching hash and real full-RLS request transport are also tested.
- Canonical Stage B control-plane suite: 896 passing tests.
- Canonical normal-deployment suite: 146 passing root tests plus its existing backend startup/client-IP prerequisite.
- RLS package verification: 24 passing tests. Regeneration changed source/checksum bindings only; all eight changed SQL files are identical after normalizing their source-hash markers. No RLS semantics changed.
- Workflow YAML: 95 valid files. Capability graph: 666 capabilities, 213 classified AWS calls, zero unmapped calls or identity/manifest violations. Artifact-contract and rotation-contract checks passed.
- Additional expanded regression selection: 803/810 passed. All seven failures were independently reproduced from an extracted untouched base commit: six stale assertions in `production-green-stage-b-policy-split.test.mjs`, and the existing backend-health-recovery dependency-isolation test resolving `jszip`. These remain explicit review/CI blockers wherever those suites are required; they are not waived, rewritten or hidden by this correction.

Final hostile review checked omission/replay of evidence, self-rehashed bodies, source/tree/bootstrap substitution, role/network/environment/secret-reference drift, exact CloudTrail associations, additional workers hidden under renamed families, unsupported successor receipts, conditional-write loss/unknown outcome, post-CAS drift, raw-CAS writer substitution, expiry, unrelated backend/frontend generations, and transport/workflow ordering. The trusted component-state store remains the existing IAM/CAS authority; this correction does not claim protection against an administrator rewriting that entire authority outside the governed protocol.

The complete changed-path set still classifies as EMERGENCY_RECOVERY through unchanged classification rules; no normal-lane bypass was introduced.

No governed worker-successor proof exists. Supersession stays unavailable rather than being inferred from generic receipts or task disappearance. No remaining implementation gap was demonstrated in the tested retention vertical slice; live release readiness remains conditional on fresh exact-main evidence, bounded approval freshness, IAM readback, broker/configuration convergence, signing-key/rotation inventory, RLS/runtime receipts and protected human authorization. Existing unrelated base-test failures must be resolved or dispositioned by their owners before any gate requiring them can pass.

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

## PR #618 bounded CI and service-worker review closure

Reviewed head: `5f59efa0272854cdb59170c9fe9bb350fe43827e`. Before editing, a mocked inventory containing the exact historical worker and a renamed-family RUNNING service worker returned one worker and passed retention verification. Service membership was incorrectly used to exclude workload identity. It describes ECS management, not whether a task executes worker code.

The shared census now resolves every task definition before workload exclusion. Canonical worker role, immutable worker repository image and worker entrypoint/command (including effective task overrides) identify worker-capable tasks. Weaker worker-like signals are ambiguous and fail closed; unreadable/incomplete definitions also fail closed. Family/container names never authenticate a runtime. Service names do not classify workloads. Reference generation and terminal closure use the same census; the exact retained object still must match its signed standalone identity. No service worker is implicitly trusted.

New regressions cover 17 workload/override combinations, retained service-membership substitution and unreadable/incomplete service definitions. The actual reference generator and terminal inventory are exercised against the same renamed-service role/image/command/ambiguous and unrelated backend/frontend cases. Additional workers are rejected before package acceptance, and ambiguous definitions cannot disappear from inventory. This changes no printing, worker lifecycle or production resources.

### Required CI root-cause inventory

Five failed check instances (four names) share one first failing command: `npm run check:dependency-audit`. Release Candidate `rc-trust-critical`, Deployment Audit `quality-gates`, and AWS DR `validate` reach it through their source guardrails; both push/PR Quality Gate `security` jobs invoke the same gate. The exact gate fails identically on archived untouched base `a32d2cc8cf56914425ce49ac867569e7470dfd7a` and reviewed head; their root lockfiles are identical. No required checks were pending at this initial snapshot.

| Required check | Initial status | Evidence |
|---|---|---|
| audit | SKIPPED | [job](https://github.com/T-ej2003/genuine-scan-main/actions/runs/37086374607/job/111097593945) |
| rc-release-checklist | SUCCESS | [job](https://github.com/T-ej2003/genuine-scan-main/actions/runs/37086374582/job/111097567781) |
| docker | SUCCESS | [job](https://github.com/T-ej2003/genuine-scan-main/actions/runs/37086374693/job/111097432620) |
| rc-staging-smoke | SKIPPED | [job](https://github.com/T-ej2003/genuine-scan-main/actions/runs/37086374582/job/111097568507) |
| db-backed-auth-security | SUCCESS | [job](https://github.com/T-ej2003/genuine-scan-main/actions/runs/37086374599/job/111097431781) |
| Terraform staging validate | SUCCESS | [job](https://github.com/T-ej2003/genuine-scan-main/actions/runs/37086374560/job/111097431908) |
| rc-governance | SUCCESS | [job](https://github.com/T-ej2003/genuine-scan-main/actions/runs/37086374582/job/111097431980) |
| docker | SUCCESS | [job](https://github.com/T-ej2003/genuine-scan-main/actions/runs/37086334282/job/111097318273) |
| frontend | SUCCESS | [job](https://github.com/T-ej2003/genuine-scan-main/actions/runs/37086334282/job/111097318195) |
| rc-trust-critical | FAILURE | [job](https://github.com/T-ej2003/genuine-scan-main/actions/runs/37086374582/job/111097431708) |
| frontend | SUCCESS | [job](https://github.com/T-ej2003/genuine-scan-main/actions/runs/37086374693/job/111097432347) |
| gitleaks | SUCCESS | [job](https://github.com/T-ej2003/genuine-scan-main/actions/runs/37086374573/job/111097431562) |
| validate | FAILURE | [job](https://github.com/T-ej2003/genuine-scan-main/actions/runs/37086374703/job/111097431660) |
| integration | SUCCESS | [job](https://github.com/T-ej2003/genuine-scan-main/actions/runs/37086374693/job/111097432569) |
| Staging IAM policy lint | SUCCESS | [job](https://github.com/T-ej2003/genuine-scan-main/actions/runs/37086374560/job/111097431680) |
| security | FAILURE | [job](https://github.com/T-ej2003/genuine-scan-main/actions/runs/37086374693/job/111097432371) |
| quality-gates | FAILURE | [job](https://github.com/T-ej2003/genuine-scan-main/actions/runs/37086374607/job/111097431822) |
| backend | SUCCESS | [job](https://github.com/T-ej2003/genuine-scan-main/actions/runs/37086374693/job/111097432337) |
| integration | SUCCESS | [job](https://github.com/T-ej2003/genuine-scan-main/actions/runs/37086334282/job/111097318250) |
| db-backed-auth-security | SUCCESS | [job](https://github.com/T-ej2003/genuine-scan-main/actions/runs/37086334156/job/111097317685) |
| security | FAILURE | [job](https://github.com/T-ej2003/genuine-scan-main/actions/runs/37086334282/job/111097318142) |
| gitleaks | SUCCESS | [job](https://github.com/T-ej2003/genuine-scan-main/actions/runs/37086334149/job/111097317616) |
| backend | SUCCESS | [job](https://github.com/T-ej2003/genuine-scan-main/actions/runs/37086334282/job/111097318304) |

### Dependency remediation stop condition

The actual production dependency tree has one directly vulnerable installed `braces` instance and one advisory, [GHSA-vfj7-8cjw-p6xm](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm), high severity (nested brace-pattern stack exhaustion). The audit reports five affected package names through these paths:

- Direct `tailwindcss@3.4.19` → `chokidar@3.6.0` → `braces@3.0.3`.
- `tailwindcss@3.4.19` → `micromatch@4.0.8` → `braces@3.0.3`.
- `tailwindcss@3.4.19` → `fast-glob@3.3.3` → `micromatch@4.0.8` → `braces@3.0.3`.

All five root-lock entries are production dependencies; the vulnerable pattern parser is reached by Tailwind's file-pattern tooling. A build/watch exposure does not justify suppressing the production audit. The advisory has no patched braces release; npm registry latest remains 3.0.3. npm's offered Tailwind 4.3.3 remedy is a major migration, outside this bounded authorization. There is no compatible lockfile-only patch. Package manifests and lockfiles therefore remain unchanged. No waiver, ignore, audit threshold change or release bypass was added. Required CI stays blocked pending an upstream patch or separately authorized compatible removal/migration. Recommendation: review this isolated P1 correction, then scope dependency remediation separately; do not merge while required checks remain red.

The six policy-split assertions and one backend-recovery `jszip` isolation assertion are independent base failures, not dependency-advisory aliases. Re-running the same files on base and head does not justify weakening assertions. They were not the first failures of current required jobs and are left unchanged in this bounded correction.

### P1 correction validation

- Focused historical-runtime plus actual reference-generator tests: 298/298 pass (87 identity/retention tests, 211 generator tests); 19 new named regressions plus six generator/closure consistency combinations.
- Canonical Stage B control-plane suite: 915/915 pass; closure/bootstrap/component-state/reconciliation/release-workflow selection: 269/269 pass; normal-deployment suite: 146/146 pass plus backend startup/client-IP prerequisites. Counts overlap and are not summed as unique tests.
- Artifact contracts: 23/23 pass; full RLS verification: 24/24 pass. Workflow YAML: 95 valid; capability graph: 666 capabilities and 213 classified calls, zero violations. Branch-secret-diff and whitespace checks pass.
- The seven specifically reproduced base assertions fail on both exact base and head (8 selected tests: 1 pass, 7 fail). The source guardrails reach and fail at the unchanged dependency audit after their preceding guards pass. No PR regression was demonstrated in these failures.

Adversarial diff review checked service/family renaming, independent role/image/entrypoint/command signals, role/command/container overrides, mutable/foreign images, weak display-name signals, unreadable definitions, retained service substitution, unrelated services, shared generator/closure routing and unchanged exact-object matching. These tests prove this classifier boundary; they do not waive required CI or authorize production.

## Override projection P1 closure

Reviewed head: `12bc56b0333ce71df467e27714f1ba1bfe21fa8e`. Before editing, both renamed-standalone role-override and command-override reproducers classified raw ECS data as `WORKER` but `observeStageBEcs` output as `DEFINITELY_NON_WORKER`. The task projection discarded `overrides` before the shared census. This was information loss, not a classifier rule defect.

The projection now carries a detached copy of the existing ECS override structure, preserving all fields consumed by the canonical classifier (role, container name, command and entrypoint). Missing overrides remain missing. No alternate schema, classifier or worker authority was introduced. Overrides identify additional worker-capable tasks for rejection; they never authenticate the retained historical object. Signed reference/audit bindings cover the generated observations through the existing evidence chain.

### Bounded identity field audit

`historicalWorkerTasks` has two input routes: generator → `observeStageBEcs` → projected tasks; handoff/apply/closure → raw `describeTasks`. Both fetch full definitions directly from `describeTaskDefinition` inside the same census. Exact-object preparation/revalidation independently fetches the bound task and definition; it never consumes the reduced observation as a substitute for immutable/runtime identity.

| Field | Raw ECS available | Reference census | Apply verification | Terminal/closure |
|---|---|---|---|---|
| taskArn, taskDefinitionArn | Yes | Preserved | Raw read | Raw read |
| group, lastStatus, desiredStatus | Yes | Preserved | Raw read | Raw read |
| startedBy | If present | Not consumed by classifier or exact matching | Raw; not authority | Raw; not authority |
| overrides.taskRoleArn | If present | Preserved | Raw read | Raw read |
| overrides.containerOverrides[].name/command/entryPoint | If present | Preserved | Raw read | Raw read |
| Other override fields, including environment/executionRoleArn | If present | Complete overrides preserved; exact identity independently re-read | Raw, validated/hashed | Raw, validated/hashed |
| definition.taskRoleArn | Yes | Direct full definition read | Direct full definition read | Direct full definition read |
| definition.executionRoleArn | Yes | Not a census signal; direct exact-identity read | Validated and hashed | Validated and hashed |
| definition.containerDefinitions (image, command, entryPoint, name) | Yes | Direct full definition read | Direct full definition read | Direct full definition read |
| Complete definition content/environment/secret references | Yes | Exact identity independently read and hashed | Independently read and hashed | Independently read and hashed |
| task.clusterArn, launchType, platformVersion, createdAt | Yes | Exact identity independently read | Validated/hashed as contracted | Validated/hashed as contracted |
| task.containers[].imageDigest | Yes | Exact identity independently read | Validated | Validated |
| task.attachments + ENI subnet/IP/groups/public-IP | Yes | Exact identity + ENI independently read | Independently read and validated | Independently read and validated |

No other required census field was found lost. Deliberately absent display/metadata fields are not promoted to authority. Pending/transitional census tasks pass through the same task projection and override preservation.

Regression coverage adds twelve raw/projected semantic-equivalence cases (standalone/service role and command, entrypoint, ambiguous name, unrelated/backend/frontend overrides, absent/empty overrides), preserves raw identity against projected-object mutation, and extends actual generator-versus-terminal inventory checks with nine override variants. Existing retained-object override/source/command tampering tests still fail closed. No application, printing, worker lifecycle, IAM, dependency or production changes are part of this correction.

Recommendation: keep this field-preservation regression whenever census inputs change. Required dependency audit remains a separate unwaived blocker; do not merge until required CI and fresh exact-head review pass.

Override-fix validation: focused historical/runtime-generator 311/311 pass; canonical Stage B 927/927 pass (plus the final detached-retained-identity test in the focused run); closure/bootstrap/component-state/reconciliation 269/269 pass; normal deployment 146/146 pass plus startup/client-IP prerequisites. Artifact contracts 23/23 and full RLS verification 24/24 pass. Workflow YAML: 95 valid; graph: 666 capabilities, 213 classified AWS calls, zero violations. No manifest/lock changes or dependency remediation. Counts overlap and are not unique-test totals.

Final diff review verified full override preservation before every active-task status split, shared census use by reference/terminal paths, raw exact-identity re-read at apply/closure, independent copied observations, absent/empty compatibility and signed audit binding. No new AWS call, capability or production authority was added.

## Retained-state broker binding and runtime dependency closure

Correction base: `c48c5cc0cb5c40acc981851e31a3e77781fc5105`. The exact-head P1 was valid: full-RLS request construction read historical authority only from optional transport, while subsequent approval collection used durable retention. A later release could therefore sign one hash and send none.

Approval collection and full-RLS apply now call the same `resolveHistoricalRuntimeAuthority` helper over the existing signed handoff verifier. Full-RLS execution reads the canonical consistent-read component-state client and full ECS reader using the existing release-deployer credential runner. State schema/integrity, retained signature and exact live runtime/inventory are verified before any broker invocation. Initial transport retains bootstrap/source/freshness checks; retained state authenticates its consumed durable proof. Both present must agree, including the existing signed-binding identity constraint. Missing, malformed, unsigned, conflicting or unexpectedly removed authority fails before mutation. No environment hash overrides durable authority. No new evidence, IAM, worker operation or provenance enum was introduced.

The full-RLS regression executes all seven broker phases and the application canary for initial transport, retained state without transport, matching authorities, and retained authority after actual backend then frontend normal component transactions. The latter omits transport and uses a newer release source. Receipt/state generations advance through the existing transaction's intermediate CAS writes; retention remains unchanged and no normal receipt remains. Approval input and broker resolution return the identical canonical hash. Five execution-boundary failure cases assert zero broker calls. Existing real RSA broker tests reject request/approval hash mismatch before nonce consumption.

The dependency root cause is corrected in the manifest, not waived in the audit. `tailwindcss-animate` is imported only by `tailwind.config.ts`; its production peer edge had incorrectly promoted Tailwind's build parser closure. It moves to devDependencies with the exact same `^1.0.7` declaration and locked 1.0.7 release. npm regenerated lock metadata without changing any retained package version. The root production audit still checks browser-runtime dependencies; backend/worker still share the independently audited pruned backend lock. The final frontend Nginx stage still receives only built static assets. No audit code, severity, exception or threshold changed. The unpatched advisory continues to exist in build tooling; this does not claim it is patched.

Regression policy tests retain rejection of high runtime frontend/backend and transitive findings, prove worker/backend runtime packaging equivalence, and assert that the build-only Tailwind chain is dev-only in lock metadata and cannot enter the frontend runtime stage. Production audit now passes with zero high/critical runtime findings. Frontend build, all frontend tests, backend build/trust-critical/tests and the complete `verify:release:source` command pass after restoring incomplete local locked dependencies; no package upgrade was performed.

Mechanical full-RLS regeneration was required because authenticated source inputs changed. All eight changed SQL artifacts differ only by the source-contract hash/package marker; policy, grants and SQL behavior are unchanged. Generated checksum/catalogue/lifecycle records bind the new source rather than reusing stale evidence.

Validation: canonical Stage B control-plane 944/944; focused authority/full-RLS/approval/audit policy 219/219; full-RLS alone 15/15; normal deployment 146/146; closure/bootstrap/component-state/reconciliation 269/269. Full release-source pipeline passes, including 268 frontend unit tests plus 12 trust-critical frontend tests, backend checks/tests, dependency/security/deployment/DR guards. Additional RC smoke-config contracts: 33/33. Workflow YAML, artifact graph and capability/dependency graph pass; no new AWS capability. Counts overlap, not a unique total.

Hostile diff review checked raw-state/unsigned-retention substitution, omitted transport, deleted retention, conflicting transport, read failure, same/new source release after both normal transactions, shared resolver use, pre-broker verification ordering, request/approval equality, dependency version invariance, build/runtime separation, and unchanged high/critical runtime rejection. Recommendation: require fresh exact-head review and every legitimate required check before merging; then return directly to fresh protected-main release preparation. This repository work authorizes no production operation.

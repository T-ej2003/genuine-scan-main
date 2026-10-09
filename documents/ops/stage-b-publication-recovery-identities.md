# Recovering a published Stage-B broker with descendant tooling

A completed publication keeps its original `preparation.sourceSha`, tooling-input tree, package and receipt. A source correction never relabels that version or permits a replacement publication merely to advance its source.

`prepare-cutover` authenticates the original native `PUBLISHED` receipt, immutable version and source authority. If the executing checkout differs, it must be clean canonical protected main and an authenticated descendant of the publication source. The cutover preparation records `recoveryTooling.sourceSha`, its tree digest and the original publication-result digest. Fresh cutover and state-refresh authorizations bind that complete preparation. Alias CAS and closure preserve the original release source. An unrelated, sibling, ancestor, dirty or unverifiable checkout fails.

For output reconciliation, supply the original canonical publication planning inputs to `prepare-cutover`. The producer authenticates the tfvars binding and canonical refresh report. Only the exact reviewed output name, before value and after value are included in `outputReconciliation`, bound to the publication result, immutable broker target and cutover state. Cutover and post-CAS refresh require the identical set of changes. Closure requires every reconciled output to be a no-op at its approved after value. Other drift fails; no output name is globally mutable.

After reconciliation, preserve a private digest-bound transport `{ "request": <successful reconcile request>, "result": <authenticated result> }`. The canonical `run-production-green-stage-b-preflight.mjs`, checker-trust attestation, and approval-input producers accept its path through `--broker-recovery` and its exact SHA256 through `--broker-recovery-sha256`. They authenticate native publication/reconciliation receipts, current protected tooling, live alias/version and resulting Terraform state. The preflight attestation preserves the original release source and binds the separate tooling source and recovery references; the approval payload retains the original broker release source. A raw caller-supplied recovery label or unsigned observation is not authority.

Recovery does not renew expired mutation authority. Prepare and authorize the remaining exact write; authenticate completed receipts read-only instead of replaying registration, pruning, policy convergence, publication or alias CAS. Keep the original publication source distinct from the new tooling checkout in operator records.

Approval publication uses the existing public `publishStageBApproval` operation with `expectedSourceSha` set to the authenticated original release source. Its independent-checker signature, approval ID, and idempotency token continue binding that release; the tooling checkout is not an approval relabelling input.

## Original renderer and rotation handoff

Original-release task expectations execute the exact Git commit's task renderer, Stage-B constants, runtime-dependency validator and JSON templates together. These bytes are materialized as one private Git archive and evaluated in a separate process without inherited credentials. Missing modules, unsupported Git entries, symlinks or failed original validation stop recovery. The descendant renderer never fills gaps in original material. The normal same-source renderer remains unchanged.

The rotation bootstrap accepts the same native `--broker-recovery` / `--broker-recovery-sha256` transport as preflight. Its public producer authenticates completed publication, cutover and closure before selecting the original release source. It independently requires the executing checkout to equal the authenticated clean protected-main tooling identity. The image authorization, administrator report, checker-trust report, root-drop proof, inventory operation and rotation configuration retain the release source. The checker-trust report must bind the identical recovery references, and the image release must match the authenticated broker. Runtime configuration and the preparation manifest record the separate recovery-tooling binding. `PROTECTED_MAIN_SHA` reports tooling; `RELEASE_SOURCE_SHA` reports the immutable release.

This handoff does not authorize a replacement publication, inventory registration, alias replay, new rotation, shorter grace or broader IAM policy. A rotation task newly prepared by trusted tooling is a new exact authorized payload; it cannot alter the identity of the previously published broker or its task expectations.

The public regression now executes administrator preflight, release readiness, original checksum materialization, tfvars generation, live observation, approval collection/preparation and rotation bootstrap in a sealed descendant checkout. Its generated checksums differ from the original release. A signed historical-runtime handoff remains mandatory; inventory revision 7 stays selected and registration is forbidden in the fixture.

Rotation bootstrap scans live ECS observations without confusing canonical `secrets[].{name,valueFrom}` selectors with secret values. Only exact reference objects accepted by the existing production Secrets Manager parser receive this treatment; plaintext, extra fields, malformed selectors and foreign-account references still fail closed. The original report bytes and signed digest are unchanged.

### Fresh operational evidence audit (PR #647)

The QR selector proves a fresh live read performed by protected recovery tooling,
not the source that previously published the broker. Its GitHub workflow/run,
artifact digest and payload must all bind the authenticated tooling SHA. Bootstrap
rechecks its 30-minute lifetime, ticket, exact task definition and AWSCURRENT
version. Neither an old release-source proof nor another tooling source supplies
this authority.

| Artifact | Producer → consumer | Lifetime / regeneratable | Expected identity | Reason |
|---|---|---|---|---|
| Published broker / publication receipt | Native publication → cutover, closure, recovery | Durable / no replay | RELEASE_SOURCE | Immutable version and code provenance |
| Reviewed output reconciliation | Native preparation → cutover and state refresh | Exact state predecessor / reprepare | RELEASE_SOURCE | Authenticates original release's exact output transition |
| Historical checksums, migrations, package, full task renderer | Original Git tree → public tfvars producer and approval collector | Immutable / reconstruct exact bytes | RELEASE_SOURCE | Descendant bytes must never redefine release contracts |
| Image authorization and image identities | Canonical image producer → preflight/bootstrap | Authenticated immutable publication; no QR-style TTL / reuse only under compatibility contract | RELEASE_SOURCE | Preserve original release and reusable image publication |
| Administrator report and release-preflight/attestation | Public preflight/checker → approval/bootstrap | Fresh report / regenerate | RELEASE_SOURCE with authenticated RECOVERY_TOOLING binding | Current observation of the exact original release target |
| Stage-B approval | Canonical approval producer → reviewed broker | Expiring / renew exact approval | RELEASE_SOURCE | Broker version and original contracts determine approval target |
| QR selector resolution | Protected workflow → GitHub artifact resolver → bootstrap | 30 minutes / regenerate | RECOVERY_TOOLING | Fresh operational live selector read from current protected main |
| Root-drop signature | Canonical root operator producer → bootstrap/control plane | 15 minutes / regenerate | RELEASE_SOURCE with authenticated RECOVERY_TOOLING execution | Exact rotation/image/administrator continuity; administrator digest binds the recovery tooling |
| Artifact-signing binding | Canonical bootstrap → runtime constructor | Durable / authenticate existing binding | RELEASE_SOURCE | Key bindings belong to original selected release |
| Rotation config, readiness and runtime verification | Bootstrap / governed overlap / independent verifier → rotation lifecycle | Transaction/state-bound / reconcile | RELEASE_SOURCE with authenticated RECOVERY_TOOLING execution | Original deployment identity survives; verifier's checkout is protected recovery tooling |

| Overlap workflow, job, production deployment and receipt artifact metadata | Release Gate → overlap receipt resolver | Exact run/attempt / fresh governed execution | RECOVERY_TOOLING | GitHub execution provenance identifies current protected tooling |
| Overlap receipt payload | Governed deployment → receipt resolver / overlap verifier | Durable exact deployment / reconcile | RELEASE_SOURCE | Receipt describes the immutable release; native recovery context independently binds its producer tooling |

The overlap resolver derives workflow provenance only from the authenticated native
recovery context, never a caller-supplied alternative SHA. Run, job, GitHub deployment
and artifact metadata must match that tooling identity. Receipt payload source must
independently match the original release. Missing/cloned recovery authority, mismatched
run/job/artifact sources or a receipt relabelled as the tooling release fail closed.
The verifier also requires the resolved workflow SHA to equal the digest-bound runtime
configuration's `recoveryTooling.sourceSha`. Two different authorized descendants
cannot contribute to one overlap operation. The canonical prepare-overlap producer
records that execution SHA in its hashed readiness evidence; Release Gate compares
it with its authenticated checkout and re-fetches protected main immediately before
the overlap ECS deployment step. Cleanup keeps its separate existing readiness
contract. If protected main
advances before Release Gate executes, the C-bound configuration cannot be paired
with a D workflow. Before native preparation, regenerate a D-bound runtime and
fresh operational proofs. After native preparation, preserve the C artifacts and
reconcile the native rotation state; dispatch only after a canonical D-bound
preparation and exact authorization can be authenticated. The current bootstrap
requires a fresh output directory and has no
proven automatic import of an already-prepared C rotation state/fixture into D;
stop at that boundary rather than copying or relabelling them. If main advances
after a C workflow executes, authenticate and finish that C operation from its
original configuration and receipt; do not rewrite the C configuration or
historical closure. The public fixture proves rejection and post-execution
continuation, not cross-directory native state migration.
The sealed public descendant test continues through the governed overlap operation,
receipt resolution, independent overlap verifier and native rotation verification
adapter into persisted `verified` state. The original release identity survives and
the full 30-day cleanup deadline is calculated from actual fixture verification time.
These fixtures prove contracts, not a production deployment or business acceptance.

Root-drop and independent overlap verification use the existing native broker
recovery transport and digest when their selected release is historical. The
native reader authenticates publication, closure, lineage and clean protected
checkout before either producer/verifier may execute from descendant tooling.
A recovery config without that authenticated context is rejected. Fresh root-drop
signatures retain the release source; they do not change the published broker.

Release Gate's rotation deployment job checks out its explicit
`EXECUTION_SOURCE_SHA` (the workflow's protected-main SHA), independently of
`DEPLOY_SHA` / `RELEASE_GIT_SHA`. Before credentials or writes, it verifies the
clean exact checkout, original release ancestry, and current protected-main
identity for descendant tooling. The existing historical-target authorization
(Release Train identity or exact release tag), required gates, environment
approval and release-bound readiness remain mandatory. Normal application
release checkout behavior is unchanged. The full fixture executes the actual
YAML target-resolution and checkout-verification shell blocks against a private
local Git origin before the overlap operation; workflow metadata alone is not
proof of which checkout executed the scripts.

Release Gate YAML participates in the canonical clean-room RLS source contract.
A workflow correction therefore requires `npm run rls:full-generate` and
`npm run rls:full-verify` for the descendant tooling tree. Those newly generated
checksums and SQL contract markers belong to B; recovery must still load the
original A material from its exact Git tree for the already-published broker.
Regenerating B evidence neither republishes broker13 nor renews mutation authority.

## Hostile review after PR #648 integration — 2026-10-09

Protected main is `931bf86391d57cd0489162f8ef7b73f1896a42aa`; its tree exactly matches PR #648's reviewed `33e4a55757` tree. All 33 merged-head checks, including Deployment Audit, Docker and database integration, succeeded. PR #647 preserves `a76c1a1e65` through a merge, without rebasing its reviewed commits. Generated RLS and OSV evidence conflicts are resolved by canonical regeneration and a fresh reachability review of the combined inputs. SQL changes remain generated contract markers rather than database policy changes.

| Evidence boundary | Immutable identity | Executing identity | Review result |
| --- | --- | --- | --- |
| Published broker, package, receipt and alias target | Original A / authenticated v13 | Authenticated descendant B | No publication or identity rewrite permitted |
| Cutover and post-CAS reconciliation | A, exact output before/after and broker identity | B with native publication-bound lineage | Other output drift rejected; closure consumes the same evidence |
| Historical checksum, migration/package/source contracts | Exact Git material A | B supplies tooling | Public tfvars producer authenticates A bytes; collector independently expects A |
| Task expectations and hashes | Complete original renderer A | Isolated original Git archive invoked by B | No current constants or renderer fallback |
| Approval collection/preparation/publication | Release A | Recovery context explicitly binds B | Signed historical handoff and exact live broker remain mandatory |
| Fresh QR selector and GitHub artifact | Operational B | B | Expired evidence can be regenerated without relabelling A |
| Rotation bootstrap/config/root-drop | Payload A, explicit recovery references | B | Both identities must authenticate; inventory reuse remains exact |
| Release Gate rotation execution | Deployment/rotation A | Clean protected-main B | Existing image authorization and deployment guards preserved |
| Overlap receipt / verification | Receipt payload A | Workflow, job and artifact B; environment authority describes release A | Native authenticated A→B context mandatory |
| Initial overlap and later normal release | Their independently authenticated release identities | Exact governed source | No automatic release dispatch or production proof inferred from tests |

New main changes Docker base identities and generated release contracts. They belong to B and cannot be substituted into v13's original release material. Future application image reuse must be decided by the canonical impact classifier; registry remediation does not authorize reuse of incompatible images.

Self-review: P0=0; P1=0 in the inspected changed recovery path. One P2 fixture hygiene issue was found by the local branch guard: new synthetic VPC IDs and literal secret references. The regression now uses the existing Stage-A fixture VPC identity and secret-ARN fixture helper; the guard is unchanged. No production implementation was changed for this finding. All callers, optional source/checksum defaults, original-renderer dependencies and workflow/payload provenance splits were inspected. The clone-based public handoff must be rerun from the committed merged head, followed by new exact-head GitHub review and CI. Previous head results do not approve the merged head.

Recommendation: keep the complete descendant public-handoff regression required whenever workflow provenance, original release rendering or artifact resolvers change. Production execution and live adoption remain outside this validation task.


## Advancing operational tooling after immutable closure — 2026-10-10

The previous review missed a permanent closure-checkout restriction. The native
reader, closure revalidation and returned recovery context all reused the
historical execution checkout as today's checkout. A legitimate protected-main
advance therefore stranded fresh preflight and rotation evidence. That earlier
P1=0 conclusion is superseded by this audit.

Three identities are independently authenticated:

- A is the original release, including the publication receipt and v13.
- B is the signed historical cutover/closure execution. Its preparation, signature,
  source/tree and A→B ancestry remain mandatory and immutable.
- C is the clean canonical current protected-main checkout. B→C ancestry and its
  exact tree are authenticated independently; a later D is authenticated afresh.

The read-only recovery reader uses current checkout C. Mutating executors still
require the exact prepared execution checkout and exact authorization. No
historical receipt is rewritten and no mutation is authorized by ancestry alone.
A recovery context is branded only after complete native signature/receipt,
publication, live alias/version, Terraform state and prerequisite authentication.
It exposes `historicalTooling` B separately from `tooling` C.

| Boundary / producer → consumer | Release / payload | Historical execution | Current execution / workflow | Required proof |
| --- | --- | --- | --- | --- |
| Publication → adoption | A / immutable v13 | Publication preparation | C only reads | Native signed receipt, exact code/version and original authority |
| Cutover → CAS → output reconciliation → closure | A and exact reviewed outputs | Signed B | Future reads from C | Native signed B preparation, exact publication and output set; no replay |
| Closure → recovery approval | A | Immutable B closure | Clean protected-main C | A→B→C lineage, exact trees, native receipts and unchanged live state |
| Administrator/checker/release preflight | A / original contracts | Closure digest B | Fresh C | Exact signed report context C plus A publication/B closure digests |
| tfvars/binding → approval collection/preparation | A checksums, full original renderer and images | Publication / retained-runtime receipts | C | Original Git A bytes independently authenticated; no current-tree fallback |
| Fresh QR workflow → resolution → bootstrap | Operational identifier | None | Workflow/job/artifact C | Exact fresh C, expiry, selector/task/secret binding; unrelated sources fail |
| Fresh root-drop → bootstrap | A release payload | Prior signed evidence, if adopted | Current producer C | Native release/root trust and current protected-main recovery context |
| Bootstrap → runtime config | A and exact inventory predecessor | Config execution E recorded | Fresh producer C creates E=C | Exact C report/QR and original A material; no registration replay |
| Release Gate → completed deployment receipt | Receipt A / rotation A | Workflow E | E=C when executed | Native environment approval plus run/job/artifact E and exact A payload |
| Completed receipt/config → overlap verifier | A | Recorded E, unchanged | Current C or later D | B→E→current lineage, E tree, current protected main, exact A/B anchors |
| Runtime verification → terminal overlap handoff | A / same rotation | Completed deployment E | Current authenticated verifier | Exact task/image/state/readiness/receipt and native runtime acceptance |
| Initial overlap → Release Train / Release Gate | Independently selected exact release | Authenticated rotation evidence | Explicit governed workflow checkout | Existing gate/compatibility/approval contracts; no implicit deployment |

Completed workflow evidence is not a fresh selector: it retains its original
execution E and must satisfy B≤E≤current. Fresh selectors and freshly signed
preflight reports must match current tooling exactly. Runtime configuration
adoption authenticates E's tree and unchanged A publication/B closure anchors;
it does not modify the configuration to match C or D.

The clone-based public regression commits B, C and D against a private Git origin,
keeps different original/current checksums, runs the actual public preflight,
approval, root-drop, QR/bootstrap, Release Gate checkout shell and overlap
verifier, then verifies C's completed deployment/configuration from D. All
external mutation boundaries are controlled fixtures; live AWS is never invoked.
Completed publication/registration/pruning/policy/closure call counts and B's
handoff bytes must remain unchanged. Exact-head CI and review are still required.

Docker diagnosis is independent: both original failed jobs and the PR rerun fail
before Compose assertions while pulling the approved immutable Alpine image,
with `toomanyrequests: Rate exceeded`. This is registry throttling, not evidence
of an application assertion or image-identity defect. No Docker/security workflow
change is included in this recovery correction.

Recommendation: retain this complete advancing-tooling fixture when any recovery
artifact producer or consumer changes. Do not use passing controlled tests as
production deployment or business-acceptance evidence.


### Final hostile self-review of the advancing-tooling correction

| Severity | File / contract | Failure mode found | Correction / remaining state |
| --- | --- | --- | --- |
| P0 | Complete inspected recovery graph | None found | 0 known |
| P1 | Native executor reader, closure and recovery approval | Historical B was permanently required as current tooling | Authenticate signed B independently; authenticate clean protected-main C/D through existing canonical ancestry; preserve historical bytes |
| P1 | Overlap receipt resolver | Completed workflow E was incorrectly required to equal today's tooling | Authenticate workflow/job/artifact E, B→E→current lineage and unchanged payload A independently |
| P2 | Public overlap verifier | A completed runtime config E could strand verification after another main advance | Authenticate exact E tree and original A/publication/B-closure anchors without rewriting config or replaying deployment |
| P2 | Read-only closure proof adapter | New execution-source verification needed a synchronous native adapter | Wire the same native boundary for direct closure readers; no permissive fallback |
| P3 | Independent clone fixtures / CI registry | Local disk exhaustion and external immutable-image throttling | Private advancing-origin fixture shares Git objects; one proven merged clean worktree removed; Docker checks unchanged |

All P1/P2 findings above are corrected. Remaining known P0=0, P1=0, P2=0 in
the inspected changed recovery path. The complete branch diff, all six public
recovery-reader callers, direct closure callers, optional/default checksum/source
selection, original renderer dependencies and artifact resolver identities were
reviewed. No ambiguous identity boundary remains in this changed public handoff.

Current local evidence: 93 focused tests passed, including the real private-Git
A→B→C→D public handoff with different contract inputs at each operational advance;
1,626 broader tests passed with two existing skips; 151 audit/OSV policy tests
passed; both actual Docker Compose tests passed. Canonical source security,
workflow YAML, capability/dependency closure, RLS verification, fresh OSV/browser
reachability and diff checks passed. Disk-limited earlier runs are failed attempts,
not passing evidence. The successful final broader run includes the previously
blocked independent image-reuse CLI clone test.

PR #647 is not merged. New exact-head Codex review and required CI must pass
before it can be considered merge-ready. Production mutations remain zero;
controlled fixture verification does not claim production deployment.

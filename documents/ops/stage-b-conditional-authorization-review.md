# Stage B conditional authorization: implementation and hostile review

Status: **production-disabled implementation; review required before merge**. This document grants no production authority. No production workflow, authorization issuance, KMS signing, inventory operation, infrastructure change or deployment was performed.

Baseline: `b1fb80e051d58dfba37149b5cd26d88808928f6a`, authenticated against freshly fetched `origin/main`. Worktree: `/private/tmp/mscqr-conditional-authorization`; branch: `codex/stage-b-conditional-authorization`. Authoritative private specification: `CONDITIONAL_AUTHORIZATION_IMPLEMENTATION_SPEC.md`, exact SHA-256 `87c3f139c98ab8d93e120e2eaf3180514b2e257a090f85f11aa8e9f989227367`. Historical broker release and original rotation/inventory evidence are not rewritten.

## Implemented path and trust boundaries

1. The existing `prepare-production-cutover-runtime.mjs` accepts an opt-in, hash-bound `--conditional-seed` / `--conditional-seed-sha256` pair. It rejects the conditional branch before credentials or input access while the source flag is false. The canonical bootstrap emits static auxiliary files without consuming root evidence or verifier MFA. The derivation builder prepares an exact **no-op** infrastructure plan, seals source/modules/lockfiles/native tools and required inputs, checks fresh authoritative observations, and publishes the preparation through the existing encrypted coordinator store. It does not dispatch the approval workflow.
2. `production-cutover-conditional-issuance.mjs` issues only ROOT_DROP, INVENTORY_ADOPTION or ROTATION_SUCCESSOR authority envelopes. Each uses a separately approved exact-message request, the actual root or independent-checker STS principal, its correct concrete KMS key, canonical policy and public-key fingerprint, a confirmed conditional issuance claim, distinct dispatch/result/completion records, one native Sign attempt, and local RSA-PSS verification of the returned signature. Issuance never requires the later four-envelope bundle. The approved request digest records the external human approval boundary; possession of a self-hash alone is not approval.
3. The existing protected Stage B release-transition workflow has an isolated `prepare-overlap-conditional` producer. It authenticates the private preparation reference, protected tooling SHA, historical release SHA, ticket, workflow, environment, actual independent reviewer and attempt 1. It emits the exact `production-stage-b-conditional-overlap-authorization` / `authorization.json` contract consumed by the verifier. It returns before broker hydration, publication, alias cutover, Terraform or KMS operations. Existing broker phases retain their paths.
4. The existing operator's `conditional-continuation` mode invokes the continuation **in the same process**. It verifies all four authorities, claims the global rotation/predecessor execution, establishes interactive verifier MFA, rechecks that process-owned session, authenticates the separately approved QR artifact, and only then enters root signing and exact runtime materialization.
5. Actual root/adoption/successor signing CLIs accept only a journal-issued native signer capability. A plain callback cannot bypass the claim. The native boundary verifies the phase, exact key, canonical message, runtime and dependency hashes, identity, private output availability and confirmed dispatch ownership. Root writes are exclusive in this lane. Successor signing defers state/fixture persistence to the separately authorized prepare-overlap phase.
6. The canonical runtime composition constructs the production adapters and calls the existing PREPARE_OVERLAP control plane. A substituted composition object, caller-created context, alternate config, FULL mode or arbitrary effect is rejected. The real state adapter writes only the signed successor state and original fixture. The real task consumer rebuilds and checks the complete fixed task payload, roles, secret selectors, image and operation/execution tags. It requires a native claim before registration. Readiness requires confirmed local persistence and confirmed or independently reconciled registration.

`CONDITIONAL_LANE_ENABLED` remains a literal `false` in protected source. No environment variable enables it, and there is no legacy fallback from a rejected conditional request. The workflow rejects the branch before AWS credentials. Existing approved exact-hash execution remains available and now checks the shared rotation conflict at its signing/operator/registration boundaries.

## Freshness and bounded execution

- Root-drop remains **900 seconds**; QR remains **1800 seconds**. Existing consumer checks remain authoritative and run again before native effects.
- Authorization payloads bind an absolute execution window of at most 30 minutes. Advance issuance is bounded to at most 30 minutes before that window; it does not permit early execution or move either endpoint. This proposed issuance policy needs governance acceptance before activation. Actual GitHub approval observation freshness remains independently enforced.
- The sealed window must end before the pinned administrator signature, checker signature, image observation/signature and Stage B approval expire. Renewal changes the derivation and requires new authorities.
- The root path has a monotonic budget of at most 780 seconds, leaving reserve inside the unchanged root TTL. QR must have sufficient remaining lifetime before root dispatch. Evidence can still expire or AWS can fail; the result is a stop, not an extended TTL.
- Immutable preparation happens before signing. Conditional consumption reads the sealed plan and verifies current Terraform state and live execution-role policy; it never regenerates or applies a plan.
- Native signing/registration runners require `AWS_MAX_ATTEMPTS=1` and `AWS_RETRY_MODE=standard`, isolate credentials, pin executable bytes and use a 60-second child deadline. Live observations, source/identity checks and exact file hashes are revalidated; cached success is not authority.

## Execution state machine and ambiguous outcomes

`UNCLAIMED -> CLAIM_CONFIRMED -> DISPATCH_RESERVED -> RESULT_RECORDED -> COMPLETED_CONFIRMED`.

A lost claim response grants no ownership. Failure after dispatch reservation is `OUTCOME_UNKNOWN`; neither a write-once result object nor a previous PASS permits retry. The global rotation claim is independent of substituted authorization/predecessor IDs, and both execution lanes contend for the same decision key. Claims are not removed or automatically rearmed.

**KMS:** a successful Sign with a lost response can be unrecoverable. The caller cannot recover by signing the message again. A captured result is recorded separately from verification and completion; artifact-write or verification failure never triggers another Sign.

**ECS:** the actual registration consumer attempts bounded read-only reconciliation after an ambiguous result. The proof must come through the authoritative reader, with complete task/audit pagination, one exact active task definition, exact content/tags, the same registeredBy/session, execution ID, request, operation identity and 60-second dispatch interval, plus a unique native CloudTrail event/request ID. Read-only reconciliation has a maximum 30-second total deadline and a 16 MiB cumulative response bound; only matching task definitions are retained. Missing, denied, delayed, conflicting or insufficient evidence remains UNKNOWN. Reconciliation appends proof; it grants no new registration permission.

These are **at-most-one application dispatch permissions**, not exactly-once AWS execution. No AWS idempotency guarantee is invented. An ambiguous local state/fixture write can leave partial local files and remains stopped for review; it does not authorize production changes or automatic replay.

## Hostile review: confirmed corrections

| Attack / integration defect | Enforcement |
| --- | --- |
| CA-01 Caller-created context or native callback bypasses journal ownership | Journal-issued in-process capabilities required at actual signing and prepare-overlap consumers; copied/plain values rejected. |
| CA-02 Issuance uses another authority or stale/changed key | Exact STS authority, key/policy/public-key checks, concrete root-drop alias resolution and pre-dispatch rechecks. Root-drop and root-attestation keys remain distinct. |
| CA-03 Claimed Sign receives substituted key, message, phase or dependency | Validate before native dispatch, then verify actual signature and exact result. |
| CA-04 Protected workflow artifact substituted or self-reviewed | Actual GitHub run/artifact digest, source, workflow, attempt, environment configuration and reviewer checks; production serialization round trip tested. |
| CA-05 JSON duplicate/prototype keys or byte/hash confusion | Strict parser, canonical payload hashes and separate exact-file/runtime byte hashes. |
| CA-06 Role/source/runtime/secret/task/tag substitution | Entire derivation and exact canonical task/native request comparison; factory config must equal materialized config. |
| CA-07 Sealed plan overwritten by late planning | Conditional adapter uses saved no-op bytes, current state and current policy, with no init/plan/apply during consumption. |
| CA-08 IAM, Stage A, artifact secret or deployment operation leaks through composition | Conditional control-plane skips reconciliation/bootstrap/provision, rejects Stage A apply, requires no-op infrastructure and PREPARE_OVERLAP, and applies a native read allowlist. |
| CA-09 Legacy lane races conditional lane | Shared atomic rotation sentinel plus actual legacy signing/operator/registration guards. |
| CA-10 Wrong result overrides failed inner command, lost Sign or lost registration response | Native result handling and durable records; unknown Sign cannot replay; ECS exact read-only reconciliation only. |
| CA-11 Unusable output directory burns a signature | Private output/path/availability checks before Sign, exclusive conditional outputs and no automatic replacement signing. |
| CA-12 Executable or pinned evidence changes | Exact source/file/tool census and private-path checks; existing root/QR and pinned-evidence expiry checks retained. |

Reviewed source boundaries: [issuance](../../scripts/aws/production-cutover-conditional-issuance.mjs#L30), [prepare authority](../../scripts/aws/production-cutover-consumption-journal.mjs#L85), [native signer](../../scripts/aws/production-cutover-consumption-journal.mjs#L98), [protected producer](../../scripts/aws/production-cutover-conditional-workflow.mjs#L47), [canonical adapters](../../scripts/aws/production-cutover-production-adapters.mjs#L263), [native registration](../../scripts/aws/production-overlap-task-definition.mjs#L162), and [disabled source gate](../../scripts/aws/production-green-stage-b-contract.mjs#L577). No framework-specific Node CLI reference was available in the security skill; the review focused on input validation, authority separation, credential isolation and native mutation boundaries.

No confirmed P0/P1 source integration finding remains from this local review. Independent PR/security review is still required; this statement is not production readiness or proof against every possible defect.

## Validation and limits

- Focused conditional contract, issuance, workflow, journal, replay, expiry, credential and native-fault tests passed. Tests use local cryptographic keys and mocked external services, never production KMS.
- The integrated rehearsal enables only a disposable source copy. It exercises actual protected-workflow issuance serialization, the existing runtime bootstrap, canonical runtime composition, actual conditional state, artifact, checker-chain, Stage A, saved infrastructure-plan, completed-inventory, readiness and ECS adapters, the actual control plane, encrypted coordinator object interfaces, and native lost-registration read-only reconciliation. A caller callback cannot stand in for the actual phase capability.
- Other control-plane evidence/discovery inputs in that rehearsal are authenticated-shape fixtures. This is **not** an entirely unmocked production entrypoint-to-AWS test. Full live observation/sealing, hosted GitHub approval transport, real permissions/CloudTrail availability, physical MFA, timing under live AWS latency and production acceptance are not established here. No `END_TO_END_PASS` production claim is made.
- Final cutover/runtime/producer/credential/verifier/rehearsal and conditional validation passed **249/249** tests before the final bounded-reconciliation fault test; the final exact-head run is recorded in the PR. This includes the static-preparation, saved no-op plan, native-entrypoint, issuance and canonical composition checks after the security corrections.
- The broader Stage B run recorded 1,758 passes, two skips and one disk-space failure in an existing full-clone CLI fixture. That unchanged CLI test passed separately using sparse/shared local clone transport to omit unrelated installer blobs. The original broad run is not relabeled green.
- Frontend tests passed 296/296. Production frontend build, typecheck, changed JavaScript syntax, source security guardrails, 99 workflow YAML checks and whitespace checks passed. Source security checks reported the existing three missing optional release-evidence references; they are not filled or fabricated.
- Full hosted CI and independent review are pending. Full repository CI is not claimed locally. Logs are retained under `/private/tmp/mscqr-conditional-*.log`; no private production evidence or credentials are committed.

## Operator interface after separate governance approval

These commands are interface descriptions, **not executable production approvals**. They fail at the source-disabled gate today.

1. Use the existing runtime preparation command and all its normal authenticated recovery inputs, adding `--conditional-seed PRIVATE_FILE --conditional-seed-sha256 EXACT_FILE_SHA`. It returns the sealed derivation digest, coordinator release ID and preparation reference. It does not sign or dispatch.
2. Build each exact phase request with `conditionalIssuanceRequest(D, payload)`. Obtain separate approval of that phase's exact request, key, source and command. Invoke `production-cutover-conditional-issuance.mjs` with `--derivation`, `--derivation-sha256`, `--request`, `--request-sha256`, `--approved-request-sha256`, and `--output`. File SHA arguments are exact bytes; approved-request SHA is the canonical exact-message request digest. One phase is one independently approved invocation.
3. Separately authorize the existing Stage B transition workflow for `prepare-overlap-conditional`, using the returned preparation reference, historical `source_sha`, exact protected `tooling_sha`, ticket, release ID and round `0`. Its protected production environment requires its own reviewer. Download/verify its artifact through the canonical consumer; never hand-create the fourth envelope.
4. After all four authorities are valid, separately approve/obtain fresh QR evidence. Invoke the existing operator with `--mode conditional-continuation` and the seven exact derivation/bundle/workflow/QR arguments consumed by `runConditionalContinuationCli`. Require outer `TF_WORKSPACE=default`, `AWS_MAX_ATTEMPTS=1` and `AWS_RETRY_MODE=standard`; interactive verifier MFA stays in that process. The lane ends at authenticated prepare-overlap readiness, with zero UpdateService calls.
5. Deployment, approval publication, infrastructure changes and any recovery from terminal ambiguity remain outside this lane and require their own existing authorizations.

## Remaining governance and production readiness

Before any activation: approve the phase authority mapping and bounded advance-issuance policy; authenticate the merged tooling SHA and all new source-bound approvals; review exact claim/receipt prefixes and existing least-privilege permissions for each actual principal (including consistent DynamoDB receipt reads and CloudTrail reconciliation reads); verify retained audit availability; approve a timed non-mutating rehearsal; and authorize production use separately. No IAM grant or feature activation is included in this change.

Recommendation: keep the first enabled operation limited to prepare-overlap readiness, retain the 120-second root reserve, and accept a stopped UNKNOWN outcome rather than weaken replay protection. Validate journal/audit access and private output storage before starting any short-lived chain. Broader deployment automation or additional features are outside this correction.

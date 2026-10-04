# Generic release prerequisites and broker-policy ownership

This local implementation extends the existing Stage B runner. It does not add a workflow, table, writer role, or deployment service. Production execution remains separately approved. Application-only releases with no broker transition retain the existing path.

## Release sequence

1. Authenticate protected main and exact-main immutable image publication.
2. `prepare-publication` diagnoses prerequisite changes. It returns `prepare-registration` when canonical task definitions need registration, then `prepare-policy` when broker policy convergence is needed. Preparation performs no mutation.
3. `prepare-registration` captures an independently approved saved plan targeting the canonical task-definition resources. `authorize-registration` signs its exact source/tree, binary/logical plan, executable artifacts, state, alias predecessor, and prerequisites. `register` consumes that authority once.
4. Registration authenticates the returned concrete ARNs/revisions against Terraform state and ECS readback. The execution receipt binds the desired definition, immutable images, source/tree and authorization. No service update, task launch, worker replacement, or traffic change is authorized. Predecessors remain registered (`skip_destroy`).
5. Derive the broker task map from those authenticated outputs. Derive its IAM target by replacing only the exact executor/canary revision resources in the canonical broker policy. There is no latest-version lookup or revision arithmetic.
6. `prepare-policy`, `authorize-policy`, and `converge-policy` bind the exact predecessor and derived successor. A native single-attempt policy-version write is serialized as described below. A validated Terraform refresh-only saved plan reconciles state; a fresh normal policy plan must be no-op.
7. Existing publication, cutover approval, native alias RevisionId CAS, and refresh-only alias reconciliation follow. Registration and policy convergence receipts remain nonterminal. Full-RLS/task-launch authority remains closed until existing terminal release/component-state gates pass.

Use `node scripts/aws/run-stage-b-staged-broker.mjs --input <private-request.json> --input-sha256 <exact-request-hash> --output <new-private-result.json>`. Requests use the existing private artifact/backend/tfvars/source-authentication contract. Each mutation operation requires its own signed, unexpired authorization and one-use journal. A later approval cannot authorize an earlier mutation retroactively.

The policy receipt must include the exact registration chain used to derive it. Source/tree, signed preparation, durable execution receipt, live definition identity, and resulting policy are reauthenticated between phases. Receipts from another release or another registration cannot be substituted.

## Fixed broker-policy ownership

All routine convergence and separately approved pruning contend on:

`production#iam-policy-owner#arn:aws:iam::368992683803:policy/mscqr-production-rls-approval-broker-runtime`

The record uses the existing authenticated component-state table. Conditional acquisition requires absent ownership or the exact previously released generation. Metadata includes owner UUID, generation, source, and operation identity. The key never includes release SHA or approval ID. There is no TTL, timeout stealing, delete/unlock command, or automatic exception release.

Acquire before predecessor authentication; verify the exact approved target; attempt the native IAM mutation once; independently authenticate its successor and inventory; reconcile state; persist the terminal receipt; complete and release using the exact owner and generation. The ordinary Terraform infrastructure executor rejects broker-policy mutation, so it cannot bypass this boundary. AWS CLI retries are disabled for the native mutation.

Uncertainty retains ownership and consumes mutation authority. Readback is diagnosis, never another mutation authorization. A crash before mutation also retains ownership. An unused task-definition revision or published Lambda version has no launch/cutover authority simply because it exists. Future runs authenticate their own exact outputs.

Pruning uses `prepare-pruning`, `authorize-pruning`, and `prune`, with an explicit nondefault version and exact inventory. It is separately approved, never selected by latest/oldest heuristics, and uses the same ownership record. Convergence never silently prunes to free policy-version slots.

The guarantee is **no concurrent authorized automation writer** after successful acquisition. Root and `mscqr-ops-admin` remain administrative exceptions. Observed administrative drift fails closed; do not automatically rebaseline. Snapshot hashes cannot guarantee detection of an administrator mutating and restoring the original state.

## One-use reservation and pruning recovery

Convergence and pruning authenticate signed authority, then atomically reserve its existing S3 one-use journal **before** acquiring policy ownership. Reservation performs no IAM mutation. A consumed approval cannot create another ownership generation; concurrent copies have only one reservation winner. The subsequent owner binds that authorization digest as its operation identity, and the mutation intent binds the exact owner/generation.

If reservation succeeds but acquisition fails, the executor reports `reservationConsumed` and read-only diagnosis required. The reservation remains consumed; no IAM mutation is attempted and no competing owner is released. An uncertain acquisition preserves its attempted ownership identity for diagnosis. Inspect the original reservation and consistent ownership record; never reuse the approval, infer an unlock, or retry acquisition blindly. Any future mutation needs fresh authority after the existing ownership/recovery boundary is satisfied.

Uncertain pruning recovery validates the original saved pruning plan and intent's exact target. It compares canonical version inventories as collections. Success requires the predecessor inventory minus only the approved non-default version, the same default version and the same operative policy document. An exact predecessor is `RECOVERED_NO_WRITE`; every other state retains ownership. Exact successful recovery persists/authenticates one terminal receipt and completes/releases only the original generation, without calling `DeletePolicyVersion` again.

## Prior-writer proof and recovery

The actual staged executor uses the named `mscqr-production-release-deployer` profile. The operator profile assumes that exact role from `mscqr-production-bootstrap-mfa`; its session name is operator configuration, not a workflow/job identity binding. No duration override was observed during the investigation. The canonical infrastructure runbook requests 3,600 seconds for the release role. Its maximum duration is externally managed, not established by this source-only validation. Recovery never infers expiration from either value.

Existing GitHub release jobs use `aws-actions/configure-aws-credentials@v6`, with GitHub OIDC issuer `token.actions.githubusercontent.com`, default session name `GitHubActions`, and default requested duration 3,600 seconds when not overridden. Neither default name binds a run/job ID. OIDC does not supply the action's normal session tags. A job can obtain more than one session, and credentials can survive the runner; job completion is not revocation. These jobs do not supply credentials to the current named-profile staged executor.

Before a policy writer acquires ownership, it resolves one temporary session, authenticates `GetCallerIdentity`, and independently authenticates the matching STS issuance event from regional CloudTrail through read-only CloudTrail calls using the existing `mscqr-ops-admin` profile. The record binds the access-key identifier **hash**, assumed-role ARN/user ID, event ID, issue time and concrete credential expiration. Secrets and raw CloudTrail events are not persisted or logged.

All subsequent native policy writes and Terraform commands use that session's frozen environment, with no profile/provider refresh. The writer command runner rejects credential redirection and new STS assumptions. A new executor still contends on the same fixed ownership record and cannot replay the occupied authorization journal. Missing or delayed issuance history fails closed before acquisition; there is no polling/timeout unlock. Regional issuance in eu-west-2 is required; unknown/global-region history is not substituted.

`verify-policy-writer-termination` is read-only. It re-reads the exact held owner/generation, independently reauthenticates the recorded CloudTrail issuance, then reads the authenticated regional STS HTTPS server Date using a fixed HEAD request with redirects/caching disabled. Recovery is denied until this time is strictly later than the **actual authenticated STS expiration**. The expiration describes credentials, not a lock lease: elapsed time alone cannot release ownership. This proves the pinned writer cannot perform another authorized AWS write; it does **not** claim the OS process has physically exited.

`recover-policy` uses that verifier before reading the uncertain IAM outcome or authorization journal. It authenticates the original signed preparation at its durable execution time, its one-use reservation, owner/generation, source/tree, unchanged alias and prerequisite chain. It never replays IAM. An exact unchanged predecessor/inventory can be recorded as recovered without durable policy change. An exact successor requires authenticated inventory, unchanged role/traffic, exact Terraform state and a normal policy plan proving no-op. If state reconciliation is still needed, recovery retains ownership and stops for the existing separately approved state-reconciliation path; it does not apply an expired approval. Unknown outcomes, substituted receipts, unavailable evidence, or source-binding mismatch retain ownership. A durable terminal receipt is persisted or authenticated before owner/generation-checked completion/release. No force unlock exists.

Normal successful execution retains its existing receipt/release sequence and needs **no session revocation**. Recovery uses passive proof only. Root/ops-admin remain explicit administrative exceptions; no mutate-and-restore detection guarantee is claimed.

### Alternative proof evaluation

| Mechanism | Process stopped? | Credentials unusable? | Previous execution only? | Other/new sessions affected? | Propagation / mutation | Recovery sufficient? |
| --- | --- | --- | --- | --- | --- | --- |
| GitHub terminal job | Job state only | No | Identifies job, not every session | No | No IAM write | No |
| GitHub-hosted runner teardown | Runner lifetime only; not copied processes | No | Runner only | No | No IAM write | No |
| OIDC JWT expiry | No | Existing STS credentials survive | Token only | No | No IAM write | No |
| Authenticated STS expiry + pinned writer | No physical-process claim | Yes for exact credential | Yes, unique key hash + issuance | No | No IAM propagation/write | Selected; outcome/journal still required |
| AWSRevokeOlderSessions | No | Deny after propagation | All role sessions before cutoff | Also current recovery/unrelated older sessions | New IAM write; not an instantaneous guarantee | Not selected |
| Explicit aws:TokenIssueTime deny | No | Deny after propagation | Cutoff, not one execution | All matching older sessions | New IAM write; independent propagation proof needed | Not selected |
| Session-name/tag deny | No | Deny after propagation | Names/tags can be reused or absent | Matching sessions may overlap | New IAM write; identity ambiguity | Not selected |
| Journal / terminal receipt alone | No | No | Exact operation evidence | No | Existing conditional receipt | Necessary for outcome, insufficient for termination |

Active revocation would require independently approved IAM authority, a cutoff that excludes the old writer, proven propagation, and a recovery session issued after that cutoff. It is unnecessary here and is not implemented.

AWS documents [STS session duration and identity](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html), [CloudTrail issuance expiration fields](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html), and [the role-wide cutoff and propagation behavior of revocation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html). The credential action's defaults are in its [v6.0.0 source](https://github.com/aws-actions/configure-aws-credentials/blob/v6.0.0/src/index.ts).

## Local verification and security binding

`npm run test:production-green-stage-b-control-plane` includes ownership, generic prerequisite, staged broker, reference-audit, historical-runtime, and terminal closure tests. Future-release fixtures use the same framework with three different source/image identities and returned revisions 17, 42, and 103; revision arithmetic is not authority. Additional tests exercise single native IAM mutation, uncertainty, refresh-only reconciliation, and cross-receipt substitution.

The broad OSV reviewed-input boundary remains unchanged. After the implementation was final, the authorized security-owner revalidation independently reviewed all 23 changed boundary inputs, traced four real braces@3.0.3 build calls to the same repository-controlled Tailwind globs, checked the canonical browser module census and diagnostic source maps, and rechecked unchanged runtime packaging. Only the reviewed-input hash was rebound to `8f07fedd754f2b88af97d34b295b20b94c4c714b44030e3558631c1a39edeb5c`. The raw HIGH/unpatched advisory remains visible. Scope, owner, advisory, version and expiry (2026-11-02) are unchanged. Evidence is in `documents/security/generic-release-osv-revalidation-2026-10-04.json`. No production execution or AWS mutation was performed.

Recommendation: retain one fixed ownership domain for this one policy. Parallelism belongs between independent release components, never between writers of this shared policy; additional lock infrastructure is unnecessary.

## Final local validation (2026-10-04)

- Stage B control plane: 1,145/1,145 passed.
- Focused ownership/session/prerequisite/executor suites: 97/97 passed (19 ownership, 23 session, 27 prerequisite, 28 executor).
- Additional normal deployment/state, permission, closure and OSV policy suites: 345/345 passed.
- OSV policy/hostile suites: 89/89 passed. Fresh canonical browser closure: 3,993 modules, 204 packages, no braces. Diagnostic build source maps: 1,606 sources, no affected library/walker match. Raw scan still reports HIGH, unpatched GHSA-vfj7-8cjw-p6xm / CVE-2026-93687.
- Capability/dependency graphs: 740 capabilities, 250 AWS calls, zero unmapped/classification/source-policy contradictions. Artifact contracts: 23/23 passed. Workflow YAML: 95 files valid.
- Additional workflow contracts: 39/40 passed. The untouched delegation diagnostic throws `TypeError: Cannot destructure property executionSurface of undefined` at `workflow-delegation-registry.mjs:328`, from the assertion at test line 37. The identical failure was reproduced using archived exact protected main `d6f515fe393e0bcfda76e248aa8b3f2f3aae10e4`; it is unrelated and was not changed.
- Two earlier test attempts failed solely because a disposable Git clone exhausted disk space. After deleting only verified disposable investigation/test copies, the unmodified clone test and full Stage B suite passed.
- No live termination proof, IAM write, publication, alias cutover, Full-RLS, checker MFA, commit or push was performed. The proof mechanism is implemented and mock/contract-tested; current live role maximum duration and any actual held session's expiry remain unclaimed.
- Full hosted Deployment Audit has not run for this uncommitted tree. The local fresh OSV runtime gate passes. PR readiness is local, not merge approval.

The source-only operational handoff is review of the final local diff and these test/evidence results. Keep expired-session diagnosis separate from any future mutation authorization; a fresh session never revives consumed approval.

## PR 622 P1 correction validation (2026-10-05)

Both fresh P1 findings were reproduced before correction. One-use replay now fails before ownership acquisition; uncertain pruning success is authenticated against the exact approved successor inventory. The final broad-input security revalidation reviewed the four changed executable inputs against the prior reviewed head, repeated actual braces instrumentation and the canonical production browser census, and preserved every acceptance field except its input hash. No production mutation occurred.

Validation: focused ownership/session/prerequisite/executor 112/112; Stage B 1,160/1,160; additional regressions 345/345; artifact contracts 23/23; capability graph valid (740 capabilities, 250 AWS calls); workflow YAML 95 valid. Future A/B/C fixtures remain green. Additional workflow contracts remain 39/40 with the unchanged protected-main delegation failure above. Fresh OSV runtime gate passes with the visible HIGH/unpatched finding; final secret scan and hostile self-review are clean.

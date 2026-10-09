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

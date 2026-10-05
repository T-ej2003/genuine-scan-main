# Registration successor verification and recovery

Normal readback and registration recovery share the same strict task-definition state comparison. They authenticate exact revision identities; neither lookup uses latest nor revision arithmetic.

The allowed representation equivalences are enumerated:

| Field | Rule |
| --- | --- |
| Named task-local volume | Absent ECS `host` and structurally empty `host: {}` are equivalent. Names must match and be unique. Host paths, unknown host fields, EFS, Docker, FSx, S3 and launch-time configuration remain rejected. Terraform's empty nested configuration lists and `configure_at_launch: false` retain their existing strict validation. |
| Fault injection | Omitted/null and false mean disabled. True cannot authenticate against a default-disabled approved definition. A computed-value marker never authorizes enabling it. |
| Container definitions | Parse JSON and compare every field. Only absent/null environment, mountPoints, portMappings, systemControls and volumesFrom lists normalize to empty lists; absent/null container CPU normalizes to zero. Environment and secret entries compare by unique name, preserving exact values/references. Command/entrypoint order and every other value remain exact. |
| IPC/PID mode | Absent/null and empty string are equivalent. Explicit non-default values remain distinct. |
| Generated identity | Validate ARN family/account/region/revision, family ID and unqualified ARN. Live ECS must independently authenticate the exact state ARN/revision. |
| Computed mask | Only generated identity, disabled fault injection, and empty task-local volume `configure_at_launch` outputs are accepted. Known nested masks remain exact; unknown fields/configuration fail closed. |

No generic field stripping, retry, authorization reset, registration, or Terraform apply is added by this correction. Missing/malformed/ambiguous evidence continues to block recovery.

For already committed registrations, preserve the original consumed authorization, saved plan, acquisition/registration intent and concrete successor definitions. After merge, invoke the existing read-only `recover-registration` operation. Only successful canonical live/state authentication may persist `TASK_REGISTERED`; never register another revision to manufacture that receipt.

Tests cover normal/recovery equivalence and security-changing negatives. Set `MSCQR_REGISTRATION_VERIFIER_FIXTURE` to a private captured fixture containing the approved plan, full Terraform root state and all twelve exact ECS observations to additionally exercise real-release normal verification, native state recovery and the complete read-only registration recovery chain. Raw production fixtures and authentication material must not be committed.

Recommendation: retain these representation regressions when upgrading the pinned Terraform provider; new provider defaults require explicit semantic review rather than expanding a generic ignore list.

AWS API references: [Volume](https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_Volume.html), [HostVolumeProperties](https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_HostVolumeProperties.html), and [ContainerDefinition](https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_ContainerDefinition.html). The equivalence is restricted to structurally empty host configuration and the enumerated absent/default fields; non-default settings never normalize into absence.

## Validation and merge boundary

The twelve captured production successors pass normal verification and governed read-only recovery locally. The focused prerequisite/executor run passes 228/228, including both private-fixture tests. The relevant Stage-B control-plane run passes 1,380 tests (two private-fixture tests skipped). The unrelated image-reuse CLI clone test could not complete under local disk exhaustion and was excluded from that rerun; no assertion was changed. Reference-audit, ECS rotation and artifact-contract tests pass 271/271. Capability graph and workflow YAML validation pass; OSV policy tests pass 81/81.

Adversarial review found no valid unresolved normalization bypass: named volume configurations, enabled fault injection, namespace changes, roles, images, commands, environment, secrets and unknown provider fields remain authenticated or rejected. No AWS mutation, registration replay or production receipt was performed.

The security owner authorized the exact reviewed-input rebind from `08dbe5c4660ca72dd955d700d2a7632aa82e0e5676f8266486e262ba1af62bbe` to `4cfa8680b60e5df249679b50896d116437a20c714b4be447ab52517f5231b725`. Only the four intentional verifier/test inputs changed inside the existing boundary. Advisory, package/version, scope, rationale, owner, reachability conclusion and expiry (`2026-11-02`) remain unchanged. A fresh unfiltered source scan still reports the finding; the canonical runtime gate passes against a fresh traced production build. The build never loads these verifier files, its braces patterns remain repository-controlled Tailwind globs, and browser closure excludes braces.

Hosted required checks remain merge gates. After merge, stop before production execution; the next operation is read-only recovery of the existing twelve registrations.

## Read-only recovery source identity

`recover-registration` authenticates two identities after the original signed authorization, immutable consumed reservation and registration intent authenticate. Transaction source/tree remain the original approved commit. Recovery tooling is separately required to be the freshly fetched, clean canonical protected main; the original transaction must be its ancestor and its original tooling-input tree must match preparation.

This distinction exists only for `REGISTRATION_RECOVERY` / `READ_ONLY_EXACT_SUCCESSOR`. Normal `readCheckout`, registration authorization and saved-plan mutation execution retain their exact-main equality checks. The recovery AWS runner admits an enumerated read-only command census, and its Terraform runner permits only `show -json`. The sole durable write remains the existing guarded `TASK_REGISTERED` phase receipt after exact live/state successor authentication; it is not mutation authority.

Recovered receipts retain original `sourceSha`/`treeSha256` and include `recovery: { mode, transaction: { sourceSha, treeSha256 }, tooling: { sourceSha, treeSha256 } }`. An already persisted normal receipt is authenticated and reused unchanged. An immutable recovered receipt retains its actual historical tooling provenance, verified by exact Git tree and ancestry under current clean protected main; later tooling must not rewrite it.

Adversarial questions: neither mismatched transaction source nor recovery-tooling identity can authorize a production mutation. Current main cannot replace original preparation, signature, consumed reservation, intent, plan, artifact set, image or successor authority. Tests deny omitted mode, non-main/dirty tooling, invalid signature, missing reservation/intent, altered original hashes, substituted provenance and mutation hooks/commands. The twelve captured real successors remain local read-only fixtures; tests persist only in-memory/mock receipts, never production receipts. After merge, stop before production recovery and broker-policy pruning.

Validation for the source-binding correction: focused/native and captured-fixture run 257/257; final prerequisite/dispatch run 129/129; other relevant Stage-B tests 1,154/1,154. The unchanged image-reuse CLI clone test is deferred to hosted full closure because of local disk limits. Capability graph and workflow validation pass. Fresh unfiltered OSV scan, traced production build and canonical runtime gate pass, with 89/89 policy tests. Only the reviewed-input binding changes from 4cfa8680b60e5df249679b50896d116437a20c714b4be447ab52517f5231b725 to 56ac13c2ab62ce960dd4ed0f25bc06ab420231fc705a858948d0de1937c7ceb5; all acceptance semantics and expiry remain unchanged. Adversarial review: no valid unresolved finding; no production mutation performed.

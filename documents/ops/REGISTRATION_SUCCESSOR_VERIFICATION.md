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

The existing OSV acceptance is intentionally unchanged. This executable-input change produces reviewed-input hash `4cfa8680b60e5df249679b50896d116437a20c714b4be447ab52517f5231b725`, differing from accepted `08dbe5c4660ca72dd955d700d2a7632aa82e0e5676f8266486e262ba1af62bbe`. Merge remains blocked on the separately authorized canonical security-owner review/binding process and hosted checks. After merge, stop before production execution; the next operation is read-only recovery of the existing twelve registrations.

# Production Green Stage B refresh-only contract

The Stage B refresh-only command produces a temporary non-deployable Terraform
refresh plan, reads its JSON with `terraform show -json`, and writes a structured
refresh report. Console text such as `No changes.` is not authoritative.

Acquisition is fail-closed: the plan command must exit 0 or 2, the exact private
temporary plan must be non-empty, and a separate successful `terraform show -json`
must provide the parsed plan bytes. The report records the plan, show stdout, and
show stderr hashes plus both command exit codes. Diagnostic, errored, truncated,
wrapper, state, or otherwise incomplete JSON is recorded as a blocked acquisition;
it is never classified as no-change evidence.

The classifier also requires the eight source-defined `plan.checks` entries to be
present, unique, and explicitly `pass` at both check and instance level:
`production_only`, `stage_a_bindings`, `stage_a_runtime_secrets`,
`stage_a_release_resources`, `release_bindings`, `immutable_images`,
`read_only_canary_secret`, and `retained_task_definition_families`. Missing,
unknown, duplicate, malformed, `fail`, `error`, or `unknown` checks produce
`FAILED_CHECK` before resource or output classification.

The only accepted statuses are:

- `NO_CHANGES`: no non-no-op resource changes and no output changes;
- `REVIEWED_OUTPUT_RECONCILIATION`: no resource changes and only the reviewed
  `bound_images` and proven-empty `task_definition_arns` outputs changed.

Any managed-resource action, unknown output, unexpected output value, unknown or
sensitive value, failed check, provider/backend error, malformed JSON, stale state,
or mismatched tfvars/image/state binding blocks planning. The temporary refresh plan
is deleted and is never a deployable saved plan.

`bound_images` must equal the five immutable image references in the canonical tfvars
binding report. `task_definition_arns` is accepted only when protected-main defines
the output and the bound Stage B state contains no current task-definition addresses,
which proves the proposed value is `{}` before apply.

Production callers must provide the Stage B state backup explicitly:

```text
--stage-b-state-backup <fresh-stage-b-state.json>
```

The refresh report binds tooling SHA/tree digest, Stage A and Stage B state identity,
tfvars and binding-report hashes, image-evidence hash, backend metadata hash,
`TF_DATA_DIR`, and workspace. The planner, production closure, validator, and apply
wrapper accept the report only when that binding and the successful acquisition proof
are exact. Omitted `resource_changes` or `output_changes` are normalized only after
the complete plan envelope and eight-check inventory are validated.

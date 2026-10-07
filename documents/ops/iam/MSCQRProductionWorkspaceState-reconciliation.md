# WorkspaceState policy version-capacity reconciliation

This target-specific operation converges only `MSCQRProductionGreenStageBWorkspaceState` when its five managed-policy version slots are occupied. It adds no policy authority beyond the protected-main document at `documents/ops/iam/MSCQRProductionGreenStageBWorkspaceState-v2.json`.

Preparation authenticates the exact default, all five version documents, attachment topology, declared one-statement delta, and the uniquely oldest non-default deletion candidate. The dedicated protected-environment workflow independently authorizes the exact preparation. Execution reauthenticates the complete inventory immediately before the single approved deletion, creates one successor as default, and verifies the declared document. Conditional S3 journal records prevent either mutation from being replayed and support fail-closed reconciliation after interruption.

`CreateDate` is used only to choose that candidate: repeated timestamps on newer versions are allowed, but a tie for the oldest eligible non-default version fails closed. The default version is never eligible for deletion.

An existing reservation can be adopted only by a fresh authorization for the same source and exact transition, with an unchanged authenticated pre-state and no deletion, creation, or terminal journal record. The old reservation remains unchanged; after the first mutation-attempt record, recovery follows the original transaction and never reinterprets it as zero-write. After an authorized write, only explicitly retryable IAM read failures or the exact authenticated pre-write state are retried, using the bounded delays in the contract. Stable contradictions and permanent read errors fail closed.

When an adopted reservation already has progress records, each record must bind to the current authorization before normal reconciliation resumes. If the final pre-delete read exhausts only its transient retry budget, a durable prewrite-failure record proves that `DeletePolicyVersion` was not called; restart may perform one bounded CAS and write attempt, while a recorded retry attempt is never replayed.

The checker authorization is revalidated after the final live-state CAS and before each policy mutation. If it expires after the approved deletion, reconciliation stops before creating the successor; an expired authorization never authorizes a write.

Use a clean protected-main checkout and private output directory (`umask 077`):

```sh
npm run production:workspace-state-reconciliation -- --mode prepare --source-sha "$PROTECTED_MAIN_SHA" --admin-profile "$ADMIN_PROFILE" --preparation-out "$PRIVATE_DIR/preparation.json"

gh workflow run authorize-production-workspace-state-policy-reconciliation.yml --ref main \
  -f source_sha="$PROTECTED_MAIN_SHA" \
  -f preparation_json_base64="$(base64 < "$PRIVATE_DIR/preparation.json" | tr -d '\n')" \
  -f preparation_file_sha256="$(shasum -a 256 "$PRIVATE_DIR/preparation.json" | awk '{print $1}')"

npm run production:workspace-state-reconciliation -- --mode execute --source-sha "$PROTECTED_MAIN_SHA" \
  --preparation "$PRIVATE_DIR/preparation.json" \
  --preparation-file-sha256 "$PREPARATION_FILE_SHA256" \
  --authorization-workflow-run-id "$AUTHORIZATION_WORKFLOW_RUN_ID" \
  --authorization-workflow-run-attempt 1 --admin-profile "$ADMIN_PROFILE" \
  --result-out "$PRIVATE_DIR/result.json"
```

The production mutation is never performed by tests, PR validation, or authorization. The operator must stop if preparation cannot identify one safe non-default version or if any live binding changes.

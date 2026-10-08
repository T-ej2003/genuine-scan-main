# WorkspaceState policy version-capacity reconciliation

This target-specific operation converges only `MSCQRProductionGreenStageBWorkspaceState` when its five managed-policy version slots are occupied. It adds no policy authority beyond the protected-main document at `documents/ops/iam/MSCQRProductionGreenStageBWorkspaceState-v2.json`.

Preparation authenticates the exact default, all five version documents, attachment topology, declared one-statement delta, and the uniquely oldest non-default deletion candidate. The dedicated protected-environment workflow independently authorizes the exact preparation. Execution reauthenticates the complete inventory immediately before the single approved deletion, creates one successor as default, and verifies the declared document. Conditional S3 journal records prevent either mutation from being replayed and support fail-closed reconciliation after interruption.

`CreateDate` is used only to choose that candidate: repeated timestamps on newer versions are allowed, but a tie for the oldest eligible non-default version fails closed. The default version is never eligible for deletion.

An existing reservation can be adopted only by a fresh authorization for the same source and exact transition, with an unchanged authenticated pre-state and no deletion, creation, or terminal journal record. The old reservation remains unchanged; after the first mutation-attempt record, recovery follows the original transaction and never reinterprets it as zero-write. After an authorized write, only explicitly retryable IAM read failures or the exact authenticated pre-write state are retried, using the bounded delays in the contract. Stable contradictions and permanent read errors fail closed.

The reservation remains bound to its original authorization. Later attempt and prewrite-failure records may be bound to the fresh authorization that adopted it, but those records must authenticate independently and share one preparation, authorization, and provenance binding. Delete completion must match the attempt that actually issued the delete (the retry attempt when present). Continuation preparation and execution verify these links while retaining the immutable reservation. If the final pre-delete observation fails before the AWS call, a durable prewrite-failure record proves that `DeletePolicyVersion` was not called. Its disposition distinguishes recoverable read/freshness failure from a stable security contradiction: only the former can enter the exact-state and fresh-authorization continuation checks. Stable contradictions remain fail-closed. A recorded retry attempt is never replayed.

The checker authorization is revalidated after the final live-state CAS and before each policy mutation. If it expires after the approved deletion, reconciliation stops before creating the successor; an expired authorization never authorizes a write.

The authorization workflow transports exact preparation bytes as deterministic gzip plus base64 and verifies the SHA-256 of the decoded, uncompressed file. A continuation preparation contains only a SHA-256 reference to the original preparation and the authenticated journal digests; it does not embed the five policy documents again. For continuation authorization and execution, pass the original base preparation as a separate compressed input/file with its own SHA-256. The checker and executor verify each exact file hash and require the continuation's canonical base-preparation digest to match the validated base. The maximum five-version fixture measures 16,096 bytes for normal authorization and 17,869 bytes for continuation authorization, below the 49,152-byte test ceiling and GitHub's 65,535-byte total-input limit.

Use a clean protected-main checkout and private output directory (`umask 077`):

```sh
npm run production:workspace-state-reconciliation -- --mode prepare --source-sha "$PROTECTED_MAIN_SHA" --admin-profile "$ADMIN_PROFILE" --preparation-out "$PRIVATE_DIR/preparation.json"

gh workflow run authorize-production-workspace-state-policy-reconciliation.yml --ref main \
  -f source_sha="$PROTECTED_MAIN_SHA" \
  -f preparation_json_gzip_base64="$(gzip -n -c "$PRIVATE_DIR/preparation.json" | base64 | tr -d '\n')" \
  -f preparation_file_sha256="$(shasum -a 256 "$PRIVATE_DIR/preparation.json" | awk '{print $1}')"

npm run production:workspace-state-reconciliation -- --mode execute --source-sha "$PROTECTED_MAIN_SHA" \
  --preparation "$PRIVATE_DIR/preparation.json" \
  --preparation-file-sha256 "$PREPARATION_FILE_SHA256" \
  --authorization-workflow-run-id "$AUTHORIZATION_WORKFLOW_RUN_ID" \
  --authorization-workflow-run-attempt 1 --admin-profile "$ADMIN_PROFILE" \
  --result-out "$PRIVATE_DIR/result.json"
```

For `prepare-continuation`, keep the original `base-preparation.json` and produce the compact continuation from it:

```sh
npm run production:workspace-state-reconciliation -- --mode prepare-continuation --source-sha "$PROTECTED_MAIN_SHA" \
  --base-preparation "$PRIVATE_DIR/base-preparation.json" \
  --base-preparation-file-sha256 "$BASE_PREPARATION_FILE_SHA256" \
  --continuation-kind "$CONTINUATION_KIND" \
  --admin-profile "$ADMIN_PROFILE" \
  --preparation-out "$PRIVATE_DIR/continuation.json"
```

Submit the original and compact files separately:

```sh
gh workflow run authorize-production-workspace-state-policy-reconciliation.yml --ref main \
  -f source_sha="$PROTECTED_MAIN_SHA" \
  -f preparation_json_gzip_base64="$(gzip -n -c "$PRIVATE_DIR/continuation.json" | base64 | tr -d '\n')" \
  -f preparation_file_sha256="$(shasum -a 256 "$PRIVATE_DIR/continuation.json" | awk '{print $1}')" \
  -f base_preparation_json_gzip_base64="$(gzip -n -c "$PRIVATE_DIR/base-preparation.json" | base64 | tr -d '\n')" \
  -f base_preparation_file_sha256="$(shasum -a 256 "$PRIVATE_DIR/base-preparation.json" | awk '{print $1}')"

npm run production:workspace-state-reconciliation -- --mode execute --source-sha "$PROTECTED_MAIN_SHA" \
  --preparation "$PRIVATE_DIR/continuation.json" \
  --preparation-file-sha256 "$CONTINUATION_FILE_SHA256" \
  --base-preparation "$PRIVATE_DIR/base-preparation.json" \
  --base-preparation-file-sha256 "$BASE_PREPARATION_FILE_SHA256" \
  --authorization-workflow-run-id "$AUTHORIZATION_WORKFLOW_RUN_ID" \
  --authorization-workflow-run-attempt 1 --admin-profile "$ADMIN_PROFILE" \
  --result-out "$PRIVATE_DIR/result.json"
```

The production mutation is never performed by tests, PR validation, or authorization. The operator must stop if preparation cannot identify one safe non-default version or if any live binding changes.

# Signer-installer Terraform state reflection reconciliation

This operation records one already-correct live IAM role representation in the existing initial-activation reconciler Terraform state. It never changes AWS IAM. It is valid only while live discovery is `EXACT_AUTHORIZER_POLICY_UPDATE` and the saved state holds `aws_iam_role.signer_policy_installer.inline_policy=[]` and `tags=null`. The authenticated refresh-only plan must show exactly that role changing to the protected-source `ProductionSignerPolicyInstaller` inline policy and `tags={}`. It must contain no other `resource_drift` or output changes. Terraform may omit `resource_changes` or include canonical configured resources with exact `no-op` actions; every create, update, delete, replace, read, or unknown action is rejected.

The operation is separate from normal installation. It preserves the strict normal-plan drift validator. Preparation binds protected source, account/region, exact backend, state lineage/serial/SHA-256 and S3 VersionId/ETag, saved-plan SHA-256, and the canonical policy. Protected-environment approval authorizes those exact bytes. Execution checks the same live predecessor and applies the saved **refresh-only** plan once. It reads the complete resulting state and immediately creates a fresh normal plan. The normal plan must have zero drift and exactly one `aws_iam_policy.bootstrap_operator_policy_authorizer` update; that update is **not** applied by this operation.

## Operator sequence

Use a clean isolated checkout of exact protected `origin/main`. Keep `workdir` outside the repository with mode `0700`; the canonical command verifies private file modes. Do not use `terraform refresh`, `terraform state push`, state import/removal, manual IAM changes, or a normal Terraform apply.

```sh
source_sha="$(git rev-parse HEAD)"
test "$source_sha" = "$(git rev-parse origin/main)"
test -z "$(git status --porcelain=v1 --untracked-files=all)"
workdir="$(mktemp -d /private/tmp/mscqr-signer-state-reconciliation.XXXXXX)"
chmod 700 "$workdir"
install -d -m 700 "$workdir/terraform-data"
npm run production:initial-activation-reconciler:signer-state-reconcile -- \
  --mode prepare --source-sha "$source_sha" --admin-profile mscqr-production-root \
  --terraform-data-dir "$workdir/terraform-data" \
  --saved-plan-out "$workdir/refresh.tfplan" \
  --preparation-out "$workdir/preparation.json"
```

Review the preparation and complete `terraform show -json "$workdir/refresh.tfplan"`. Hash and encode the **exact private bytes** without editing them. Dispatch `authorize-production-initial-activation-signer-state-reconciliation.yml` with its declared `source_sha`, `preparation_base64`, and `preparation_sha256` inputs. Wait for actual protected-environment approval and a successful first run attempt. Preparation and authorization expire after 30 minutes.

Dispatch `execute-production-initial-activation-signer-state-reconciliation.yml` using its declared inputs: the same source SHA, exact preparation and saved-plan base64 bytes and SHA-256 digests, and the successful authorization run ID and attempt. The executor authenticates GitHub artifact provenance, runs under the exact bootstrap OIDC role, checks the saved-state preimage, and writes only the authorized refresh-only Terraform state. It emits a private result. Verify that result and its read-only post-plan before resuming the existing normal authorizer-policy reconciliation.

## Interrupted or ambiguous state write

If execution fails after the Terraform state write might have begun, **do not rerun the saved plan blindly**. Preserve preparation, plan, authorization run identity, and result/logs. Read-only `--mode recovery-prepare` accepts only the exact authorized successor state, including serial increment, full state hash, S3 VersionId and ETag advancement, and current canonical live IAM. It binds the original authorization and requires a fresh protected-environment authorization through `authorize-production-initial-activation-signer-state-reconciliation-recovery.yml`. The corresponding `execute-production-initial-activation-signer-state-reconciliation-recovery.yml` verifies the exact successor and fresh normal plan with **zero** Terraform state or AWS mutation. If the backend is still the predecessor, create a fresh ordinary preparation and authorization; if it is neither, stop for diagnosis.

The recovery CLI has the same argument names as the existing initial-activation reconciler state-reconciliation runbook, using `production:initial-activation-reconciler:signer-state-reconcile` and this operation's four dedicated workflows. No recovery action can install the pending authorizer policy update.

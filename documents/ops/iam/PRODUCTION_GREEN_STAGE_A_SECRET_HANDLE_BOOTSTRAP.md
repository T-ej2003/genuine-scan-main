# Production green Stage A secret-handle IAM bootstrap

`MSCQRProductionGreenStageAReadOnlyCanarySecretCreate-v1.json` is the one-time,
exactly scoped managed policy document for the Stage A Terraform execution path.
It allows creation of only the Phase 4 read-only-canary handle request and the
dependent tag operation for that generated ARN family, plus the provider's
read-only `secretsmanager:GetResourcePolicy` read for that exact generated ARN
family. It grants no secret-value, version, lifecycle, KMS, IAM, STS, or list
authority.

An authorized IAM administrator must attach this policy once to
`mscqr-production-release-deployer` through the approved IAM governance path.
If no non-root IAM administrator exists, root may be used only for this one IAM
bootstrap event. Root must not initialize, plan, or apply Terraform. Root
credentials must be removed from the active/default profile immediately after
the attachment is verified.

## Updating an already-attached managed policy

Merging a policy correction does not update AWS. An already-attached policy must
be versioned through the same authorized IAM administrator path before Terraform
recovery. Use root only when no approved non-root IAM administrator exists; root
must perform only this managed-policy version update and read-back, never
Terraform. The policy remains attached only to
`mscqr-production-release-deployer`.

Run the following without embedding credentials, session tokens, passwords, MFA
codes, or a guessed policy ARN:

```sh
set -euo pipefail
POLICY_NAME='MSCQRProductionGreenStageAReadOnlyCanarySecretCreate'
POLICY_DOCUMENT="$PWD/documents/ops/iam/MSCQRProductionGreenStageAReadOnlyCanarySecretCreate-v1.json"
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
POLICY_ARN="$(aws iam get-policy --policy-arn "arn:aws:iam::${ACCOUNT_ID}:policy/${POLICY_NAME}" --query Policy.Arn --output text)"
ROLE_NAME='mscqr-production-release-deployer'

# Create the new default version from the exact merged source document.
NEW_VERSION_ID="$(aws iam create-policy-version \
  --policy-arn "$POLICY_ARN" \
  --policy-document "file://${POLICY_DOCUMENT}" \
  --set-as-default \
  --query PolicyVersion.VersionId --output text)"

# Read back the default document and compare semantic JSON, not formatting.
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
aws iam get-policy-version --policy-arn "$POLICY_ARN" --version-id "$NEW_VERSION_ID" \
  --query PolicyVersion.Document --output json > "$TMP_DIR/live-policy.json"
cmp <(jq -S . "$POLICY_DOCUMENT") <(jq -S . "$TMP_DIR/live-policy.json")

# Confirm the exact attachment target and the exact read-only ARN boundary.
test "$(aws iam list-entities-for-policy --policy-arn "$POLICY_ARN" --query 'length(PolicyRoles) + length(PolicyUsers) + length(PolicyGroups)' --output text)" = 1
test "$(aws iam list-entities-for-policy --policy-arn "$POLICY_ARN" --query 'PolicyRoles[0].RoleName' --output text)" = "$ROLE_NAME"
jq -e '
  ([.Statement[].Action] | flatten | sort) == [
    "secretsmanager:CreateSecret",
    "secretsmanager:GetResourcePolicy",
    "secretsmanager:TagResource"
  ] and
  ([.Statement[] | select(.Action == "secretsmanager:GetResourcePolicy") | .Resource] == [
    "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase4/read-only-canary-database-url-??????"
  ])' "$TMP_DIR/live-policy.json"
```

If `create-policy-version` reports AWS's five-version limit, list versions and
delete only an old non-default version; never delete the active default:

```sh
aws iam list-policy-versions --policy-arn "$POLICY_ARN" \
  --query 'Versions[].{Id:VersionId,Default:IsDefaultVersion,Created:CreateDate}' --output table
# After reviewing the table, delete one explicitly selected non-default version:
aws iam delete-policy-version --policy-arn "$POLICY_ARN" --version-id <old-non-default-version>
```

After live verification, remove/log out root credentials immediately if root was
used, then obtain a fresh bootstrap-operator MFA session and verify the
`mscqr-production-release-deployer` caller before Terraform recovery.

## Recovery sequence after the live policy update

1. Obtain a fresh release-deployer MFA session and verify its assumed-role ARN.
2. Verify `secretsmanager:GetResourcePolicy` is effective for the existing Phase 4
   ARN; do not read a secret value.
3. Initialize the approved Stage A backend and verify state contains
   `aws_secretsmanager_secret.read_only_canary` with the existing ARN.
4. Untaint only that resource:

   ```sh
   terraform -chdir=infra/aws/terraform/production-green-stage-a \
     untaint aws_secretsmanager_secret.read_only_canary
   ```

5. Run a fresh Stage A refresh/plan and require `0 add, 0 change, 0 destroy`.
   Stop on any replacement, deletion, or recreation proposal; do not recreate or
   delete the existing secret.
6. Verify `stage_b_prerequisites.read_only_canary_database_secret_arn` equals the
   existing ARN, then continue to Stage B only after the clean Stage A plan.

After the attachment is verified, obtain a fresh MFA-backed
`mscqr-production-release-deployer` session and verify its assumed-role identity
before running the already reviewed Stage A plan. The empty-handle guarantee is
provided by the Stage A Terraform resource, absence of any
`aws_secretsmanager_secret_version` or value-bearing field, and the exact saved
plan; IAM does not prove that a `CreateSecret` request lacks `SecretString` or
`SecretBinary`.

# Initial-activation reconciler Terraform state reconciliation

`PRODUCTION_INITIAL_ACTIVATION_RECONCILER_STATE_RECONCILIATION` is a one-purpose, protected-environment operation for the existing initial-activation reconciler Terraform backend. It does not reconcile IAM.

The operation accepts only a refresh-only saved plan whose complete drift envelope is:

- `aws_iam_policy.reconciler.attachment_count`: `0` to `1`.
- `aws_iam_role.reconciler.managed_policy_arns`: `[]` to the exact reconciler policy ARN.

Preparation binds protected source, backend identity, raw state lineage/serial/SHA-256, S3 VersionId and ETag, canonical live attachment topology, saved-plan bytes, and this exact drift envelope. Authorization is independently protected-environment approved. Execution applies only the authorized saved refresh-only plan through the bootstrap OIDC role.

The bootstrap role has two additional read-only prerequisites: `s3:GetBucketPolicy` on the exact production-artifacts bucket and `iam:GetRolePolicy` on its own exact role. They are used only to reauthenticate State B and the bootstrap-policy revision immediately before and after the saved-plan transaction; they grant no object, bucket-policy mutation, or unrelated IAM capability. The existing target-locked bootstrap installer must first converge that inline policy revision.

Bootstrap-policy installation now prepares and authorizes the exact observed predecessor generation. Only the two tracked historical documents and the current canonical document are recognized; an authorization for one predecessor generation cannot mutate another.

The operation rejects normal Terraform actions, IAM mutations, added drift, output drift, state substitution, authorization substitution, and post-state changes outside those two fields. Replay and ambiguous-write recovery require the complete prepared successor state, not merely the refreshed attachment fields. It verifies the live IAM attachment remains unchanged, then generates a fresh normal installation plan and requires the existing strict installation validator to observe no `resource_drift` and exactly the already-reviewed `aws_iam_policy.reconciler` update. It never executes that update.

## Governed operator sequence

This is the only supported path. Do not use `terraform refresh`, `terraform
state push`, a manual state edit or replacement, normal `terraform apply`, a
fresh plan at execution time, direct S3 state replacement, or manual IAM repair.

### 0. Establish protected source and private paths

Start from the current protected `main` source in a clean checkout. The
preparation, saved plan, and Terraform data directory are private artifacts;
keep them outside the repository and mode `0700`/`0600` as created and verified
by the canonical command.

```sh
git fetch origin main
git checkout main
git pull --ff-only origin main
test -z "$(git status --porcelain=v1 --untracked-files=all)"
source_sha="$(git rev-parse HEAD)"
test "$source_sha" = "$(git rev-parse origin/main)"

workdir="$(mktemp -d /private/tmp/mscqr-reconciler-state-reconciliation.XXXXXX)"
chmod 700 "$workdir"
install -d -m 700 "$workdir/terraform-data"
preparation="$workdir/preparation.json"
saved_plan="$workdir/refresh.tfplan"
```

### 1. Prepare the exact refresh-only transaction

Use the root AWS CLI login profile required by the protected source. This
authenticates State B, the bootstrap policy, Terraform state identity, and the
live IAM attachment topology; it saves `terraform plan -refresh-only`, permits
only the two documented fields, and does not persist state or mutate IAM.

```sh
npm run production:initial-activation-reconciler:state-reconcile -- --mode prepare \
  --source-sha "$source_sha" \
  --admin-profile mscqr-production-root \
  --terraform-data-dir "$workdir/terraform-data" \
  --saved-plan-out "$saved_plan" \
  --preparation-out "$preparation" >/dev/null

test -s "$preparation"
test -s "$saved_plan"
```

### 2. Bind authorization inputs to exact bytes

The Node commands below hash the exact bytes and the standard `base64` stream
is newline-stripped only after encoding, so decoding reconstructs exactly the
hashed input on both macOS and GNU/Linux. They do not print either private
artifact.

```sh
sha256_file() {
  node -e 'const fs=require("fs"),crypto=require("crypto"); process.stdout.write(crypto.createHash("sha256").update(fs.readFileSync(process.argv[1])).digest("hex"))' "$1"
}

preparation_sha256="$(sha256_file "$preparation")"
saved_plan_sha256="$(sha256_file "$saved_plan")"
preparation_base64="$(base64 < "$preparation" | tr -d '\n')"
saved_plan_base64="$(base64 < "$saved_plan" | tr -d '\n')"
```

### 3. Authorize

Dispatch the dedicated authorization workflow with the exact preparation
bytes. It revalidates the decoded digest and requires protected-environment
human approval. It does not apply the plan.

```sh
gh workflow run authorize-production-initial-activation-reconciler-state-reconciliation.yml \
  --ref main \
  -f source_sha="$source_sha" \
  -f preparation_base64="$preparation_base64" \
  -f preparation_sha256="$preparation_sha256"

gh run list \
  --workflow authorize-production-initial-activation-reconciler-state-reconciliation.yml \
  --commit "$source_sha" --event workflow_dispatch --limit 10
# Select the newly dispatched run, then set its exact ID:
authorization_run_id="<authorization-run-id>"
gh run watch "$authorization_run_id" --exit-status
authorization_run_attempt="$(gh run view "$authorization_run_id" --json attempt,conclusion --jq '.attempt')"
test "$(gh run view "$authorization_run_id" --json conclusion --jq '.conclusion')" = success
test "$authorization_run_attempt" = 1
```

### 4. Validity window

The preparation is valid for **1800 seconds (30 minutes)** from the
preparation artifact's `createdAt` timestamp. Authorization and execution both
verify this deadline. If it expires, source changes, or any bound artifact
changes, stop and create a fresh preparation with a fresh authorization; never
replace only one bound artifact or reuse an authorization from an older
preparation.

### 5. Execute exactly the authorized saved plan

Only after the authorization run is successful and human-approved, dispatch
the dedicated execution workflow. It decodes and hashes the exact preparation
and saved-plan bytes, then applies that saved refresh-only plan through the
bootstrap OIDC role. It never regenerates a plan.

```sh
gh workflow run execute-production-initial-activation-reconciler-state-reconciliation.yml \
  --ref main \
  -f source_sha="$source_sha" \
  -f preparation_base64="$preparation_base64" \
  -f preparation_sha256="$preparation_sha256" \
  -f saved_plan_base64="$saved_plan_base64" \
  -f saved_plan_sha256="$saved_plan_sha256" \
  -f authorization_workflow_run_id="$authorization_run_id" \
  -f authorization_workflow_run_attempt="$authorization_run_attempt"
```

### 6. Expected completion and restart rules

The result JSON must show `remoteIamMutationCount=0` and
`refreshOnlyApplyCount=1`. Its authenticated `planSemantics` requires
`terraformResourceAddCount=0`, `terraformResourceChangeCount=0`, and
`terraformResourceDestroyCount=0`—the corresponding
`REMOTE_IAM_MUTATION_COUNT=0`, `TERRAFORM_RESOURCE_ADD_COUNT=0`,
`TERRAFORM_RESOURCE_CHANGE_COUNT=0`, `TERRAFORM_RESOURCE_DESTROY_COUNT=0`,
and `TERRAFORM_REFRESH_ONLY_APPLY_COUNT=1` invariants. The backend must become
the exact authenticated successor, live IAM must remain unchanged, and the
fresh normal installation plan must report `resource_drift=[]` with only
`aws_iam_policy.reconciler:update` pending. Stop before that policy update.

If preparation fails, investigate read-only and prepare fresh. If source,
predecessor-state CAS, or additional Terraform drift changes, stop. If an
execution result is ambiguous, use the canonical replay/recovery path: an
`EXACT_SUCCESSOR` can complete with zero additional state mutation, while an
`UNKNOWN` state fails closed. Never blindly repeat refresh-only apply.

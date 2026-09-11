# Exact-complete Terraform state reconciliation

Use this narrowly when the production initial-activation IAM topology is already `EXACT_COMPLETE`, the normal Terraform plan has zero actionable changes, and its only refresh drift is the two source-bound mixed-recovery attachment fields. It is a Terraform refresh-only state operation: it has zero remote IAM, Secrets Manager, and ECS writes.

Prepare from a clean protected main checkout with the root profile. The preparation admits only `aws_iam_policy.mixed_recovery.attachment_count` from `0` to `1` and `aws_iam_role.mixed_recovery.managed_policy_arns` from `[]` to the exact recovery policy ARN. It authenticates the exact role, policy, attachment, no inline policies, policy document, seven-secret scope, and absent permissions boundary.

```sh
npm run production:initial-activation-reconciler:exact-complete-state-reconcile -- --mode prepare --source-sha "$SOURCE_SHA" --admin-profile mscqr-production-root --terraform-data-dir "$DATA" --saved-plan-out "$ARTIFACTS/refresh.tfplan" --preparation-out "$ARTIFACTS/preparation.json"
gh workflow run authorize-production-initial-activation-exact-complete-state-reconciliation.yml -f source_sha="$SOURCE_SHA" -f preparation_base64="$(base64 < "$ARTIFACTS/preparation.json" | tr -d '\n')" -f preparation_sha256="$(sha256sum "$ARTIFACTS/preparation.json" | awk '{print $1}')"
```

After protected authorization, execute only the saved refresh-only plan through `execute-production-initial-activation-exact-complete-state-reconciliation.yml`, passing `source_sha`, `preparation_base64`, `preparation_sha256`, `saved_plan_base64`, `saved_plan_sha256`, `authorization_workflow_run_id`, and `authorization_workflow_run_attempt`.

Execution verifies the same source, authorization, state object identity, live IAM topology, and attachment before applying the refresh-only plan. It then requires an exact state successor and a second normal Terraform plan with zero resource drift and zero actionable changes. If the exact successor persists but the original transaction expires before completion evidence is published, do not retry the saved plan: prepare the exact successor with `--mode recovery-prepare`, obtain a fresh protected authorization through `authorize-production-initial-activation-exact-complete-state-reconciliation-recovery.yml`, then use `execute-production-initial-activation-exact-complete-state-reconciliation-recovery.yml`. That recovery performs zero Terraform applies and accepts only the authenticated one-serial successor, exact attachment topology, and clean normal plan. Any other drift, attachment, inline policy, policy document, boundary representation, or plan action fails closed. The following no-op installer transaction remains a separate fresh authorization.

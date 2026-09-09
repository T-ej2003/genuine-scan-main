# Governed ProviderReadOnly reconciliation

This contract changes only the customer-managed policy
`arn:aws:iam::368992683803:policy/MSCQRProductionGreenStageBProviderReadOnly`.
Its desired document is always read from
`documents/ops/iam/MSCQRProductionGreenStageBProviderReadOnly-v1.json` in an
exact, clean protected-main checkout. Neither the policy ARN nor policy
document is accepted from an operator argument.

## Operator sequence

1. Run `npm run production:provider-readonly-reconciliation -- --mode prepare`
   from protected main with the governed root read profile and a private
   preparation output. Preparation reads IAM only. It authenticates the exact
   predecessor document, all policy versions, and the complete policy-centric
   user/group/role attachment topology.
2. Dispatch
   `.github/workflows/authorize-production-provider-readonly-policy-reconciliation.yml`
   once with the exact preparation bytes and SHA-256. The `production`
   environment supplies the independent human approval. The completed workflow
   publishes one authorization artifact; it performs no AWS action.
3. Dispatch
   `.github/workflows/execute-production-provider-readonly-policy-reconciliation.yml`
   with the same preparation bytes/SHA and the completed authorization run
   ID/attempt. Its protected `production` job assumes the exact OIDC reconciler
   role. The CLI rejects local execution and independently authenticates the
   earlier GitHub run, artifact, environment, and approval before constructing
   the AWS runner.

Execution repeats protected-source and live-IAM CAS checks, conditionally
reserves the authorization in the production artifact bucket, records the
write attempt, and issues at most one `CreatePolicyVersion` with
`SetAsDefault=true`. The request uses `AWS_MAX_ATTEMPTS=1`. A lost response is
resolved only by bounded readback: the exact desired document must be the new
default and the version inventory must be the exact predecessor plus one.
Otherwise the outcome remains ambiguous and no retry is permitted.

The S3 journal is keyed by the deterministic operation ID, so repeated
preparation or authorization artifacts for the same authenticated pre-state
cannot create another transaction namespace. The terminal record consumes the
authorization across machines. The exact-prefix journal write grant requires
both AES256 encryption and `If-None-Match: *`, so the executor cannot overwrite
an existing transaction record. If a crash
occurs after the IAM write but before terminal persistence, a retry recognizes
the exact post-state and writes only the terminal record. If the durable write
attempt exists while IAM remains in the predecessor state, the transaction is
ambiguous and requires governed investigation; it never repeats the IAM write.

## Version retention and mutation ceiling

The repository has no reviewed ProviderReadOnly policy-version pruning rule.
Preparation therefore permits one through four versions and fails closed at
five. It never selects or deletes a version. The transaction grants neither
`iam:DeletePolicyVersion` nor `iam:SetDefaultPolicyVersion` and performs no
attachment mutation.

The executor remains the existing protected-production OIDC role
`mscqr-production-initial-activation-policy-reconciler`. Its source policy adds
only exact ProviderReadOnly read/CreatePolicyVersion access and Get/Put access
to the dedicated reconciliation-journal prefix. Updating that executor policy
is a separate governed installation-plan transaction. The existing root
bootstrap contract can update only its exact inline permissions predecessor;
the installation plan can then update only the reconciler managed policy from
its exact predecessor and fails closed at five versions. Merging this source
does not modify production IAM.

# One-time signer Terraform capability

This procedure closes the authorization gap for the initial convergence of
`infra/aws/terraform/production-security-rebaseline-signer`. It uses the
existing MFA-backed `mscqr-production-bootstrap-operator` identity to create an authenticated temporary version of the existing
`MSCQRProductionGreenStageARelease` managed policy, then assumes the existing
`mscqr-production-release-deployer` role with that exact temporary managed
policy as its STS session policy. This prevents its other attached release
permissions from being available to signer Terraform. It does not create a
role, backend, workflow, or production bootstrap.

Before the first signer transition, reconcile
`MSCQRProductionBootstrapOperator-v2.json` through the existing source-bound
`production-bootstrap-operator-policy-reconciliation` workflow. It folds the
MFA-gated exact-policy read/`iam:CreatePolicyVersion` grant into the existing
bootstrap inline policy, whose non-whitespace size is 1,963 of IAM's 2,048
aggregate user-policy character limit. It adds no second inline policy and no
permanent KMS or signer-role read permission. Do not edit the live user policy
manually.

The managed policy is temporarily replaced with a signer-only document. The
temporary release-deployer session includes the exact signer IAM/KMS
permissions plus the read-only IAM-role/KMS census needed to prove signer
resources are absent. The census is performed after the temporary policy is
active, before Terraform initialization or planning; KMS key/alias pagination
is read one service page at a time. The other policies attached to the release
deployer are unchanged. Do not run Stage-A operations while this window is
open. After convergence, the canonical source policy is restored as the
default. The consumed temporary policy version remains non-default as a
replay marker; only the MFA-backed bootstrap operator can change the default.
Before each policy-version change, the controller proves the managed policy
is attached only to the release-deployer and is not used as a permissions
boundary. `CreatePolicyVersion` is issued once with AWS CLI retries disabled;
an ambiguous response is resolved only by AWS readback, never by retrying the
mutation.

## Preconditions

- Use a clean checkout whose `HEAD`, fetched `origin/main`, and authorized
  `--source-sha` are identical. The script enforces this before each phase.
- Use the fresh MFA `GetSessionToken` profile `mscqr-production-bootstrap-mfa`
  for the exact `mscqr-production-bootstrap-operator` IAM user. Its canonical
  signer capability policy permits only the source-bound signer policy
  transition and exact readback needed here. The controller assumes the
  release-deployer role with only the temporary signer policy as its STS
  session policy; the release role trust enforces MFA.
- The signer `init` phase uses the committed provider lock in read-only mode;
  if the locked provider cannot satisfy the root, stop before planning and
  update the lock through reviewed source first.
- Confirm the approved change reference for the separate Terraform apply.
- Keep the saved plan, Terraform state export, and evidence file in private
  directories with mode `0700`; files must be mode `0600`.
- The script fails closed if the role/alias already exists, any key already
  carries the exact signer tags, the managed policy differs from protected
  source, it has another consumer or permissions-boundary use, or fewer than
  two policy-version slots are free.

## Procedure

Set `SOURCE_SHA` to the exact protected-main SHA, use the established
`BOOTSTRAP_PROFILE`, and generate a unique `TRANSITION_ID` for this one-time
authorization.
Use an evidence file outside
the repository. Set a restrictive shell umask before creating local plan or
state files:

```sh
umask 077
SOURCE_SHA=$(git rev-parse HEAD)
TRANSITION_ID=$(uuidgen)
BOOTSTRAP_PROFILE='mscqr-production-bootstrap-mfa'
npm run production:signer-temporary-capability -- \
  --phase install --source-sha "$SOURCE_SHA" --transition-id "$TRANSITION_ID" \
  --bootstrap-profile "$BOOTSTRAP_PROFILE" \
  --state-file /private/tmp/signer-convergence/capability.json
```

The installer records the source, transition ID, and prior default version in
the private evidence file before issuing the one policy-version mutation. If
the process stops before it reports `INSTALLED`, retry only the readback
recovery phase with the same values; it never repeats the mutation:

```sh
npm run production:signer-temporary-capability -- \
  --phase recover-install --source-sha "$SOURCE_SHA" --transition-id "$TRANSITION_ID" \
  --bootstrap-profile "$BOOTSTRAP_PROFILE" \
  --state-file /private/tmp/signer-convergence/capability.json
```

Recovery succeeds only when AWS readback proves that exact transition's
temporary policy is active and the recorded steady version is still present.
If it cannot prove that state, stop and preserve the evidence for review.

Initialize only the documented backend through the restricted signer session, then generate a saved plan:

```sh
npm run production:signer-temporary-capability -- \
  --phase init --source-sha "$SOURCE_SHA" --transition-id "$TRANSITION_ID" \
  --bootstrap-profile "$BOOTSTRAP_PROFILE" \
  --state-file /private/tmp/signer-convergence/capability.json
npm run production:signer-temporary-capability -- \
  --phase plan --source-sha "$SOURCE_SHA" --transition-id "$TRANSITION_ID" \
  --bootstrap-profile "$BOOTSTRAP_PROFILE" \
  --plan-output /private/tmp/signer-convergence/signer.tfplan \
  --state-file /private/tmp/signer-convergence/capability.json
terraform -chdir=infra/aws/terraform/production-security-rebaseline-signer show \
  -no-color /private/tmp/signer-convergence/signer.tfplan
```

Review the displayed plan and obtain the separate human apply approval. The
following check derives JSON from the saved plan itself, accepts only creates
of the exact four source-defined signer resources, binds its bytes, and
records the approval reference:

```sh
npm run production:signer-temporary-capability -- \
  --phase verify-plan --source-sha "$SOURCE_SHA" --transition-id "$TRANSITION_ID" \
  --bootstrap-profile "$BOOTSTRAP_PROFILE" \
  --saved-plan /private/tmp/signer-convergence/signer.tfplan \
  --approval-reference '<approved-change-ticket>' \
  --state-file /private/tmp/signer-convergence/capability.json
```

Apply remains a separate operator phase, rechecks protected main and the
saved-plan hash, and requires the same separately approved change reference:

```sh
npm run production:signer-temporary-capability -- \
  --phase apply --source-sha "$SOURCE_SHA" --transition-id "$TRANSITION_ID" \
  --bootstrap-profile "$BOOTSTRAP_PROFILE" \
  --saved-plan /private/tmp/signer-convergence/signer.tfplan \
  --approval-reference '<approved-change-ticket>' \
  --state-file /private/tmp/signer-convergence/capability.json
```

Verify exact Terraform ownership and live IAM/KMS/OIDC readback, then revoke
the temporary version by restoring the source policy:

```sh
npm run production:signer-temporary-capability -- \
  --phase verify-convergence --source-sha "$SOURCE_SHA" --transition-id "$TRANSITION_ID" \
  --bootstrap-profile "$BOOTSTRAP_PROFILE" \
  --saved-plan /private/tmp/signer-convergence/signer.tfplan \
  --terraform-state /private/tmp/signer-convergence/terraform.tfstate \
  --state-file /private/tmp/signer-convergence/capability.json
npm run production:signer-temporary-capability -- \
  --phase revoke --source-sha "$SOURCE_SHA" --transition-id "$TRANSITION_ID" \
  --bootstrap-profile "$BOOTSTRAP_PROFILE" \
  --state-file /private/tmp/signer-convergence/capability.json
npm run production:signer-temporary-capability -- \
  --phase verify-absent --source-sha "$SOURCE_SHA" --transition-id "$TRANSITION_ID" \
  --bootstrap-profile "$BOOTSTRAP_PROFILE" \
  --state-file /private/tmp/signer-convergence/capability.json
```

For a stop before Terraform apply, `revoke --abort-before-apply-confirmed`
requires confirmation that no apply ran. An `INSTALLING` record can be
revoked even when the post-install census found pre-existing signer resources:
that state cannot enter init, plan, or apply. Revocation still requires a
complete IAM/KMS census; pagination or read errors leave the capability in
place and preserve the pending evidence for retry. `INSTALLED`, `PLAN_GENERATED`,
and `PLAN_REVIEWED` evidence additionally require an authoritative absent-role
and absent-alias readback before abort revocation. If apply partially creates
resources, stop: do not claim cleanup or remove the capability until the exact
signer state/live resource condition is reconciled through a separately
approved Terraform operation.

## Boundary

The temporary policy permits the exact signer state and lock objects, the
fixed signer role and inline policy, and the tagged RSA-3072 `SIGN_VERIFY`
key/alias plus readback. It grants no other Terraform state access, IAM role
target, KMS data-plane operation, ECS/RDS/Secrets Manager permission, or
application deployment permission. `kms:ListAliases` is read-only and
region-bound because AWS does not support alias-level resource scoping for
that list API. The final source-bound readback uses the existing signer
verifier, which validates exact GitHub OIDC trust, signer policy, key policy,
alias target, and zero unexpected KMS grants.

This document and its tests define a future operator procedure. Merging this
PR does not run any phase or mutate production.

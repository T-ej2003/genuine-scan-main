# One-time signer Terraform capability

This procedure closes the authorization gap for the initial convergence of
`infra/aws/terraform/production-security-rebaseline-signer`. The normal
MFA-backed `mscqr-production-bootstrap-operator` and the
`mscqr-production-release-deployer` cannot create policy versions. A separate
GitHub OIDC role, `mscqr-production-signer-policy-installer`, is assumed only
by the exact `production-signer-policy-transition` environment workflow after
its independent environment approval. That role can create versions only on
the existing `MSCQRProductionGreenStageARelease` policy.

The existing governed InitialActivation reconciler installation root creates
the installer role and its inline policy. The separate GitHub
`production-signer-policy-transition` environment must require reviewers,
disallow administrator bypass, and allow only the `main` branch; its workflow
checks that exact branch allowlist before requesting AWS credentials. The
reconciler bootstrap workflow may create
that exact role and write the exact named inline policy as part of its
source-bound, reviewed Terraform installation. Its permanent `iam:PutRolePolicy`
grant is scoped to the exact installer role ARN; IAM does not support an inline
policy-name condition for that API, so the reviewed source-bound plan and
canonical Terraform policy document enforce the inline policy name and content.
The bootstrap workflow can provision the role's policy but cannot change its
trust or assume the installer role. The release-deployer has no permission to
modify or assume it. The signer transition
workflow accepts only the fixed install/revoke phases, verifies protected-main
SHA and actual environment approval, and derives both policy documents from
repository source. The workflow does not accept an ARN or policy document.
Its caller and reusable workflow both grant the required `actions: read`
permission for approval-history verification, alongside the existing source
read and OIDC permissions. Approval evidence is written only after creating
and verifying a runner-temporary directory owned by the job with mode `0700`;
the evidence writer independently enforces that private-parent contract.

Policy installation and revocation are performed only by
`.github/workflows/production-signer-policy-transition.yml`. The MFA bootstrap
profile remains the identity for signer state readback and the separately
authorized Terraform plan/apply path through the release-deployer role. The
replay marker is retained as a non-default managed-policy version after
revocation; no workflow deletes policy versions.

## Preconditions

- Use a clean checkout whose `HEAD`, fetched `origin/main`, and authorized
  `--source-sha` are identical. The script enforces this before each phase.
- Use the fresh MFA `GetSessionToken` profile `mscqr-production-bootstrap-mfa`
  for the exact `mscqr-production-bootstrap-operator` IAM user. That identity
  has no `iam:CreatePolicyVersion` permission. The separately approved OIDC
  installer workflow performs policy transitions. Terraform access continues
  through `mscqr-production-release-deployer` with the exact temporary signer
  policy as its STS session policy; the release role trust enforces MFA.
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

Use the full exact protected-main SHA and a unique transition ID. Keep local
outputs in a private directory:

```sh
umask 077
mkdir -m 700 /private/tmp/signer-convergence
SOURCE_SHA=$(git rev-parse HEAD)
TRANSITION_ID=$(uuidgen)
BOOTSTRAP_PROFILE=mscqr-production-bootstrap-mfa
```

The independently approved GitHub environment is the only path that changes
the managed policy version. Trigger installation and save the resulting
`capability.json` artifact privately:

```sh
gh workflow run production-signer-policy-transition.yml \
  -f phase=policy-install -f source_sha="$SOURCE_SHA" \
  -f transition_id="$TRANSITION_ID"
```

Download that run's `production-signer-policy-transition-evidence` artifact.
The workflow also uploads a `production-signer-policy-transition-recovery`
artifact before the policy write. If the run fails after installation starts,
use that pending `INSTALLING` evidence with `recover-install`; do not dispatch
a second install transition. The protected environment accepts only the exact
`main` branch deployment rule and rejects additional branch or tag rules.
Then establish the fresh MFA bootstrap session and use the artifact as
`--state-file` with `recover-install`. If the exact temporary policy is active,
recovery performs the authenticated signer-resource absence census and writes
`INSTALLED`. If the durable record exists but AWS still has the unchanged
steady policy and no matching temporary version, recovery writes `REVOKED`
without an AWS write; run `verify-absent` and start a new transition ID. If
readback is ambiguous, stop; do not initialize Terraform.

```sh
npm run production:signer-temporary-capability -- \
  --phase recover-install --source-sha "$SOURCE_SHA" --transition-id "$TRANSITION_ID" \
  --bootstrap-profile "$BOOTSTRAP_PROFILE" --state-file /private/tmp/signer-convergence/capability.json
npm run production:signer-temporary-capability -- \
  --phase init --source-sha "$SOURCE_SHA" --transition-id "$TRANSITION_ID" \
  --bootstrap-profile "$BOOTSTRAP_PROFILE" --state-file /private/tmp/signer-convergence/capability.json
npm run production:signer-temporary-capability -- \
  --phase plan --source-sha "$SOURCE_SHA" --transition-id "$TRANSITION_ID" \
  --bootstrap-profile "$BOOTSTRAP_PROFILE" --plan-output /private/tmp/signer-convergence/signer.tfplan \
  --state-file /private/tmp/signer-convergence/capability.json
terraform -chdir=infra/aws/terraform/production-security-rebaseline-signer show -no-color \
  /private/tmp/signer-convergence/signer.tfplan
```

Review the saved plan and obtain the separate human apply authorization. Bind
that authorization reference to the plan, apply, and verify convergence:

```sh
npm run production:signer-temporary-capability -- \
  --phase verify-plan --source-sha "$SOURCE_SHA" --transition-id "$TRANSITION_ID" \
  --bootstrap-profile "$BOOTSTRAP_PROFILE" --saved-plan /private/tmp/signer-convergence/signer.tfplan \
  --approval-reference "$CHANGE_REFERENCE" --state-file /private/tmp/signer-convergence/capability.json
npm run production:signer-temporary-capability -- \
  --phase apply --source-sha "$SOURCE_SHA" --transition-id "$TRANSITION_ID" \
  --bootstrap-profile "$BOOTSTRAP_PROFILE" --saved-plan /private/tmp/signer-convergence/signer.tfplan \
  --approval-reference "$CHANGE_REFERENCE" --state-file /private/tmp/signer-convergence/capability.json
npm run production:signer-temporary-capability -- \
  --phase verify-convergence --source-sha "$SOURCE_SHA" --transition-id "$TRANSITION_ID" \
  --bootstrap-profile "$BOOTSTRAP_PROFILE" --saved-plan /private/tmp/signer-convergence/signer.tfplan \
  --terraform-state /private/tmp/signer-convergence/terraform.tfstate \
  --state-file /private/tmp/signer-convergence/capability.json
```

Keep the plan, Terraform state export, and evidence in private mode-0700
directories and files with mode 0600.

After `verify-convergence` records `CONVERGED`, base64-encode that evidence
file and compute its SHA-256. Trigger revocation through the same protected
environment workflow, supplying the same source SHA and transition ID plus
that evidence payload and digest:

```sh
gh workflow run production-signer-policy-transition.yml \
  -f phase=policy-revoke -f source_sha="$SOURCE_SHA" \
  -f transition_id="$TRANSITION_ID" \
  -f evidence_base64="$EVIDENCE_BASE64" \
  -f evidence_sha256="$EVIDENCE_SHA256"
```

Download the workflow's `REVOKED` evidence artifact, replacing the prior local
state file, then run the local `verify-absent` phase with the bootstrap
profile. That phase proves the canonical steady policy is active and the exact
temporary version remains only as a non-default replay marker.
If the revoke run stops after AWS has restored the steady policy but before
the final evidence upload, rerun the same protected revoke transition with the
original `CONVERGED` evidence. It performs exact readback and completes the
`REVOKED` evidence without creating another policy version.

```sh
npm run production:signer-temporary-capability -- \
  --phase verify-absent --source-sha "$SOURCE_SHA" --transition-id "$TRANSITION_ID" \
  --bootstrap-profile "$BOOTSTRAP_PROFILE" --state-file /private/tmp/signer-convergence/capability.json
```

A stop before Terraform apply still requires the protected `policy-revoke`
workflow. Set `abort_before_apply=true` and submit the exact evidence artifact;
the environment approval authorizes restoring steady policy only from
`INSTALLING`, `INSTALLED`, `PLAN_GENERATED`, or `PLAN_REVIEWED`. The apply path
records `APPLY_STARTED` before Terraform runs, and that state cannot use the
abort path. If apply started or partially created resources, stop and preserve
the capability until a separately approved Terraform operation resolves the
exact signer state.

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

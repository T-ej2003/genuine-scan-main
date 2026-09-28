# One-time signer Terraform capability

This incremental procedure converges
`infra/aws/terraform/production-security-rebaseline-signer` in the existing
production estate. It does not bootstrap production.

The immutable component IAM broker is the only identity that can create or
delete managed-policy versions for `MSCQRProductionGreenStageARelease`. The
bootstrap operator, release deployer, and GitHub OIDC signer publisher have no
direct policy-version mutation permission. The publisher can invoke only
immutable broker version `15`, which accepts a fixed source-owned authorization
document. Versions `13` and `14` perform the fixed install and revoke operations
through MFA-backed component sessions.

The broker binds repository, protected source SHA, account, region, purpose,
transition ID, exact policy ARN, canonical predecessor and successor documents,
and a durable S3 lifecycle ledger. The ledger is authoritative. A local or
downloaded pre-apply artifact cannot authorize abort after the broker records
`APPLY_STARTED`.

## One-time broker generation convergence

Merging source does not change the deployed immutable broker. Before the signer
transition, converge the additive broker generation through the existing
successor mechanism:

1. Apply the reviewed incremental `production-initial-activation-policy-reconciler`
   delta. It changes the existing signer publisher to `lambda:InvokeFunction`
   on broker version `15` and adds the exact `broker-recovery-successor.json`
   object to the existing recovery-successor evidence reader.
2. Dispatch `.github/workflows/authorize-component-broker-recovery-successor.yml`
   from the exact protected-main SHA with `successor=signer` and a fresh UUID.
3. From that exact clean source, run:

   ```sh
   npm run production:component-broker-signer-successor -- execute RUN_ID TRANSITION_ID
   ```

The existing exceptional root-MFA successor controller can publish only versions
`13`, `14`, and `15`, install only the five canonical broker/session inline
policies, and close the third immutable lineage record. It cannot choose the
signer managed-policy document. Normal signer operations after this convergence
are non-root and MFA-backed.

## Signer transition

Use the full current protected-main SHA, one transition UUID, and private files:

```sh
umask 077
mkdir -m 700 /private/tmp/signer-convergence
SOURCE_SHA=$(git rev-parse HEAD)
TRANSITION_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')
BOOTSTRAP_PROFILE=mscqr-production-bootstrap-mfa
```

Authorize installation through the solo-operator protected environment:

```sh
gh workflow run production-signer-policy-transition.yml \
  -f phase=policy-install -f source_sha="$SOURCE_SHA" \
  -f transition_id="$TRANSITION_ID"
```

Download `production-signer-policy-transition-evidence` as
`/private/tmp/signer-convergence/broker-state.json`. The workflow only archives
the canonical broker authorization. The local controller then uses the MFA
bootstrap operator to invoke broker version `13` and recover exact installation
evidence:

```sh
chmod 600 /private/tmp/signer-convergence/broker-state.json
```

```sh
npm run production:signer-temporary-capability -- \
  --phase recover-install --source-sha "$SOURCE_SHA" --transition-id "$TRANSITION_ID" \
  --bootstrap-profile "$BOOTSTRAP_PROFILE" \
  --broker-state-file /private/tmp/signer-convergence/broker-state.json \
  --state-file /private/tmp/signer-convergence/capability.json
npm run production:signer-temporary-capability -- \
  --phase init --source-sha "$SOURCE_SHA" --transition-id "$TRANSITION_ID" \
  --bootstrap-profile "$BOOTSTRAP_PROFILE" \
  --broker-state-file /private/tmp/signer-convergence/broker-state.json \
  --state-file /private/tmp/signer-convergence/capability.json
npm run production:signer-temporary-capability -- \
  --phase plan --source-sha "$SOURCE_SHA" --transition-id "$TRANSITION_ID" \
  --bootstrap-profile "$BOOTSTRAP_PROFILE" \
  --broker-state-file /private/tmp/signer-convergence/broker-state.json \
  --plan-output /private/tmp/signer-convergence/signer.tfplan \
  --state-file /private/tmp/signer-convergence/capability.json
```

Review the saved plan. Bind the separate apply authorization, then apply and
verify. The controller advances the broker ledger through `PLAN_GENERATED`,
`PLAN_REVIEWED`, `APPLY_AUTHORIZED`, and `APPLY_STARTED` before Terraform can
mutate. It records `APPLIED` and `CONVERGED` only after those operations succeed.

```sh
npm run production:signer-temporary-capability -- \
  --phase verify-plan --source-sha "$SOURCE_SHA" --transition-id "$TRANSITION_ID" \
  --bootstrap-profile "$BOOTSTRAP_PROFILE" \
  --broker-state-file /private/tmp/signer-convergence/broker-state.json \
  --saved-plan /private/tmp/signer-convergence/signer.tfplan \
  --approval-reference "$CHANGE_REFERENCE" \
  --state-file /private/tmp/signer-convergence/capability.json
npm run production:signer-temporary-capability -- \
  --phase apply --source-sha "$SOURCE_SHA" --transition-id "$TRANSITION_ID" \
  --bootstrap-profile "$BOOTSTRAP_PROFILE" \
  --broker-state-file /private/tmp/signer-convergence/broker-state.json \
  --saved-plan /private/tmp/signer-convergence/signer.tfplan \
  --approval-reference "$CHANGE_REFERENCE" \
  --state-file /private/tmp/signer-convergence/capability.json
npm run production:signer-temporary-capability -- \
  --phase verify-convergence --source-sha "$SOURCE_SHA" --transition-id "$TRANSITION_ID" \
  --bootstrap-profile "$BOOTSTRAP_PROFILE" \
  --broker-state-file /private/tmp/signer-convergence/broker-state.json \
  --saved-plan /private/tmp/signer-convergence/signer.tfplan \
  --terraform-state /private/tmp/signer-convergence/terraform.tfstate \
  --state-file /private/tmp/signer-convergence/capability.json
```

Each broker authorization is valid for 30 minutes. If it expires before a
pre-apply advance, dispatch `policy-install` again with the same source and
transition, then replace `broker-state.json` with the new artifact. The broker
accepts only a later approval and retains consumed authorization history.
If a process loses an acknowledgement, rerun the same phase with the same
private files. The client reauthenticates the exact broker transition; an
existing saved plan is reused only by byte digest. After an ambiguous Terraform
apply, run `verify-convergence` instead of applying the saved plan again.

After convergence, dispatch `policy-revoke` with the same source and transition.
Replace `broker-state.json` with the returned artifact, then run:

```sh
npm run production:signer-temporary-capability -- \
  --phase revoke --source-sha "$SOURCE_SHA" --transition-id "$TRANSITION_ID" \
  --bootstrap-profile "$BOOTSTRAP_PROFILE" \
  --broker-state-file /private/tmp/signer-convergence/broker-state.json \
  --state-file /private/tmp/signer-convergence/capability.json
npm run production:signer-temporary-capability -- \
  --phase verify-absent --source-sha "$SOURCE_SHA" --transition-id "$TRANSITION_ID" \
  --bootstrap-profile "$BOOTSTRAP_PROFILE" \
  --broker-state-file /private/tmp/signer-convergence/broker-state.json \
  --state-file /private/tmp/signer-convergence/capability.json
```

For an authorized abort before apply, add `--abort-before-apply-confirmed` to
the `revoke` phase. The broker compares submitted evidence with its current
ledger and rejects abort at `APPLY_STARTED`, `APPLIED`, or `CONVERGED`, including
when an older valid artifact is supplied.

The temporary policy remains limited to the exact signer state and lock objects,
signer role and inline policy, and tagged RSA-3072 `SIGN_VERIFY` key/alias. It
grants no unrelated state, IAM, KMS data-plane, ECS, RDS, Secrets Manager, or
application deployment authority.

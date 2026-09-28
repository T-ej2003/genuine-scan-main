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

### Resume the verified second successor after the S3 metadata limit

The 2026-09-28 recovery attempt already published immutable broker versions
`10/11/12` and converged all five successor IAM policies. Its recovery
reservation is `VERIFIED`; only the second closure on `identity-bootstrap.json`
is missing. Preserve both existing journals and those live generations. The
closure controller pins this exact historical reservation, verifies the live
versions and policies, fences the consumed owner, and writes only the new
reservation owner and missing closure. It cannot republish Lambda versions or
reapply IAM policies on this path.

After this source change merges, authorize from the **new** protected-main SHA
using the existing workflow, `successor=recovery`, and the **same** transition
ID `22955a47-da8b-4d7f-a01d-cc39fbef5a5c`. The workflow reads the existing
`VERIFIED` reservation and binds its exact body digest and ETag in a fresh
authorization. Do not reuse the consumed run or choose a new transition ID.
After the protected environment approves the new run, execute from that exact
clean source in an interactive terminal:

```sh
node scripts/aws/component-broker-recovery-successor-cli.mjs execute RUN_ID \
  22955a47-da8b-4d7f-a01d-cc39fbef5a5c
```

Authenticate the resulting `identity-bootstrap.json` body, compact closure
metadata digest, `VERIFIED` reservation, and live versions `10/11/12` before
starting the signer successor. The original first-successor metadata remains
unchanged. The full second and later third closure records live in the
versioned journal body; each S3 metadata value is its canonical SHA-256 digest.
The executor checks the aggregate UTF-8 bytes of every metadata key and value
against S3's 2,048-byte limit before `PutObject`.

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
  -f transition_source_sha="$SOURCE_SHA" \
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
If recovery authority expires after the ledger reaches `APPLIED`, renew
`policy-recover` and run `verify-convergence`; do not run Terraform apply again.
If a revoke acknowledgement is lost and its authority expires after the ledger
reaches `REVOKED`, renew `policy-revoke` and retry readback. The broker verifies
canonical steady state without creating another policy version.
If a process loses an acknowledgement, rerun the same phase with the same
private files. The client reauthenticates the exact broker transition; an
existing saved plan is reused only by byte digest. After an ambiguous Terraform
apply, run `verify-convergence` instead of applying the saved plan again.
If readback proves the apply stopped after creating only a canonical subset,
dispatch `policy-recover` with the original `transition_source_sha`, current
protected-main `source_sha`, and the same transition ID, then replace the
private broker-state artifact. This authority is accepted only after the
broker's durable ledger has reached `APPLY_STARTED`. Create a new private plan
with `--phase recover-plan`, review it with
`--phase recover-verify-plan`, and execute it with `--phase recover-apply`.
Each command uses the same common source, transition, profile, broker-state,
and capability-state arguments; the plan phases additionally use
`--plan-output` or `--saved-plan` and the review/apply phases use a fresh
`--approval-reference`. The broker binds every recovery attempt after
`APPLY_STARTED`; another partial failure requires a newly generated and
separately reviewed plan. Old recovery plans cannot replay.

After convergence, dispatch `policy-revoke` with the original transition source
and the then-current protected main. The workflow accepts a descendant only
when the signer cleanup contract is unchanged. A later approval can renew an
expired revoke authorization without changing the transition identity:

```sh
CURRENT_MAIN_SHA=$(git rev-parse origin/main)
gh workflow run production-signer-policy-transition.yml \
  -f phase=policy-revoke -f source_sha="$CURRENT_MAIN_SHA" \
  -f transition_source_sha="$SOURCE_SHA" \
  -f transition_id="$TRANSITION_ID"
```

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
If the broker is still at `INSTALLING` and no temporary policy was created,
the same `revoke` command works even when `capability.json` does not yet exist.
It authenticates the exact canonical steady policy, asks the broker to record
`REVOKED` without a policy-version write, then creates `capability.json` for
the normal `verify-absent` step. A lost revoke acknowledgement can be retried
with renewed `policy-revoke` authorization; the broker's durable ledger and
steady-policy readback decide whether the retry is safe.
If installation wrote the exact temporary policy before its acknowledgement was
lost, the same abort path delegates restoration to the broker and records that
temporary version for the normal absence readback.

The temporary policy remains limited to the exact signer state and lock objects,
signer role and inline policy, and tagged RSA-3072 `SIGN_VERIFY` key/alias. It
grants no unrelated state, IAM, KMS data-plane, ECS, RDS, Secrets Manager, or
application deployment authority.

### Signer session authority

The two existing component session roles directly trust the exact same-account
`mscqr-production-bootstrap-operator` IAM user with MFA. AWS STS permits that
same-account user to assume a role through its direct resource-based trust
without another `sts:AssumeRole` allow in the user policy; the user has no
permissions boundary. The normal release-deployer assumption remains separately
listed in the bootstrap policy. See the [AWS AssumeRole API authorization rules](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html).

The protected workflow publishes `SIGNER_AUTHORIZE` to broker version 15. The
broker persists that authorization in the signer policy transition ledger.
Before dispatch, the signer successor broker reads the exact policy, recovery,
and signer successor reservation objects to authenticate its immutable lineage;
its execution policy grants those three object reads and the signer ledger read.
`production-signer-broker-transition-cli.mjs` obtains an MFA-backed bootstrap
session and asks version 13 or 14 for `SIGNER_PROVE_INSTALL_SESSION` or
`SIGNER_PROVE_REVOKE_SESSION`. Those read-only operations authenticate against
the same signer ledger and validate the signer-specific session binding before
`SIGNER_INSTALL`, `SIGNER_ADVANCE`, `SIGNER_RECOVERY`, or `SIGNER_REVOKE` can run.
The ordinary component installation and cleanup archives cannot authorize a
signer operation. The broker ledger remains authoritative if a local state
artifact is stale; abort after `APPLY_STARTED` is rejected. Every signer
mutation also requires an MFA session issued after the current signer
authorization, including when an operator invokes the broker directly.

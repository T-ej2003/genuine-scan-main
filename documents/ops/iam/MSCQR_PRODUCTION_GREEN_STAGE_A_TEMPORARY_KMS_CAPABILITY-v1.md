# Temporary Stage-A KMS creation capability

`kms:CreateKey`, `kms:TagResource`, `kms:PutKeyPolicy`, and `kms:CreateAlias` are not part of the
steady-state `MSCQRProductionGreenStageARelease` policy. AWS requires the
first two for the tagged key creation and requires the temporary caller to have
`kms:PutKeyPolicy` so KMS lockout-safety can validate the supplied initial key
policy. That administration permission is bounded to the tagged
`RSA_3072`/`SIGN_VERIFY` root-drop key. The canonical Terraform `CreateKey`
request uses the AWS default `BypassPolicyLockoutSafetyCheck=false`; the launch
path never requests the bypass. The alias
operation is scoped to
the exact root-drop alias ARN and its associated key is limited to the
production-tagged `RSA_3072`/`SIGN_VERIFY` key family. The only permitted exception is an
administrator-controlled managed-policy version window described by
`MSCQRProductionGreenStageATemporaryRootDropCreation-v1.json`.

The administrator must use the canonical producer:

The authenticated release-read preflight writes both the fresh Stage-A state
backup and `stage-a-state-identity.json` in the private release artifact
directory. Authorization must consume both artifacts; it must not derive an
expected identity from the state backup itself.

```sh
npm run stage-a:temporary-kms-capability -- \
  --phase authorize \
  --source-sha <fresh-protected-main-sha> \
  --transition-id <fresh-transition-id> \
  --plan-sha256 <fresh-saved-plan-sha256> \
  --plan-json <fresh-classified-plan-json> \
  --stage-a-state <fresh-stage-a-state> \
  --stage-a-state-identity <fresh-stage-a-state-identity> \
  --state-file <private-capability-state.json> \
  --admin-profile <explicit-administrator-profile> \
  --release-profile mscqr-production-release-deployer
```

The saved Stage-A plan is then applied exactly once with the release profile.
The producer records `STAGE_A_APPLY`, and only independently verified Terraform
ownership of both the root-drop key and alias can advance the state to
`ROOT_DROP_OWNERSHIP_VERIFIED`. Apply failure must use the producer's abort
path; it may not leave the temporary default active.

After ownership verification, run the producer's `revoke` phase. It creates a
new default policy version from the steady-state source, verifies the source
document, and removes only the exact temporary version. `verify-absent` must
then observe the steady-state policy and no temporary version. The cutover
runtime consumes that `ABSENCE_VERIFIED` evidence and rejects every other state.

The locked AWS provider (`hashicorp/aws` `6.56.0`) also reads a created
`aws_kms_key.root_drop` with `kms:DescribeKey`, `kms:GetKeyPolicy`,
`kms:GetKeyRotationStatus`, and `kms:ListResourceTags`. Those read permissions
are steady-state, read-only authority in `MSCQRProductionGreenStageBProviderReadOnly`;
the root-drop key policy exposes the same readback set to the release role.
The administrator preflight simulates all four actions before any Stage-A
mutation.

The administrator profile is used only for the IAM policy-version transition;
the release profile is used for the exact production apply and readback. No
credential, token, MFA value, or secret is stored in the evidence.

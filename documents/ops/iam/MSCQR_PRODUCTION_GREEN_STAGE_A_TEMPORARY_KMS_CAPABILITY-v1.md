# Temporary Stage-A KMS creation capability

`kms:TagResource` is not part of the steady-state
`MSCQRProductionGreenStageARelease` policy. AWS requires that action when tags
are supplied to `CreateKey`, so the only permitted exception is an
administrator-controlled managed-policy version window described by
`MSCQRProductionGreenStageATemporaryRootDropCreation-v1.json`.

The administrator must use the canonical producer:

```sh
npm run stage-a:temporary-kms-capability -- \
  --phase authorize \
  --source-sha <fresh-protected-main-sha> \
  --transition-id <fresh-transition-id> \
  --plan-sha256 <fresh-saved-plan-sha256> \
  --plan-json <fresh-classified-plan-json> \
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

The administrator profile is used only for the IAM policy-version transition;
the release profile is used for the exact production apply and readback. No
credential, token, MFA value, or secret is stored in the evidence.

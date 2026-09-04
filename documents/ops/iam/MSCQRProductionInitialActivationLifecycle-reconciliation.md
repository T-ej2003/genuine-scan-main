# Production initial-activation lifecycle policy reconciliation

`PRODUCTION_INITIAL_ACTIVATION_LIFECYCLE_POLICY_RECONCILIATION` is a one-target governed repair for `arn:aws:iam::368992683803:policy/MSCQRProductionInitialActivationLifecycle`.

It accepts only the authenticated `v1` predecessor with SHA-256 `2a90146c8fc8f6062198650134c0e92724cc4dd69720bde629fd0752e4432c71`, or an already-reconciled source document. The desired document is always `documents/ops/iam/MSCQRProductionInitialActivationLifecycle-v1.json` with SHA-256 `7e9eef0b5dd5c089f4734a43cbc40ed963078dc500828c2e592cc07f04c6d564`.

The approval artifact binds the protected source, exact target, predecessor, desired document, complete release-role policy set, target-policy entity boundary, version count, and a single `iam:CreatePolicyVersion` request with `SetAsDefault=true`. The target policy may be attached only to `mscqr-production-release-deployer`, with no users, groups, or permissions-boundary usage. It authorizes neither policy attachment changes, `iam:SetDefaultPolicyVersion`, nor `iam:DeletePolicyVersion`; the production-environment approval freshness limit is checked again immediately before the write.

The executor uses the independently authenticated root operator, rereads the exact live state immediately before mutation, and performs one create at most. It requires post-write readback of a new default version with the exact desired canonical document and unchanged attachments. If a response is lost after AWS accepted the create, exact desired readback finalizes completion without another version creation.

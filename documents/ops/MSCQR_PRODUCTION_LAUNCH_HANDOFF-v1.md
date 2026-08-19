# MSCQR launch handoff

This is a planning handoff, not authorization evidence. It was generated while repairing the release-deployer KMS capability. The next execution must resolve a fresh merged `origin/main` SHA and regenerate every source-bound artifact.

The complete launch producer/consumer graph is in `documents/ops/MSCQR_PRODUCTION_LAUNCH_HANDOFF_MANIFEST-v1.json`. Its hard pre-mutation gate includes the temporary Stage-A KMS creation-capability lifecycle: authorization, exact saved-plan apply, root-drop ownership verification, revocation, and independent absence verification must complete before the governed ECS cutover.

Operator-owned boundaries are explicit: approval metadata, a fresh rotation identifier, the root-only signing session, and MFA/verifier actions. No password, secret value, private key, session credential, or MFA value is an artifact. The next run must discard the failed serial-42/43 binary plan as executable input and all other stale executable artifacts, but retain the recorded failed-apply provenance bindings (source, transition, plan SHA, state identity, and CreateKey evidence) required to authenticate the exact existing 1/0 key. It must authorize the exact temporary recovery capability before provider refresh, read Stage-A state afresh, classify a new non-targeted recovery plan, and apply only that new plan once its exact mutation envelope is reviewed.

No canonical producer was missing during discovery. The repository owns the Stage-A prerequisite/recovery, rotation, root evidence, runtime, inventory, broker proof, cutover, convergence, verification, and onboarding transitions named in the manifest.

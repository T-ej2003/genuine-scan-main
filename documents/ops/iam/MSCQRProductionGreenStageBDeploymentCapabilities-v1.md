# Stage B production deployment capability graph

Generated from the permission manifest, reviewed source policies, release probes, canonical recovery, zero-registration forward recovery, publisher policy, Terraform runtime policy actions, and the production path. Do not edit generated capability rows manually.

- Phases: 56
- Capability nodes: 668
- Unique AWS actions: 157
- Identities: GITHUB_IMAGE_PUBLISHER, ADMINISTRATOR, ROOT_OPERATOR, BOOTSTRAP_OPERATOR, RELEASE_DEPLOYER, INDEPENDENT_CHECKER, ECS_EXEC_VERIFIER_OPERATOR, SERVICE_RUNTIME, INITIAL_ACTIVATION_RECONCILER, BOOTSTRAP_OPERATOR_POLICY_AUTHORIZER, MIXED_RECOVERY_EXECUTOR, APP_ONLY_DEPLOYER, APP_ONLY_VERIFIER_LAUNCHER, APP_ONLY_PERMISSION_PROVISIONER

| Order | Phase | Source |
|---:|---|---|
| 1 | app-only-permission-bootstrap | `scripts/aws/run-production-app-only-bootstrap.mjs` |
| 2 | app-only-live-compatibility | `scripts/aws/run-production-app-only-verifier.mjs` |
| 3 | app-only-permission-provisioning | `scripts/aws/production-app-only-provisioning.mjs` |
| 4 | app-only-backend-activation | `scripts/aws/production-app-only-activation.mjs` |
| 5 | protected-main-checkout | `scripts/aws/stage-b-release-gate.mjs` |
| 6 | dependency-installation | `package.json` |
| 7 | rls-package-verification | `scripts/rls/verify-full-rls-package.mjs` |
| 8 | image-impact-classification | `scripts/aws/validate-stage-b-image-reuse.mjs` |
| 9 | image-workflow-dispatch | `scripts/aws/dispatch-production-green-stage-b-images.mjs` |
| 10 | image-artifact-verification | `.github/workflows/production-green-stage-b-image-build.yml` |
| 11 | schema-v4-image-evidence | `scripts/aws/production-green-stage-b-image-evidence.mjs` |
| 12 | administrator-release-oidc-trust-convergence | `scripts/aws/converge-production-release-oidc-trust.mjs` |
| 13 | administrator-normal-backend-activation-convergence | `scripts/aws/production-normal-backend-activation.mjs` |
| 14 | administrator-iam-simulation | `scripts/aws/validate-production-green-stage-b-permissions.mjs` |
| 15 | administrator-kms-signing | `scripts/aws/validate-production-green-stage-b-permissions.mjs` |
| 16 | bootstrap-mfa-session | `documents/security/rls-program/PRODUCTION_GREEN_STAGE_B_INFRASTRUCTURE_RUNBOOK.md` |
| 17 | verifier-role-assumption | `scripts/aws/establish-production-ecs-exec-verifier-session.mjs` |
| 18 | release-role-assumption | `documents/security/rls-program/PRODUCTION_GREEN_STAGE_B_INFRASTRUCTURE_RUNBOOK.md` |
| 19 | release-direct-read-preflight | `scripts/aws/run-production-green-stage-b-preflight.mjs` |
| 20 | release-preflight-checker-trust-attestation | `scripts/aws/production-release-preflight-checker-attestation.mjs` |
| 21 | backend-config-generation | `scripts/aws/generate-production-green-stage-b-backend-config.mjs` |
| 22 | terraform-initialization | `scripts/aws/run-production-green-stage-b-preflight.mjs` |
| 23 | backend-metadata-validation | `scripts/aws/stage-b-terraform-backend-contract.mjs` |
| 24 | workspace-validation | `scripts/aws/stage-b-terraform-workspace.mjs` |
| 25 | canonical-backend-recovery | `scripts/aws/recover-stage-b-backend-task-definition.mjs` |
| 26 | backend-health-recovery | `scripts/aws/recover-production-backend-health.mjs` |
| 27 | runtime-consumability-evidence | `scripts/aws/prepare-production-ecs-runtime-consumability.mjs` |
| 28 | runtime-consumability-convergence | `scripts/aws/converge-production-ecs-runtime-policy.mjs` |
| 29 | existing-revision-forward-recovery | `scripts/aws/forward-recover-stage-b-existing-revision.mjs` |
| 30 | stage-b-state-pull | `scripts/aws/run-production-green-stage-b-preflight.mjs` |
| 31 | stage-a-state-read | `scripts/aws/run-production-green-stage-b-preflight.mjs` |
| 32 | stage-a-handoff-generation | `scripts/aws/generate-production-green-stage-a-prerequisites.mjs` |
| 33 | root-drop-evidence-signing | `scripts/aws/produce-production-root-drop-evidence.mjs` |
| 34 | tfvars-generation | `scripts/aws/generate-production-green-stage-b-tfvars.mjs` |
| 35 | refresh-only | `scripts/refresh-production-green-stage-b.mjs` |
| 36 | saved-plan-generation | `scripts/plan-production-green-stage-b.mjs` |
| 37 | plan-json-canonicalization | `scripts/plan-production-green-stage-b.mjs` |
| 38 | reference-audit | `scripts/aws/generate-production-green-stage-b-reference-audit.mjs` |
| 39 | plan-bound-permission-report | `scripts/aws/validate-production-green-stage-b-permissions.mjs` |
| 40 | production-closure | `scripts/aws/validate-stage-b-deployment-closure.mjs` |
| 41 | validator | `scripts/plan-production-green-stage-b.mjs` |
| 42 | wrapper-verify-only | `scripts/apply-production-green-stage-b.mjs` |
| 43 | wrapper-apply | `scripts/apply-production-green-stage-b.mjs` |
| 44 | post-apply-verification | `scripts/aws/verify-production-green-stage-b-ecs-observations.mjs` |
| 45 | runtime-activation-boundary | `scripts/aws/create-production-green-stage-b-approval.mjs` |
| 46 | normal-backend-activation | `scripts/aws/production-normal-backend-activation.mjs` |
| 47 | initial-activation-lifecycle | `scripts/aws/manage-production-initial-activation-lifecycle.mjs` |
| 48 | dual-slot-rebaseline-durable-evidence | `scripts/aws/persist-production-dual-slot-rebaseline-durable-evidence.mjs` |
| 49 | stage-a-production-artifacts-policy-recovery | `scripts/aws/run-production-stage-a-production-artifacts-recovery.mjs` |
| 50 | stage-a-production-artifacts-state-reconciliation | `scripts/aws/run-production-stage-a-production-artifacts-reconciliation.mjs` |
| 51 | initial-activation-lifecycle-policy-reconciliation | `scripts/aws/run-production-initial-activation-lifecycle-policy-reconciliation.mjs` |
| 52 | provider-readonly-policy-reconciliation | `scripts/aws/reconcile-production-provider-readonly-policy.mjs` |
| 53 | bootstrap-operator-policy-reconciliation | `scripts/aws/production-bootstrap-operator-policy-reconciliation.mjs` |
| 54 | mixed-dual-slot-recovery-iam-preflight | `scripts/aws/preflight-production-mixed-dual-slot-recovery-iam.mjs` |
| 55 | mixed-dual-slot-recovery-execution | `scripts/aws/recover-production-mixed-dual-slot-topology.mjs` |
| 56 | stage-b-exact-refresh-only-state-reconciliation | `scripts/aws/reconcile-production-green-stage-b-state.mjs` |

# Stage B production deployment capability graph

Generated from the permission manifest, reviewed source policies, release probes, canonical recovery, zero-registration forward recovery, publisher policy, Terraform runtime policy actions, and the production path. Do not edit generated capability rows manually.

- Phases: 51
- Capability nodes: 439
- Unique AWS actions: 148
- Identities: GITHUB_IMAGE_PUBLISHER, ADMINISTRATOR, ROOT_OPERATOR, BOOTSTRAP_OPERATOR, RELEASE_DEPLOYER, INDEPENDENT_CHECKER, ECS_EXEC_VERIFIER_OPERATOR, SERVICE_RUNTIME, INITIAL_ACTIVATION_RECONCILER, BOOTSTRAP_OPERATOR_POLICY_AUTHORIZER, MIXED_RECOVERY_EXECUTOR

| Order | Phase | Source |
|---:|---|---|
| 1 | protected-main-checkout | `scripts/aws/stage-b-release-gate.mjs` |
| 2 | dependency-installation | `package.json` |
| 3 | rls-package-verification | `scripts/rls/verify-full-rls-package.mjs` |
| 4 | image-impact-classification | `scripts/aws/validate-stage-b-image-reuse.mjs` |
| 5 | image-workflow-dispatch | `scripts/aws/dispatch-production-green-stage-b-images.mjs` |
| 6 | image-artifact-verification | `.github/workflows/production-green-stage-b-image-build.yml` |
| 7 | schema-v4-image-evidence | `scripts/aws/production-green-stage-b-image-evidence.mjs` |
| 8 | administrator-release-oidc-trust-convergence | `scripts/aws/converge-production-release-oidc-trust.mjs` |
| 9 | administrator-normal-backend-activation-convergence | `scripts/aws/production-normal-backend-activation.mjs` |
| 10 | administrator-iam-simulation | `scripts/aws/validate-production-green-stage-b-permissions.mjs` |
| 11 | administrator-kms-signing | `scripts/aws/validate-production-green-stage-b-permissions.mjs` |
| 12 | bootstrap-mfa-session | `documents/security/rls-program/PRODUCTION_GREEN_STAGE_B_INFRASTRUCTURE_RUNBOOK.md` |
| 13 | verifier-role-assumption | `scripts/aws/establish-production-ecs-exec-verifier-session.mjs` |
| 14 | release-role-assumption | `documents/security/rls-program/PRODUCTION_GREEN_STAGE_B_INFRASTRUCTURE_RUNBOOK.md` |
| 15 | release-direct-read-preflight | `scripts/aws/run-production-green-stage-b-preflight.mjs` |
| 16 | release-preflight-checker-trust-attestation | `scripts/aws/production-release-preflight-checker-attestation.mjs` |
| 17 | backend-config-generation | `scripts/aws/generate-production-green-stage-b-backend-config.mjs` |
| 18 | terraform-initialization | `scripts/aws/run-production-green-stage-b-preflight.mjs` |
| 19 | backend-metadata-validation | `scripts/aws/stage-b-terraform-backend-contract.mjs` |
| 20 | workspace-validation | `scripts/aws/stage-b-terraform-workspace.mjs` |
| 21 | canonical-backend-recovery | `scripts/aws/recover-stage-b-backend-task-definition.mjs` |
| 22 | backend-health-recovery | `scripts/aws/recover-production-backend-health.mjs` |
| 23 | runtime-consumability-evidence | `scripts/aws/prepare-production-ecs-runtime-consumability.mjs` |
| 24 | runtime-consumability-convergence | `scripts/aws/converge-production-ecs-runtime-policy.mjs` |
| 25 | existing-revision-forward-recovery | `scripts/aws/forward-recover-stage-b-existing-revision.mjs` |
| 26 | stage-b-state-pull | `scripts/aws/run-production-green-stage-b-preflight.mjs` |
| 27 | stage-a-state-read | `scripts/aws/run-production-green-stage-b-preflight.mjs` |
| 28 | stage-a-handoff-generation | `scripts/aws/generate-production-green-stage-a-prerequisites.mjs` |
| 29 | root-drop-evidence-signing | `scripts/aws/produce-production-root-drop-evidence.mjs` |
| 30 | tfvars-generation | `scripts/aws/generate-production-green-stage-b-tfvars.mjs` |
| 31 | refresh-only | `scripts/refresh-production-green-stage-b.mjs` |
| 32 | saved-plan-generation | `scripts/plan-production-green-stage-b.mjs` |
| 33 | plan-json-canonicalization | `scripts/plan-production-green-stage-b.mjs` |
| 34 | reference-audit | `scripts/aws/generate-production-green-stage-b-reference-audit.mjs` |
| 35 | plan-bound-permission-report | `scripts/aws/validate-production-green-stage-b-permissions.mjs` |
| 36 | production-closure | `scripts/aws/validate-stage-b-deployment-closure.mjs` |
| 37 | validator | `scripts/plan-production-green-stage-b.mjs` |
| 38 | wrapper-verify-only | `scripts/apply-production-green-stage-b.mjs` |
| 39 | wrapper-apply | `scripts/apply-production-green-stage-b.mjs` |
| 40 | post-apply-verification | `scripts/aws/verify-production-green-stage-b-ecs-observations.mjs` |
| 41 | runtime-activation-boundary | `scripts/aws/create-production-green-stage-b-approval.mjs` |
| 42 | normal-backend-activation | `scripts/aws/production-normal-backend-activation.mjs` |
| 43 | initial-activation-lifecycle | `scripts/aws/manage-production-initial-activation-lifecycle.mjs` |
| 44 | dual-slot-rebaseline-durable-evidence | `scripts/aws/persist-production-dual-slot-rebaseline-durable-evidence.mjs` |
| 45 | stage-a-production-artifacts-policy-recovery | `scripts/aws/run-production-stage-a-production-artifacts-recovery.mjs` |
| 46 | stage-a-production-artifacts-state-reconciliation | `scripts/aws/run-production-stage-a-production-artifacts-reconciliation.mjs` |
| 47 | initial-activation-lifecycle-policy-reconciliation | `scripts/aws/run-production-initial-activation-lifecycle-policy-reconciliation.mjs` |
| 48 | provider-readonly-policy-reconciliation | `scripts/aws/reconcile-production-provider-readonly-policy.mjs` |
| 49 | bootstrap-operator-policy-reconciliation | `scripts/aws/production-bootstrap-operator-policy-reconciliation.mjs` |
| 50 | mixed-dual-slot-recovery-iam-preflight | `scripts/aws/preflight-production-mixed-dual-slot-recovery-iam.mjs` |
| 51 | mixed-dual-slot-recovery-execution | `scripts/aws/recover-production-mixed-dual-slot-topology.mjs` |

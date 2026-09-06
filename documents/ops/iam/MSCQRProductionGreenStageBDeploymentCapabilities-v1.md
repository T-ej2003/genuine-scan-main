# Stage B production deployment capability graph

Generated from the permission manifest, reviewed source policies, release probes, canonical recovery, zero-registration forward recovery, publisher policy, Terraform runtime policy actions, and the production path. Do not edit generated capability rows manually.

- Phases: 46
- Capability nodes: 384
- Unique AWS actions: 134
- Identities: GITHUB_IMAGE_PUBLISHER, ADMINISTRATOR, ROOT_OPERATOR, BOOTSTRAP_OPERATOR, RELEASE_DEPLOYER, INDEPENDENT_CHECKER, ECS_EXEC_VERIFIER_OPERATOR, SERVICE_RUNTIME, INITIAL_ACTIVATION_RECONCILER

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
| 13 | release-role-assumption | `documents/security/rls-program/PRODUCTION_GREEN_STAGE_B_INFRASTRUCTURE_RUNBOOK.md` |
| 14 | release-direct-read-preflight | `scripts/aws/run-production-green-stage-b-preflight.mjs` |
| 15 | release-preflight-checker-trust-attestation | `scripts/aws/production-release-preflight-checker-attestation.mjs` |
| 16 | backend-config-generation | `scripts/aws/generate-production-green-stage-b-backend-config.mjs` |
| 17 | terraform-initialization | `scripts/aws/run-production-green-stage-b-preflight.mjs` |
| 18 | backend-metadata-validation | `scripts/aws/stage-b-terraform-backend-contract.mjs` |
| 19 | workspace-validation | `scripts/aws/stage-b-terraform-workspace.mjs` |
| 20 | canonical-backend-recovery | `scripts/aws/recover-stage-b-backend-task-definition.mjs` |
| 21 | backend-health-recovery | `scripts/aws/recover-production-backend-health.mjs` |
| 22 | runtime-consumability-evidence | `scripts/aws/prepare-production-ecs-runtime-consumability.mjs` |
| 23 | runtime-consumability-convergence | `scripts/aws/converge-production-ecs-runtime-policy.mjs` |
| 24 | existing-revision-forward-recovery | `scripts/aws/forward-recover-stage-b-existing-revision.mjs` |
| 25 | stage-b-state-pull | `scripts/aws/run-production-green-stage-b-preflight.mjs` |
| 26 | stage-a-state-read | `scripts/aws/run-production-green-stage-b-preflight.mjs` |
| 27 | stage-a-handoff-generation | `scripts/aws/generate-production-green-stage-a-prerequisites.mjs` |
| 28 | root-drop-evidence-signing | `scripts/aws/produce-production-root-drop-evidence.mjs` |
| 29 | tfvars-generation | `scripts/aws/generate-production-green-stage-b-tfvars.mjs` |
| 30 | refresh-only | `scripts/refresh-production-green-stage-b.mjs` |
| 31 | saved-plan-generation | `scripts/plan-production-green-stage-b.mjs` |
| 32 | plan-json-canonicalization | `scripts/plan-production-green-stage-b.mjs` |
| 33 | reference-audit | `scripts/aws/generate-production-green-stage-b-reference-audit.mjs` |
| 34 | plan-bound-permission-report | `scripts/aws/validate-production-green-stage-b-permissions.mjs` |
| 35 | production-closure | `scripts/aws/validate-stage-b-deployment-closure.mjs` |
| 36 | validator | `scripts/plan-production-green-stage-b.mjs` |
| 37 | wrapper-verify-only | `scripts/apply-production-green-stage-b.mjs` |
| 38 | wrapper-apply | `scripts/apply-production-green-stage-b.mjs` |
| 39 | post-apply-verification | `scripts/aws/verify-production-green-stage-b-ecs-observations.mjs` |
| 40 | runtime-activation-boundary | `scripts/aws/create-production-green-stage-b-approval.mjs` |
| 41 | normal-backend-activation | `scripts/aws/production-normal-backend-activation.mjs` |
| 42 | initial-activation-lifecycle | `scripts/aws/manage-production-initial-activation-lifecycle.mjs` |
| 43 | dual-slot-rebaseline-durable-evidence | `scripts/aws/persist-production-dual-slot-rebaseline-durable-evidence.mjs` |
| 44 | stage-a-production-artifacts-policy-recovery | `scripts/aws/run-production-stage-a-production-artifacts-recovery.mjs` |
| 45 | stage-a-production-artifacts-state-reconciliation | `scripts/aws/run-production-stage-a-production-artifacts-reconciliation.mjs` |
| 46 | initial-activation-lifecycle-policy-reconciliation | `scripts/aws/run-production-initial-activation-lifecycle-policy-reconciliation.mjs` |

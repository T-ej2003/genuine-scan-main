# Stage B production deployment capability graph

Generated from the permission manifest, reviewed source policies, release probes, canonical recovery, zero-registration forward recovery, publisher policy, Terraform runtime policy actions, and the production path. Do not edit generated capability rows manually.

- Phases: 40
- Capability nodes: 325
- Unique AWS actions: 130
- Identities: GITHUB_IMAGE_PUBLISHER, ADMINISTRATOR, ROOT_OPERATOR, BOOTSTRAP_OPERATOR, RELEASE_DEPLOYER, INDEPENDENT_CHECKER, ECS_EXEC_VERIFIER_OPERATOR, SERVICE_RUNTIME

| Order | Phase | Source |
|---:|---|---|
| 1 | protected-main-checkout | `scripts/aws/stage-b-release-gate.mjs` |
| 2 | dependency-installation | `package.json` |
| 3 | rls-package-verification | `scripts/rls/verify-full-rls-package.mjs` |
| 4 | image-impact-classification | `scripts/aws/validate-stage-b-image-reuse.mjs` |
| 5 | image-workflow-dispatch | `scripts/aws/dispatch-production-green-stage-b-images.mjs` |
| 6 | image-artifact-verification | `.github/workflows/production-green-stage-b-image-build.yml` |
| 7 | schema-v3-image-evidence | `scripts/aws/production-green-stage-b-image-evidence.mjs` |
| 8 | administrator-release-oidc-trust-convergence | `scripts/aws/converge-production-release-oidc-trust.mjs` |
| 9 | administrator-normal-backend-activation-convergence | `scripts/aws/production-normal-backend-activation.mjs` |
| 10 | administrator-iam-simulation | `scripts/aws/validate-production-green-stage-b-permissions.mjs` |
| 11 | administrator-kms-signing | `scripts/aws/validate-production-green-stage-b-permissions.mjs` |
| 12 | bootstrap-mfa-session | `documents/security/rls-program/PRODUCTION_GREEN_STAGE_B_INFRASTRUCTURE_RUNBOOK.md` |
| 13 | release-role-assumption | `documents/security/rls-program/PRODUCTION_GREEN_STAGE_B_INFRASTRUCTURE_RUNBOOK.md` |
| 14 | release-direct-read-preflight | `scripts/aws/run-production-green-stage-b-preflight.mjs` |
| 15 | backend-config-generation | `scripts/aws/generate-production-green-stage-b-backend-config.mjs` |
| 16 | terraform-initialization | `scripts/aws/run-production-green-stage-b-preflight.mjs` |
| 17 | backend-metadata-validation | `scripts/aws/stage-b-terraform-backend-contract.mjs` |
| 18 | workspace-validation | `scripts/aws/stage-b-terraform-workspace.mjs` |
| 19 | canonical-backend-recovery | `scripts/aws/recover-stage-b-backend-task-definition.mjs` |
| 20 | backend-health-recovery | `scripts/aws/recover-production-backend-health.mjs` |
| 21 | runtime-consumability-evidence | `scripts/aws/prepare-production-ecs-runtime-consumability.mjs` |
| 22 | runtime-consumability-convergence | `scripts/aws/converge-production-ecs-runtime-policy.mjs` |
| 23 | existing-revision-forward-recovery | `scripts/aws/forward-recover-stage-b-existing-revision.mjs` |
| 24 | stage-b-state-pull | `scripts/aws/run-production-green-stage-b-preflight.mjs` |
| 25 | stage-a-state-read | `scripts/aws/run-production-green-stage-b-preflight.mjs` |
| 26 | stage-a-handoff-generation | `scripts/aws/generate-production-green-stage-a-prerequisites.mjs` |
| 27 | root-drop-evidence-signing | `scripts/aws/produce-production-root-drop-evidence.mjs` |
| 28 | tfvars-generation | `scripts/aws/generate-production-green-stage-b-tfvars.mjs` |
| 29 | refresh-only | `scripts/refresh-production-green-stage-b.mjs` |
| 30 | saved-plan-generation | `scripts/plan-production-green-stage-b.mjs` |
| 31 | plan-json-canonicalization | `scripts/plan-production-green-stage-b.mjs` |
| 32 | reference-audit | `scripts/aws/generate-production-green-stage-b-reference-audit.mjs` |
| 33 | plan-bound-permission-report | `scripts/aws/validate-production-green-stage-b-permissions.mjs` |
| 34 | production-closure | `scripts/aws/validate-stage-b-deployment-closure.mjs` |
| 35 | validator | `scripts/plan-production-green-stage-b.mjs` |
| 36 | wrapper-verify-only | `scripts/apply-production-green-stage-b.mjs` |
| 37 | wrapper-apply | `scripts/apply-production-green-stage-b.mjs` |
| 38 | post-apply-verification | `scripts/aws/verify-production-green-stage-b-ecs-observations.mjs` |
| 39 | runtime-activation-boundary | `scripts/aws/create-production-green-stage-b-approval.mjs` |
| 40 | normal-backend-activation | `scripts/aws/production-normal-backend-activation.mjs` |

# Stage B production deployment capability graph

Generated from the permission manifest, reviewed source policies, release probes, canonical recovery, zero-registration forward recovery, publisher policy, Terraform runtime policy actions, and the production path. Do not edit generated capability rows manually.

- Phases: 33
- Capability nodes: 224
- Unique AWS actions: 103
- Identities: GITHUB_IMAGE_PUBLISHER, ADMINISTRATOR, BOOTSTRAP_OPERATOR, RELEASE_DEPLOYER, INDEPENDENT_CHECKER, ECS_EXEC_VERIFIER_OPERATOR, SERVICE_RUNTIME

| Order | Phase | Source |
|---:|---|---|
| 1 | protected-main-checkout | `scripts/aws/stage-b-release-gate.mjs` |
| 2 | dependency-installation | `package.json` |
| 3 | rls-package-verification | `scripts/rls/verify-full-rls-package.mjs` |
| 4 | image-impact-classification | `scripts/aws/validate-stage-b-image-reuse.mjs` |
| 5 | image-workflow-dispatch | `scripts/aws/dispatch-production-green-stage-b-images.mjs` |
| 6 | image-artifact-verification | `.github/workflows/production-green-stage-b-image-build.yml` |
| 7 | schema-v3-image-evidence | `scripts/aws/production-green-stage-b-image-evidence.mjs` |
| 8 | administrator-iam-simulation | `scripts/aws/validate-production-green-stage-b-permissions.mjs` |
| 9 | administrator-kms-signing | `scripts/aws/validate-production-green-stage-b-permissions.mjs` |
| 10 | bootstrap-mfa-session | `documents/security/rls-program/PRODUCTION_GREEN_STAGE_B_INFRASTRUCTURE_RUNBOOK.md` |
| 11 | release-role-assumption | `documents/security/rls-program/PRODUCTION_GREEN_STAGE_B_INFRASTRUCTURE_RUNBOOK.md` |
| 12 | release-direct-read-preflight | `scripts/aws/run-production-green-stage-b-preflight.mjs` |
| 13 | backend-config-generation | `scripts/aws/generate-production-green-stage-b-backend-config.mjs` |
| 14 | terraform-initialization | `scripts/aws/run-production-green-stage-b-preflight.mjs` |
| 15 | backend-metadata-validation | `scripts/aws/stage-b-terraform-backend-contract.mjs` |
| 16 | workspace-validation | `scripts/aws/stage-b-terraform-workspace.mjs` |
| 17 | canonical-backend-recovery | `scripts/aws/recover-stage-b-backend-task-definition.mjs` |
| 18 | existing-revision-forward-recovery | `scripts/aws/forward-recover-stage-b-existing-revision.mjs` |
| 19 | stage-b-state-pull | `scripts/aws/run-production-green-stage-b-preflight.mjs` |
| 20 | stage-a-state-read | `scripts/aws/run-production-green-stage-b-preflight.mjs` |
| 21 | stage-a-handoff-generation | `scripts/aws/generate-production-green-stage-a-prerequisites.mjs` |
| 22 | tfvars-generation | `scripts/aws/generate-production-green-stage-b-tfvars.mjs` |
| 23 | refresh-only | `scripts/refresh-production-green-stage-b.mjs` |
| 24 | saved-plan-generation | `scripts/plan-production-green-stage-b.mjs` |
| 25 | plan-json-canonicalization | `scripts/plan-production-green-stage-b.mjs` |
| 26 | reference-audit | `scripts/aws/generate-production-green-stage-b-reference-audit.mjs` |
| 27 | plan-bound-permission-report | `scripts/aws/validate-production-green-stage-b-permissions.mjs` |
| 28 | production-closure | `scripts/aws/validate-stage-b-deployment-closure.mjs` |
| 29 | validator | `scripts/plan-production-green-stage-b.mjs` |
| 30 | wrapper-verify-only | `scripts/apply-production-green-stage-b.mjs` |
| 31 | wrapper-apply | `scripts/apply-production-green-stage-b.mjs` |
| 32 | post-apply-verification | `scripts/aws/verify-production-green-stage-b-ecs-observations.mjs` |
| 33 | runtime-activation-boundary | `scripts/aws/create-production-green-stage-b-approval.mjs` |

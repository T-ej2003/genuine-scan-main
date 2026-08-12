# Stage B production deployment capability graph

Generated from the permission manifest, reviewed source policies, release probes, publisher policy, Terraform runtime policy actions, and the 31-phase production path. Do not edit generated capability rows manually.

- Phases: 31
- Capability nodes: 180
- Unique AWS actions: 95
- Identities: GITHUB_IMAGE_PUBLISHER, ADMINISTRATOR, BOOTSTRAP_OPERATOR, RELEASE_DEPLOYER, ECS_EXEC_VERIFIER_OPERATOR, SERVICE_RUNTIME

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
| 17 | stage-b-state-pull | `scripts/aws/run-production-green-stage-b-preflight.mjs` |
| 18 | stage-a-state-read | `scripts/aws/run-production-green-stage-b-preflight.mjs` |
| 19 | stage-a-handoff-generation | `scripts/aws/generate-production-green-stage-a-prerequisites.mjs` |
| 20 | tfvars-generation | `scripts/aws/generate-production-green-stage-b-tfvars.mjs` |
| 21 | refresh-only | `scripts/refresh-production-green-stage-b.mjs` |
| 22 | saved-plan-generation | `scripts/plan-production-green-stage-b.mjs` |
| 23 | plan-json-canonicalization | `scripts/plan-production-green-stage-b.mjs` |
| 24 | reference-audit | `scripts/aws/generate-production-green-stage-b-reference-audit.mjs` |
| 25 | plan-bound-permission-report | `scripts/aws/validate-production-green-stage-b-permissions.mjs` |
| 26 | production-closure | `scripts/aws/validate-stage-b-deployment-closure.mjs` |
| 27 | validator | `scripts/plan-production-green-stage-b.mjs` |
| 28 | wrapper-verify-only | `scripts/apply-production-green-stage-b.mjs` |
| 29 | wrapper-apply | `scripts/apply-production-green-stage-b.mjs` |
| 30 | post-apply-verification | `scripts/aws/verify-production-green-stage-b-ecs-observations.mjs` |
| 31 | runtime-activation-boundary | `scripts/aws/create-production-green-stage-b-approval.mjs` |

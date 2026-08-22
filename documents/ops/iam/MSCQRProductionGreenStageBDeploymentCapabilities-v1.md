# Stage B production deployment capability graph

Generated from the permission manifest, reviewed source policies, release probes, canonical recovery, zero-registration forward recovery, publisher policy, Terraform runtime policy actions, and the production path. Do not edit generated capability rows manually.

- Phases: 36
- Capability nodes: 267
- Unique AWS actions: 125
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
| 9 | administrator-iam-simulation | `scripts/aws/validate-production-green-stage-b-permissions.mjs` |
| 10 | administrator-kms-signing | `scripts/aws/validate-production-green-stage-b-permissions.mjs` |
| 11 | bootstrap-mfa-session | `documents/security/rls-program/PRODUCTION_GREEN_STAGE_B_INFRASTRUCTURE_RUNBOOK.md` |
| 12 | release-role-assumption | `documents/security/rls-program/PRODUCTION_GREEN_STAGE_B_INFRASTRUCTURE_RUNBOOK.md` |
| 13 | release-direct-read-preflight | `scripts/aws/run-production-green-stage-b-preflight.mjs` |
| 14 | backend-config-generation | `scripts/aws/generate-production-green-stage-b-backend-config.mjs` |
| 15 | terraform-initialization | `scripts/aws/run-production-green-stage-b-preflight.mjs` |
| 16 | backend-metadata-validation | `scripts/aws/stage-b-terraform-backend-contract.mjs` |
| 17 | workspace-validation | `scripts/aws/stage-b-terraform-workspace.mjs` |
| 18 | canonical-backend-recovery | `scripts/aws/recover-stage-b-backend-task-definition.mjs` |
| 19 | backend-health-recovery | `scripts/aws/recover-production-backend-health.mjs` |
| 20 | existing-revision-forward-recovery | `scripts/aws/forward-recover-stage-b-existing-revision.mjs` |
| 21 | stage-b-state-pull | `scripts/aws/run-production-green-stage-b-preflight.mjs` |
| 22 | stage-a-state-read | `scripts/aws/run-production-green-stage-b-preflight.mjs` |
| 23 | stage-a-handoff-generation | `scripts/aws/generate-production-green-stage-a-prerequisites.mjs` |
| 24 | root-drop-evidence-signing | `scripts/aws/produce-production-root-drop-evidence.mjs` |
| 25 | tfvars-generation | `scripts/aws/generate-production-green-stage-b-tfvars.mjs` |
| 26 | refresh-only | `scripts/refresh-production-green-stage-b.mjs` |
| 27 | saved-plan-generation | `scripts/plan-production-green-stage-b.mjs` |
| 28 | plan-json-canonicalization | `scripts/plan-production-green-stage-b.mjs` |
| 29 | reference-audit | `scripts/aws/generate-production-green-stage-b-reference-audit.mjs` |
| 30 | plan-bound-permission-report | `scripts/aws/validate-production-green-stage-b-permissions.mjs` |
| 31 | production-closure | `scripts/aws/validate-stage-b-deployment-closure.mjs` |
| 32 | validator | `scripts/plan-production-green-stage-b.mjs` |
| 33 | wrapper-verify-only | `scripts/apply-production-green-stage-b.mjs` |
| 34 | wrapper-apply | `scripts/apply-production-green-stage-b.mjs` |
| 35 | post-apply-verification | `scripts/aws/verify-production-green-stage-b-ecs-observations.mjs` |
| 36 | runtime-activation-boundary | `scripts/aws/create-production-green-stage-b-approval.mjs` |

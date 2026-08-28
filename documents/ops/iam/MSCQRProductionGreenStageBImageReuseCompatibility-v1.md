# Stage B image-reuse compatibility

The machine-readable JSON in this directory is the canonical reviewed artifact.
This Markdown file documents that artifact for human review only; it is not an
authorization input or provenance authority.

The canonical reviewed boundary is:

```text
schema version: 2
identity model: tooling-input-tree-sha256
image release: a63da17024415c2764452b86f1dcbce0af4ae9b8
comparison base: a63da17024415c2764452b86f1dcbce0af4ae9b8
tooling revision: 755d4283a9c49d7b914519230b258029154da86a
comparison head identity: tooling-input-tree-sha256
comparison head: 51b0f76fa42fc61d23f51cd65d30e50b6ca123648e648f10d556be81d1f1e447
tooling input tree: 51b0f76fa42fc61d23f51cd65d30e50b6ca123648e648f10d556be81d1f1e447
rules version: stage-b-image-reuse-v4
image reuse compatible: true
image build inputs changed: false
trusted tooling only paths: (none)
image affecting files: (none)
reason: The reviewed tooling input tree contains no image-affecting changes relative to the image release.
```

The canonical changed-file classification is:

| file | category | imageAffecting |
| --- | --- | --- |
| .github/workflows/authorize-production-stage-a-reconciliation.yml | ciOnly | false |
| documents/ops/iam/MSCQR_PRODUCTION_STAGE_A_APPROVAL_KEY_RECONCILIATION_CAPABILITY-v1.md | documentationOnly | false |
| documents/ops/iam/MSCQRProductionGreenStageBArtifactContracts-v1.json | documentationOnly | false |
| documents/ops/iam/MSCQRProductionGreenStageBDeploymentCapabilities-v1.json | documentationOnly | false |
| documents/ops/iam/MSCQRProductionGreenStageBDeploymentCapabilities-v1.md | documentationOnly | false |
| documents/ops/iam/MSCQRProductionGreenStageBImageReuseCompatibility-v1.json | documentationOnly | false |
| documents/ops/iam/MSCQRProductionGreenStageBImageReuseCompatibility-v1.md | documentationOnly | false |
| documents/security/rls-program/PRODUCTION_GREEN_STAGE_B_TWO_SHA_IDENTITY.md | documentationOnly | false |
| package.json | toolingOnly | false |
| scripts/apply-production-green-stage-b.mjs | toolingOnly | false |
| scripts/aws/dispatch-production-green-stage-b-images.mjs | toolingOnly | false |
| scripts/aws/generate-production-green-stage-b-capability-graph.mjs | toolingOnly | false |
| scripts/aws/generate-production-green-stage-b-tfvars.mjs | toolingOnly | false |
| scripts/aws/production-cutover-control-plane.mjs | toolingOnly | false |
| scripts/aws/production-cutover-production-adapters.mjs | toolingOnly | false |
| scripts/aws/production-github-environment-approval.mjs | toolingOnly | false |
| scripts/aws/production-green-stage-b-image-evidence.mjs | toolingOnly | false |
| scripts/aws/production-image-authorization.mjs | toolingOnly | false |
| scripts/aws/production-release-dispatch-contract.mjs | toolingOnly | false |
| scripts/aws/production-stage-a-approval-key-reconciliation-authorization.mjs | toolingOnly | false |
| scripts/aws/run-production-green-stage-b-preflight.mjs | toolingOnly | false |
| scripts/aws/run-production-stage-a-approval-key-reconciliation.mjs | toolingOnly | false |
| scripts/aws/stage-b-artifact-contract.mjs | toolingOnly | false |
| scripts/aws/stage-b-image-publication-identity.mjs | toolingOnly | false |
| scripts/aws/validate-stage-b-image-reuse.mjs | toolingOnly | false |
| scripts/tests/fixtures/canonical-image-authorization.mjs | testOnly | false |
| scripts/tests/production-green-stage-b-deployment-identity.test.mjs | testOnly | false |
| scripts/tests/production-green-stage-b-identity-capabilities.test.mjs | testOnly | false |
| scripts/tests/production-green-stage-b-image-dispatch.test.mjs | testOnly | false |
| scripts/tests/production-green-stage-b-image-evidence.test.mjs | testOnly | false |
| scripts/tests/production-green-stage-b-image-impact.test.mjs | testOnly | false |
| scripts/tests/production-green-stage-b-permission-preflight.test.mjs | testOnly | false |
| scripts/tests/production-green-stage-b-tfvars-generator.test.mjs | testOnly | false |
| scripts/tests/production-image-authorization.test.mjs | testOnly | false |
| scripts/tests/production-stage-a-approval-key-reconciliation-authorization.test.mjs | testOnly | false |
| scripts/tests/production-stage-a-approval-key-reconciliation-capability.test.mjs | testOnly | false |
| scripts/tests/stage-b-artifact-contract.test.mjs | testOnly | false |

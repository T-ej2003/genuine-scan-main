# Stage B image-reuse compatibility

The machine-readable JSON in this directory is the canonical reviewed artifact.
This Markdown file documents that artifact for human review only; it is not an
authorization input or provenance authority.

The canonical reviewed boundary is:

```text
schema version: 2
identity model: tooling-input-tree-sha256
image release: b3b477a37b50d7796ec9c3225c176f02f04023dc
comparison base: b3b477a37b50d7796ec9c3225c176f02f04023dc
tooling revision: a446d7f8947be6d336b53007276f9e597aa2cb30
comparison head identity: tooling-input-tree-sha256
comparison head: c3af4023ed8c30584794eec1c0b126d9ea93dfecaa43142b84effad967563511
tooling input tree: c3af4023ed8c30584794eec1c0b126d9ea93dfecaa43142b84effad967563511
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
| documents/ops/iam/MSCQRProductionGreenStageBArtifactContracts-v1.json | documentationOnly | false |
| documents/ops/iam/MSCQRProductionGreenStageBDeploymentCapabilities-v1.json | documentationOnly | false |
| documents/ops/iam/MSCQRProductionGreenStageBDeploymentCapabilities-v1.md | documentationOnly | false |
| documents/ops/iam/MSCQRProductionGreenStageBImageReuseCompatibility-v1.json | documentationOnly | false |
| documents/ops/iam/MSCQRProductionGreenStageBImageReuseCompatibility-v1.md | documentationOnly | false |
| documents/security/rls-program/PRODUCTION_GREEN_STAGE_B_TWO_SHA_IDENTITY.md | documentationOnly | false |
| scripts/apply-production-green-stage-b.mjs | toolingOnly | false |
| scripts/aws/dispatch-production-green-stage-b-images.mjs | toolingOnly | false |
| scripts/aws/generate-production-green-stage-b-capability-graph.mjs | toolingOnly | false |
| scripts/aws/generate-production-green-stage-b-tfvars.mjs | toolingOnly | false |
| scripts/aws/production-cutover-control-plane.mjs | toolingOnly | false |
| scripts/aws/production-green-stage-b-image-evidence.mjs | toolingOnly | false |
| scripts/aws/production-image-authorization.mjs | toolingOnly | false |
| scripts/aws/production-release-dispatch-contract.mjs | toolingOnly | false |
| scripts/aws/stage-b-artifact-contract.mjs | toolingOnly | false |
| scripts/aws/stage-b-image-publication-identity.mjs | toolingOnly | false |
| scripts/aws/validate-stage-b-image-reuse.mjs | toolingOnly | false |
| scripts/tests/fixtures/canonical-image-authorization.mjs | testOnly | false |
| scripts/tests/production-green-stage-b-deployment-identity.test.mjs | testOnly | false |
| scripts/tests/production-green-stage-b-image-dispatch.test.mjs | testOnly | false |
| scripts/tests/production-green-stage-b-image-evidence.test.mjs | testOnly | false |
| scripts/tests/production-green-stage-b-image-impact.test.mjs | testOnly | false |
| scripts/tests/production-green-stage-b-permission-preflight.test.mjs | testOnly | false |
| scripts/tests/production-green-stage-b-tfvars-generator.test.mjs | testOnly | false |
| scripts/tests/production-image-authorization.test.mjs | testOnly | false |
| scripts/tests/stage-b-artifact-contract.test.mjs | testOnly | false |

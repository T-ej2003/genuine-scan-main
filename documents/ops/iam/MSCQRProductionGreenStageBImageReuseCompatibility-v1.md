# Stage B image-reuse compatibility

The machine-readable JSON in this directory is the canonical reviewed artifact.
This Markdown file documents that artifact for human review only; it is not an
authorization input or provenance authority.

The canonical reviewed boundary is:

```text
schema version: 2
identity model: tooling-input-tree-sha256
image release: e4b0794dcf3b61ab2b43c38ff328736092a6e12c
comparison base: e4b0794dcf3b61ab2b43c38ff328736092a6e12c
tooling revision: 8fffdaa1f3124727d0e8b2a2deb5561b75861822
comparison head identity: tooling-input-tree-sha256
comparison head: 0490657cef2955fce9faff5ef652794fd56fb21bf39e2314b6a305c8b69c96ab
tooling input tree: 0490657cef2955fce9faff5ef652794fd56fb21bf39e2314b6a305c8b69c96ab
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
| .github/workflows/authorize-production-dual-slot-rebaseline-recovery.yml | ciOnly | false |
| documents/ops/iam/MSCQRProductionGreenStageBImageReuseCompatibility-v1.json | documentationOnly | false |
| documents/ops/iam/MSCQRProductionGreenStageBImageReuseCompatibility-v1.md | documentationOnly | false |
| documents/security/MSCQR_PARTIAL_REBASELINE_SUCCESSOR_RECOVERY_THREAT_MODEL.md | documentationOnly | false |
| documents/security/PRODUCTION_DUAL_SLOT_REBASELINE.md | documentationOnly | false |
| scripts/aws/authorize-production-dual-slot-rebaseline-recovery.mjs | toolingOnly | false |
| scripts/aws/prepare-production-cutover-runtime.mjs | toolingOnly | false |
| scripts/aws/production-cutover-production-adapters.mjs | toolingOnly | false |
| scripts/aws/production-cutover-runtime-bootstrap.mjs | toolingOnly | false |
| scripts/aws/production-dual-slot-rebaseline-contract.mjs | toolingOnly | false |
| scripts/aws/production-github-environment-approval.mjs | toolingOnly | false |
| scripts/aws/rebaseline-production-dual-slot.mjs | toolingOnly | false |
| scripts/tests/fixtures/partial-rebaseline-runtime.mjs | testOnly | false |
| scripts/tests/production-cutover-runtime-bootstrap.test.mjs | testOnly | false |
| scripts/tests/production-dual-slot-rebaseline-workflow.test.mjs | testOnly | false |
| scripts/tests/production-dual-slot-rebaseline.test.mjs | testOnly | false |
| scripts/aws/validate-stage-b-image-reuse.mjs | toolingOnly | false |

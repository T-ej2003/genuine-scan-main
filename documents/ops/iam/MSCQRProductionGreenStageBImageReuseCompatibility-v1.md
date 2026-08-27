# Stage B image-reuse compatibility

The machine-readable JSON in this directory is the canonical reviewed artifact.
This Markdown file documents that artifact for human review only; it is not an
authorization input or provenance authority.

The reviewed comparison is anchored by the canonical image-reuse boundary:

```text
image release: b3b477a37b50d7796ec9c3225c176f02f04023dc
comparison base: b3b477a37b50d7796ec9c3225c176f02f04023dc
tooling revision: 6bc78143cc1c11c645b87a9e1c4ca3b875b1aabf
tooling input tree: f4edaed5593336f2bf67051735122838cf3df63cc4eb21dbcfdb5429503b2fe8
rules version: stage-b-image-reuse-v4
image reuse compatible: true
image build inputs changed: false
```

The canonical report classifies the protected workflow change as
`trustedToolingOnly` only after proving that the exact release publication step is
unchanged, the Dockerfile/build context/package installation remain under
`release-source`, and signing/verification helpers execute from the protected tooling
checkout. The immutable release source remains `b3b477a37b50d7796ec9c3225c176f02f04023dc`;
the trusted tooling source is
separate. All other changed paths must still classify as non-image-affecting, and any
application, Dockerfile, dependency, build-argument, or unknown change remains
image-affecting or fail-closed. `imageAffectingFiles` is empty and
`imageBuildInputsChanged` is false only for this authenticated boundary.

The canonical changed-file classification is:

| file | category | imageAffecting |
| --- | --- | --- |
| documents/ops/iam/MSCQRProductionGreenStageBArtifactContracts-v1.json | documentationOnly | false |
| documents/ops/iam/MSCQRProductionGreenStageBDeploymentCapabilities-v1.json | documentationOnly | false |
| documents/ops/iam/MSCQRProductionGreenStageBDeploymentCapabilities-v1.md | documentationOnly | false |
| documents/ops/iam/MSCQRProductionGreenStageBImageReuseCompatibility-v1.json | documentationOnly | false |
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

The report contains `comparisonBaseSha` for the image release, the complete classified
diff, and a SHA256 of the tooling input tree with the JSON and Markdown evidence excluded.
Those exclusions break the evidence self-reference and make regeneration deterministic. Runtime validation
recomputes the exact diff and tree digest and requires an exact report match. The
trusted-workflow proof also fingerprints the complete effective publication inputs: workflow
inputs, inherited publication environment, release checkout, dependency installation, Node
setup/cache, AWS publication role, publisher command, working directory, shell, and strategy.
The proof covers the publisher's image-affecting environment contract, including platform,
ECR targets, Dockerfiles, build contexts, source/build labels, and verified RLS bindings;
unknown publication-looking inherited inputs fail closed while unrelated environment values
remain outside the image publication fingerprint.
The fingerprint also covers every `build-and-attest` step through immutable-image
publication; only the two explicitly named trusted-tooling checkout steps are excluded.
An unreviewed pre-publication step or source mutation therefore fails closed.
Runtime validation
recomputes that fingerprint and requires the release and protected-tooling values to match.
The production validator separately authenticates the protected checkout and the exact
tooling-input tree represented above. Any future image-build input change invalidates the
report and requires a new exact-SHA image publication. A stale report for another release
SHA cannot authorize this release.

## Publication identity and tag namespaces

The four-image Stage B publisher is the only producer of the canonical `<release-sha>`
tag. Before ECR or Docker access, Stage B requires `IMAGE_TAG`, `SOURCE_RELEASE_SHA`,
and the image checkout SHA to be the same lowercase 40-character commit. The workflow
definition/tooling SHA is a separate identity: it authenticates the protected workflow
source and may differ from the image release SHA only when the exact reviewed reuse
report proves the pair is image-compatible. The backend-only publisher uses the
separate `<release-sha>-backend-only` namespace while retaining `<release-sha>` as its
source and checkout identity.

After a Stage B workflow completes, the dispatcher records GitHub-observed run and
artifact metadata in a private, atomic schema-2 publication-identity report. That
report binds `workflowDefinitionSha` to the actual workflow run head and
`imageReleaseSha` to the immutable image content. Image evidence
requires that report and its hash, the exact four-service canonical JSONL, and the
canonical artifact-byte hash. A filename, numeric run ID, or caller-supplied workflow
metadata cannot satisfy the evidence boundary. Different tooling and image-release
SHAs therefore require explicit canonical reuse authorization; same-SHA publications
retain the direct binding path.

## Authorization paths

Image authorization has two mutually exclusive, fail-closed paths. The reuse path
requires `imageReuseCompatible=true` and the complete reviewed two-SHA/source and
supply-chain bindings above. When the impact report says `newImagesRequired=true`,
reuse remains false: authorization instead requires a successful canonical signed-image
workflow whose exact protected-main SHA, immutable release SHA, workflow run, complete
artifact set, immutable digests, ECR readback, Cosign identity/issuer, transparency-log
inclusion, SPDX predicate, and provenance predicate all match the verified evidence.
For this path, `imageReleaseSha` and the build/provenance checkout SHA must equal the
protected-main source SHA that triggered `newImagesRequired`; a prior release image
cannot pass merely because its trusted workflow tooling used that source SHA.
The publication identity must be for the current protected workflow run; stale evidence
from an earlier run or SHA cannot satisfy fresh-image authorization.

`newImagesRequired` is only the rebuild requirement, never proof that rebuilding happened.
The fresh-publication path is the only path that satisfies that requirement, and it does
not relax digest, identity, transparency-log, attestation, or downstream recovery gates.

Descendant recovery validates every changed-file category independently. `trustedToolingOnly`
is an additional authenticated category for the dedicated workflow proof; it does not bypass
the existing allowlist for other non-image categories.

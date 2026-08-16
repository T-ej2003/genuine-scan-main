# Stage B image-reuse compatibility

The reviewed comparison is anchored by the two-SHA image boundary:

```text
image release: 29bf92a14d5e832575009bd76b16886feff62cbd
tooling:       a37fe2559f15094494122825a7d7365ca1218120
report identity: tooling-input-tree-sha256
tooling tree:  a2bcf00ea3bbfa636e41843ffb1f17c744fc077c055c772c30aecb2322395802
```

The canonical report classifies the protected workflow change as
`trustedToolingOnly` only after proving that the exact release publication step is
unchanged, the Dockerfile/build context/package installation remain under
`release-source`, and signing/verification helpers execute from the protected tooling
checkout. The immutable release source remains `29bf…`; the trusted tooling source is
separate. All other changed paths must still classify as non-image-affecting, and any
application, Dockerfile, dependency, build-argument, or unknown change remains
image-affecting or fail-closed. `imageAffectingFiles` is empty and
`imageBuildInputsChanged` is false only for this authenticated boundary.

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
recomputes that fingerprint and requires the release and protected-tooling values to match. The
production wrapper separately authenticates the exact pair by requiring
`HEAD == tooling_sha == origin/main`; CI review mode validates a proposed tree without
claiming it is protected main. Any future image-build input change invalidates the report
and requires a new exact-SHA image publication. A stale report for another release SHA
cannot authorize this release.

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

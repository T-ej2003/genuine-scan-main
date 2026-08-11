# Stage B image-reuse compatibility

The reviewed comparison is anchored by:

```text
image release: c45f2d788ce29c2067bfb4e8afff46f8b1c238ea
tooling:       cc2d6f61b662dcc15ebc9ec774f647bf3c1e964c
report identity: tooling-input-tree-sha256
tooling tree:  83c74278063da0e04f6af8fcc892a07961126361f0b5c79d1aaab9cfba6eb485
```

The canonical report classifies the comparison files as the compatibility report itself,
the permission manifest, the permission validator, and the image-reuse/preflight tests. All are
non-image-affecting, so `imageAffectingFiles` is empty and the existing immutable images
may be reused by the explicit two-SHA contract. `imageBuildInputsChanged` is false.
No image rebuild is required for this compatibility transition.

The report contains `comparisonBaseSha` for the image release, the complete classified
diff, and a SHA256 of the tooling input tree with the JSON and Markdown evidence excluded.
Those exclusions break the evidence self-reference and make regeneration deterministic. Runtime validation
recomputes the exact diff and tree digest and requires an exact report match. The
production wrapper separately authenticates the exact pair by requiring
`HEAD == tooling_sha == origin/main`; CI review mode validates a proposed tree without
claiming it is protected main. Any future image-build input change invalidates the report
and requires a new exact-SHA image publication.

## Publication identity and tag namespaces

The four-image Stage B publisher is the only producer of the canonical `<release-sha>`
tag. Before ECR or Docker access, Stage B requires `IMAGE_TAG`, `SOURCE_RELEASE_SHA`,
and the checked-out Git SHA to be the same lowercase 40-character commit. The
backend-only publisher uses the separate `<release-sha>-backend-only` namespace while
retaining `<release-sha>` as its source and checkout identity.

After a Stage B workflow completes, the dispatcher records GitHub-observed run and
artifact metadata in a private, atomic publication-identity report. Image evidence
requires that report and its hash, the exact four-service canonical JSONL, and the
canonical artifact-byte hash. A filename, numeric run ID, or caller-supplied workflow
metadata cannot satisfy the evidence boundary.

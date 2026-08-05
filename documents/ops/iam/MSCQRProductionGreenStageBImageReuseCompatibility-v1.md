# Stage B image-reuse compatibility

The reviewed comparison is anchored by:

```text
image release: 7245a6036492f875654c414473737e33c1422f3c
tooling:       the exact protected-main commit validated separately by the production checkout gate
report identity: tooling-input-tree-sha256
```

The intervening diff contains no Dockerfile, application source, dependency lockfile,
image workflow/build configuration, generated runtime RLS package, or other image-build
input. It contains deployment validators, audit/preflight/wrapper code, closure fixtures,
CI/docs, and a Terraform provider lock checksum. Therefore immutable images from the
image release may be reused by the explicit two-SHA contract.

The report contains `comparisonBaseSha` for the image release, the complete classified
diff, and a SHA256 of the tooling input tree with the report JSON excluded. That exclusion
is the only self-reference break and makes regeneration deterministic. Runtime validation
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

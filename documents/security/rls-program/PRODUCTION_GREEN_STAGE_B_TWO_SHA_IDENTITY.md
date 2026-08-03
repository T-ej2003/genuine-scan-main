# Production Green Stage B two-SHA identity contract

Stage B has two independent source identities:

```text
tooling_sha
  -> clean origin/main checkout
  -> Terraform configuration, validator, audit, permission preflight, wrapper

image_release_sha
  -> protected-main workflow dispatch input
  -> exact workflow checkout
  -> canonical artifact and administrator ECR readback
  -> signed image evidence
  -> Terraform image variables and current task-definition images
```

The image-evidence report is schema version 3 and contains `imageReleaseSha`; it does
not contain `toolingSha`. It also carries a signed `ecr-immutable-tag` proof and an
explicit `superseded: false` marker. This is deliberate: image evidence authenticates
the immutable image publication chain, while plan-bound artifacts authenticate the
joined deployment.

Image provenance uses a reviewed 24-hour validity window. Permission preflight remains
independently plan-bound and expires after 15 minutes; the reference audit has its own
15-minute live-observation window. A longer image window cannot authorize a different
digest because the canonical report SHA, release/workflow/artifact identity, plan image
variables, and all twelve current task definitions remain exact joins.

Every approved plan must contain:

- `tooling_sha`
- `image_release_sha`
- `canonical_image_evidence_sha256`

The reference audit and signed permission report copy those values and the final wrapper
requires exact equality across the plan, audit, permission report, signed image evidence,
and checked-out tooling HEAD. Missing or legacy single-`releaseSha` deployment identity
is rejected.

Image reuse uses the reviewed compatibility report's non-self-referential tooling-input
tree identity. The report records `comparisonBaseSha` as `image_release_sha`,
`comparisonHeadIdentity` as `tooling-input-tree-sha256`, the complete classified diff,
classification-rules version, and the input-tree digest. The input-tree digest includes
all tracked tooling-tree content except the report JSON itself; excluding that one
artifact prevents a commit/report hash cycle. Runtime validation recomputes both the
complete diff and the tree digest for the requested pair and requires exact equality with
the checked-in report. The production checkout still independently requires
`HEAD == tooling_sha == origin/main`, fetched complete history, the protected remote
default branch `main`, and a clean worktree. Therefore a report is not transferable to a
different tooling content tree, while CI review mode can validate a proposed tree without
pretending it is already protected main.

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
not contain `toolingSha`. It carries authoritative `DescribeRepositories` evidence for
each unique image repository, requiring `imageTagMutability=IMMUTABLE`, and the explicit
capability `revocationModel=time-bounded-no-supersession-registry`. This is deliberate:
there is no authenticated supersession registry in the current contract, so the report
does not claim `superseded: false`; immediate revocation is unavailable until that
separate capability exists. Image evidence authenticates the immutable image publication
chain, while plan-bound artifacts authenticate the joined deployment.

The publication-identity report is schema version 2 and keeps the workflow definition
SHA separate from the image release SHA. `workflowDefinitionSha` must equal the
protected tooling checkout that executed the workflow, while `imageReleaseSha` must
equal the source bound to the immutable images. When those values differ, image
authorization must include the independently derived canonical reuse report for the
exact `imageReleaseSha -> toolingSha` pair; a valid-looking SHA or an arbitrary older
image cannot cross this boundary.

Image provenance uses a reviewed 24-hour validity window. Permission preflight remains
independently plan-bound with a 60-minute validity window; the reference audit has its
own 60-minute live-observation window. A longer image window cannot authorize a different
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

## Recovery binding

The canonical backend recovery consumes both identities and the existing image
authorization artifact. `tooling_sha` authenticates the clean protected checkout and
recovery machinery; `image_release_sha` authenticates the immutable image and is the
only SHA rendered into task-definition `RELEASE_GIT_SHA`. Recovery requires the
bindings, authorized backend digest, image-release SHA, and authorization envelope to
match exactly. A legacy task definition whose `RELEASE_GIT_SHA` was populated from the
tooling SHA is not relabeled or adopted; its complete semantic fingerprint fails closed.

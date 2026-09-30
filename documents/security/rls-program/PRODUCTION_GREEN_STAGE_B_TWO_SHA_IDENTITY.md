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

The image-evidence report is schema version 4. It keeps `publicationSourceSha` (the
historical workflow/artifact source), `currentSourceSha` (the protected source consuming
the images), and `imageReleaseSha` as distinct fields. Those extra fields appear only for
cross-source reuse and include the canonical compatibility-report SHA; a direct fresh
publication proves the same identity through its existing exact workflow and release bindings.
It carries authoritative `DescribeRepositories` evidence for each unique image repository,
requiring `imageTagMutability=IMMUTABLE`, and the explicit capability
`revocationModel=time-bounded-no-supersession-registry`. This is deliberate:
there is no authenticated supersession registry in the current contract, so the report
does not claim `superseded: false`; immediate revocation is unavailable until that
separate capability exists. Image evidence authenticates the immutable image publication
chain, while plan-bound artifacts authenticate the joined deployment.

The publication-identity report is schema version 2 and keeps the workflow definition SHA
separate from the current consuming source. `workflowDefinitionSha` is the immutable
historical publication source and must never be rewritten to equal a later protected
checkout. When a consumer differs, image authorization must include the independently
derived canonical reuse report for the exact `imageReleaseSha -> currentSourceSha` pair;
a valid-looking SHA or an arbitrary older image cannot cross this boundary.

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

## Persisted-record compatibility (PR #604)

The upgrade audit uses protected pre-PR source `68d8c76`, not an intermediate
unmerged PR head. No historical object is rewritten to add image provenance.

| Persisted structure | Historical authentication | New writes / upgrade behavior |
| --- | --- | --- |
| Rotation config | Approved exact byte SHA-256; no version/image field; runtime SHA was sourceSha | Version 2 requires explicit imageReleaseSha; original legacy bytes load with the original sourceSha runtime binding |
| Rotation coordinator state and runtime proofs | Original config identity and persisted proof SHA | Legacy config retains original proof semantics; new config uses explicit image provenance |
| Overlap readiness | Version 1, hashed bytes, exact original authorization/task bindings | Version 2 joins explicit authenticated image SHA; legacy cleanup derives sourceSha only from exact original binding shape |
| Activation claim | Version 1 canonical bytes and original transaction hash | Version 2 includes imageReleaseSha; immutable v1 claim retries without replacement |
| Activation completion | Version 1 canonical bytes, claim SHA and S3 version | Completion retains claim version and original identity; v2 records bind image SHA |
| Inventory replay key | Original logical operation hash | Unchanged key prevents a legacy row becoming invisible or launching twice |
| Inventory replay row | Original full-identity hash | New identityVersion 2 stores imageReleaseSha and hashes it; version-specific readback rejects mixed fields |
| Onboarding evidence for legacy completion | Authenticated v1 claim plus evidence digest and source-bound health | Legacy interpretation enabled only by a validated v1 claim; fresh evidence requires explicit image SHA |
| Signed image authorization / manifests | Existing versioned signed identity and digest | No historical shape rewritten; explicit image SHA is read from canonical authentication |
| Schema-2 approval | Signed current governance releaseSha | Image provenance remains separately authenticated; approval schema unchanged |
| RLS/release receipts | Existing source/image digest and package hashes | Receipt shape unchanged; regenerated package hashes follow authoritative source |
| Component deployment records | Existing image source, digest and task ARN | Persisted field shape unchanged |

Upgrade tests exercise pre-PR rotation configs, activation claim bytes/completion,
and replay rows with the post-PR validators. Fresh paths use distinct tooling and
image SHAs. State serial 107 remains authoritative; this PR performs no production
or Terraform-state mutation.

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

The image-evidence report is schema version 2 and contains `imageReleaseSha`; it does
not contain `toolingSha`. This is deliberate: image evidence authenticates the image
publication chain, while plan-bound artifacts authenticate the joined deployment.

Every approved plan must contain:

- `tooling_sha`
- `image_release_sha`
- `canonical_image_evidence_sha256`

The reference audit and signed permission report copy those values and the final wrapper
requires exact equality across the plan, audit, permission report, signed image evidence,
and checked-out tooling HEAD. Missing or legacy single-`releaseSha` deployment identity
is rejected.

Image reuse is compatible only when the complete diff from `image_release_sha` to
`tooling_sha` contains no image build input: no Dockerfile, runtime source, dependency
lockfile, generated runtime package, or build configuration. Tooling-only changes may
reuse immutable signed images; image-affecting changes require a new image release.

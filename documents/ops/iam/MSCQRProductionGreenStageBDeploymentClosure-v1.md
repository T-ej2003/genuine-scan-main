# Stage B deployment closure

This contract is the single offline closure gate for `infra/aws/terraform/production-green-stage-b`.
The machine-readable resource matrix is [MSCQRProductionGreenStageBDeploymentClosure-v1.json](./MSCQRProductionGreenStageBDeploymentClosure-v1.json).

## Supported production plan

The sanitized current production shape is validated by structural address-set completeness:

| Action | Count | Boundary |
| --- | ---: | --- |
| no-op | derived | every remaining canonical managed address; retained ECS history is append-only |
| create | 12 | the four candidate definitions and eight executor definitions |
| update | 3 | broker Lambda, reviewed alias, and exact managed broker policy |
| delete/replacement | 0 | always rejected |

The validator classifies every resource by exact Terraform address, type, identity, and lifecycle action. The apply wrapper consumes the same classification and blocks if any resource is unclassified.

## Shared contract boundaries

- Current task definitions are append-only create/no-op resources; revision-keyed retained definitions are no-op only.
- `aws_iam_policy.broker` is the only managed-policy update admitted, and its account, ARN, name, path, and canonical policy statements are checked.
- `aws_iam_role_policy_attachment.broker` is the only broker attachment admitted and must remain the exact imported no-op.
- Broker Lambda, alias, permission, logs, roles, role policies, replay table, and task definitions are admitted only at their exact Stage B addresses.
- Deletes, replacements, service/database/load-balancer/DNS/traffic resources, legacy inline broker policy, and unrelated IAM resources are rejected.
- Reference audit, permission preflight, validator, and apply wrapper use the same resource classifier; the wrapper emits `unclassifiedResources: []` before `ready-to-apply`.

## Required check

```text
npm run stage-b:deployment-closure:pull-request
```

The package command runs the explicit `pull-request` closure mode. It verifies the generated RLS package, formats and validates the Stage B Terraform root without a backend, checks all Terraform declarations against the matrix, validates the 73-resource fixture, runs the full Stage B control-plane suite, and runs the plan, audit, preflight, and wrapper regression suites. The pull-request mode may return `merge-ready-reuse-compatible` or `merge-ready-new-images-required`; it never authorizes a deployment.

Production operators using final rotation evidence must invoke `npm run stage-b:deployment-closure:production:strict-final-rotation -- <complete production evidence arguments>` from a protected-main checkout. This named standalone entrypoint explicitly selects `STRICT_FINAL_ROTATION`; the generic `stage-b:deployment-closure:production` command intentionally fails unless its caller explicitly supplies exactly one lifecycle contract. Authenticated-overlap activation remains workflow-governed because its complete state-byte and identity bindings are reconstructed and revalidated at the mutation job. Both entrypoints use `check-production-activation-rotation.mjs`, so standalone and workflow execution enforce the same underlying contract semantics. Production mode rejects `newImagesRequired`, pull-request impact reports, unmerged tooling SHAs, stale compatibility reports, and missing signed image evidence. The apply wrapper independently requires `--closure-mode production`.

The canonical Stage A prerequisite handoff is part of permission preflight. It requires the exact Stage A state object plus five region-bound, read-only live checks: EC2 subnet, route-table, and security-group descriptions, ECS cluster description, and RDS DB-instance description. AWS does not expose resource-level authorization for these Describe APIs, so each exact action uses `Resource: "*"` with `aws:RequestedRegion=eu-west-2`; no write action is granted.

For an image-affecting pull request, the deterministic private CI artifact `stage-b-image-impact-<run>.json` records the exact classified diff and returns:

```text
Merge permitted; fresh protected-main images required before production deployment.
```

That result is merge readiness only. It contains no image digests and cannot satisfy the production wrapper.

This gate is offline and does not publish images, call mutating AWS APIs, generate a production plan, mutate state, or apply Terraform.

## Two-SHA deployment identity

The deployment intentionally separates the tooling/source commit from the image source
commit. `tooling_sha` identifies the clean `origin/main` checkout running Terraform,
audit, permission preflight, validation, and the apply wrapper. `image_release_sha`
identifies the exact workflow checkout that built the immutable images.

Signed image evidence authenticates `imageReleaseSha`, the canonical workflow artifact,
and the four repository/tag/digest bindings; it does not contain `toolingSha`. The plan,
reference audit, permission report, and wrapper join both chains through the three required
plan variables: `tooling_sha`, `image_release_sha`, and
`canonical_image_evidence_sha256`. The wrapper also requires the checked-out tooling HEAD
to equal `tooling_sha`.

## Evidence freshness classes

Image provenance is immutable after publication: the signed report carries the exact
release/workflow/artifact identity, four digest bindings, and authoritative
`DescribeRepositories` evidence for each unique repository. Each repository must report
`imageTagMutability=IMMUTABLE`; exclusion-based mutability is rejected. The report uses
`revocationModel=time-bounded-no-supersession-registry`: this is an explicit capability
statement, not a claim that an external supersession registry was consulted. Immediate
revocation is unavailable until a separately authenticated supersession registry exists.
The evidence class is valid for 24 hours (`86400000` ms), which covers credential
transitions and the full plan/audit/preflight workflow without weakening its signature or
digest joins. It is rejected for a wrong release, workflow, artifact, digest, account,
region, repository configuration, or unsupported revocation model.

Permission preflight and the plan-bound reference audit use a 60-minute validity window
(`3600000` ms) to cover the reviewed deployment sequence. This operational window does
not replace exact hash, caller, policy, state-serial, workspace, reference, and plan
bindings: any bound-value change invalidates the evidence immediately. Saved-plan
validity is binding-based rather than time-only. Operators should still move directly
from permission signing to closure and apply; 60 minutes is a safety window, not a
reason to pause indefinitely. These live windows are intentionally separate from
immutable image provenance; the wrapper still requires exact permission, audit, and
plan-to-image digest joins before apply.

Image reuse is permitted only when the reviewed compatibility report for the exact image
release and tooling-input tree contains no Dockerfile, dependency lockfile, runtime
source, generated runtime package, or other image-build input change. Runtime validation
recomputes the complete diff and input-tree digest and compares it with that report; it
never replaces the reviewed classification dynamically. The report excludes only its own
JSON bytes from the input-tree digest, so its identity is deterministic and
non-self-referential. The production wrapper separately requires
`HEAD == tooling_sha == origin/main`, a fetched protected-main ref, complete history, and
a clean worktree. CI closure uses review mode and does not require a pull-request head to
equal origin/main.

## Protected-checkout regression boundary

The apply-wrapper regression harness first proves one complete artifact set reaches
`ready-to-apply`. Checkout-negative fixtures then clone that baseline and mutate exactly one
protected-main property, so artifact-gate failures remain separately testable and cannot mask
the checkout invariant under test. The wrapper’s artifact-presence checks intentionally remain
before protected-checkout validation; this order is part of the current implementation contract.
The regression suite also covers the real non-verify-only boundary: a valid first read followed
by a drifted second read must reject before the injected apply dependency is called, while a
fully valid pair calls that dependency once with the saved-plan path.

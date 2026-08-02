# Stage B deployment closure

This contract is the single offline closure gate for `infra/aws/terraform/production-green-stage-b`.
The machine-readable resource matrix is [MSCQRProductionGreenStageBDeploymentClosure-v1.json](./MSCQRProductionGreenStageBDeploymentClosure-v1.json).

## Supported production plan

The sanitized current production shape is 73 resources:

| Action | Count | Boundary |
| --- | ---: | --- |
| no-op | 58 | retained history, imported roles/policies, exact broker attachment, and persistent resources |
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
npm run stage-b:deployment-closure
```

The command verifies the generated RLS package, formats and validates the Stage B Terraform root without a backend, checks all Terraform declarations against the matrix, validates the 73-resource fixture, runs the full Stage B control-plane suite, and runs the plan, audit, preflight, and wrapper regression suites.

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

Image reuse is permitted only when the intervening commit diff contains no Dockerfile,
dependency lockfile, runtime source, generated runtime package, or other image-build
input change. Any such change requires a new exact-SHA image publication.

# Production Green Stage B Terraform backend access

This is the reviewed least-privilege contract for the non-root
`mscqr-production-release-deployer` role.

## Proven Terraform request shape

Terraform initializes by probing its configured key before it can select a CLI
workspace. The prior base-key/workspace configuration therefore contradicted its
base-key deny. The reviewed configuration now points directly at the existing
production object and uses Terraform's `default` CLI workspace; the explicit
`deployment_environment = "production"` input retains the environment guard.

| Operation | Exact request/resource |
| --- | --- |
| bucket validation | `s3:GetBucketLocation` on the bucket ARN |
| state refresh | `s3:GetObject` on the production state ARN |
| state persistence | `s3:PutObject` on the production state ARN |
| lock acquisition | `s3:PutObject` on the production `.tflock` ARN |
| lock ownership/read | `s3:GetObject` on the production `.tflock` ARN |
| lock release | `s3:DeleteObject` on the production `.tflock` ARN |

The legacy base key and its lock object are denied for reads and writes. The
production state object is never deletable by the release role. The policy does
not grant `s3:ListBucket`, arbitrary object access, bucket administration,
versioning changes, or encryption changes.

The plan, closure, verify-only, and pre-apply gates read Terraform's initialized
backend metadata, require backend type `s3`, and accept only the reviewed bucket,
key, region, encryption, and lockfile values plus Terraform's known null defaults.
They reject unknown options and endpoint, credential, role, proxy, path-style,
workspace-prefix, DynamoDB-lock, KMS, TLS, retry, or validation overrides.

## Exact policy

The source of truth is
`MSCQRProductionGreenStageBWorkspaceState-v2.json`. The two explicit deny
statements protect against stale overlapping identity policies until the reviewed
administrator publication removes the old Stage B statements from
`MSCQRProductionGreenStageARelease`.

The surviving Stage A S3 contract is recorded separately in
`MSCQRProductionGreenStageAReleaseS3Contract-v1.json`; it contains no Stage B
bucket/key grant.

## Publication boundary

This PR changes source-controlled contracts and offline tests only. After manual
merge, the approved administrator must publish the exact reviewed managed-policy
version. Then a fresh release session may generate the canonical backend config,
verify `GetBucketLocation`, initialize the direct production-state backend, select
the `default` workspace, and create a local state backup. Terraform must be the only actor exercising
lock and state writes during the later approved saved-plan wrapper run.

No production state, lock, IAM, ECR, runtime, database, network, or traffic
resource is changed by this PR.

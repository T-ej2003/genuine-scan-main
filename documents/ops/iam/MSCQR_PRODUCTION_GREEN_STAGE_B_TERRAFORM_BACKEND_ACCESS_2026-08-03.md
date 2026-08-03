# Production Green Stage B Terraform backend access

This is the reviewed least-privilege contract for the non-root
`mscqr-production-release-deployer` role.

## Proven Terraform request shape

Terraform v1.15.7's S3 backend uses the default workspace key prefix `env:`. Its
workspace discovery calls `ListObjectsV2` with the single prefix `env:/`; it does
not first require `HeadBucket`, and it does not use the configured base key as a
workspace-discovery prefix. Selecting `production` addresses the exact state and
lock objects below.

| Operation | Exact request/resource |
| --- | --- |
| bucket validation | `s3:GetBucketLocation` on the bucket ARN |
| workspace discovery | `s3:ListBucket` with `s3:prefix=env:/` |
| state refresh | `s3:GetObject` on the production state ARN |
| state persistence | `s3:PutObject` on the production state ARN |
| lock acquisition | `s3:PutObject` on the production `.tflock` ARN |
| lock ownership/read | `s3:GetObject` on the production `.tflock` ARN |
| lock release | `s3:DeleteObject` on the production `.tflock` ARN |

The configured default key and its lock object are denied. The production state
object is never deletable by the release role. The policy does not grant
unconditioned `s3:ListBucket`, arbitrary object access, bucket administration,
versioning changes, or encryption changes.

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
version and remove only the stale Stage B statements from the Stage A inline
policy. Then a fresh release session may verify `GetBucketLocation`, Terraform
workspace discovery, exact state read, backend initialization, workspace
selection, and a local state backup. Terraform must be the only actor exercising
lock and state writes during the later approved saved-plan wrapper run.

No production state, lock, IAM, ECR, runtime, database, network, or traffic
resource is changed by this PR.

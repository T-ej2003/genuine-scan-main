# Production Green Stage B ECR image evidence

The release-deployer is an infrastructure applier, not the image-publisher or image-verifier. The dedicated image-publisher identity owns the reviewed Stage B ECR publication contract. The release role receives no ECR read or mutation authority for this evidence path.

## Approved evidence flow

An approved administrator reads `ecr:DescribeImages` for exactly these repositories:

- `arn:aws:ecr:eu-west-2:368992683803:repository/mscqr-backend`
- `arn:aws:ecr:eu-west-2:368992683803:repository/mscqr-worker`

The executor and canary images use the backend repository, so the four bindings are:

- backend: release SHA tag in `mscqr-backend`
- worker: release SHA tag in `mscqr-worker`
- RLS executor: `<release-sha>-rls-executor` in `mscqr-backend`
- read-only canary: `<release-sha>-rls-canary` in `mscqr-backend`

The administrator generates a report containing the release SHA, canonical workflow run, canonical artifact SHA, exact repository/tag/digest records, observation time, account, region, and verifier ARN. The report is signed with the existing Stage B KMS signing contract. The apply wrapper verifies the detached signature and all four bindings; it does not call ECR.

The canonical workflow artifact is authoritative. A failed duplicate workflow cannot become authoritative because it has no accepted artifact and its immutable-tag collision does not alter the canonical tag-to-digest binding.

## IAM boundary

The checked-in publisher policy grants ECR publication/read operations only to the dedicated image-publisher role and scopes repositories to the two exact Stage B repository ARNs. It does not grant those permissions to the release-deployer. No `ecr:PutImage`, layer-upload, delete, repository-policy, or repository-creation permission is added to the release role.

The live release-role `ecr:DescribeImages` request was observed as an explicit identity-policy deny. The exact live policy ARN, version, statement SID, and conditions must be captured by the approved administrator before deployment; they are not inferred from this repository and must not be overridden with an Allow. The signed administrator report is the approved alternative boundary.

## Required report fields

The wrapper requires a detached signature and verifies:

- fixed Stage B KMS key and signing algorithm
- approved administrator verifier identity
- release SHA and workflow run
- canonical artifact SHA
- exact account and region
- all four repository/tag/digest bindings
- fresh observation and signature timestamps

Unsigned, caller-supplied, modified, stale, duplicate-run, wrong-repository, wrong-region, or digest-mismatched evidence is rejected.

# Production green Stage B publisher bootstrap operator

This package is repository-only. It prepares the narrowly scoped non-root path needed to
create the dedicated GitHub OIDC image-publisher role; it does not create any AWS resource.

## Identities and scope

- Human MFA operator: `arn:aws:iam::368992683803:user/mscqr-production-bootstrap-operator`
- New bootstrap role: `arn:aws:iam::368992683803:role/mscqr-production-stage-b-publisher-bootstrap`
- Sole managed role: `arn:aws:iam::368992683803:role/mscqr-production-stage-b-image-publisher`
- Sole managed policy: `arn:aws:iam::368992683803:policy/MSCQRProductionGreenStageBImagePublisher`
- Immutable publisher boundary: `arn:aws:iam::368992683803:policy/MSCQRProductionStageBImagePublisherBoundary`
- Maximum bootstrap-role session: 3,600 seconds (the AWS IAM minimum)
- Publisher Terraform root: `infra/aws/terraform/production-green-stage-b-image-publisher/`
- State bucket: `mscqr-production-terraform-state-368992683803-eu-west-2`
- Publisher state key: `mscqr/production/rls-green/stage-b-image-publisher/terraform.tfstate`

The new role trusts only the existing bootstrap user with
`aws:MultiFactorAuthPresent = true`. It does not trust root, GitHub Actions, application
roles, the Stage A deployer, or existing deployment roles. It has only exact-role IAM
operations, exact policy/attachment management, exact S3 publisher-state/lockfile access,
and read-only verification actions. The bootstrap role cannot change or detach the
boundary, so it cannot give the publisher role effective permissions beyond reviewed ECR.

## Required one-time break-glass event

The current account has no non-root role that can create the bootstrap role. Before the
normal path exists, an independently approved break-glass event must create only the
bootstrap role, its inline policy, and the immutable publisher boundary from
`infra/aws/terraform/production-green-stage-b-publisher-bootstrap/`. The saved plan must
have exactly three additions, no changes, destroys, or replacements. Record the root
security event and plan checksum. Root must not run the publisher Terraform root.

## Normal operation after bootstrap

1. Obtain a human-approved MFA-backed temporary session for the existing bootstrap user.
2. Assume `mscqr-production-stage-b-publisher-bootstrap` for at most one hour.
3. Initialise and plan only the publisher root with the exact publisher state key and
   lockfile contract.
4. Reject any resource other than the publisher role, its exact managed ECR-only policy,
   and their attachment.
5. Apply the reviewed saved plan, verify role and policy hashes, then configure the
   environment-only publisher role ARN in a separately approved step.

The bootstrap user has no console password and no standing access key. The missing human
access mechanism is an approved temporary credential-issuance path for one MFA session;
it must not create a permanent user key. Without that mechanism, stop.

## Rollback

After the publisher role is removed or handed to a separately approved operator path,
apply a separately approved destroy plan for the bootstrap root. This affects only the
bootstrap role, inline policy, and publisher permissions boundary. It must not alter images, databases, secrets, ECS,
Lambda, services, DNS, traffic, or Stage A resources.

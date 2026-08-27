# Production green Stage B publisher bootstrap

This isolated pre-Stage-A root creates the root-exclusive asymmetric attestation key and the
MFA-only role `mscqr-production-stage-b-publisher-bootstrap`, its inline policy, and the immutable
maximum-permissions boundary `MSCQRProductionStageBImagePublisherBoundary`. Root alone may sign
with `alias/mscqr-production-root-attestation`; the release deployer may authenticate and verify
that key but cannot sign. The role may apply
only `../production-green-stage-b-image-publisher/`, which creates only
`mscqr-production-stage-b-image-publisher`, the exact managed policy
`MSCQRProductionGreenStageBImagePublisher`, and their reviewed attachment.

The bootstrap role cannot modify or detach the boundary. The publisher role cannot exceed
the boundary's ECR-only permissions even if its trust or attached policy is later altered.

It has no authority over Stage A, application infrastructure, databases, ECS, Lambda,
networking, Secrets Manager, KMS decrypt, traffic, or unrelated IAM identities. The attestation
key exists before release-preflight evidence and Stage A, preventing a checker-role bootstrap
cycle. The bootstrap role can
read and write only the publisher state object and S3 lockfile recorded in
`state-backend-contract.json`; it cannot read Stage A, staging, DR, application, or this
bootstrap root's state.

## One-time bootstrap boundary

The bootstrap role does not yet exist, so a separately approved break-glass event is
required to apply this root once. That event must use a saved plan containing only the
root-exclusive attestation key and alias, this role, its inline policy, and the immutable publisher permissions boundary, record the root use as a security event, and use the exact
bootstrap state key from `state-backend-contract.json`. Root must never plan or apply the
publisher root itself.

## Normal operator path

1. A human obtains an MFA-backed temporary session for
   `mscqr-production-bootstrap-operator` through the approved credential mechanism.
2. The user assumes `mscqr-production-stage-b-publisher-bootstrap`; its maximum session
   is the AWS minimum of one hour.
3. Terraform runs only in `../production-green-stage-b-image-publisher/` using the
   `publisherStateKey` and S3 lockfile from `state-backend-contract.json`.
4. Verify the created publisher role's exact trust and inline-policy hashes, then let the
   temporary bootstrap session expire.

The existing bootstrap operator intentionally has no console password and no standing
access key. If no approved credential mechanism can issue the short-lived initial MFA
session, stop: do not create a permanent key or invent another trust principal.

## Rollback

A separately approved Terraform destroy of this isolated root removes the attestation key only
after its deletion window and removes the bootstrap role and its inline policy. It must occur only after all signed evidence has expired or been superseded and the publisher root has been removed
or transferred to a separately approved replacement operator path. It never deletes
images, application infrastructure, secrets, databases, services, or traffic resources.

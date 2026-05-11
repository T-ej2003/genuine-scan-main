# Object Storage Verification Checklist

Last updated: 2026-05-11

## Scope

This checklist verifies object storage access during a manual failover drill. It does not decommission MinIO, migrate buckets, delete objects, or clean up storage.

## Pre-Check Gates

- [ ] Target standby region selected: Mumbai / Cape Town.
- [ ] Object storage mode identified: native S3 / compatible endpoint / existing MinIO-backed deployment.
- [ ] Bucket or endpoint identifier recorded.
- [ ] Credential source recorded without secret values.
- [ ] Required IAM role, access key, or approved credential path confirmed.
- [ ] Network path from standby app server confirmed.
- [ ] Database recovery plan reviewed before any write test.

## Read Verification

- [ ] Confirm app env points to the approved object storage target.
- [ ] Confirm bucket/endpoint is reachable from selected standby app server.
- [ ] Verify a known non-sensitive object can be read, if available.
- [ ] Verify application read path that depends on object storage, if approved.
- [ ] Record evidence location in the RTO/RPO template.

## Write Verification Gate

Do not run write tests until database recovery plan is approved.

- [ ] Incident commander approved write test.
- [ ] Database restore target is approved for the test.
- [ ] Test object/key naming avoids production collision.
- [ ] Retention or cleanup owner assigned for test object.
- [ ] Write behavior verified through the application or approved storage client.
- [ ] Test object evidence recorded without sensitive payloads.

## MinIO Safety

- [ ] Do not delete MinIO buckets.
- [ ] Do not delete MinIO volumes.
- [ ] Do not remove MinIO containers.
- [ ] Do not decommission MinIO as part of Phase 3.
- [ ] Do not use destructive Docker cleanup commands.

## Failure Handling

- [ ] If reads fail, capture endpoint, region, and error class without secrets.
- [ ] If writes fail, stop write testing and preserve logs.
- [ ] Confirm whether failure is credentials, network, bucket policy, or application configuration.
- [ ] Record blocker, owner, and next action in the RTO/RPO template.

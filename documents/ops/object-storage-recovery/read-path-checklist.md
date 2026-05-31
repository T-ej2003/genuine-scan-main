# Object Storage Read Path Checklist

Last updated: 2026-05-31

## Checklist

- [ ] Identify safe non-sensitive test object.
- [ ] Verify app can read required public/private asset.
- [ ] Verify backend object dependency that matters for recovery.
- [ ] Verify production/ASG mode is S3/default-credentials with empty endpoint and static credential fields.
- [ ] Verify ASG launch template uses `HttpTokens=required`, `HttpEndpoint=enabled`, and `HttpPutResponseHopLimit=2`.
- [ ] Verify current ASG instances have the expected instance profile attached.
- [ ] Verify Mumbai read path.
- [ ] Verify Cape Town read path.
- [ ] Inspect backend logs for object storage errors.
- [ ] Confirm no MinIO endpoint appears in production/ASG evidence.
- [ ] Confirm access denied errors are absent.
- [ ] Record evidence without secrets.

## Evidence Table

| Region | Object/key description | Result | Evidence link | Owner |
| --- | --- | --- | --- | --- |
| Mumbai |  |  |  |  |
| Cape Town |  |  |  |  |

## Notes

- Use a safe object that does not expose customer data.
- Do not paste object credentials into evidence.
- Do not change bucket policy during this checklist unless separately approved.

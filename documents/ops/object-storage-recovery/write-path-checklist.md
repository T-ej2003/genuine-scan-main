# Object Storage Write Path Checklist

Last updated: 2026-05-31

Run this only after database recovery and write gate approval.

## Checklist

- [ ] Database recovery approved.
- [ ] Write gate approved.
- [ ] S3/default-credentials read-path proof completed.
- [ ] Safe test upload selected.
- [ ] Test object/key naming avoids production collision.
- [ ] Metadata/database linkage verification plan approved.
- [ ] Object exists after upload.
- [ ] Application can read the uploaded test object.
- [ ] Rollback/cleanup plan for test object is assigned.
- [ ] Evidence recorded without sensitive payloads.

## Do Not Do

- Do not delete production objects.
- Do not delete buckets.
- Do not delete MinIO data automatically.
- Do not run write tests before database recovery is approved.

## Evidence Table

| Region | Test object/key | DB linkage result | Readback result | Cleanup owner | Evidence |
| --- | --- | --- | --- | --- | --- |
| Mumbai |  |  |  |  |  |
| Cape Town |  |  |  |  |  |

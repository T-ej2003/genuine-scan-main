# MSCQR AWS Legacy Cleanup Inventory

Last updated: 2026-06-03

This document describes the read-only legacy cleanup inventory classifier. It is classification and operator review only. It does not delete, stop, detach, mutate, or modify AWS resources, Route 53 records, IAM resources, S3 buckets, RDS databases, security groups, certificates, or cleanup artifacts.

## Command

Use an uploaded archive:

```bash
npm run ops:legacy-cleanup-inventory -- --archive artifacts/aws-cleanup-inventory/20260603T103903Z.tar.gz
```

Use an extracted inventory directory:

```bash
npm run ops:legacy-cleanup-inventory -- --inventory-dir artifacts/aws-cleanup-inventory/20260603T103903Z
```

With no argument, the classifier scans `artifacts/aws-cleanup-inventory/` and selects the newest complete archive. The `20260603T100141Z` inventory is expected to be incomplete because it contains a broken combined region-loop directory. Later archives with separate `ap-south-1`, `af-south-1`, `eu-west-2`, and `us-east-1` directories are higher confidence after validation.

## Outputs

The classifier writes local reports beside the selected inventory timestamp:

- `classified-resources.json`
- `classified-resources.md`
- `classification-summary.txt`

Each classified resource includes classification, service, region, resource type, ID/name/ARN, evidence, risk, recommended action, console review checklist, and notes.

## Classification Buckets

- `KEEP`: active production or required operational infrastructure.
- `REVIEW_REQUIRED`: ambiguous or insufficient evidence; no action.
- `SAFE_TO_STOP`: reversible compute-like stop candidate after visual confirmation and separate approval.
- `SAFE_TO_DELETE_LATER`: conservative future candidate after visual AWS Console confirmation and separate approval.
- `NEVER_DELETE_WITHOUT_BACKUP`: data-bearing or identity-critical resource that requires backup/export/snapshot and explicit approval before any future action.

Anything ambiguous remains `REVIEW_REQUIRED`.

## Hard Production Rules

- Route 53 apex `mscqr.com` geolocation records, `www.mscqr.com` CNAME, MX, NS, SOA, TXT, DMARC, DKIM, SPF, and ACM validation records are `KEEP`.
- Current Mumbai, Cape Town, and London ALBs are `KEEP`.
- Target groups attached to current ALBs or ASGs are `KEEP`.
- Current production ASGs, EC2 instances, GitHub runner, attached EBS volumes, attached security groups, and attached ENIs are `KEEP`.
- RDS instances, clusters, and manual snapshots are `NEVER_DELETE_WITHOUT_BACKUP`.
- Production S3 artifact buckets are `KEEP`.
- ALB log buckets are `KEEP` or `REVIEW_REQUIRED`; they are not cleanup targets in this pass.
- IAM roles/policies are `REVIEW_REQUIRED` unless recognized as current production/GitHub roles, then `KEEP`.
- GitHub deploy role and auto-failover read-only role are `KEEP`.
- MinIO-related AWS resources are `REVIEW_REQUIRED` unless proven local/dev only.

## Console Review Protocol

1. Review one resource at a time.
2. Open the AWS Console service page for the resource type.
3. Verify the region, resource ID/name, tags, attachments, listeners, DNS references, IAM references, and workflow references.
4. Capture a screenshot before any future cleanup action.
5. Fill a separate approval ledger with owner, evidence path, resource ID, region, and approver.
6. Future terminal actions are allowed only in a separate approved cleanup pass.
7. Capture a post-action inventory and confirm the resource state changed as expected.

Legacy cleanup remains blocked until inventory classification, visual AWS Console confirmation, approval evidence, and post-action verification are all complete.

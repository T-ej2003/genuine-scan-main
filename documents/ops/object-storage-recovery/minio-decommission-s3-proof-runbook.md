# Phase C MinIO Decommission / S3 Proof Runbook

Last updated: 2026-05-31

## Purpose

Prove MSCQR production and ASG DR paths use S3/default credentials and do not depend on MinIO. This runbook is evidence-first and non-destructive.

Do not delete MinIO data automatically. Do not change production DNS. Do not mutate AWS except through separately approved write-test gates. Do not touch secrets.

## MinIO Usage Inventory

| Reference | Classification | Phase C decision |
| --- | --- | --- |
| `docker-compose.yml` | Production standalone EC2 path | Must remain free of MinIO services, MinIO volumes, and MinIO dependencies. |
| `docker-compose.local.yml` `minio`, `minio-init`, `minio_data` | Local development only | Preserve for local development behind the explicit `local-minio` profile. Do not use in production. |
| `docker-compose.asg-web.yml` | Production/ASG DR path | Must remain free of MinIO services, MinIO volumes, and MinIO dependencies. |
| `backend/src/services/objectStorageService.ts` endpoint/static credential mode | Legacy custom S3-compatible path | Keep generic support, but ASG web mode must force S3/default credentials. |
| `backend/src/index.ts` production startup object-storage validation | Production startup validation | Keep object storage required. Known default/static credential rejection remains. |
| `documents/ops/aws-asg-web-ssm-parameter-manifest.json` | Production/DR guardrail | Keep MinIO root credentials excluded and object endpoint/static credentials forced empty. |
| `scripts/dr/bootstrap-asg-web-node.sh` | Production/DR guardrail | Reject non-empty endpoint/static credential SSM inputs and path-style true in ASG web mode. |
| ASG launch template `MetadataOptions` | Production/DR guardrail | Keep IMDSv2 required, endpoint enabled, and `HttpPutResponseHopLimit=2` so Dockerized backend can use instance-profile credentials. |
| `backend/.env.example`, `docker-compose.local.yml` | Local configuration docs | Allowed only for local Docker Compose guidance. |
| `backend/tests/objectStorageConfigContract.test.js` | Test-only | Keep as custom endpoint contract coverage. |

## S3 Proof Checklist

- [ ] Confirm production/ASG object storage mode is `default-credentials`.
- [ ] Confirm `OBJECT_STORAGE_ENDPOINT` is empty.
- [ ] Confirm `OBJECT_STORAGE_ACCESS_KEY` and `OBJECT_STORAGE_SECRET_KEY` are empty.
- [ ] Confirm `OBJECT_STORAGE_FORCE_PATH_STYLE` is unset or `false`.
- [ ] Confirm `/api/health/ready` reports object storage configured and ready.
- [ ] Confirm launch template MetadataOptions are `HttpTokens=required`, `HttpEndpoint=enabled`, and `HttpPutResponseHopLimit=2`.
- [ ] Confirm current ASG instances have the expected instance profile attached.
- [ ] Confirm at least one safe non-sensitive object read path works.
- [ ] Confirm backend logs show no MinIO endpoint, access denied, or endpoint-resolution errors.
- [ ] Confirm production deploy commands target `redis backend worker frontend` explicitly and do not run a bare Compose profile that can start local-only services.
- [ ] Preserve evidence under `documents/ops/evidence/` or the approved incident evidence location.

## Production Compose Rule

Production must not start MinIO or `minio-init`. The active and standby Ansible deploy paths must use the default production compose file only:

```bash
docker compose --profile worker build backend worker frontend
docker compose --profile worker up -d --no-build redis backend worker frontend
```

Local MinIO remains available only for developer workflows:

```bash
docker compose -f docker-compose.yml -f docker-compose.local.yml --profile local-minio up -d minio minio-init
```

## No-Secret Validation Commands

Run from the repository root on the operator workstation:

```bash
npm run check:minio-decommission-readiness
npm run check:aws-dr-safety
npm run verify:guardrails
```

Names-only ASG SSM preflight. This prints parameter names only, not values:

```bash
aws ssm describe-parameters \
  --region ap-south-1 \
  --parameter-filters "Key=Path,Option=Recursive,Values=/mscqr/prod/ap-south-1/asg-web/" \
  --query 'Parameters[].Name' \
  --output text | tr '\t' '\n' | sort
```

Verify forbidden ASG object-storage parameter names are absent or intentionally empty by reviewing names only first:

```bash
aws ssm describe-parameters \
  --region ap-south-1 \
  --parameter-filters "Key=Path,Option=Recursive,Values=/mscqr/prod/ap-south-1/asg-web/" \
  --query 'Parameters[?contains(Name, `OBJECT_STORAGE_ENDPOINT`) || contains(Name, `OBJECT_STORAGE_ACCESS_KEY`) || contains(Name, `OBJECT_STORAGE_SECRET_KEY`) || contains(Name, `OBJECT_STORAGE_FORCE_PATH_STYLE`) || contains(Name, `MINIO_ROOT`)].Name' \
  --output text | tr '\t' '\n' | sort
```

If any forbidden name appears, do not print its value. Remove or correct it only through the approved secret-management process.

Launch template and live instance metadata proof:

```bash
aws autoscaling describe-auto-scaling-groups \
  --region ap-south-1 \
  --auto-scaling-group-names mscqr-mumbai-dr-asg \
  --query 'AutoScalingGroups[0].{LaunchTemplate:LaunchTemplate,Instances:Instances[].InstanceId}' \
  --output json

aws ec2 describe-launch-template-versions \
  --region ap-south-1 \
  --launch-template-id lt-02570cc00f696ee4c \
  --versions 18 \
  --query 'LaunchTemplateVersions[].LaunchTemplateData.{IamInstanceProfile:IamInstanceProfile,MetadataOptions:MetadataOptions}' \
  --output json
```

For each current ASG instance ID:

```bash
aws ec2 describe-instances \
  --region ap-south-1 \
  --instance-ids <instance-id> \
  --query 'Reservations[].Instances[].{Id:InstanceId,IamInstanceProfile:IamInstanceProfile,MetadataOptions:MetadataOptions}' \
  --output json
```

## Read-Path Proof

Production health proof:

```bash
curl -fsS https://www.mscqr.com/api/health/ready | jq '.dependencies.objectStorage'
curl -fsS https://www.mscqr.com/healthz
```

ASG/Mumbai evidence capture when ASG health needs correlation:

```bash
TARGET_REGION_GROUP=mumbai \
AWS_REGION=ap-south-1 \
ASG_NAME=mscqr-mumbai-dr-asg \
TARGET_GROUP_ARN=arn:aws:elasticloadbalancing:ap-south-1:368992683803:targetgroup/mscqr-mumbai-frontend-tg/68982ccd4d8c26c1 \
READY_URL=https://www.mscqr.com/api/health/ready \
npm run ops:asg-health-evidence
```

Bucket read-only proof. Choose a safe, non-sensitive object key already approved for evidence:

```bash
BUCKET=mscqr-prod-aps1-artifacts-368992683803-ap-south-1 \
TEST_OBJECT_KEY=<safe-non-sensitive-existing-key> \
scripts/dr/object-storage-readiness.sh
```

If no safe object key is approved, run the bucket-only read check and record that object-level readback is pending:

```bash
BUCKET=mscqr-prod-aps1-artifacts-368992683803-ap-south-1 \
scripts/dr/object-storage-readiness.sh
```

## Optional Write-Path Proof

Run only after write gate approval. This creates one namespaced test object and leaves it in place unless a separate cleanup confirmation is supplied.

```bash
BUCKET=mscqr-prod-aps1-artifacts-368992683803-ap-south-1 \
CONFIRM_OBJECT_WRITE_TEST=I_APPROVE_OBJECT_STORAGE_WRITE_TEST \
scripts/dr/object-storage-write-test-approved.sh
```

Optional cleanup of only the generated DR test object:

```bash
BUCKET=mscqr-prod-aps1-artifacts-368992683803-ap-south-1 \
CONFIRM_OBJECT_WRITE_TEST=I_APPROVE_OBJECT_STORAGE_WRITE_TEST \
CONFIRM_DELETE_TEST_OBJECT=I_APPROVE_DELETE_DR_TEST_OBJECT \
scripts/dr/object-storage-write-test-approved.sh
```

Do not delete production objects. Do not bulk-delete prefixes. Do not delete buckets.

## MinIO Data Archival Plan

Before any MinIO service retirement, preserve a local archive or platform snapshot and record the evidence owner.

Inventory local MinIO without printing credentials:

```bash
docker compose -f docker-compose.yml -f docker-compose.local.yml --profile local-minio ps minio minio-init
docker volume ls | grep -E '(^|_)minio_data$' || true
docker volume inspect genuine-scan-main_minio_data
docker exec genuine-scan-minio sh -lc 'du -sh /data && find /data -maxdepth 2 -type d | sed -n "1,80p"'
```

Create a read-only local archive only after the storage owner approves the archive location:

```bash
ARCHIVE_DIR="$PWD/artifacts/dr/minio-archive-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$ARCHIVE_DIR"
docker run --rm \
  -v genuine-scan-main_minio_data:/data:ro \
  -v "$ARCHIVE_DIR":/archive \
  alpine:3.20 \
  sh -lc 'tar -C /data -czf /archive/minio-data.tgz . && sha256sum /archive/minio-data.tgz > /archive/minio-data.tgz.sha256'
```

Record:

- archive path
- archive hash
- MinIO volume name
- approval timestamp
- rollback owner
- retention decision

Do not delete MinIO containers, volumes, buckets, or archive files as part of this runbook.

## Rollback Plan

- If S3 read proof fails, keep MinIO data untouched and stop Phase C promotion.
- If ASG guardrails fail, fix repo/bootstrap/docs and rerun local validation.
- If optional write proof fails, preserve the test artifact evidence and assign reconciliation owner.
- If any app path still points to MinIO, classify it as local-only, legacy single-node, or production/DR risk before changing it.
- Keep Phase D blocked until read proof, archival plan, and rollback ownership are approved.

## Evidence Commands

Capture local guardrail evidence:

```bash
git diff --check
npm run check:minio-decommission-readiness
npm run check:aws-dr-safety
npm run verify:guardrails
npm run check:documents
```

Capture production read-path evidence:

```bash
date -u
dig +short www.mscqr.com
curl -fsS https://www.mscqr.com/healthz
curl -fsS https://www.mscqr.com/api/health/ready | jq '.dependencies.objectStorage'
```

Capture bucket-level evidence:

```bash
BUCKET=mscqr-prod-aps1-artifacts-368992683803-ap-south-1 scripts/dr/object-storage-readiness.sh
```

Save outputs in the approved evidence location. Do not paste secret values into evidence.

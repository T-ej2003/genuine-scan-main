# ECS/Fargate Object Storage Modes

MSCQR supports three production-safe object storage modes:

1. Custom S3-compatible / MinIO mode
   - Required env:
     - `OBJECT_STORAGE_BUCKET`
     - `OBJECT_STORAGE_REGION` or `AWS_REGION`
     - `OBJECT_STORAGE_ENDPOINT`
     - `OBJECT_STORAGE_ACCESS_KEY`
     - `OBJECT_STORAGE_SECRET_KEY`
   - Recommended:
     - `OBJECT_STORAGE_FORCE_PATH_STYLE=true`

2. Native AWS S3 with static credentials
   - Required env:
     - `OBJECT_STORAGE_BUCKET`
     - `OBJECT_STORAGE_REGION` or `AWS_REGION`
     - `OBJECT_STORAGE_ACCESS_KEY`
     - `OBJECT_STORAGE_SECRET_KEY`
   - Leave unset unless you have a special routing requirement:
     - `OBJECT_STORAGE_ENDPOINT`
   - Recommended:
     - `OBJECT_STORAGE_FORCE_PATH_STYLE=false`

3. Native AWS S3 with ECS task role / AWS SDK default credential chain
   - Required env:
     - `OBJECT_STORAGE_BUCKET`
     - `OBJECT_STORAGE_REGION` or `AWS_REGION`
   - Must be left unset:
     - `OBJECT_STORAGE_ENDPOINT`
     - `OBJECT_STORAGE_ACCESS_KEY`
     - `OBJECT_STORAGE_SECRET_KEY`
   - Recommended:
     - leave `OBJECT_STORAGE_FORCE_PATH_STYLE` unset or set it to `false`

## ECS Task-Role Contract

For the standard ECS/Fargate production deployment, set only:

```env
OBJECT_STORAGE_BUCKET=<your-s3-bucket-name>
OBJECT_STORAGE_REGION=<bucket-region>
```

Or use `AWS_REGION` instead of `OBJECT_STORAGE_REGION` if that is how your task definition is already standardized.

Do not set these values for task-role mode:

```env
OBJECT_STORAGE_ENDPOINT=
OBJECT_STORAGE_ACCESS_KEY=
OBJECT_STORAGE_SECRET_KEY=
```

`OBJECT_STORAGE_FORCE_PATH_STYLE` should be omitted or set to `false` for native AWS S3.

## IAM Requirement

The ECS task role must have S3 permissions for the target bucket. At minimum, the backend needs access to:

- `s3:PutObject`
- `s3:GetObject`
- `s3:HeadBucket`

Scope these permissions to the bucket and the object prefix pattern used by the application.

## Runtime Behavior

- When static credentials are present, MSCQR passes them explicitly to the AWS SDK.
- When static credentials are absent, MSCQR does not inject a credentials block and the AWS SDK uses its default credential chain.
- Production startup accepts task-role mode when bucket plus region are configured and no static object-storage credentials are supplied.

## Local Development

No ECS changes are required for local Docker Compose + MinIO development. The local MinIO flow still uses the endpoint plus static credentials path.

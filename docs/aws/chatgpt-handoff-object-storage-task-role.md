# ChatGPT Handoff: ECS Task-Role Object Storage

## What Changed

- Backend object storage now supports three explicit modes:
  - custom S3-compatible / MinIO with endpoint plus static credentials
  - native AWS S3 with static credentials
  - native AWS S3 with ECS task role / AWS SDK default credential chain
- Production startup validation now accepts ECS task-role mode when bucket plus region are configured and no static object-storage credentials are provided.
- Object-storage utility messaging and env examples were updated to match the new contract.
- AWS operator documentation was added for ECS/Fargate deployments.

## Files Changed

- `.env.example`
- `backend/.env.example`
- `README.md`
- `docs/aws/object-storage-task-role.md`

The runtime code for this behavior is already present in:

- `backend/src/services/objectStorageService.ts`
- `backend/src/index.ts`
- `backend/scripts/migrate-local-uploads-to-object-storage.ts`

## Exact ECS Env Contract

Required for ECS task-role mode:

```env
OBJECT_STORAGE_BUCKET=<your-s3-bucket-name>
OBJECT_STORAGE_REGION=<bucket-region>
```

`AWS_REGION` may be used instead of `OBJECT_STORAGE_REGION` if that is already the environment standard in the task definition.

Must be removed or left unset for ECS task-role mode:

```env
OBJECT_STORAGE_ENDPOINT
OBJECT_STORAGE_ACCESS_KEY
OBJECT_STORAGE_SECRET_KEY
```

Should remain unset or be explicitly false for native AWS S3:

```env
OBJECT_STORAGE_FORCE_PATH_STYLE=false
```

## What To Remove From The ECS Task Definition

- `OBJECT_STORAGE_ENDPOINT`
- `OBJECT_STORAGE_ACCESS_KEY`
- `OBJECT_STORAGE_SECRET_KEY`
- any MinIO-only object-storage values copied into the backend container for production
- any `OBJECT_STORAGE_FORCE_PATH_STYLE=true` setting used only for MinIO compatibility

## What Should Remain In The ECS Task Definition

- `OBJECT_STORAGE_BUCKET`
- `OBJECT_STORAGE_REGION` or `AWS_REGION`
- the ECS task role / execution role wiring used by your platform
- any unrelated backend secrets and runtime variables already required by production

## Verification Commands Run

```bash
node backend/node_modules/typescript/bin/tsc -p backend/tsconfig.json --noEmit
rg -n "OBJECT_STORAGE_ENDPOINT requires|default-credentials|credentials:" backend/src/services/objectStorageService.ts backend/src/index.ts
python3 - <<'PY'
from pathlib import Path
for name in ['backend/src/services/objectStorageService.ts','backend/src/index.ts']:
    print(f'--- {name} ---')
    for i, line in enumerate(Path(name).read_text().splitlines(), 1):
        if 'default-credentials' in line or 'OBJECT_STORAGE_ENDPOINT requires' in line or 'task role' in line or 'credentials:' in line:
            print(f'{i}: {line}')
PY
```

## Commit SHA After Commit

- Runtime fix commit already on this branch: `6df728524a393bc6d33a9fb9fb0c06e4f5cac128`

## Known Caveats

- Local Docker Compose still intentionally uses the MinIO endpoint plus static credentials flow.
- `uploadObjectFromFile` currently buffers the file in memory before upload. This is acceptable for current behavior, but streaming or multipart upload would be the next scalability hardening step for larger evidence or compliance artifacts.
- ECS image architecture and ECR publishing are handled separately. Use [docs/aws/chatgpt-handoff-ecs-image-architecture.md](/Users/abhiramteja/Downloads/genuine-scan-main/docs/aws/chatgpt-handoff-ecs-image-architecture.md:1) for buildx publishing, manifest verification, and task-definition image update steps.

## Exact Next Manual AWS Deployment Steps

1. Update the ECS task definition for the backend container.
2. Keep `OBJECT_STORAGE_BUCKET` and `OBJECT_STORAGE_REGION` or `AWS_REGION`.
3. Remove `OBJECT_STORAGE_ENDPOINT`, `OBJECT_STORAGE_ACCESS_KEY`, and `OBJECT_STORAGE_SECRET_KEY`.
4. Remove `OBJECT_STORAGE_FORCE_PATH_STYLE=true` if it was copied from a MinIO deployment.
5. Confirm the ECS task role has `s3:PutObject`, `s3:GetObject`, and `s3:HeadBucket` access for the production bucket.
6. Register a new task definition revision.
7. Deploy the new revision to the ECS service.
8. Verify service startup logs no longer show the production object-storage refusal.
9. Verify `/health/ready` reports object storage as configured and ready.

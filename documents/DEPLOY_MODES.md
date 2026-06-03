# Deploy Modes

## Fast Deploy

Use this when the branch already passed CI or local release verification and you want the shortest Lightsail path.

```bash
cd ~/genuine-scan-main
git fetch origin
git checkout codex/industry-grade-hardening
git pull --ff-only origin codex/industry-grade-hardening

export GIT_SHA=$(git rev-parse --short HEAD)
unset DOCKER_BUILD_VERIFY
unset RUN_DB_MIGRATIONS_ON_START

docker compose build backend frontend
docker compose run --rm backend npx prisma migrate deploy
docker compose --profile worker up -d --force-recreate redis backend worker frontend
```

## Strict Pre-Release Verify

Use this before high-risk production releases or security-sensitive changes.

```bash
cd ~/genuine-scan-main
git fetch origin
git checkout codex/industry-grade-hardening
git pull --ff-only origin codex/industry-grade-hardening

export GIT_SHA=$(git rev-parse --short HEAD)
export DOCKER_BUILD_VERIFY=true

npm run verify:release
docker compose build backend frontend
docker compose run --rm backend npx prisma migrate deploy
docker compose --profile worker up -d --force-recreate redis backend worker frontend

unset DOCKER_BUILD_VERIFY
```

## Post-Deploy Checks

```bash
docker compose ps
docker compose logs backend --tail=120
docker compose logs worker --tail=120
docker compose logs frontend --tail=120
curl -fsS http://127.0.0.1:4000/health/ready
npm run smoke:release
```

## ASG Web Node Mode

Use this only for ASG web/backend instances that point at shared regional Redis and S3 through environment injection. It intentionally has no worker, Redis, or MinIO service:

```bash
docker compose -f docker-compose.asg-web.yml up -d --build backend frontend
```

Standalone regional EC2 hosts that are responsible for the single worker must opt in explicitly:

```bash
docker compose --profile worker up -d --build redis backend worker frontend
```

## Local MinIO Mode

MinIO is dev/local only. Production uses regional S3 through default credentials with an empty `OBJECT_STORAGE_ENDPOINT`, no static object-storage keys, and path-style addressing disabled.

Enable local MinIO intentionally through the local override and profile:

```bash
docker compose -f docker-compose.yml -f docker-compose.local.yml --profile local-minio up -d minio minio-init
```

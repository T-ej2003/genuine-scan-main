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
docker compose up -d redis minio
docker compose up minio-init
docker compose up -d --force-recreate backend worker frontend
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
docker compose up -d redis minio
docker compose up minio-init
docker compose up -d --force-recreate backend worker frontend

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

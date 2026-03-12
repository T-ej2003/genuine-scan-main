# Lightsail Printing Update Commands

## Purpose

Use these commands on the AWS Lightsail instance after your printing and printer UX changes are pushed to GitHub.

These commands are written for the Lightsail browser terminal opened with `Connect using SSH`.

## Standard Docker Compose update

```bash
cd ~/genuine-scan-main
git fetch origin
git checkout codex/printing-architecture-ipp-gateway
git pull --ff-only origin codex/printing-architecture-ipp-gateway
git rev-parse HEAD
git status --short

docker compose build backend frontend
docker compose run --rm backend npx prisma migrate deploy
docker compose up -d --force-recreate backend frontend
docker compose ps
docker compose logs backend --tail=80
docker compose logs frontend --tail=80
curl -fsS http://127.0.0.1/healthz
```

## Verify the server matches your local commit

Run this locally:

```bash
git rev-parse HEAD
git status --short
```

Run this on Lightsail:

```bash
cd ~/genuine-scan-main
git rev-parse HEAD
git status --short
```

Expected result:

- `git rev-parse HEAD` matches the local commit hash
- `git status --short` is empty on the server after the deploy
- `docker compose ps` shows `backend` healthy and `frontend` running

## Full container refresh

Use this only when you want a completely fresh recreate of the app containers:

```bash
cd ~/genuine-scan-main
docker compose down --remove-orphans
docker compose build --no-cache backend frontend
docker compose run --rm backend npx prisma migrate deploy
docker compose up -d backend frontend
docker compose ps
```

## If a site connector workstation is used

Redeploy the updated signed workstation connector package or refresh its `agent.env` values so the site gateway can continue polling outbound.

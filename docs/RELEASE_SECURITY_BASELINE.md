# Release Security Baseline

This repository treats credential-like defaults in tracked infra/config files as a release-security failure, not a convenience feature.

## Fail-Closed Environment Variables

These values must never carry fallback credentials in tracked files:

- `MINIO_ROOT_USER`
- `MINIO_ROOT_PASSWORD`
- `OBJECT_STORAGE_ACCESS_KEY`
- `OBJECT_STORAGE_SECRET_KEY`

For Docker Compose, use required env forms such as `${VAR:?Set VAR in environment or .env}` so local operators must supply values explicitly in an untracked `.env` or shell session.

## Files That Must Never Carry Fallback Credentials

- `docker-compose*.yml`
- `.env.example`
- `backend/.env.example`
- `README.md`
- `docs/**/*.md`
- `.github/workflows/**/*.yml`

These files may document variable names and fail-closed usage, but they must not contain password-like fallback literals or example credential values.

## Local Development Contract

- Local Compose users set MinIO bootstrap credentials and object-storage runtime credentials in an untracked `.env`.
- AWS/task-role deployments should prefer ambient credentials and keep static object-storage secrets unset unless a custom S3-compatible endpoint requires them.
- Tracked examples may leave sensitive vars empty, but never populated with realistic defaults.

## Guardrail

The baseline guard script `scripts/check-baseline-secret-patterns.mjs` blocks:

- known legacy fallback literals from the old MinIO/object-storage baseline
- fallback default forms on `MINIO_ROOT_*`
- fallback default forms on `OBJECT_STORAGE_ACCESS_KEY` / `OBJECT_STORAGE_SECRET_KEY`

This keeps `main` clean so future PRs do not inherit a poisoned secret-scanner baseline.

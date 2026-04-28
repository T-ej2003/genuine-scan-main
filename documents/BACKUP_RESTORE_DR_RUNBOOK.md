# Backup, Restore, and Disaster Recovery

## Scope

This platform depends on:

- PostgreSQL as the system of record
- Redis for distributed coordination, rate limits, cache invalidation, and worker leases
- S3-compatible object storage for evidence, screenshots, and generated artifacts

## Backup Cadence

### PostgreSQL

- Enable automated daily snapshots on the database host.
- Take an additional manual snapshot before every production schema cutover.
- Keep at least one weekly retained snapshot outside the normal daily retention window.

### Redis

- Persist Redis with `appendonly yes` and periodic `RDB` snapshots.
- Copy `dump.rdb` and `appendonly.aof` off-host on a daily schedule.
- Redis is not the source of truth, but losing it should not destroy business data.

### Object Storage

- Enable bucket versioning where possible.
- Run a nightly bucket sync or snapshot export.
- Retain evidence/object metadata from Postgres together with the bucket backup window.

## Restore Drill

### PostgreSQL Restore

1. Restore the latest clean snapshot into an isolated database instance.
2. Point a staging copy of the app at the restored database.
3. Run:

```bash
docker compose run --rm backend npx prisma migrate deploy
docker compose exec -T backend node -e "require('http').get('http://127.0.0.1:4000/health/ready',r=>{process.exit(r.statusCode===200?0:1)})"
```

4. Validate:
   - admin login
   - manufacturer login
   - public verify
   - incident list
   - printer status view

### Redis Restore

1. Restore Redis from the latest AOF/RDB backup.
2. Restart only the Redis container or instance.
3. Restart backend and worker after Redis is healthy.
4. Validate:
   - `/health/ready`
   - dashboard refresh
   - notification refresh
   - worker resumes queued jobs without duplicate processing

### Object Storage Restore

1. Restore the bucket snapshot to a new bucket or isolated namespace.
2. Point `OBJECT_STORAGE_BUCKET` to the restored bucket in staging.
3. Validate:
   - incident evidence retrieval
   - support report screenshot retrieval
   - compliance/export artifact retrieval

## Rollback Drill

1. Stop frontend, backend, and worker.
2. Restore Postgres snapshot if the release changed schema or state incorrectly.
3. Restore Redis only if coordination state is corrupted.
4. Re-point object storage if artifact writes were damaged.
5. Checkout the prior known-good git SHA.
6. Rebuild and redeploy containers.
7. Run release smoke checks again.

## Recovery Objectives

- Database restore must be rehearsed until it can be completed inside the agreed outage window.
- Redis restore should be treated as coordination recovery, not source-of-truth recovery.
- Object storage restore must preserve evidence integrity and object hash metadata.

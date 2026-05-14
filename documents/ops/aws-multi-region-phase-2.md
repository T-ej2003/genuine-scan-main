# AWS Multi-Region Setup Phase 2

Last updated: 2026-05-11

## Architecture Summary

MSCQR / Genuine Scan keeps London as the active production region. Mumbai and Cape Town are manually deployable standby app-server regions. Phase 2 is about making those standby servers repeatable to deploy and verify; it is not a traffic automation, DNS, database-replication, or object-storage migration phase.

The tested deployment model remains the existing project convention:

- Git branch: `main`
- Remote app path: `/home/ubuntu/genuine-scan-main`
- Remote user: `ubuntu`
- Deployment playbook: `ops/deploy/deploy.yml`
- Runtime: Docker / Docker Compose
- Edge container: the existing frontend Nginx container from `docker-compose.yml`
- Local operator inventory: `ops/deploy/inventory.ini`

## Phase 2 Includes

- Safe sample inventory groups for `primary`, `mumbai`, `capetown`, `standby`, and `standby_regions`.
- Manual bootstrap playbook for new Mumbai and Cape Town hosts.
- Manual standby deployment through the same known-good `ops/deploy/deploy.yml` flow.
- Manual HTTP health checks by server IP.
- Local helper scripts for deploy and health-check commands.
- Region env examples that use placeholders only and do not contain secrets.

## Phase 2 Excludes

- Automatic failover.
- Route 53 failover routing.
- Public DNS or certbot setup for Mumbai or Cape Town.
- Active-active multi-write database architecture.
- MinIO cleanup, MinIO decommission, or destructive object-storage migration.

## Verified State

The known-good deploy command successfully deployed both standby servers:

- Mumbai
- Cape Town

Both standby servers previously reported commit `bd73ba9`.

Health checks passed on both:

- `/healthz`
- `/api/health/ready`

Docker Compose services were healthy on both:

- `genuine-scan-backend`
- `genuine-scan-frontend`
- `genuine-scan-worker`
- `genuine-scan-redis`
- `genuine-scan-minio`

Redis and MinIO were intentionally untouched.

## Inventory Setup

Copy the committed sample and fill the local-only inventory:

```bash
cp ops/deploy/inventory.example.ini ops/deploy/inventory.ini
```

Replace:

- `YOUR_PRIMARY_SERVER_IP`
- `YOUR_MUMBAI_SERVER_IP`
- `YOUR_CAPETOWN_SERVER_IP`
- SSH private key paths

The real `ops/deploy/inventory.ini` stays ignored by Git.

Required group shape:

```ini
[primary]
primary ansible_host=YOUR_PRIMARY_SERVER_IP ansible_user=ubuntu

[mumbai]
mumbai ansible_host=YOUR_MUMBAI_SERVER_IP ansible_user=ubuntu region_name=mumbai

[capetown]
capetown ansible_host=YOUR_CAPETOWN_SERVER_IP ansible_user=ubuntu region_name=capetown

[standby:children]
mumbai
capetown

[standby_regions:children]
mumbai
capetown
```

`standby` is the preferred operator limit because it matches the known-good deployment runbook. `standby_regions` is kept as a compatibility alias.

## Region Env Setup

Keep real env files local-only or pre-seeded on the server. Do not commit real env files.

Safe examples:

```bash
.env.production.mumbai.example
.env.production.capetown.example
```

The current proven standby deployment command uses the env files already present on the remote app servers. Do not overwrite real `.env` or `backend/.env` files during Phase 2 rough-edge fixes.

## Bootstrap Commands

Bootstrap is only for new or freshly rebuilt standby servers. Skip bootstrap on already-provisioned servers when Docker, Docker Compose, Nginx, UFW, and health checks are already good.

Bootstrap Mumbai:

```bash
ansible-playbook -i ops/deploy/inventory.ini ops/deploy/bootstrap-standby.yml --limit mumbai
```

Bootstrap Cape Town:

```bash
ansible-playbook -i ops/deploy/inventory.ini ops/deploy/bootstrap-standby.yml --limit capetown
```

Bootstrap both standby regions:

```bash
ansible-playbook -i ops/deploy/inventory.ini ops/deploy/bootstrap-standby.yml --limit standby
```

Known bootstrap warning: on existing servers, package managers may report `containerd.io conflicts with containerd`. Do not rerun bootstrap unnecessarily on already-working servers; use deploy and health-check commands instead.

## Deploy Commands

Known-good tested command:

```bash
ansible-playbook -i ops/deploy/inventory.ini ops/deploy/deploy.yml --limit standby
```

Preferred helper command:

```bash
scripts/deploy-standby.sh standby
```

Compatibility helper command:

```bash
scripts/deploy-standby.sh standby_regions
```

Deploy one standby region:

```bash
scripts/deploy-standby.sh mumbai
scripts/deploy-standby.sh capetown
```

The helper now calls `ops/deploy/deploy.yml` directly. That keeps standby deployment aligned with the proven production path: existing app directory, existing git ownership behavior, `git fetch --prune`, `git reset --hard`, npm checks, production guardrails, and `docker compose --profile worker up -d --build` for standalone EC2 hosts that intentionally own the singleton worker.

## Health Check Commands

Preferred helper command:

```bash
scripts/health-check-regions.sh standby
```

Compatibility helper command:

```bash
scripts/health-check-regions.sh standby_regions
```

Check one standby region:

```bash
scripts/health-check-regions.sh mumbai
scripts/health-check-regions.sh capetown
```

Checks use HTTP by server IP:

- `/healthz`
- `/api/health/ready`

They also print the target commit and Docker Compose service state.

## Rollback And Manual Recovery Notes

- Roll back by redeploying a known-good commit or branch through the same playbook with an explicit `-e branch=<branch-or-tag>` override.
- Keep database recovery manual. Do not point a standby service at the primary write database unless incident command has approved the recovery path.
- Keep DNS movement manual and out of Phase 2 automation.
- Do not run certbot or configure public HTTPS for Mumbai or Cape Town in this phase.
- Do not delete, prune, decommission, or clean up MinIO volumes, buckets, data, or containers.
- If Docker Compose fails, inspect `docker compose ps` and `docker compose logs backend worker frontend --tail=120` on the target host.

## Completion Checklist

- [ ] `ops/deploy/inventory.ini` has real local-only values.
- [ ] Bootstrap was run only for new or rebuilt standby servers.
- [ ] Mumbai deploy succeeds through `ops/deploy/deploy.yml --limit mumbai` or `scripts/deploy-standby.sh mumbai`.
- [ ] Cape Town deploy succeeds through `ops/deploy/deploy.yml --limit capetown` or `scripts/deploy-standby.sh capetown`.
- [ ] `scripts/deploy-standby.sh standby` succeeds for both standby regions.
- [ ] `scripts/health-check-regions.sh standby` succeeds for both standby regions.
- [ ] Redis and MinIO remain untouched unless a separately approved task says otherwise.
- [ ] No automatic failover, Route 53 failover, standby certbot, active-active DB writes, destructive Docker cleanup, or MinIO cleanup was introduced.

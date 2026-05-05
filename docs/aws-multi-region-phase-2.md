# AWS Multi-Region Setup Phase 2

Last updated: 2026-05-05

## Architecture summary

MSCQR / Genuine Scan keeps the current primary production region as the active serving region. Mumbai and Cape Town are manually deployable standby regions. Operators can bootstrap, deploy, and health-check each standby region with Ansible, but traffic movement remains a manual business and incident-command decision.

Phase 2 uses the existing repository deployment model:

- Git branch: `main`
- Remote app path: `/home/ubuntu/genuine-scan-main`
- Runtime: Docker / Docker Compose
- Edge container: the existing frontend Nginx container from `docker-compose.yml`
- Host OS: Ubuntu
- Local operator inventory: `ops/deploy/inventory.ini`

## Phase 2 includes

- Safe sample inventory groups for `primary`, `mumbai`, `capetown`, and `standby_regions`.
- Manual bootstrap for Mumbai and Cape Town hosts.
- Manual app deployment to Mumbai and Cape Town from `main`.
- Region env-file handoff for standby secrets and per-region URLs.
- Manual HTTP health checks by server IP.
- Documentation and local helper scripts for repeatable operator commands.

## Phase 2 excludes

- Automatic failover.
- Route 53 failover routing.
- Public DNS or certbot setup for Mumbai or Cape Town.
- Active-active multi-write database architecture.
- MinIO cleanup, MinIO decommission, or destructive object-storage migration.

## Inventory setup

Copy the committed sample and fill the local-only inventory:

```bash
cp ops/deploy/inventory.example.ini ops/deploy/inventory.ini
```

Replace:

- `YOUR_PRIMARY_SERVER_IP`
- `YOUR_MUMBAI_SERVER_IP`
- `YOUR_CAPETOWN_SERVER_IP`
- SSH private key paths

The important inventory groups are:

- `primary`
- `mumbai`
- `capetown`
- `standby_regions`, with `mumbai` and `capetown` as children

The real `ops/deploy/inventory.ini` stays ignored by Git.

## Region env setup

Create ignored local env files on the operator workstation or pre-seed them on each standby server. The recommended operator-workstation path is:

```bash
cp .env.production.mumbai.example .env.production.mumbai
cp .env.production.capetown.example .env.production.capetown
```

Fill only the files you are deploying. Do not commit real env files.

The standby deploy playbook uses:

- `.env.production.mumbai` for the Mumbai group.
- `.env.production.capetown` for the Cape Town group.
- `backend/.env.production.<region>` if you intentionally keep a backend-only env file.

When a local ignored env file exists on the operator workstation, the playbook uploads it to the target server with mode `0600`. If no local env file exists, the playbook uses an already-present remote env file at `/home/ubuntu/genuine-scan-main/.env.production.<region>`.

If `backend/.env.production.<region>` is not present, the region root env is copied to `backend/.env` as well. This matches the current Docker Compose requirement that backend runtime values exist at `backend/.env`.

## Bootstrap commands

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
ansible-playbook -i ops/deploy/inventory.ini ops/deploy/bootstrap-standby.yml --limit standby_regions
```

Bootstrap installs Git, curl, UFW, Nginx, Docker, the Docker Compose plugin, and `python3-pip`. It starts Docker, adds the `ubuntu` user to the Docker group, allows ports `22/tcp` and `80/tcp`, and leaves host Nginx stopped so the existing Docker frontend can bind port 80.

## Deploy commands

Deploy Mumbai:

```bash
ansible-playbook -i ops/deploy/inventory.ini ops/deploy/deploy-standby.yml --limit mumbai
```

Deploy Cape Town:

```bash
ansible-playbook -i ops/deploy/inventory.ini ops/deploy/deploy-standby.yml --limit capetown
```

Deploy both standby regions:

```bash
ansible-playbook -i ops/deploy/inventory.ini ops/deploy/deploy-standby.yml --limit standby_regions
```

Or use the helper:

```bash
scripts/deploy-standby.sh mumbai
scripts/deploy-standby.sh capetown
scripts/deploy-standby.sh standby_regions
```

The deploy playbook clones or updates the repo, checks out `main`, refuses to deploy over uncommitted remote changes, applies a region env file when present, runs `docker compose pull`, and then runs `docker compose up -d --build`. It restarts host Nginx only when a project-specific host Nginx config exists.

## Health check commands

Check Mumbai:

```bash
ansible-playbook -i ops/deploy/inventory.ini ops/deploy/health-check-standby.yml --limit mumbai
```

Check Cape Town:

```bash
ansible-playbook -i ops/deploy/inventory.ini ops/deploy/health-check-standby.yml --limit capetown
```

Check both standby regions:

```bash
ansible-playbook -i ops/deploy/inventory.ini ops/deploy/health-check-standby.yml --limit standby_regions
```

Or use the helper:

```bash
scripts/health-check-regions.sh mumbai
scripts/health-check-regions.sh capetown
scripts/health-check-regions.sh standby_regions
```

Checks use HTTP by server IP:

- `/healthz`
- `/api/health/ready`

## Rollback and manual recovery notes

- Roll back by redeploying a known-good commit or branch through the same playbook with an explicit `-e branch=<branch-or-tag>` override.
- Keep database recovery manual. Do not point a standby service at the primary write database unless incident command has approved the recovery path.
- Keep DNS movement manual and out of this Phase 2 automation.
- Do not run certbot or configure public HTTPS for Mumbai or Cape Town in this phase.
- Do not delete MinIO volumes, buckets, data, or containers as part of standby deployment.
- If Docker Compose fails, inspect `docker compose ps` and `docker compose logs backend worker frontend --tail=120` on the target host.

## Completion checklist

- [ ] `ops/deploy/inventory.ini` has real local-only values.
- [ ] `ansible-playbook ... bootstrap-standby.yml --limit mumbai` succeeds.
- [ ] `ansible-playbook ... bootstrap-standby.yml --limit capetown` succeeds.
- [ ] Mumbai has a real `.env.production.mumbai`.
- [ ] Cape Town has a real `.env.production.capetown`.
- [ ] `ansible-playbook ... deploy-standby.yml --limit mumbai` succeeds.
- [ ] `ansible-playbook ... deploy-standby.yml --limit capetown` succeeds.
- [ ] `ansible-playbook ... health-check-standby.yml --limit standby_regions` succeeds.
- [ ] No automatic failover, Route 53 failover, standby certbot, active-active DB writes, or MinIO cleanup was introduced.

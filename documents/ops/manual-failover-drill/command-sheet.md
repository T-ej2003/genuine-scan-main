# Manual Failover Drill Command Sheet

Last updated: 2026-05-11

## Scope

These commands support Phase 3 manual failover drills. They do not automate DNS, do not implement automatic failover, do not create active-active writes, and do not clean up MinIO.

Run from the operator workstation:

```bash
cd /Users/abhiramteja/Downloads/genuine-scan-main
```

## Local Prep

```bash
git status --short --branch
git pull origin main
npm run check:documents
```

Confirm local inventory exists:

```bash
test -f ops/deploy/inventory.ini
```

List standby inventory targets:

```bash
ansible-inventory -i ops/deploy/inventory.ini --graph standby
ansible-inventory -i ops/deploy/inventory.ini --graph standby_regions
```

## Standby Deploy

Preferred both-region deploy:

```bash
scripts/deploy-standby.sh standby
```

Compatibility alias:

```bash
scripts/deploy-standby.sh standby_regions
```

Single-region deploy:

```bash
scripts/deploy-standby.sh mumbai
scripts/deploy-standby.sh capetown
```

Known-good direct Ansible command:

```bash
ansible-playbook -i ops/deploy/inventory.ini ops/deploy/deploy.yml --limit standby
```

## Health Checks

Both standby regions:

```bash
scripts/health-check-regions.sh standby
```

Single region:

```bash
scripts/health-check-regions.sh mumbai
scripts/health-check-regions.sh capetown
```

Direct endpoint checks by inventory target:

```bash
ansible -i ops/deploy/inventory.ini standby -m command -a "curl -fsS http://127.0.0.1/healthz"
ansible -i ops/deploy/inventory.ini standby -m command -a "curl -fsS http://127.0.0.1/api/health/ready"
```

## Service Evidence

Commit and Docker Compose status:

```bash
ansible -i ops/deploy/inventory.ini standby -m command -a "git -C /home/ubuntu/genuine-scan-main rev-parse --short HEAD"
ansible -i ops/deploy/inventory.ini standby -m command -a "docker compose -f /home/ubuntu/genuine-scan-main/docker-compose.yml --project-directory /home/ubuntu/genuine-scan-main ps"
```

Recent logs:

```bash
ansible -i ops/deploy/inventory.ini standby -m command -a "docker compose --project-directory /home/ubuntu/genuine-scan-main logs backend --tail=120"
ansible -i ops/deploy/inventory.ini standby -m command -a "docker compose --project-directory /home/ubuntu/genuine-scan-main logs frontend --tail=120"
ansible -i ops/deploy/inventory.ini standby -m command -a "docker compose --project-directory /home/ubuntu/genuine-scan-main logs worker --tail=120"
```

## Database Drill Evidence

Use the approved database console or approved CLI profile for real restore work. Do not paste credentials into commands or docs.

Record:

- Source database identifier.
- Backup/snapshot identifier.
- Restore target region.
- Restore start and end time.
- Connection test result from the selected standby app server.

## Object Storage Drill Evidence

Use approved read-only verification first. Do not delete, migrate, or decommission MinIO during this drill.

Record:

- Bucket or endpoint identifier.
- Credential source, not the credential value.
- Read verification result.
- Write verification result only after database recovery plan is approved.

## Manual DNS Note

DNS changes are documentation-only for Phase 3. Do not run DNS automation. Do not add Route 53 failover routing. Only manually change DNS if incident command explicitly approves it during a real recovery or separately approved drill.

Record any approved manual DNS change in the RTO/RPO worksheet.

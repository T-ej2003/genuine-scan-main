# MSCQR Multi-Region Deployment Runbook

Last reviewed: 2026-04-28  
Production domain: `https://www.mscqr.com`  
Production baseline after SEO polish: `9148e06`

## Deployment Model

MSCQR production currently uses London as the active production region, with Mumbai and Cape Town as warm standby targets.

Documentation-only changes under `documents/**`, `docs/**`, Markdown/MDX, or DOCX files no longer trigger the deployment audit path. Validation workflows still run where configured; production server deploys remain on the approved deployment flow.

## GitHub Release Orchestration

Normal production deployment starts from GitHub Actions -> `Release Train`.

`Release Train` resolves the target main-branch SHA, dispatches or waits for:

- `quality-gate.yml`
- `secret-scan.yml`
- `deployment-audit.yml`

After all three pass for the exact target SHA, it dispatches `release-gate.yml` for that same SHA. `Release Train` never deploys directly.

`Release Gate` is the final protected production deploy gate only. It keeps the existing `production` GitHub Environment approval and the Ansible deployment job. If `Release Gate` reports missing required gates, stop and run `Release Train` for the target SHA. Direct `Release Gate` use with `expert_override=true` is an emergency expert-only path after human verification.

Operator commands:

```bash
gh workflow run release-train.yml --ref main -f git_ref=main
gh workflow run release-train.yml --ref main -f git_ref=main -f target_sha=<main_sha>
```

Expert-only direct gate:

```bash
gh workflow run release-gate.yml --ref <main_sha> -f git_ref=main -f target_sha=<main_sha> -f expert_override=true
```

DR automation work should happen on `aws-dr-finish` or an approved feature branch, not directly on `main`.

Deploy sequence:

1. Deploy London first.
2. Verify London public health and `/verify` render behavior.
3. Deploy standby only after London is clean.
4. Confirm all regions are on the same commit and Docker services are healthy.

The real Ansible inventory is intentionally local-only:

```text
ops/deploy/inventory.ini
```

It must remain ignored by Git. The committed safe sample is:

```text
ops/deploy/inventory.example.ini
```

Do not commit private key contents, real secrets, or local-only operator inventory changes.

## Runtime Baseline

All deployment targets should use:

```text
Node.js v24 LTS
npm 11.x
```

Older Node.js runtimes can fail TypeScript/build steps with modern syntax errors.

## Local Pre-Deploy Checks

Run these before deployment:

```bash
npm run verify:seo
npm run typecheck
npm run build
npm run verify:guardrails
npm run verify:ci:frontend
npm run verify:release
```

Expected release-test warnings can include fallback/security test logs around unavailable optional tables or ownership fallback behavior. The command result is what matters: the final exit code must be `0`.

## Deploy London

```bash
ansible-playbook -i ops/deploy/inventory.ini ops/deploy/deploy.yml --limit london
```

Then check London:

```bash
ansible -i ops/deploy/inventory.ini london -m shell -a 'cd /home/ubuntu/genuine-scan-main && docker compose ps'
```

Run public checks:

```bash
curl -I https://www.mscqr.com/
curl -I https://www.mscqr.com/platform
curl -I https://www.mscqr.com/verify
curl -I https://www.mscqr.com/robots.txt
curl -I https://www.mscqr.com/sitemap.xml
curl -s -H "Cache-Control: no-cache" "https://www.mscqr.com/robots.txt?robots_check=$(date +%s)" | grep -n "verify"
npm run smoke:verify-browser
```

Expected robots lines:

```text
Allow: /verify
Allow: /verify/
Disallow: /verify-email
```

## Deploy Standby

Deploy standby only after London is healthy:

```bash
ansible-playbook -i ops/deploy/inventory.ini ops/deploy/deploy.yml --limit standby
```

The Phase 2 helper is a safe wrapper around the same known-good deploy playbook:

```bash
scripts/deploy-standby.sh standby
scripts/health-check-regions.sh standby
```

`standby_regions` is also accepted when the inventory defines that alias:

```bash
scripts/deploy-standby.sh standby_regions
scripts/health-check-regions.sh standby_regions
```

Bootstrap is only for new or rebuilt standby servers. Do not rerun bootstrap unnecessarily on already-provisioned Mumbai or Cape Town servers; existing hosts can hit the package conflict `containerd.io conflicts with containerd`. If Docker Compose services are healthy and `/healthz` plus `/api/health/ready` pass, use deploy and health-check commands instead.

Verified Phase 2 state: Mumbai and Cape Town previously deployed to commit `bd73ba9`, health checks passed, and Redis plus MinIO were intentionally untouched.

For AWS Multi-Region Setup Phase 2 standby-only operations, use the commands documented in:

```text
documents/ops/aws-multi-region-phase-2.md
```

Confirm all regions:

```bash
ansible -i ops/deploy/inventory.ini mscqr_servers -m shell -a 'cd /home/ubuntu/genuine-scan-main && git rev-parse --short HEAD && docker compose ps'
```

Confirm standby robots from repo files:

```bash
ansible -i ops/deploy/inventory.ini standby -m shell -a 'cd /home/ubuntu/genuine-scan-main && grep -n "verify" public/robots.txt'
```

## Post-Deploy Operator Checklist

- Confirm London, Mumbai, and Cape Town run the intended commit.
- Confirm backend and frontend containers are healthy where expected.
- Confirm `https://www.mscqr.com/verify` visibly renders while logged out.
- Confirm `https://www.mscqr.com/verify/` canonicalizes to `/verify`.
- Confirm `https://www.mscqr.com/robots.txt` loads and explicitly allows `/verify`.
- Confirm `https://www.mscqr.com/sitemap.xml` loads and excludes private/result URLs.
- Run URL Inspection in Search Console for `/verify` after public SEO changes.
- Inspect one sample `/verify/<code>` URL and confirm it remains excluded by `noindex`.

## AWS Multi-Region DR Docs

- [AWS DR automation framework](aws-dr-automation.md)
- [Phase 3 manual failover readiness](aws-multi-region-phase-3.md)
- [Phase 4 controlled manual DNS cutover](aws-multi-region-phase-4.md)
- [Phase 5 database recovery strategy](aws-multi-region-phase-5.md)
- [Phase C MinIO decommission / S3 proof](aws-multi-region-phase-6.md)
- [Final multi-region disaster recovery runbook](aws-multi-region-disaster-recovery-runbook.md)

## Safety Boundaries

Deployment work must not change:

- Auth logic or permissions
- QR verification business logic
- API contracts
- Database schema
- Object-storage configuration or IAM mode
- Production security gates
- Dashboard/private route protection
- Robots/noindex/sitemap policy unless the task is explicitly an indexing fix

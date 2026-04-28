# MSCQR Multi-Region Deployment Runbook

Last reviewed: 2026-04-28  
Production domain: `https://www.mscqr.com`  
Production baseline after SEO polish: `9148e06`

## Deployment Model

MSCQR production currently uses London as the active production region, with Mumbai and Cape Town as warm standby targets.

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
Node.js v20.20.2
npm 10.8.2
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

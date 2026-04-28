# MSCQR Paid Services Inventory

This inventory separates production requirements from optional integrations and labels each one as:

- `Subscription / vendor cost`
- `Infra cost but self-hostable`
- `Free but operationally required to configure`

## Required for production

| Item | Classification | Why it matters | Repo evidence |
| --- | --- | --- | --- |
| Domain and DNS for `mscqr.com` / `www.mscqr.com` | `Subscription / vendor cost` | Production deployment docs assume ownership of the MSCQR domain and DNS records for public access and TLS cutover. | `documents/AWS_EC2_DEPLOY_MSCQR.md`, `README.md` |
| Frontend, backend, and worker hosting/compute | `Subscription / vendor cost` | MSCQR ships as multiple runtime services and production docs assume cloud compute for the app, API, and worker processes. | `docker-compose.yml`, `documents/AWS_EC2_DEPLOY_MSCQR.md` |
| PostgreSQL database | `Infra cost but self-hostable` | Backend startup refuses to run without `DATABASE_URL`. Managed RDS/Postgres costs money, but self-hosting is possible. | `backend/src/index.ts`, `backend/.env.example`, `documents/deployment-audit/ENTERPRISE_CHECKLIST.md` |
| Redis coordination | `Infra cost but self-hostable` | Production startup explicitly requires Redis for coordination and worker behavior. | `backend/src/index.ts`, `backend/src/services/redisService.ts`, `docker-compose.yml` |
| S3-compatible object storage | `Infra cost but self-hostable` | Production startup explicitly requires object storage for evidence, screenshots, and generated artifacts. | `backend/src/index.ts`, `backend/src/services/objectStorageService.ts`, `documents/BACKUP_RESTORE_DR_RUNBOOK.md` |
| SMTP/email delivery | `Infra cost but self-hostable` | Invites, password resets, and incident/customer emails depend on SMTP transport being configured. | `backend/src/index.ts`, `backend/src/services/auth/authEmailService.ts`, `backend/src/services/incidentEmailService.ts` |
| Let's Encrypt TLS | `Free but operationally required to configure` | Production HTTPS is expected, but the documented certificate flow uses Let's Encrypt rather than a paid certificate vendor. | `documents/AWS_EC2_DEPLOY_MSCQR.md` |

## Optional / conditional

| Item | Classification | When to pay for it | Repo evidence |
| --- | --- | --- | --- |
| Sentry frontend/backend monitoring | `Subscription / vendor cost` | Optional hosted error tracking and traces if you want centralized monitoring. | `.env.example`, `backend/.env.example`, `backend/src/observability/sentry.ts` |
| Google OAuth for customer verify flows | `Free but operationally required to configure` | Google sign-in needs a configured Google app, but there is no direct MSCQR subscription charge. | `backend/.env.example`, `backend/src/services/customerVerifyOAuthService.ts` |
| CAPTCHA / reCAPTCHA for incident or abuse protection | `Free but operationally required to configure` | Needed only if you enable CAPTCHA-backed abuse protection on public flows. | `backend/.env.example`, `backend/src/services/captchaService.ts` |
| SIEM webhook sink | `Subscription / vendor cost` | Optional if you want MSCQR events forwarded into a commercial SIEM or managed security stack. Self-hosting is possible, but most teams pay a vendor here. | `backend/.env.example`, `backend/src/services/siemOutboxService.ts` |
| SOAR platform / auto-containment destination | `Subscription / vendor cost` | Optional if you want automated response workflows tied into an external security operations platform. | `backend/.env.example`, `backend/src/services/soarService.ts` |
| Managed KMS / managed QR signer | `Subscription / vendor cost` | Optional if you use a managed key/signing service instead of repo-managed env keys. | `backend/.env.example`, `backend/src/services/qrTokenService.ts`, `documents/SECURITY_KEY_ROTATION_RUNBOOK.md` |
| Apple Developer account and notarization for macOS connector releases | `Subscription / vendor cost` | Required only if you want officially signed/notarized macOS connector packages for manufacturers. | `backend/.env.example` |
| Windows code-signing certificate / signing pipeline | `Subscription / vendor cost` | Required only if you want signed Windows connector installers instead of unsigned distributions. | `documents/backend/local-print-agent/install/windows/WINDOWS_SIGNED_RELEASE.md`, `backend/.env.example` |

## Notes

- Redis, PostgreSQL, object storage, and SMTP are production dependencies even when they are self-hosted.
- Google OAuth and reCAPTCHA are usually low-cost or free at small scale, but they still require external account setup and operational ownership.
- Managed QR signing is not mandatory. MSCQR can run with locally managed signing keys, but the codebase reserves a boundary for future managed signing.

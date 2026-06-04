# MSCQR SMTP Readiness Runbook

## Scope

This runbook covers production-safe SMTP readiness for request-access intake, public support acknowledgements, support replies, and incident-update notifications.

## Required Environment Variables

- `SMTP_SMOKE_ENABLED=true`
- `SMTP_SMOKE_TO=<staging-owned inbox>`
- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_USER`
- `SMTP_PASS`
- `SMTP_FROM`
- Optional: `REQUEST_ACCESS_NOTIFY_EMAIL`, `SUPPORT_NOTIFY_EMAIL`

Do not commit SMTP credentials or staging inbox secrets.

## Staging Smoke Command

```bash
npm run smoke:smtp
```

If `SMTP_SMOKE_ENABLED` or `SMTP_SMOKE_TO` is missing, the command skips and prints a clear reason. That skip is acceptable for normal PR CI, but not enough for launch readiness.

## Expected Success Output

- `ok: true`
- `skipped: false`
- four result blocks:
  - `requestAccess`
  - `supportAck`
  - `supportReply`
  - `incidentUpdate`
- each result should show `sent: true` or `delivered: true`
- output must mask email addresses and must not print `SMTP_PASS`

## Safe Failure Modes

- Public request-access/support endpoints persist the DB record before email delivery.
- If SMTP is missing, disabled, dry-run, or rejected, the stored record keeps delivery status/error code.
- Public users see customer-safe confirmation or fallback copy, never raw SMTP/provider errors.
- Operators can inspect delivery state in the platform support console.

## DNS Checklist

- SPF includes the SMTP provider for the sender domain.
- DKIM is enabled and passing for `SMTP_FROM` domain.
- DMARC policy exists and aligns with the intended sender domain.
- `SMTP_FROM` domain is aligned with `SMTP_USER` or explicitly authorized by the SMTP provider.
- Bounce handling is configured for the sender domain.
- Reply-to/support/admin inboxes are owned and monitored by MSCQR.

## Inbox Verification Checklist

- Send the opt-in SMTP smoke to a staging-owned inbox.
- Confirm all four smoke emails arrive.
- Confirm subject lines include MSCQR context and no secrets.
- Confirm replies route to the intended support/admin inbox.
- Confirm spam/junk placement is acceptable before launch.

## Credential Rotation

- Rotate `SMTP_PASS` in the provider console.
- Update the deployment secret store only.
- Run `npm run smoke:smtp` with staging smoke env.
- Do not rotate by editing code or committing `.env`.

## Disable Sending Safely

- Set `EMAIL_DISABLED=true` or remove SMTP credentials for environments where sending is not allowed.
- Confirm intake records still persist and show disabled/skipped delivery status.
- Re-enable only after a successful smoke.

## No-Secrets Policy

- Never commit SMTP passwords, API keys, provider tokens, or production inbox credentials.
- Never print full SMTP headers or passwords in CI logs.
- Use JSON capture only in test/E2E mode.

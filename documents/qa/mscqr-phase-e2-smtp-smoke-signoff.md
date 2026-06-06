# MSCQR Phase E2 SMTP Smoke Sign-off

Date: 2026-06-06
Status: Yellow until staging-owned SMTP credentials and inbox proof are attached.

## Current code status

`backend/scripts/smoke-smtp-phase-e.js` now:

- Skips by default when SMTP smoke is not explicitly enabled.
- Fails closed when `SMTP_SMOKE_REQUIRED=true` and required config is missing.
- Sends request-access admin notification.
- Sends request-access acknowledgement.
- Sends public support admin notification.
- Sends public support acknowledgement.
- Sends support reply.
- Sends incident update notification.
- Reports provider acceptance counts without printing SMTP credentials.

## Required staging smoke environment

Use staging-owned SMTP credentials and a staging inbox. Do not commit credentials.

```bash
SMTP_SMOKE_ENABLED=true
SMTP_SMOKE_REQUIRED=true
SMTP_SMOKE_TO=<staging inbox>
SMTP_HOST=<redacted>
SMTP_PORT=<redacted>
SMTP_USER=<redacted>
SMTP_PASS=<redacted>
SMTP_FROM=<verified sender>
REQUEST_ACCESS_NOTIFY_EMAIL=<staging admin inbox>
SUPPORT_NOTIFY_EMAIL=<staging support inbox>
```

Recommended command:

```bash
npm run smoke:smtp
```

## Inbox proof

If an inbox API is available, attach provider/inbox evidence for the generated `smokeId` showing accepted or delivered messages for:

- Request-access admin notification.
- Request-access acknowledgement.
- Public support admin notification.
- Public support acknowledgement.
- Support reply.
- Incident update smoke.

If no inbox API is available, manually verify the staging inbox and attach:

- Smoke ID.
- Masked recipient.
- Timestamp.
- Message subjects.
- Provider accepted counts from script output.

## Launch readiness

Current readiness is Yellow because no staging-owned SMTP credentials or inbox API proof were available locally. The script behavior is now fail-closed when a required launch gate asks for proof.

CTO recommendation: promote this to a staging-only required gate with a dedicated test inbox and retention policy; do not run it against production customer mailboxes.

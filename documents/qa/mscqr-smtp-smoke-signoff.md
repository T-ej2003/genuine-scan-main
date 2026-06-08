# MSCQR SMTP Smoke Sign-off

Date: 2026-06-08
Status: Yellow until staging-owned SMTP credentials and inbox proof are attached.

## Required Mode

`SMTP_SMOKE_REQUIRED=true` fails closed when SMTP smoke is disabled or required SMTP configuration is missing.

Use staging-owned SMTP credentials and staging-owned inboxes only. Do not use production personal or customer inboxes.

## SMTP Command

```bash
set +x
SMTP_SMOKE_ENABLED=true \
SMTP_SMOKE_REQUIRED=true \
SMTP_SMOKE_TO="$STAGING_SMOKE_INBOX" \
SMTP_HOST="$STAGING_SMTP_HOST" \
SMTP_PORT="$STAGING_SMTP_PORT" \
SMTP_USER="$STAGING_SMTP_USER" \
SMTP_PASS="$STAGING_SMTP_PASS" \
SMTP_FROM="$STAGING_SMTP_FROM" \
REQUEST_ACCESS_NOTIFY_EMAIL="$STAGING_REQUEST_ACCESS_INBOX" \
SUPPORT_NOTIFY_EMAIL="$STAGING_SUPPORT_INBOX" \
npm run smoke:smtp
```

Safe skip check:

```bash
npm run smoke:smtp
```

Required fail-closed check:

```bash
SMTP_SMOKE_REQUIRED=true npm run smoke:smtp
```

## Covered Messages

The smoke sends production-safe test messages through existing mail services:

- request-access admin notification
- request-access acknowledgement
- public support admin notification
- public support acknowledgement
- support reply
- incident update smoke

The script prints JSON evidence with:

- `smokeId`
- masked recipient
- SMTP diagnostics without passwords
- per-message `providerMessageId`
- provider response code
- masked accepted/rejected recipients
- subject
- reference
- timestamp
- safe diagnostic/error code

## Inbox Proof

Attach one of:

- provider API evidence showing accepted/delivered messages for the generated `smokeId`
- manual inbox screenshot/log with message subjects, timestamp, masked recipient, and smoke ID

Required subject set:

- `MSCQR access request <smokeId>-RA: MSCQR staging smoke`
- `MSCQR access request received (<smokeId>-RA)`
- `MSCQR support issue <smokeId>-SUP: SMTP smoke support admin notification`
- `MSCQR support request received (<smokeId>-SUP)`
- `Re: SMTP smoke support reply [<smokeId>-SUP]`
- `MSCQR incident update smoke <smokeId>`

## Current Sign-off

- Safe skip mode: Green.
- Required fail-closed mode: Green.
- Provider acceptance metadata: Green in tooling.
- Real provider/inbox proof: Yellow, awaiting staging credentials and inbox verification.

CTO recommendation: use a dedicated retained launch-smoke mailbox and provider API access for repeatable evidence. Manual screenshots are acceptable for launch, but provider API verification is more scalable for future release gates.

## Real deployed SMTP provider smoke evidence

Status: YELLOW overall; Green only for provider acceptance.

Environment: production EC2 deployed backend container  
Checked at UTC: 2026-06-08T14:25:42.754Z  
Evidence file: `documents/qa/evidence/smtp-smoke-evidence.txt`

Provider result:
- SMTP auth verification passed.
- Required SMTP smoke completed with `ok: true`.
- Smoke ID: `SMTP-20260608T142542Z-9bd03f`.
- Request-access admin notification accepted by provider.
- Request-access acknowledgement accepted by provider.
- Public support admin notification accepted by provider.
- Public support acknowledgement accepted by provider.
- Public support reply accepted by provider.
- Incident update smoke accepted by provider.
- Rejected recipient count: 0 for all templates.
- Fallback used: false.

Inbox proof:
- Recorded recipient was a masked Gmail inbox.
- Gmail receipt proves arrival to that mailbox only.
- This does not satisfy the staging-owned inbox requirement in this sign-off.

Security note:
- SMTP mailbox password was rotated after accidental exposure during diagnostics.
- Evidence is redacted and excludes SMTP password, full recipient, cookies, tokens, and secrets.

Status: Green for deployed production SMTP provider acceptance. Yellow for launch SMTP sign-off until staging-owned inbox proof is attached.

## Real deployed SMTP smoke and inbox evidence

Status: YELLOW

Environment: production EC2 deployed backend container  
Checked at UTC: 2026-06-08T14:25:42.754Z  
Evidence file: `documents/qa/evidence/smtp-smoke-evidence.txt`

SMTP result:
- SMTP auth verification passed.
- Required SMTP smoke completed with `ok: true`.
- Smoke ID: `SMTP-20260608T142542Z-9bd03f`.
- Request-access admin notification accepted by provider.
- Request-access acknowledgement accepted by provider.
- Public support admin notification accepted by provider.
- Public support acknowledgement accepted by provider.
- Public support reply accepted by provider.
- Incident update smoke accepted by provider.
- Rejected recipient count: 0 for all templates.
- Fallback used: false.

Inbox observation:
- Gmail inbox shows the request-access admin notification.
- Gmail inbox shows the request-access acknowledgement.
- Gmail inbox shows the support admin notification.
- Gmail inbox shows the support acknowledgement.
- Gmail inbox shows the support reply/update.
- Gmail inbox shows the incident update smoke.
- Gmail subjects include `SMTP-20260608T142542Z-9bd03f`.
- This Gmail observation is not staging-owned inbox proof and cannot be used to mark final SMTP launch readiness Green.

Security note:
- SMTP mailbox password was rotated after accidental exposure during diagnostics.
- Evidence is redacted and excludes SMTP password, full recipient, cookies, tokens, and secrets.

Status: Green for deployed production SMTP provider acceptance. Yellow for final SMTP launch readiness because staging-owned inbox proof is still missing.

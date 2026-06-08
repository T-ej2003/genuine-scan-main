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

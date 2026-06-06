# MSCQR SMTP Smoke Sign-off

Date: 2026-06-06
Status: Yellow until staging SMTP credentials and inbox proof are attached.

## Required Mode

`SMTP_SMOKE_REQUIRED=true` fails closed when SMTP smoke is disabled or required SMTP configuration is missing.

Use staging-owned SMTP credentials and staging inboxes only. Do not use production personal or customer inboxes.

```bash
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

## Covered Messages

The smoke sends production-safe test messages through existing mail services:

- request-access admin notification
- request-access acknowledgement
- public support admin notification
- public support acknowledgement
- support reply
- incident update smoke

The script prints masked recipient/provider acceptance metadata only. It must not print SMTP passwords or full credential values.

## Inbox Proof

Attach one of:

- provider API evidence showing accepted/delivered messages for the generated `smokeId`
- manual inbox screenshot/log with message subjects, timestamp, masked recipient, and smoke ID

Required subject set:

- `MSCQR access request <smokeId>-RA`
- `MSCQR access request received (<smokeId>-RA)`
- `MSCQR support issue <smokeId>-SUP`
- `MSCQR support request received (<smokeId>-SUP)`
- support reply subject
- incident update smoke subject

## Current Sign-off

- Safe skip mode: Green.
- Required fail-closed mode: Green.
- Real provider/inbox proof: Yellow, awaiting staging credentials.

CTO recommendation: wire this into staging release-candidate evidence using a dedicated inbox with retention and no customer data.

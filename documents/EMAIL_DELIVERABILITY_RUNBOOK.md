# MSCQR Production Email Deliverability Runbook

MSCQR treats SMTP provider acceptance and inbox placement as different checks.

When the backend reports `emailSent=true`, it means the SMTP provider accepted the intended recipient for that message. It does not prove Gmail, Outlook, or another mailbox placed the message in the inbox.

## Production SMTP Profile

Recommended Namecheap Private Email configuration:

```text
SMTP_HOST=mail.privateemail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_REQUIRE_TLS=true
SMTP_USER=administration@mscqr.com
SMTP_PASS=[REDACTED]
SMTP_FROM=administration@mscqr.com
AUTH_EMAIL_FROM=administration@mscqr.com
EMAIL_DOMAIN=mscqr.com
```

Port `465` is supported when the provider requires implicit TLS:

```text
SMTP_HOST=mail.privateemail.com
SMTP_PORT=465
SMTP_SECURE=true
SMTP_REQUIRE_TLS=true
```

`SMTP_USER` must be the full mailbox. `SMTP_FROM` must be a sender authorized for `mscqr.com`. Never commit credentials.

## Invite Sender Policy

Invite and auth onboarding emails must use the authenticated MSCQR sender as the actual SMTP `From`.

```text
Actual SMTP auth user: administration@mscqr.com
Actual SMTP From: MSCQR <administration@mscqr.com>
Reply-To: logged-in inviting admin email when valid
```

The configured sender fallback order is:

```text
SMTP_FROM -> AUTH_EMAIL_FROM -> EMAIL_FROM -> MAIL_FROM -> SMTP_USER
```

Do not use arbitrary logged-in user mailboxes as SMTP `From`. Logged-in actor email belongs in `Reply-To` only after validation. If MSCQR ever needs true per-user `From`, build a future per-user SMTP/OAuth mailbox connection flow with explicit consent, token storage, revocation, and audit controls.

## Traceable SMTP Diagnostic

Run a traceable diagnostic from the production server or container:

```bash
SMTP_TEST_TO="$CONTROLLED_SMTP_TEST_INBOX" npm --prefix backend run check:smtp
```

Run with a manual trace ID:

```bash
SMTP_TEST_TO="$CONTROLLED_SMTP_TEST_INBOX" SMTP_TEST_TRACE_ID=manual-YYYYMMDD-HHMM npm --prefix backend run check:smtp
```

The script prints the trace ID, subject, message ID, accepted count, rejected count, pending count, safe error code, and safe diagnostic. It never prints SMTP passwords.

In Gmail, search:

```text
in:anywhere "<traceId>"
```

Check Inbox and Spam. If the message is in Spam, choose "Report not spam" for the test mailbox after confirming it is the expected diagnostic.

## DNS Authentication Checklist

Run the advisory DNS helper:

```bash
EMAIL_DOMAIN=mscqr.com npm --prefix backend run check:email:dns
```

SPF: verify the current Namecheap Private Email DNS UI. A common value is:

```text
v=spf1 include:spf.privateemail.com ~all
```

DKIM:

1. Enable or generate DKIM in Namecheap Private Email.
2. Add the TXT or CNAME records exactly as Namecheap provides.
3. Wait for DNS propagation.
4. If you know the selector, run:

```bash
EMAIL_DOMAIN=mscqr.com EMAIL_DKIM_SELECTOR=<selector> npm --prefix backend run check:email:dns
```

DMARC starter:

```text
_dmarc TXT v=DMARC1; p=none; rua=mailto:administration@mscqr.com
```

Move DMARC to stricter policies only after SPF and DKIM pass consistently.

## Gmail Show Original Checklist

Open the diagnostic message in Gmail:

1. More > Show original.
2. Confirm SPF is `PASS`.
3. Confirm DKIM is `PASS`.
4. Confirm DMARC is `PASS`.
5. Confirm From domain alignment is `mscqr.com`.
6. Confirm TLS was used.

## Spam Placement Triage

If SMTP accepted the intended recipient but Gmail places the message in Spam:

1. Search `in:anywhere "<traceId>"`.
2. Check Gmail Show original for SPF, DKIM, and DMARC.
3. Send a manual email from Namecheap Private Email webmail to the same Gmail address and compare Show original.
4. Verify MSCQR app email uses one branded link, normal wording, and no URL shorteners.
5. If SPF, DKIM, and DMARC pass and Spam persists, contact Namecheap support with the message ID, UTC timestamp, recipient, and trace ID.

## Product Wording Contract

Admin UI copy must say "mail provider accepted" when SMTP accepted the intended recipient. It must not say "delivered to inbox" unless inbox receipt has been manually confirmed.

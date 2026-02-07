# Genuine Scan

Licensee + manufacturer QR authenticity platform.

## Quick Start (Local)
1. Backend: `cd backend && npm run dev`
2. Frontend: `npm run dev`

Set these environment variables in `backend/.env`:
- `QR_SIGN_PRIVATE_KEY` (Ed25519 private key, PEM)
- `QR_SIGN_PUBLIC_KEY` (Ed25519 public key, PEM)
- `PUBLIC_SCAN_WEB_BASE_URL` (e.g. `http://localhost:8080`)
- `SCAN_RATE_LIMIT_PER_MIN` (optional, default `60`)
- `QR_TOKEN_EXP_DAYS` (optional, default `3650`)

## Security Model (Threat Notes)
Prevented / detected:
- Forged QR payloads (signed tokens verified server-side).
- QR reuse (first scan redeems, further scans show fraud warning).
- Uncontrolled printing (print jobs + confirm lock printed codes).
- Batch compromise response (admin can block QR codes or full batches).

Not fully preventable:
- Someone can still photograph a physical label. Reuse will be detected and flagged as already redeemed.

## QR Security: Why It Can’t Be Usefully Duplicated
This system does **not** rely on sequential IDs or client-side checks. Every QR contains a **signed token** that is verified on the server. Copies of a QR image still fail after the first valid redemption.

How it works:
- **Signed payload (Ed25519)**: Each QR encodes a token with `qr_id`, `batch_id`, `licensee_id`, `manufacturer_id` (optional), `iat`, `exp`, and a random `nonce`. The server verifies the signature using the public key.
- **Server-side one-time redemption**: The first valid consumer scan transitions the QR to `REDEEMED`. Any later scan returns a fraud warning and the last redemption timestamp.
- **Print-lock handshake**: Manufacturers must create a print job and confirm printing. Only confirmed codes become `PRINTED`. Scans before printing return “Not activated / suspicious.”
- **Token hashing & audit logs**: Tokens are hashed in the database; events are logged (CREATED, PRINTED, REDEEMED, BLOCKED).
- **Rate limiting & abuse signals**: Scan endpoint is rate-limited and records scan counts, IPs, and device metadata.

### Technology Used
- **Ed25519 signatures** (server-side signing + verification)
- **One-time redemption state machine** (`DORMANT → PRINTED → REDEEMED`)
- **Print jobs with lock tokens** (manufacturer accountability)
- **Audit logging** for every lifecycle event
- **Scan rate limiting** + scan metadata capture

## Operational Flow
1. Super Admin allocates QR ranges to Licensees (creates received batches).
2. Licensee allocates quantities to Manufacturers (by batch).
3. Manufacturer creates a print job, downloads the signed QR pack, and confirms printing.
4. Consumer scans `/scan?t=...` and receives authenticity results.

## User Manual (Admins & Manufacturers)
### Super Admin (Platform Owner)
1. Create Licensee: add brand name, location, support details, and licensee admin credentials.
2. Allocate QR batch: generate a new batch for a licensee (these appear as “Received” batches).
3. Monitor usage: use QR Tracking to review scan history, counts, and fraud warnings.
4. Audit oversight: view all logs and filter by licensee to investigate suspicious activity.
5. Block compromised codes: block a QR or whole batch if you suspect leakage or abuse.

### Licensee Admin (Brand Owner)
1. Manage manufacturers: create manufacturer users under your licensee.
2. Assign batches by quantity: split a received batch and allocate a quantity to a manufacturer.
3. Keep batches sequential: the system always allocates the next available codes in order.
4. Review printing status: track printed vs unprinted batches and view allocation history.
5. Audit your scope: audit logs are limited to your licensee and your manufacturers only.

### Manufacturer (Production Partner)
1. See assigned batches: only batches allocated to your manufacturer appear.
2. Create print job: choose quantity, generate signed QR tokens, and download the pack.
3. Confirm printing: click “Confirm Printed” after physical printing is complete.
4. One-time protection: each QR can be redeemed once; re-scans will show a fraud warning.
5. If printing fails: discard the pack and create a new print job for a fresh set of codes.

### Consumer (Public Scan)
1. Scan the QR: opens the verify page with brand and manufacturing details.
2. Authentic first scan: shows “Genuine” and redemption timestamp.
3. Duplicate scan: shows “Already redeemed / possible counterfeit.”

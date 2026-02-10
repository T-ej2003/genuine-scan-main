# AuthenticQR User Manual

Version: 1.0  
Audience: Licensee Admin, Manufacturer  
Last Updated: 2026-02-09

## 1. Purpose
This manual defines the standard operating workflow for managing QR code allocations, manufacturer assignments, secure printing, and product verification in AuthenticQR.

The platform is designed for anti-counterfeit control:
- Licensee receives dormant QR inventory.
- Licensee assigns quantities to manufacturers.
- Manufacturer prints under server-controlled lock.
- Consumer scan validates authenticity and flags reuse.

## 2. Role Access

### Licensee Admin
Can:
- Manage manufacturers under the same licensee.
- Request additional QR inventory by quantity.
- Assign received batch quantities to manufacturers.
- Review own audit logs and manufacturer activity under same licensee.

Cannot:
- Access other licensees.
- Override Super Admin controls.

### Manufacturer
Can:
- View only assigned batches.
- Create print jobs by quantity.
- Download print packs once per print job.
- Rely on auto-confirm print state after download.

Cannot:
- Request QR inventory directly.
- Access licensee-wide admin functions.

## 3. Core Data Rules

1. QR inventory from Super Admin is stored as `DORMANT`.
2. Assignment is quantity-based and always allocated from the next available codes.
3. Overlapping ranges are prevented by server-side transaction locking.
4. Manufacturer printing is one-time controlled by print job token flow.
5. First valid consumer scan redeems; later scans show fraud/reuse warning.

## 4. Licensee Admin Guide

### 4.1 Login
1. Open the web app URL.
2. Sign in with licensee admin email and password.
3. Confirm left navigation includes `QR Requests`, `Batches`, `Manufacturers`, `Audit Logs`.

### 4.2 Manufacturers
Path: `Manufacturers`

Actions:
1. Click `Add Manufacturer`.
2. Fill `Name`, `Email`, `Password`, optional `Location`, optional `Website`.
3. Submit.
4. Use search to filter by name/email.
5. Toggle active/all status as needed.

Expected behavior:
- Only manufacturers linked to your licensee are listed.
- If the primary manufacturer endpoint is unavailable, app falls back to user list endpoint automatically.

### 4.3 Request New QR Inventory
Path: `QR Requests`

Actions:
1. Enter `Quantity`.
2. Optionally add a request note.
3. Click `Submit Request`.

Approval flow:
1. Super Admin approves request.
2. Backend allocates next available sequence automatically.
3. New allocation appears as a received batch in your `Batches` page.

Notes:
- Requesting by range is deprecated for licensee workflow.
- Quantity is the only supported request mode.

### 4.4 Assign Received Batches to Manufacturer
Path: `Batches`

Actions:
1. Find an unassigned received batch.
2. Open `Assign Manufacturer`.
3. Select manufacturer.
4. Enter quantity.
5. Submit.

Allocation behavior:
- System always uses the next unassigned QR codes in sequence.
- No overlap is allowed.
- Remaining quantity stays available for later assignments.

### 4.5 Audit Logs
Path: `Audit Logs`

Scope:
- You see only your licensee activity and your manufacturers’ actions.
- Super Admin-only actions for other licensees are not visible in your scope.

Use audit logs for:
- Allocation tracing.
- Assignment verification.
- Print/download investigation.

## 5. Manufacturer Guide

### 5.1 Login
1. Open app URL.
2. Sign in with manufacturer credentials.
3. Confirm access to assigned batch operations.

### 5.2 View Assigned Batches
Path: `Batches`

You should see:
- Batches assigned to your manufacturer account only.
- Quantity and print status indicators.

### 5.3 Create Print Job
1. Open target batch.
2. Click `Create Print Job`.
3. Enter quantity to print.
4. Submit.

System behavior:
- Server generates signed tokens for selected QR records.
- Batch reservation follows available unprinted QR count.

### 5.4 Download Print Pack
1. Click `Download ZIP` for created job.
2. Save and print labels.

Security behavior:
- Download is one-time for the same print job token.
- Server auto-confirms print state after successful download.
- Re-download attempt is blocked.

### 5.5 Print Confirmation
Expected:
- Batch/QR statuses update to printed automatically.
- No manual duplicate confirmation required in normal flow.

If status does not update:
1. Refresh page.
2. Check network/API connectivity.
3. Contact Licensee Admin with job ID and timestamp.

## 6. Consumer Scan Outcome (Reference)

When a customer scans a QR:
- First valid scan: authentic response with brand and manufacturer details.
- Repeat scan: fraud/reuse warning with redemption context.
- Invalid/tampered token: rejected as invalid.
- Not printed/blocked states: warning or invalid outcome based on policy.

## 7. Operational SOP

Daily:
1. Licensee Admin reviews pending received inventory.
2. Licensee Admin assigns only required quantity to each manufacturer.
3. Manufacturer creates print jobs only for current production run.
4. Licensee Admin checks audit logs for unexpected batch events.

Weekly:
1. Review printed vs assigned delta by manufacturer.
2. Investigate repeated scan warnings.
3. Deactivate unused manufacturer accounts.

## 8. Troubleshooting

### Issue: Manufacturers list is empty
Checks:
1. Confirm logged-in user is linked to a licensee.
2. Ensure at least one manufacturer exists under that licensee.
3. Toggle active/all status.
4. Reload page and retry.

### Issue: Batch assignment says insufficient available quantity
Checks:
1. Ensure source batch still has unassigned inventory.
2. Reduce quantity and retry.
3. Refresh to sync latest allocation state.

### Issue: Print job fails
Checks:
1. Verify batch belongs to current manufacturer.
2. Confirm requested quantity does not exceed available unprinted codes.
3. Retry if server reports batch busy/concurrency.

### Issue: Scan shows already redeemed
Meaning:
- This is expected for second and later scans of same QR.
- Treat as potential duplicate label usage if attached to different physical item.

## 9. Security Compliance Notes

Implemented controls:
- Signed QR token validation.
- One-time redemption policy.
- Server-side state transitions and audit logging.
- Print job lock and one-time download behavior.
- Rate limiting and scan metadata tracking.

Operational caveat:
- Physical image copying cannot be prevented absolutely.
- System detects and flags reuse so duplicates cannot be validated repeatedly.

## 10. Escalation Matrix

1. Manufacturer operation issue: contact Licensee Admin.
2. Cross-tenant, account, or policy issue: escalate to Super Admin.
3. Persistent API failures: collect timestamp, user ID/email, batch/job ID, and request path for investigation.

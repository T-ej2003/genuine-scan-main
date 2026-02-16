# AuthenticQR User Manual

Version: 2.0  
Audience: Super Admin, Licensee/Admin, Manufacturer, Customer (scanner/verify page)  
Last Updated: 2026-02-16

## 1. Purpose
This manual explains how to operate AuthenticQR end-to-end:
- Creating and managing tenants (licensees/organizations)
- QR inventory requests and allocations
- Manufacturer printing workflow (secure print packs)
- Customer verification outcomes (including legitimate repeat scans)
- Incident Response (IR): alerts, incidents, containment actions, and communications

AuthenticQR is designed for anti-counterfeit control:
- Licensees receive QR inventory.
- Licensees assign quantities to manufacturers.
- Manufacturers print using server-issued tokens.
- Customers verify authenticity via the public verify page.
- Policy alerts and incidents help detect duplicate labels and contain issues.

## 2. Role Access

### 2.1 Getting access (invite-based onboarding)

#### Super Admin
- Provisioned by the platform owner (no self sign-up).
- Full platform access.

#### Licensee/Admin (brand/company)
- Created and invited by Super Admin (or an org admin).
- Scoped to exactly one organization (tenant).
- Can only see licensee/manufacturer data within that org.

#### Manufacturer (factory user)
- Invited by Licensee/Admin (or Super Admin).
- Scoped to assigned batches only.

#### Customer (scanner / verification page)
- No account required.
- Access is via scanning a product QR or entering a code on the verify page.

### 2.2 Setting or resetting password
Applies to Super Admin, Licensee/Admin, and Manufacturer users:
- First-time password: accept the invite link and set a password.
- Forgot password: use the “Forgot password?” link from the login page.

Customers do not set a password (public flow).

## 3. Core Data Rules

1. QR inventory is allocated by quantity and follows the next available sequence.
2. Overlapping allocations are prevented server-side.
3. Manufacturers print using server-generated, signed QR tokens inside a print ZIP pack.
4. First customer verification is authentic when the QR is printed and valid.
5. Repeat customer verifications are normal and remain authentic unless policy/containment flags the code.

## 4. Super Admin Guide

### 4.1 Login
1. Open the web app URL.
2. Sign in with Super Admin email and password.
3. Confirm left navigation includes `Licensees`, `QR Requests`, and `IR Center`.

### 4.2 Create a licensee (tenant)
Path: `Licensees`

1. Select `Add Licensee`.
2. Fill the licensee/company details.
3. Create the licensee.

### 4.3 Approve QR inventory requests
Path: `QR Requests`

1. Filter to pending requests.
2. Approve or reject.

Expected behavior:
- Approvals allocate the next available QR sequence automatically.
- Rejections keep inventory unchanged.

### 4.4 Incident Response (IR Center)
Path: `IR Center`

Use IR Center to:
- Review policy alerts (anomaly detection)
- Create and manage incidents
- Apply containment actions (reversible)
- Send emails to reporters/org admins
- Upload evidence/attachments (if enabled)

## 5. Licensee/Admin Guide

### 5.1 Login
1. Open the web app URL.
2. Sign in with your licensee admin email and password.
3. Confirm navigation includes `QR Requests`, `Batches`, `Manufacturers`, `QR Tracking`, `Audit Logs`.

Expected behavior:
- You only see data within your licensee/org scope.

### 5.2 Manufacturers (invite factory users)
Path: `Manufacturers`

1. Select `Add Manufacturer`.
2. Fill name and email.
3. Use Invite (recommended) to email a one-time link.

Notes:
- Invites expire after 24 hours.
- If email delivery is not configured, the invite still exists in the database but the user will not receive it.

### 5.3 Request new QR inventory
Path: `QR Requests`

Actions:
1. Enter `Quantity`.
2. Optionally add a request note.
3. Click `Submit Request`.

Approval flow:
1. Super Admin approves request.
2. Backend allocates next available sequence automatically.
3. New allocation appears as a received batch in your `Batches` page.

### 5.4 Assign received batches to manufacturer
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

### 5.5 Audit logs
Path: `Audit Logs`

Scope:
- You see only your licensee activity and your manufacturers’ actions.
- Super Admin-only actions for other licensees are not visible in your scope.

Use audit logs for:
- Allocation tracing.
- Assignment verification.
- Print/download investigation.

## 6. Manufacturer Guide

### 6.1 Login
1. Open app URL.
2. Sign in with manufacturer credentials.
3. Confirm access to assigned batch operations.

### 6.2 View assigned batches
Path: `Batches`

You should see:
- Batches assigned to your manufacturer account only.
- Quantity and print status indicators.

### 6.3 Create print job
1. Open target batch.
2. Click `Create Print Job`.
3. Enter quantity to print.
4. Submit.

System behavior:
- Server generates signed tokens for selected QR records.
- Batch reservation follows available unprinted QR count.

### 6.4 Download print pack
1. Click `Download ZIP` for created job.
2. Save and print labels.

Security behavior:
- Download is one-time for the same print job token.
- Server auto-confirms print state after successful download.
- Re-download attempt is blocked.

### 6.5 Print confirmation
Expected:
- Batch/QR statuses update to printed automatically.
- No manual duplicate confirmation required in normal flow.

If status does not update:
1. Refresh page.
2. Check network/API connectivity.
3. Contact Licensee Admin with job ID and timestamp.

## 7. Customer Verification (public verify page)

### 7.1 What the customer can do
- Verify authenticity by scanning a QR or entering the code manually.
- View brand/manufacturer and printed date (when available).
- View a scan history summary (counts and coarse location hints).
- Report suspected counterfeit with optional details and photos.

### 7.2 Result states (what they mean)
- Verified Authentic: first-time verification completed successfully.
- Verified Again: you verified this product before (repeat scans are normal).
- Possible Duplicate: security policy detected unusual scan patterns. Review before trusting.
- Under investigation: the brand/platform is investigating this item/batch/org. Follow support guidance.
- Blocked / Unassigned / Invalid: the code is blocked, not printed/assigned, or not recognized.

## 8. Incident Response (Super Admin SOP)

1. Open `IR Center`.
2. Review alerts (policy triggers) and open/assign incidents.
3. Add timeline notes for each decision.
4. Apply containment actions only when needed:
   - Flag QR under investigation
   - Suspend batch
   - Suspend manufacturer users
   - Suspend org/licensee
   - Reinstate with a reason when resolved
5. Use `Communications` to email reporters or org admins and keep messages logged.

## 9. Operational SOP

Daily:
1. Licensee Admin reviews pending received inventory.
2. Licensee Admin assigns only required quantity to each manufacturer.
3. Manufacturer creates print jobs only for current production run.
4. Licensee Admin checks audit logs for unexpected batch events.

Weekly:
1. Review printed vs assigned delta by manufacturer.
2. Investigate possible duplicate warnings and customer reports.
3. Deactivate unused manufacturer accounts.

## 10. Troubleshooting

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

### Issue: Verify page shows “Possible Duplicate”
Meaning:
- The same QR shows scan patterns that do not match normal buyer behavior.
- This can indicate copied labels on multiple items.

What to do:
- Review “Why this was flagged”.
- Use “Report suspected counterfeit” if you suspect fraud.

## 11. Security Compliance Notes

Implemented controls:
- Signed QR token validation.
- Server-side state transitions and audit logging.
- Print job lock and one-time download behavior.
- Rate limiting and scan metadata tracking.
- Cookie-based sessions (HttpOnly) for admin/manufacturer access.
- Invite-based onboarding with single-use tokens.
- Refresh token rotation with reuse detection.
- CSRF protection for cookie-authenticated state-changing requests.
- IR containment actions and communications logging.

Operational caveat:
- Physical image copying cannot be prevented absolutely.
- System detects and flags reuse so duplicates cannot be validated repeatedly.

## 12. Escalation Matrix

1. Manufacturer operation issue: contact Licensee Admin.
2. Cross-tenant, account, or policy issue: escalate to Super Admin.
3. Persistent API failures: collect timestamp, user ID/email, batch/job ID, and request path for investigation.

## 13. Mandatory Compliance Statements

### 13.1 UK GDPR & Data Protection notice
`{{APP_NAME}}` processes personal data in accordance with UK GDPR and the Data Protection Act 2018. Data protection queries must be directed to `{{DPO_EMAIL}}` or `{{SUPER_ADMIN_EMAIL}}`.

### 13.2 Security & Access Control statement
The platform enforces role-based access control (Super Admin, Licensee, Manufacturer), encrypted HTTPS communication, secure password handling, and audit logging of critical actions.

### 13.3 Incident Response & Fraud Reporting
Controlled process: report intake -> review -> containment -> documentation -> resolution.

### 13.4 QR Code Usage & Non-Duplication policy
All QR codes are unique, traceable, and single-use where applicable. QR codes must not be duplicated, altered, or reused.

### 13.5 Audit Logging notice
Administrative actions, QR allocations, fraud reports, and login attempts are logged and retained for `{{RETENTION_DAYS}}` days.

### 13.6 Acceptable Use clause
Unauthorized access, reverse engineering, misuse of fraud reporting, or interference with system security is prohibited.

### 13.7 Hosting & Disclaimer statement
The platform is hosted via `{{HOSTING_PROVIDER}}` with reasonable security controls and is provided on a best-effort basis.

## Appendix A — Screenshots (reference)
Screenshots used in the in-app Help Center live in `public/docs/`.

### Customer verify outcomes
![Customer - Verified Authentic](../public/docs/customer-first-verification.png)
![Customer - Verified Again](../public/docs/customer-verified-again.png)
![Customer - Possible Duplicate](../public/docs/customer-possible-duplicate.png)
![Customer - Report dialog](../public/docs/customer-report-dialog.png)

### Admin operations
![Super Admin - Create licensee](../public/docs/superadmin-create-licensee.png)
![Super Admin - Approve QR request](../public/docs/superadmin-approve-qr-request.png)
![Manufacturer - Create print job](../public/docs/manufacturer-create-print-job.png)
![IR Center](../public/docs/ir-dashboard.png)

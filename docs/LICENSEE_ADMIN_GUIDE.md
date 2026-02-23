# AuthenticQR Licensee/Admin Procedure Guide

Document ID: AQR-SOP-LA-001  
Version: 1.0  
Last Updated: 2026-02-16

## 1. Purpose
Define the controlled operating procedure for Licensee/Admin users managing manufacturer accounts and QR inventory allocation.

## 2. Scope
This procedure applies to organization-scoped Licensee/Admin accounts.

## 3. Preconditions
- Active Licensee/Admin account.
- Organization assignment configured.
- At least one manufacturer profile available (or ability to create one).

## 4. Procedure
### 4.1 Sign in
1. Open the login page.
2. Enter Licensee/Admin credentials and select `Sign in`.
3. Confirm access to `QR Requests`, `Batches`, `Manufacturers`, and `Audit Logs`.

![Licensee Login](../public/docs/access-super-admin-login.png)

### 4.2 Create or invite manufacturer user
1. Open `Manufacturers`.
2. Select `Add Manufacturer`.
3. Enter user profile and email.
4. Use invite mode and submit.

![Create Manufacturer](../public/docs/licensee-create-manufacturer.png)

### 4.3 Request new QR inventory
1. Open `QR Requests`.
2. Enter quantity and optional note.
3. Select `Submit Request`.
4. Track approval status.

![Request QR Inventory](../public/docs/licensee-request-qr-inventory.png)

### 4.4 Assign received batch to manufacturer
1. Open `Batches`.
2. Select a received batch with available quantity.
3. Open `Assign Manufacturer`.
4. Select manufacturer and quantity.
5. Submit assignment.

![Assign Batch](../public/docs/licensee-assign-batch.png)

## 5. Acceptance Criteria
- Manufacturer can view assigned batch.
- No overlapping allocation ranges.
- Assignment event appears in audit and trace timeline.

## 6. Nonconformance and Escalation
- If assignment fails with quantity errors, refresh and verify remaining balance.
- If manufacturer cannot view batches, verify assignment target and account activation.
- Escalate unresolved allocation defects with batch ID, quantity, and timestamp.

## 7. Mandatory Compliance Statements
### 7.1 UK GDPR & Data Protection notice
`{{APP_NAME}}` processes personal data in accordance with UK GDPR and the Data Protection Act 2018. Data protection queries must be directed to `{{DPO_EMAIL}}` or `{{SUPER_ADMIN_EMAIL}}`.

### 7.2 Security & Access Control statement
The platform enforces role-based access control (Super Admin, Licensee, Manufacturer), encrypted HTTPS communication, secure password handling, and audit logging of critical actions.

### 7.3 Incident Response & Fraud Reporting
Controlled process: report intake -> review -> containment -> documentation -> resolution.

### 7.4 QR Code Usage & Non-Duplication policy
All QR codes are unique, traceable, and single-use where applicable. QR codes must not be duplicated, altered, or reused.

### 7.5 Audit Logging notice
Administrative actions, QR allocations, fraud reports, and login attempts are logged and retained for `{{RETENTION_DAYS}}` days.

### 7.6 Acceptable Use clause
Unauthorized access, reverse engineering, misuse of fraud reporting, or interference with system security is prohibited.

### 7.7 Hosting & Disclaimer statement
The platform is hosted via `{{HOSTING_PROVIDER}}` with reasonable security controls and is provided on a best-effort basis.

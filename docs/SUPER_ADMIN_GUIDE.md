# AuthenticQR Super Admin Procedure Guide

Document ID: AQR-SOP-SA-001  
Version: 1.0  
Last Updated: 2026-02-16

## 1. Purpose
Define the controlled operating procedure for Super Admin users managing tenants, inventory approvals, and incident response.

## 2. Scope
This procedure applies to platform-level Super Admin accounts.

## 3. Preconditions
- Active Super Admin account.
- Valid sign-in credentials.
- IR Center access enabled.

## 4. Procedure
### 4.1 Sign in and verify scope
1. Open the login page.
2. Enter Super Admin credentials and select `Sign in`.
3. Confirm navigation includes `Licensees`, `QR Requests`, and `IR Center`.

![Super Admin Login](../public/docs/access-super-admin-login.png)

### 4.2 Create a licensee tenant
1. Open `Licensees`.
2. Select `Add Licensee`.
3. Enter organization details.
4. Submit and confirm tenant creation.

![Create Licensee Tenant](../public/docs/superadmin-create-licensee.png)

### 4.3 Approve QR inventory requests
1. Open `QR Requests`.
2. Filter pending requests.
3. Review request details.
4. Approve or reject.

Acceptance criterion: approved requests allocate the next available QR sequence.

![Approve QR Request](../public/docs/superadmin-approve-qr-request.png)

### 4.4 Operate Incident Response
1. Open `IR Center`.
2. Review incidents, alerts, and policies.
3. Prioritize by severity and assign ownership.
4. Apply containment actions only with documented reason.

![IR Center Dashboard](../public/docs/ir-dashboard.png)

### 4.5 Configure policy rules
1. Open `IR Center` > `Policies`.
2. Select `New policy`.
3. Configure thresholds and scope.
4. Enable rule and validate alert behavior.

![Create Policy Rule](../public/docs/ir-policy-create.png)

### 4.6 Execute containment and communications
1. Open incident detail.
2. Apply action with reason.
3. Compose and send stakeholder communication.
4. Confirm timeline logging.

![Incident Actions](../public/docs/ir-incident-actions.png)

![Incident Communications](../public/docs/ir-communication-compose.png)

## 5. Records and Evidence
- Incident timeline entries.
- Audit logs for approvals/actions.
- Communication status records.

## 6. Nonconformance and Escalation
- If approvals fail repeatedly, collect request ID, timestamp, and actor email.
- If email delivery fails, validate SMTP configuration and sender domain policy.
- Escalate platform failures to the engineering owner with incident ID and logs.

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

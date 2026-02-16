# AuthenticQR Customer Verification Guide

Document ID: AQR-SOP-CU-001  
Version: 1.0  
Last Updated: 2026-02-16

## 1. Purpose
Define the customer-side verification and reporting procedure for authenticity checks.

## 2. Scope
Applies to public verify flow users (no account required).

## 3. Preconditions
- Product QR code is available.
- Internet connection is active.

## 4. Procedure
### 4.1 Verify first scan
1. Scan product QR code.
2. Review status and product details.
3. Confirm `Verified Authentic` outcome.

![Verified Authentic](../public/docs/customer-first-verification.png)

### 4.2 Validate repeat check behavior
1. Scan the same code again.
2. Confirm `Verified Again` appears.

![Verified Again](../public/docs/customer-verified-again.png)

### 4.3 Handle duplicate warning
1. If `Possible Duplicate` appears, review flag reasons.
2. Do not trust product until reviewed.

![Possible Duplicate](../public/docs/customer-possible-duplicate.png)

### 4.4 Submit suspected counterfeit report
1. Select `Report suspected counterfeit`.
2. Complete incident type and observations.
3. Add optional photos/contact details.
4. Submit report.

![Report Counterfeit](../public/docs/customer-report-dialog.png)

## 5. Acceptance Criteria
- Verification screen renders a clear status.
- Duplicate warning displays rationale.
- Report submission returns a reference and audit trail.

## 6. Escalation
- If verification is unavailable, retry and contact brand support.
- If code appears invalid or suspicious, submit report immediately.

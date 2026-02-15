# Docs Screenshots Folder

Place help/documentation screenshots in this folder.

The app loads screenshots from `/docs/<filename>` on `/help` and `/help/:role` pages.
If a file is missing, the UI shows a placeholder block with the expected filename.

## Required filenames

### Intro pages
- `access-super-admin-login.png`
- `access-licensee-admin-created-user.png`
- `access-manufacturer-create-form.png`
- `access-customer-verify-entry.png`
- `password-superadmin-account-security.png`
- `password-licensee-change-password.png`
- `password-manufacturer-account-security.png`
- `password-customer-otp-request.png`
- `password-customer-otp-verify.png`

### Super Admin
- `superadmin-create-licensee-form.png`
- `superadmin-approve-qr-request.png`
- `superadmin-allocate-qr-range.png`
- `superadmin-incident-list.png`
- `superadmin-policy-alerts.png`

### Licensee/Admin (brand/company)
- `licensee-create-manufacturer.png`
- `licensee-qr-request-submit.png`
- `licensee-assign-batch-manufacturer.png`
- `licensee-incidents-overview.png`
- `licensee-qr-tracking-filtered.png`

### Manufacturer (factory user)
- `manufacturer-batches-list.png`
- `manufacturer-create-print-job.png`
- `manufacturer-download-print-pack.png`
- `manufacturer-print-confirmed-status.png`

### Customer (scanner / verification page)
- `customer-verify-first-scan.png`
- `customer-verify-again-scan.png`
- `customer-possible-duplicate.png`
- `customer-signin-otp.png`
- `customer-claim-product.png`
- `customer-report-counterfeit-form.png`

## Automation

Use `npm run docs:screenshots` for best-effort capture.
See `/scripts/docs-screenshots.spec.ts` for TODO selectors and env vars.

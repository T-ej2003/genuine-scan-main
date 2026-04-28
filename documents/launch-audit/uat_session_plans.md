# Role UAT Session Plans

## Super Admin session

### Preconditions

- super admin credentials
- seeded or production-like licensee/manufacturer data
- access to support, governance, and incident response routes

### Test steps

1. Sign in and complete MFA.
2. Open dashboard and confirm no broken empty states.
3. Create or edit a licensee.
4. Open manufacturers and confirm scope/actions are available.
5. Review audit logs.
6. Open support queue and incident response.
7. Confirm governance pages load and action buttons are sane.

### Capture

- pass/fail per step
- screenshots of any confusing or broken state
- blocker severity

## Licensee Admin session

### Preconditions

- licensee admin credentials
- active licensee with code/batch data

### Test steps

1. Sign in.
2. Request QR or code allocation.
3. Open batches and tracking.
4. Review manufacturer relationship screens.
5. Submit a support issue.
6. Confirm legal/footer links are accessible.

## Manufacturer session

### Preconditions

- manufacturer credentials
- supported Windows or macOS device
- printer available

### Test steps

1. Sign in.
2. Open printer setup.
3. Open connector download page.
4. Install or validate the connector package on the test machine.
5. Confirm printer readiness states.
6. Attempt batch print workflow.
7. Submit a support issue if needed.

## Public verification session

### Preconditions

- valid code or signed-label token
- mobile and desktop browser

### Test steps

1. Open landing page.
2. Start verification with manual or scan entry.
3. Complete any customer sign-in or OTP step.
4. Review success or failure result wording.
5. Confirm privacy/cookie links are present.
6. Confirm no raw technical errors appear.

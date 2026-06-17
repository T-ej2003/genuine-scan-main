# Security Policy

MSCQR is a garment authentication and QR verification platform. Security reports are taken seriously because the system handles QR issuance, batch allocation, scan verification, manufacturer workflows, admin access, audit logs, and anti-counterfeit investigation data.

## Supported Versions

MSCQR is currently developed from the `main` branch.

| Version / Branch | Supported |
| --- | --- |
| `main` | Yes |
| Production deployment | Yes |
| Old commits, forks, or local test copies | No |

Security fixes are applied to the active production codebase and the current `main` branch. Older snapshots, forks, copied deployments, and abandoned branches are not supported unless agreed separately.

## Reporting a Vulnerability

Do not open a public GitHub issue for security vulnerabilities.

Report security issues by email:

**administration@mscqr.com**

Include as much detail as possible:

- A clear summary of the issue
- Affected URL, route, API endpoint, workflow, or file
- Steps to reproduce
- Impact assessment
- Screenshots, logs, or proof-of-concept details if safe to share
- Your name or contact details if you want follow-up credit or updates

## What to Report

Please report issues such as:

- Authentication or session bypass
- Broken access control between platform admins, licensee admins, manufacturers, or public users
- QR verification bypass, replay, cloning, or tampering weaknesses
- Exposure of QR secrets, invite tokens, reset tokens, session tokens, JWTs, CSRF tokens, API keys, or credentials
- Unauthorized access to batches, scan logs, audit logs, support reports, incidents, or manufacturer workflows
- SQL injection, command injection, server-side request forgery, cross-site scripting, or path traversal
- File upload or evidence handling vulnerabilities
- Insecure direct object references
- Rate-limit bypasses that could affect verification, login, invite, support, or incident flows
- Sensitive data leakage in logs, errors, client bundles, screenshots, diagnostics, or public responses

## What Not to Report

The following are usually out of scope unless they demonstrate real security impact:

- Generic automated scanner output without proof
- Missing cosmetic security headers with no exploit path
- Clickjacking on pages that do not expose sensitive actions
- Rate-limit claims without a reproducible abuse scenario
- Social engineering
- Physical attacks against user devices, printers, or infrastructure not controlled by MSCQR
- Denial-of-service testing without written permission
- Issues requiring malware, stolen credentials, or compromised accounts

## Safe Testing Rules

When testing MSCQR:

- Do not access, modify, delete, or export data that does not belong to you.
- Do not test against real brands, manufacturers, customers, or production records without permission.
- Do not perform destructive testing.
- Do not run high-volume scans, brute force, spam, credential stuffing, or denial-of-service tests.
- Do not publish vulnerability details before MSCQR has reviewed and resolved the issue.
- Stop testing and report immediately if you encounter sensitive data.

## Response Process

MSCQR will try to acknowledge valid reports within 72 hours.

After review, MSCQR may:

- Ask for more information
- Confirm the issue and begin remediation
- Mark the report as duplicate, low impact, out of scope, or not reproducible
- Apply a fix, mitigation, configuration change, or monitoring rule
- Request coordinated disclosure timing if public disclosure is appropriate

Timelines depend on severity, exploitability, affected systems, and operational risk.

## Disclosure

Do not publicly disclose a vulnerability until MSCQR confirms that the issue has been fixed or gives written approval for disclosure.

## Security Contact

Email: **administration@mscqr.com**

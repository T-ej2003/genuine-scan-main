# MSCQR Manual Verification Tracker

This file tracks every launch-signoff task that cannot be proven from repo state alone.

## Priority legend

- `P0`: launch blocker
- `P1`: should be completed before launch unless explicitly waived

## Tracker

| ID | Priority | Area | Why it matters | Acceptance criteria | Evidence required | Owner | Blocker |
| --- | --- | --- | --- | --- | --- | --- | --- |
| MVT-001 | P0 | Browser runtime cookie/storage audit | Repo code cannot prove proxy-added cookies, runtime flags, or live environment storage behavior. | Screenshots exist for cookies, local storage, session storage, and `Set-Cookie` headers for public and authenticated flows. | Browser screenshots and environment URL | User | Yes |
| MVT-002 | P0 | RDS backup evidence | Backup docs are not enough without live AWS proof. | Automated backups enabled, retention shown, latest backup timestamp captured. | AWS screenshots and note on restore drill recency | User | Yes |
| MVT-003 | P0 | Restore drill evidence | Launch is not premium-safe without restore proof. | Named restore drill date and result exist, or explicit gap is recorded. | Screenshot or internal record + note | User | Yes |
| MVT-004 | P0 | S3 bucket protections | Repo cannot prove encryption, versioning, lifecycle, or block-public-access. | All relevant production buckets show correct settings and no unsafe public exposure. | AWS screenshots + bucket purpose note | User | Yes |
| MVT-005 | P0 | CloudWatch alarm routing | Config validation is not the same as live alert ownership. | Production alarms exist and show real notification or escalation targets. | Alarms screenshot + one alarm action screenshot | User | Yes |
| MVT-006 | P0 | ACM certificate proof | Repo cannot prove production certificate state. | Certificate is issued, valid, and not close to expiry. | ACM screenshot | User | Yes |
| MVT-007 | P0 | Connector signing readiness | Connector rollout depends on external certificates/accounts. | Windows signing path and Apple notarization readiness are explicitly confirmed or explicitly missing. | Plain text note with provider/account state | User | Yes |
| MVT-008 | P1 | Live visual QA of legal/trust shell | Repo changes still need browser confirmation. | Footer links and legal pages render correctly on public, help, dashboard, verify, and connector pages. | Screenshots or short QA note | User | No |
| MVT-009 | P1 | Support privacy notice QA | Support dialog wording should be confirmed in browser. | Notice is visible, readable, and not visually broken. | Screenshot | User | No |
| MVT-010 | P0 | Clean non-production migration replay | Code fix is not complete until the full chain succeeds on a clean DB. | `prisma migrate reset` or equivalent clean replay succeeds in non-production validation DB. | Command output or screenshot | User / Shared | Yes |

## Click-by-click packets

### MVT-001: Browser runtime cookie/storage audit

USER INTERVENTION REQUIRED
Why:
Repo code cannot prove live cookies, proxy-added cookies, or final cookie flags in staging/production.
Exact action:
Capture a browser runtime cookie/storage inventory for MSCQR staging or production.
Click-by-click:
1. Open MSCQR in Chrome.
2. Open the public landing page.
3. Right-click anywhere on the page.
4. Click `Inspect`.
5. Click the `Application` tab.
6. In the left sidebar, expand `Storage`.
7. Click `Cookies`.
8. Click the MSCQR site origin.
9. Take a screenshot showing all cookie names and columns.
10. Click `Local Storage`.
11. Click the MSCQR site origin.
12. Take a screenshot showing all keys.
13. Click `Session Storage`.
14. Click the MSCQR site origin.
15. Take a screenshot showing all keys.
16. Click the `Network` tab.
17. Refresh the page.
18. Click one request to the main app origin.
19. In `Headers`, capture the `Set-Cookie` response headers if present.
20. Repeat the same process after:
- logging in as an operator
- opening the public verify flow
- opening the support issue dialog if available
Evidence to bring back:
- screenshots of Cookies, Local Storage, Session Storage
- one screenshot of response `Set-Cookie` headers
- the exact environment URL used
Blocker if skipped: Yes

### MVT-002 and MVT-003: RDS backup and restore evidence

USER INTERVENTION REQUIRED
Why:
Repo docs describe backup and restore posture, but they do not prove live AWS state.
Exact action:
Capture RDS backup and restore evidence from AWS.
Click-by-click:
1. Open AWS Console.
2. Search for `RDS`.
3. Click `RDS`.
4. In the left sidebar, click `Databases`.
5. Click the production MSCQR database instance.
6. Click the `Maintenance & backups` or `Backups` tab.
7. Capture a screenshot showing:
- automated backups enabled
- retention period
- latest automated backup time
8. Go back to the left sidebar.
9. Click `Automated backups`.
10. Take a screenshot showing the most recent backup entries.
11. If a recent restore drill exists, click the relevant restore target or internal record and capture any visible timestamp/details.
Evidence to bring back:
- screenshot of DB backup settings
- screenshot of latest automated backups
- note whether a restore drill has been run in the last 30 days
Blocker if skipped: Yes

### MVT-004: S3 bucket protections

USER INTERVENTION REQUIRED
Why:
Repo code cannot prove bucket encryption, versioning, lifecycle, or public-access blocking.
Exact action:
Capture S3 bucket control evidence for MSCQR production buckets.
Click-by-click:
1. Open AWS Console.
2. Search for `S3`.
3. Click `S3`.
4. Open the bucket used for MSCQR uploads or support evidence.
5. Click the `Properties` tab.
6. Capture screenshots of:
- Versioning
- Default encryption
- Lifecycle rules
7. Click the `Permissions` tab.
8. Capture screenshots of:
- Block public access
- Bucket policy
9. Repeat for any second bucket used for connector artifacts or public downloads, if applicable.
Evidence to bring back:
- screenshots of versioning, encryption, lifecycle, block public access, and bucket policy for each relevant bucket
- bucket names and what each bucket is used for
Blocker if skipped: Yes

### MVT-005 and MVT-006: CloudWatch and ACM

USER INTERVENTION REQUIRED
Why:
Repo checks validate CloudWatch config shape, but not live alarm routing or SSL certificate status.
Exact action:
Capture CloudWatch alarm routing and certificate evidence.
Click-by-click:
1. Open AWS Console.
2. Search for `CloudWatch`.
3. Click `CloudWatch`.
4. In the left sidebar, click `Alarms`.
5. Take a screenshot showing all production alarms for MSCQR.
6. Click one high-priority alarm.
7. Capture the section showing alarm actions or notification targets.
8. Search for `Certificate Manager`.
9. Click `ACM`.
10. Open the certificate used by MSCQR production.
11. Capture a screenshot showing:
- domain name
- status
- expiry date
Evidence to bring back:
- CloudWatch alarms screenshot
- one alarm action or notification screenshot
- ACM certificate screenshot
Blocker if skipped: Yes

### MVT-007: Connector signing readiness

USER INTERVENTION REQUIRED
Why:
Connector signing depends on external code-signing assets and accounts that are not in the repo.
Exact action:
Confirm whether signing and notarization credentials and operator access already exist.
Click-by-click:
1. Check whether you already have:
- a Windows code-signing provider or Azure Trusted Signing setup
- an Apple Developer account for notarization
- a named company publisher string you intend to ship under
2. Put the answers into a plain text note with this format:
- Windows signing provider: yes/no + provider name
- Windows publisher name: value or unknown
- Apple Developer notarization ready: yes/no
- Apple team ID available: yes/no
- Planned shipping domains: value
Evidence to bring back:
- the plain text note pasted back into chat
Blocker if skipped: Yes

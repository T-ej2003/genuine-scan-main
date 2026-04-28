# Security + Production Hardening Audit

## Security findings table

| ID | Finding | Severity | Evidence | Exact remediation | Launch blocker |
| --- | --- | --- | --- | --- | --- |
| SEC-001 | Clean-environment migration chain is broken | Critical | `documents/backend/README.md`; migration path under `backend/prisma/migrations/` | Repair chain and prove greenfield migration in CI and pre-prod | Yes |
| SEC-002 | Verify-customer legacy bearer compatibility remains available | High | `backend/src/middleware/customerVerifyAuth.ts`; `scripts/check-customer-auth-cutover.mjs` | Disable bearer compatibility in production and monitor cutover | Yes |
| SEC-003 | Legacy admin token response compatibility remains | High | `backend/src/controllers/authController.ts` | Disable legacy response mode and remove fallback after client validation | Yes |
| SEC-004 | Object storage least-privilege and lifecycle controls are not evidenced | High | Object storage integration plus production startup checks, but no IAM or bucket-policy proof in repo | Export and review IAM, bucket policy, versioning, encryption, lifecycle, public access blocks | Yes |
| SEC-005 | Support and incident uploads need formal retention/access governance | High | Support/incident upload middleware and launcher exist | Define retention, access control, redaction, and deletion handling | Yes |
| SEC-006 | Connector artifact trust is not closed until signing/notarization is proven | High | Connector distribution exists; signing remains open | Implement signed release process with checksum publication and verification SOP | Yes |
| SEC-007 | Logging is still partly unstructured | Medium | Multiple `console.*` uses in frontend/backend | Consolidate on structured logger with PII-safe field policy | No |
| SEC-008 | Mock data residue remains in app source | Medium | `src/lib/mock-data.ts` | Remove or isolate to test-only usage | No |
| SEC-009 | No external pen test evidence found | Medium | Internal scripts/tests exist, no external report present | Run focused app and auth pen test | No |

## Security strengths verified

- Production startup enforces secure-cookie posture, JWT secret presence, HTTPS public URLs, QR signing config, Redis in production, and object storage in production.
- Production startup now refuses `AUTH_LEGACY_TOKEN_RESPONSE_ENABLED=true`.
- RBAC and tenant isolation middleware exist.
- CSRF double-submit protections exist for cookie-backed flows.
- Public rate limiting exists.
- Upload validation exists with MIME and size controls.
- Nginx hardening is present, including CSP in `nginx.conf` and `nginx.https.conf`.
- Guardrail scripts passed for security hardening, public metadata, nginx hardening, trust observability, and CloudWatch config validation.
- Representative backend security tests passed.

## Production polish findings table

| ID | Finding | Severity | Evidence | Exact remediation | Launch blocker |
| --- | --- | --- | --- | --- | --- |
| POL-001 | No visible legal/trust footer completion | High | Public pages are polished but do not expose final policy links | Add footer trust/legal links across public and app shells | Yes |
| POL-002 | 404 page is too developer-like and logs client console noise | Medium | `src/pages/NotFound.tsx` | Replace with branded recovery page and remove console error | No |
| POL-003 | Some internal/support behavior is stronger in docs than in UI | Medium | Role guides are detailed; UI trust/help surfacing is lighter | Bring support/privacy/trust messaging into product shell | No |
| POL-004 | Support screenshot capture needs explicit customer-safe copy | High | Support launcher captures screenshots and diagnostics | Add consent/notice copy and link to privacy/support policy | Yes |
| POL-005 | Connector download needs explicit trust messaging | High | Connector route exists; artifact-trust completion pending | Show signed publisher, checksum, OS support, and support path | Yes |

## Pre-launch hardening checklist

- [ ] Fix the migration chain and prove clean deploy success
- [ ] Disable verify-customer bearer compatibility in production
- [ ] Disable legacy admin token response compatibility in production
- [ ] Confirm cookie flags in production:
- `Secure`
- `HttpOnly`
- `SameSite`
- domain/path scope
- [ ] Verify CORS allowlist matches production origins only
- [ ] Export and review AWS IAM and object storage least-privilege evidence
- [ ] Confirm bucket encryption, lifecycle, versioning, and public-access block settings
- [ ] Review support and incident upload access rules and retention schedule
- [ ] Standardize server and client logging; remove stray `console.*`
- [ ] Remove mock data residue from production bundle paths
- [ ] Add legal/trust footer and support privacy notice text
- [ ] Complete connector signing/notarization workflow
- [ ] Re-run targeted security tests and launch smoke suite after fixes
- [ ] Schedule an external pen test or focused security review

## Exact remediation notes

### Auth and session handling

- Prefer one production auth pattern per flow. For operators, keep secure cookie auth with CSRF. For public/customer verify, complete the cutover away from transitional bearer compatibility.
- Reduce legacy toggles in production. They are useful for migration windows, but not for steady-state premium launch.
- Launch posture now defaults verify-customer bearer compatibility away from production, while preserving an explicit rollback override if operations truly need it.

### Secrets and environment posture

- Existing startup guards are strong. The next step is evidence, not theory:
- export a redacted production env inventory
- confirm secret rotation ownership and cadence
- confirm there are no long-lived shared credentials for object storage or connector distribution

### Route/API authorization

- RBAC and tenant isolation are present, which is good.
- Before launch, run one explicit permission matrix test across high-risk endpoints using real role accounts and cross-tenant identifiers.

### Upload validation and evidence handling

- Support/incident file validation exists, which is a solid baseline.
- Now formalize who can access uploaded evidence, how long it is retained, how deletion works, and whether any malware scanning is required before scale-up.

### Security headers and HTTPS

- Nginx hardening is stronger than average.
- Final verification task: confirm the deployed edge actually serves the headers documented in repo and that all non-HTTPS paths redirect cleanly.

## Recommended next-best security upgrades from a CTO lens

1. Add an internal security evidence dashboard that records last restore drill, last secret rotation, last pen test, and last rollback rehearsal.
2. Add malware scanning or asynchronous content scanning for uploaded support/incident evidence if volumes increase.
3. Add enterprise auth roadmap items: SSO/SAML, SCIM, stronger session/device management, and customer-visible audit export.
4. Add automated permission regression tests for role and tenant isolation on every release candidate.

# MSCQR Premium Readiness Brief
**Date:** 11 Apr 2026  
**Owner:** CTO  
**Audience:** Enterprise client + operations stakeholders  
**Program:** 2-phase production hardening sprint (7 days)

---

## 1) Executive Status
MSCQR has moved beyond prototype behavior and now includes strong trust controls in code and CI.  
Current posture is **hardening in progress** with critical control layers already implemented, and final operational activation remaining.

Commercial truth statement:
- MSCQR enforces governed verification semantics and replay-aware risk handling.
- MSCQR does **not** claim physical clone-proofing or impossible-to-copy guarantees.
- Manual path remains intentionally weaker than signed-label proof.

---

## 2) 2-Phase Delivery Plan (7 Days)

### Phase 1 (Days 1-3): Launch-Blocking Controls Closure
1. **Release gate activation**
   - Configure staging smoke variables/secrets in GitHub.
   - Enforce required checks on `main`:
     - `Release Candidate Gate / rc-trust-critical`
     - `Release Candidate Gate / rc-staging-smoke`
   - Exit criterion: merge blocked unless both checks pass.

2. **Secrets and signer posture closure**
   - Complete emergency rotation for exposed secret families:
     - JWT, refresh, CSRF, MFA encryption, incident/IP salts, QR signing keys.
   - Perform dual-slot cutover, then cleanup deploy removing `*_PREVIOUS`.
   - Exit criterion: startup signer posture validated and incidents moved to resolved with evidence.

3. **Provenance safety closure**
   - Run provenance backfill dry-run and review.
   - Execute backfill only after dry-run approval.
   - Rule: unknown historical provenance remains limited/unknown.
   - Exit criterion: archived backfill report + limited-provenance semantics preserved.

4. **Runtime trust validation**
   - Run trust-critical tests, staging smoke, and migration validation.
   - Exit criterion: documented pass set for replay/manual/challenge/provenance/break-glass paths.

### Phase 2 (Days 4-7): Operational Readiness + Client Proof Pack
1. **Observability operationalization**
   - Wire trust metrics and alert definitions into active monitoring.
   - Required alerts: replay spike, limited provenance spike, challenge abandonment, break-glass usage.
   - Exit criterion: dashboards visible and at least one alert test acknowledged.

2. **Incident readiness drill**
   - Execute tabletop + live drill for:
     - replay spike
     - signer misconfiguration
     - legacy provenance anomaly
     - challenge completion failures
   - Exit criterion: timestamps, owners, actions, and postmortem notes captured.

3. **Client-facing assurance package**
   - Freeze this brief with status, controls, paid-service decisions, and timeline.
   - Exit criterion: approved single source-of-truth by engineering/security/ops.

---

## 3) What Is Already Done (Repo-Verified)
- Release-candidate gate workflow exists with:
  - `rc-trust-critical`
  - `rc-staging-smoke`
- Trust-critical suite exists in CI workflows.
- Replay hardening + changed-context handling + review-required semantics landed.
- Issuance provenance and customer-verifiable lifecycle semantics landed.
- Challenge-required/challenge-completion pathways are implemented.
- Observability artifacts exist:
  - event catalog
  - metrics extraction mapping
  - alert rule templates
  - example event fixtures
- Incident runbook and security key rotation runbook exist in docs.
- Provenance backfill commands are documented.
- Mobile verify improvements landed (including skip path in intake flow).

---

## 4) What Must Be Closed Before Premium Launch
- [ ] Staging smoke vars/secrets are configured and `rc-staging-smoke` is green.
- [ ] Branch protection/ruleset enforces both RC checks before merge.
- [ ] Provenance backfill completed (`dry-run` evidence + `execute` evidence).
- [ ] Secret rotation cutover completed, including cleanup deploy.
- [ ] Alert routing wired to active on-call channel (not just templates in repo).
- [ ] Staging-like end-to-end validation evidence pack finalized.

---

## 5) Paid Services Decision Matrix

### Must-have now (production)
- Domain + DNS ownership
- Compute hosting (frontend/backend/worker)
- PostgreSQL
- Redis
- S3-compatible object storage
- SMTP delivery
- TLS certificate operations (Let's Encrypt flow is free, but setup is operationally required)

### Optional now, likely Phase 2
- Sentry or equivalent monitoring
- SIEM sink / SOAR integration
- Managed KMS signer path
- Windows code-signing certificate
- Apple notarization account (if signed macOS distribution is required)

### Procurement references
- AWS Lightsail pricing: https://aws.amazon.com/lightsail/pricing/
- Amazon SES pricing: https://aws.amazon.com/ses/pricing/
- Amazon S3 pricing: https://aws.amazon.com/s3/pricing/
- AWS CloudWatch pricing: https://aws.amazon.com/cloudwatch/pricing/
- AWS KMS pricing: https://aws.amazon.com/kms/pricing/
- GitHub pricing: https://github.com/pricing
- Sentry pricing: https://sentry.io/pricing
- GitGuardian pricing: https://www.gitguardian.com/pricing

---

## 6) Client Meeting Checklist (Tomorrow)
- [ ] Both RC checks green on release branch.
- [ ] Staging smoke passes with real login/auth flow.
- [ ] Trust-critical suite report attached.
- [ ] Provenance backfill report attached.
- [ ] Secret rotation evidence attached.
- [ ] Alert routing evidence attached (screenshot/log).
- [ ] Incident drill evidence attached.
- [ ] Rollback runbook reviewed and owners assigned.
- [ ] Paid services approved with owner + ETA.

---

## 7) Test and Validation Evidence Required
- Backend trust-critical suite (compiled path)
- Frontend verify flow tests (including skip + mobile)
- Typecheck and production build
- Prisma migration status + deploy check in staging-like env
- RC gate jobs green
- Manual smoke for:
  - signed-first then manual fallback
  - changed-context replay (anonymous)
  - challenge-required then challenge-complete
  - limited-provenance rendering and operator labels

---

## 8) Risks and Controls
- **Residual risk:** software replay resistance improved, but physical clone-proofing is not claimed.
- **Known dependency:** managed KMS/HSM signing remains future-state until real infra/provider is wired.
- **Control approach:** explicit downgrade semantics, stronger release gating, auditable incident and rotation runbooks.

---

## 9) CTO Recommendation (for meeting close)
1. Freeze non-essential feature work for 1 week.
2. Treat RC gate + staging smoke as hard blockers for merge.
3. Close secret rotation and provenance backfill evidence first.
4. Use client meeting to align on transparent claim boundaries and operational readiness, not feature expansion.

This is the fastest credible route to premium launch confidence without overclaiming security posture.

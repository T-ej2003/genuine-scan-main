# Security Architecture Baseline (v2026-03-05)

## Scope
- Platform: Genuine Scan / MSCQR backend + direct-print workflow.
- Environment: Multi-tenant, licensee/manufacturer scoped operations.
- Baseline objective: cryptographically trusted print issuance, fail-stop controls, adaptive duplicate detection, and forensic-grade evidence.

## Standards Mapping

| Control Domain | ISO 27001 (2022) | SOC 2 | NIST CSF 2.0 | GS1 / Traceability Alignment | Implementation Evidence |
|---|---|---|---|---|---|
| Identity + access | A.5.15, A.5.16, A.8.2 | CC6.1, CC6.3 | PR.AA | Authenticated actor attribution for print/scan events | JWT auth, RBAC middleware, audit user linkage |
| Cryptographic print trust | A.8.24, A.8.28 | CC6.6, CC7.2 | PR.DS, DE.CM | Verifiable chain-of-custody for serialized code issuance | `PrinterRegistration`, `PrinterAttestation`, signed heartbeats, mTLS fingerprint checks |
| One-time issuance + consumption | A.8.12, A.8.16 | CC7.2, CC8.1 | PR.PS, DE.AE | One code issued/confirmed once with server proof | `PrintSession`, `PrintItem`, one-time render token usage, strict state transitions |
| Incident response | A.5.24-A.5.27 | CC7.4 | RS.RP, RS.AN | Security event escalation for counterfeit/print abuse | Auto fail-stop incident creation + super-user alerting |
| Logging + forensics | A.8.15, A.8.16 | CC7.2, CC7.3 | DE.CM, RC.CO | Immutable timeline export for legal/reconciliation | hash-linked `ForensicEventChain`, immutable export bundles |
| Retention + evidence | A.5.33, A.8.10 | CC3.2, CC8.1 | GV.OV, RC.RP | Export-ready records and retention controls | retention policy + compliance bundle generation |
| Duplicate detection | A.5.7, A.8.7 | CC7.2 | DE.AE | Fraud signal scoring over scan history | deterministic + anomaly score model, adaptive thresholds |

## Threat Model (Baseline)
- Counterfeit injection: cloned labels and high-velocity multi-device scan bursts.
- Print pipeline tampering: replay/render-token reuse or untrusted printer impersonation.
- Insider misuse: unauthorized batch print issuance and silent continuation after hard print failures.
- Ownership abuse: claim hijacking across accounts/devices.
- Evidence tampering: post-incident log manipulation.

## Abuse Cases and Controls
- Replay of render tokens:
  - Control: one-time render token hash + single-use `usedAt` guard + print item state checks.
- Fake printer heartbeat spoofing:
  - Control: signed payload verification + mTLS fingerprint validation + trust status enforcement.
- Silent partial print failures:
  - Control: fail-stop endpoint freezes session items and creates incident automatically.
- Ownership conflict probing:
  - Control: challenge gate (captcha step-up) on suspicious ownership conflict flows.
- Scan farm behavior:
  - Control: device graph overlap, IP velocity, cross-code correlation, geo/policy triggers.

## Incident Severity Matrix

| Severity | Trigger Examples | SLA Target |
|---|---|---|
| Critical (P1) | Print fail-stop, large-scale duplicate anomaly, key trust failure in production | 4h containment |
| High (P2) | Confirmed ownership conflict cluster, policy auto-block events | 24h containment |
| Medium (P3) | Single suspicious duplicate with moderate confidence | 72h investigation |
| Low (P4) | Informational anomaly without blocking behavior | 7d review |

## Retention Policy Baseline
- Audit/forensic event minimum: 180 days (tenant-configurable upward).
- Incident and evidence bundles: retain until explicit purge policy and no legal hold tags.
- Print trust attestations: retained for investigative timeline and replay analysis windows.

## Traceability Output (GS1-compatible semantics)
- Commission / assign / print / verify / block lineage represented as immutable events.
- Per-item print lineage available through `PrintItemEvent` and forensic chain linkage.
- Export bundles include manifest + hash-chain + integrity signatures for external review.

## Security Baseline Checklist (Signed)
- [x] Cryptographic printer trust required for issuance.
- [x] Server-controlled print state machine with single-use consumption controls.
- [x] Fail-stop incident automation with super-user notification.
- [x] Adaptive duplicate detection using deterministic + anomaly inputs.
- [x] Ownership conflict challenge escalation.
- [x] Hash-chained critical event trail and immutable export support.
- [x] Deployment-ready migration + test execution requirements documented.

## Approval
- Owner: Platform Security Engineering
- Approved date: 2026-03-05
- Signature method: SHA-256 digest over approved canonical payload (archived with release artifacts).
- Canonical signature value: `426bbfea3fc1006158b3a9ae067a6745db275dd4f871f0534890865d1e2d0658`

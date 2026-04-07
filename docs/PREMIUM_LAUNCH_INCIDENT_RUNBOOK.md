# MSCQR Premium Launch Incident Runbook

This runbook is for trust-critical launch incidents that affect public verification semantics, governed issuance claims, or signer posture. It is intentionally concrete and should be used with the audit trail, policy alerts, and `verification_trust_metric` events emitted by the backend.

## 1. Replay spike

### Trigger
- Sudden increase in `verification_trust_metric` events where:
  - `publicOutcome="REVIEW_REQUIRED"`
  - `replayState IN ("CHANGED_CONTEXT_REPEAT","RAPID_CHANGED_CONTEXT_REPEAT")`

### Immediate actions
1. Confirm the spike is real in logs and not caused by a deployment or test tenant.
2. Identify affected `licenseeRef` and `batchRef` values.
3. Review recent policy alerts and incidents for the same tenant or batch.
4. If the spike is concentrated:
   - block the affected QR code or batch
   - notify the tenant operations contact
   - preserve decision/evidence snapshots before any cleanup

### Evidence to collect
- `verification_trust_metric` samples
- recent `VerificationDecision` rows
- `VerificationEvidenceSnapshot` records
- `QrScanLog` trend for the affected QRs/batches
- related policy alerts and incidents

### Exit criteria
- replay spike explained
- containment applied or ruled unnecessary
- tenant communication sent
- incident created and linked to supporting evidence

## 2. Break-glass misuse spike

### Trigger
- Any unexpected `verification_break_glass_generate` event
- Multiple break-glass events in a short period

### Immediate actions
1. Identify the `licenseeRef`, `actorRef`, and quantity involved.
2. Verify whether the issuance was part of an approved maintenance window or emergency runbook.
3. If approval is missing:
   - suspend further direct issuance
   - notify platform security and operations immediately
   - review all labels issued in the same time window

### Evidence to collect
- break-glass trust events
- audit logs from [backend/src/controllers/qrController.ts](../backend/src/controllers/qrController.ts)
- QR provenance for the affected codes
- approval records and operator notes

### Exit criteria
- misuse confirmed or disproved
- all affected labels classified
- platform owner approves continued issuance posture

## 3. Signer misconfiguration

### Trigger
- Startup refusal tied to `QR_SIGN_PROVIDER`, `QR_SIGN_ENFORCE_ED25519_IN_PRODUCTION`, or managed signer bridge checks
- trust metrics showing unexpected `signingMode="hmac"` in a premium environment

### Immediate actions
1. Stop rollout.
2. Verify environment configuration:
   - `QR_SIGN_PROVIDER`
   - `QR_SIGN_PRIVATE_KEY`
   - `QR_SIGN_PUBLIC_KEY`
   - `QR_SIGN_ACTIVE_KEY_VERSION`
   - `QR_SIGN_KMS_KEY_REF`
   - `QR_SIGN_KMS_VERIFY_KEY_REF`
3. If managed signing is selected, confirm the managed bridge implementation is present in the deployed build.
4. If HMAC fallback appears unexpectedly, treat this as a launch-blocking configuration incident.

### Evidence to collect
- startup logs
- `verification_trust_metric` samples with signing metadata
- deployment manifest / environment diff
- recent key rotation records

### Exit criteria
- signer selection is explicit and expected
- key version and provider match the approved deployment plan
- rollback or redeploy completed if needed

## 4. Legacy provenance anomaly

### Trigger
- Unexpected rise in `limitedProvenance=true`
- support reports where historical labels present weaker-than-expected governed status

### Immediate actions
1. Run the provenance backfill in dry-run mode first:
   - `npm --prefix backend run data:backfill-qr-provenance -- --limit 500 --json`
2. Review the output:
   - `UPGRADE_GOVERNED_PRINT`
   - `REPAIR_GOVERNED_READY_AT`
   - `LEAVE_UNKNOWN_HISTORICAL`
3. Execute only after review and approval:
   - `npm --prefix backend run data:backfill-qr-provenance -- --execute --limit 500`
4. Never manually upgrade `LEGACY_UNSPECIFIED` rows without direct governed-print evidence.

### Evidence to collect
- dry-run JSON output
- affected QR code sample set
- supporting print-job / print-session evidence
- support tickets or incidents tied to the anomaly

### Exit criteria
- ambiguous historical rows remain limited or unknown
- any upgraded rows have direct governed-print evidence
- operator communication updated if customer semantics changed

## 5. Challenge completion failures

### Trigger
- `challengeRequired=true` rises while `challengeCompleted=true` stays low
- customer support reports “sign in to continue” loop or repeated session rejection

### Immediate actions
1. Check whether failures are due to:
   - session proof token mismatch
   - expired proof-bound session
   - signed-in customer mismatch
2. Review `CUSTOMER_VERIFICATION_SESSION_BOUNDARY_REJECTED` audit signals.
3. Confirm the frontend is preserving the verification session proof token during sign-in and retry.
4. If the flow is broken in production, downgrade affected support guidance to “re-scan the original label” until fixed.

### Evidence to collect
- affected verification session IDs
- boundary rejection audit logs
- frontend request traces
- trust metric samples with challenge fields

### Exit criteria
- completion flow works end-to-end for the affected path
- stale or mismatched session reuse is still blocked
- support macro updated if customers are impacted

## 6. Emergency key rotation / revocation

### Immediate actions
1. Follow [SECURITY_KEY_ROTATION_RUNBOOK.md](SECURITY_KEY_ROTATION_RUNBOOK.md).
2. If using local Ed25519 keys:
   - generate a new key pair
   - set a new `QR_SIGN_ACTIVE_KEY_VERSION`
   - deploy both signing and verification updates together
3. If using managed signing:
   - rotate in the external KMS/HSM
   - update the managed bridge configuration
   - verify the deployed build reports the new `signingKeyVersion`
4. Re-check trust events for mixed-version anomalies.

### Exit criteria
- new key version visible in startup logs and trust metrics
- old compromised key disabled according to the operational plan
- premium issuance and verification posture re-approved

## 7. Communication discipline
- Never describe these controls as clone-proof or impossible to copy.
- When customer-facing impact exists, describe the event as a verification or issuance trust incident.
- Escalate to platform security before telling a tenant that a counterfeit has been confirmed unless evidence is complete.

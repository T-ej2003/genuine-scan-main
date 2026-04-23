# Verification Trust Event Catalog

MSCQR emits structured `verification_trust_metric` events for premium-launch trust monitoring. These events are privacy-minimized by default: raw QR IDs, decision IDs, actor IDs, and customer-facing secrets are not logged directly.

## Event names

### `verification_trust_metric`
- Purpose: verification-path observability for proof tier, replay state, provenance, challenge, and signing posture.
- Emitted by: [backend/src/observability/verificationTrustMetrics.ts](../../backend/src/observability/verificationTrustMetrics.ts)
- Privacy posture:
  - `decisionRef`, `qrRef`, `licenseeRef`, `batchRef`, `actorRef` are hashed references.
  - `metadata` is recursively sanitized.
  - Sensitive metadata keys such as `email`, `token`, `session`, `proof`, `actor`, `customer`, `device`, `qr`, `licensee`, and raw `id/ref` keys are dropped.

### `verification_break_glass_generate`
- Purpose: operational alerting for restricted direct issuance.
- Emitted by: [backend/src/controllers/qrController.ts](../../backend/src/controllers/qrController.ts)
- Privacy posture:
  - `licenseeRef` and `actorRef` are hashed references.
  - `quantity` is preserved for operational triage.
  - `quantityBucket` supports metrics and alert thresholds without relying on exact counts alone.

## Canonical fields

### Shared envelope
- `schemaVersion`
- `metric`

### Verification trust state fields
- `decisionRef`
- `qrRef`
- `licenseeRef`
- `batchRef`
- `proofSource`
- `proofTier`
- `classification`
- `publicOutcome`
- `riskDisposition`
- `riskBand`
- `printTrustState`
- `issuanceMode`
- `replayState`
- `challengeRequired`
- `challengeCompleted`
- `challengeCompletedBy`
- `signingMode`
- `signingKeyVersion`
- `signingProvider`
- `replacementStatus`
- `breakGlassUsage`
- `limitedProvenance`
- `metadata.sameContextRepeat`
- `metadata.changedContextRepeat`

### Break-glass issuance fields
- `licenseeRef`
- `actorRef`
- `quantity`
- `quantityBucket`

## Monitoring objectives before premium rollout
- Proof tier mix: signed-label versus manual record checks.
- Replay review-required rate: `publicOutcome=REVIEW_REQUIRED` plus replay states.
- Same-context versus changed-context signed repeats.
- Limited-provenance rate: `limitedProvenance=true` or `printTrustState=LIMITED_PROVENANCE`.
- Break-glass usage: every `verification_break_glass_generate` event must be reviewed.
- Challenge-required and challenge-completed rates.
- Signing profile health: `signingMode`, `signingProvider`, and `signingKeyVersion`.

## Saved-search examples

### Generic log query patterns
- Review-required replay:
  - `event="verification_trust_metric" metric="verification_trust_state" publicOutcome="REVIEW_REQUIRED"`
- Changed-context signed reuse:
  - `event="verification_trust_metric" replayState IN ("CHANGED_CONTEXT_REPEAT","RAPID_CHANGED_CONTEXT_REPEAT")`
- Limited provenance:
  - `event="verification_trust_metric" limitedProvenance=true`
- Break-glass issuance:
  - `event="verification_trust_metric" metric="verification_break_glass_generate"`
- Signing fallback watch:
  - `event="verification_trust_metric" signingMode="hmac"`

Machine-readable saved searches: [verification_trust_metric.saved-searches.json](verification_trust_metric.saved-searches.json)
CloudWatch deployment guide: [CLOUDWATCH_DEPLOY.md](CLOUDWATCH_DEPLOY.md)

## Release gate expectation
- These events must be visible in the production log pipeline before premium-client launch.
- Alert rules derived from this catalog must be configured and tested.
- Alert destination bindings should be maintained from [verification_trust_metric.alert-bindings.template.json](verification_trust_metric.alert-bindings.template.json).
- Metric extraction should follow [verification_trust_metric.metrics.yml](verification_trust_metric.metrics.yml) so replay, provenance, challenge, and signer posture are measured consistently.
- Privacy review must confirm that no raw customer identifiers or proof/session tokens are emitted.

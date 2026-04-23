# CloudWatch Trust Observability Deployment

This guide applies MSCQR trust event metric filters and alarm rules in AWS (Lightsail/AWS account).

## Files of record

- `docs/observability/cloudwatch/verification-trust-metric-filters.json`
- `docs/observability/cloudwatch/verification-trust-alarms.json`

## Preconditions

- Application logs for `verification_trust_metric` are flowing to a CloudWatch log group.
- An SNS topic exists for on-call routing.
- `snsTopicArn` in alarms config is set to your real account/topic ARN.

## 1) Validate config in repo

```bash
npm run check:cloudwatch-config
```

For destination enforcement:

```bash
ENFORCE_CLOUDWATCH_DESTINATIONS=true npm run check:cloudwatch-config
```

## 2) Apply metric filters

Use the JSON file as source-of-truth and apply each filter with `aws logs put-metric-filter`.

Example:

```bash
aws logs put-metric-filter \
  --log-group-name "/mscqr/backend/application" \
  --filter-name "mscqr-trust-replay-review-required" \
  --filter-pattern '{ $.metric = "verification_trust_state" && $.publicOutcome = "REVIEW_REQUIRED" }' \
  --metric-transformations metricName=ReplayReviewRequiredCount,metricNamespace=MSCQR/Trust,metricValue=1
```

Repeat for all entries in `verification-trust-metric-filters.json`.

## 3) Apply alarms

Create/update alarms with `aws cloudwatch put-metric-alarm` using thresholds and periods from `verification-trust-alarms.json`.

Use SNS actions:

- `--alarm-actions <snsTopicArn>`
- `--ok-actions <snsTopicArn>`

For expression-based alarm (`mscqr-trust-challenge-completion-drop`), use metric math IDs exactly as defined.

## 4) Verify alarms are active

```bash
aws cloudwatch describe-alarms --alarm-name-prefix mscqr-trust-
```

Confirm all required names exist and state is not `INSUFFICIENT_DATA` for extended periods.

## 5) Test-fire and evidence

Trigger controlled test events (non-customer-impacting) and confirm SNS/on-call delivery for:

- replay review spike
- break-glass usage
- signing fallback

Archive:

- alarm transition screenshot/log
- on-call notification screenshot/log
- timestamp + operator name


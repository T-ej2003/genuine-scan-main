# Rate Limit Metric Event Catalog

MSCQR emits a structured `rate_limit_metric` warning event whenever a limiter returns HTTP `429`.

## Event fields

| Field | Meaning |
| --- | --- |
| `scope` | Exact limiter scope, including stage suffixes such as `:pre-auth`, `:ip`, or `:actor` |
| `family` | Route-family key without the stage suffix, for example `licensees.read` or `audit.export` |
| `stage` | `route`, `pre-auth`, `ip`, or `actor` |
| `method` | HTTP method for the throttled request |
| `route` | Normalized route pattern |
| `authModel` | `anonymous`, `bearer`, `cookie`, or `authenticated` |
| `offenderKind` | How the offender was fingerprinted, such as `user`, `bearer`, `gateway`, `device`, or `ip-ua` |
| `offenderRef` | Privacy-safe hashed offender fingerprint |
| `tenantRef` | Privacy-safe hashed tenant/licensee reference when known |
| `resourceRef` | Privacy-safe hashed resource identifier when known |
| `userRole` | Authenticated role when present |
| `retryAfterSec` | Retry delay communicated to clients |

## Priority route families

- `licensees.*`
- `governance.*`
- `audit.*`
- `verify.claim*`
- `printer-agent.*`
- `support.*`
- `exports.*`
- `gateway.*`

## Operator use

- Dashboard input: `/security/abuse/rate-limits`
- Alert feed input: `/security/abuse/rate-limits/alerts`
- Saved search source: [rate_limit_metric.saved-searches.json](/Users/abhiramteja/Downloads/genuine-scan-main/documents/observability/rate_limit_metric.saved-searches.json)
- Alert templates: [rate_limit_metric.alert-rules.yml](/Users/abhiramteja/Downloads/genuine-scan-main/documents/observability/rate_limit_metric.alert-rules.yml)

## Privacy rules

- Never log raw bearer tokens, cookies, tenant IDs, transfer IDs, or printer/gateway secrets.
- Use hashed refs only.
- Keep route names normalized and avoid raw query payload logging.

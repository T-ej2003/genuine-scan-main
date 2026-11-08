# Manufacturer session-capability denial diagnostics

## Current evidence boundary

On 2026-11-08, a bounded CloudWatch sample from `/ecs/mscqr-production/rls-green-backend` showed `42501 AUTH_SESSION_CAPABILITY_DENIED` Prisma events on two backend task streams. The sampled error events contained no request ID, endpoint, session selector, or tenant selector. Nearby `/health/live` request records have their own IDs; time and task-stream proximity do not establish a join. The running backend was on `e39bd219…`, before the request-ID validation in PR #807. No manufacturer or session target was established.

The checked-in `app_auth.auth_session_prepare` and `app_auth.require_authenticated_session` functions reuse the same denial text for invalid input, missing or expired capability-bound refresh rows, inactive actors, and unsupported assurance. Historical generic errors cannot be assigned one of those predicates from the existing log line. Failed transactions also cannot be assumed to have a committed audit row.

## Capture the next failure

The application-side `requireAuthenticatedSessionCapability` boundary emits one JSON line for either a SQL capability denial or its own empty/invalid-result denial. The line contains `event=auth_session_capability_denied`, an ISO timestamp, and a request ID only when it matches the HTTP entrypoint's UUID contract. It does not log capabilities, tokens, SQL error text, actor IDs, or tenant IDs. Logging failures leave the original denial and HTTP behavior unchanged. This requires a reviewed backend release; it is not active in production merely because this source exists.

In CloudWatch Logs Insights, select log group `/ecs/mscqr-production/rls-green-backend` and a bounded UTC time range, then run:

```sql
fields @timestamp, @logStream, @message
| filter @message like /auth_session_capability_denied/
| sort @timestamp desc
| limit 50
```

Each returned `@message` is one JSON log entry. With `LOG_FORMAT=json`, the correlation JSON is inside the outer entry's `message` field. With the plain logger, the correlation JSON is the entry itself. The query finds the fixed event name in either format. A null request ID cannot be joined to an HTTP request.

After deployment, use a bounded CloudWatch time window and exact task stream to find this event. Join its request ID to the existing `HTTP request completed` record only on exact ID equality within that window and stream. A valid client-supplied UUID is still untrusted correlation metadata, never authentication or authorization proof. A source-bound, approved read-only database diagnostic may then use an explicitly authorized target if the exact SQL predicate is still needed. An email address, timestamp, or IP address alone is not a failed-session selector. Do not query account-specific tables or grant canary table access on that basis.

If no joined request is available, obtain a sanitized failing `X-Request-Id` and UTC timestamp from an authorized request, plus the endpoint. If a database target must be inspected, separately approve the precise tenant and session or user identifier, diagnostic operation, expiry, and auditor. Preserve FORCE RLS and existing capability checks. Do not deploy a new SQL interface or use the database-admin diagnostic task without its own review and authorization.

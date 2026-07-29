# RC staging smoke

Staging is currently not provisioned. The authoritative `staging` environment sets `STAGING_SMOKE_ENABLED=false`; the required `rc-staging-smoke` check reports `staging_not_provisioned` without making a network request. Production hosts are prohibited in both modes.

After a staging deployment exists, set `STAGING_SMOKE_ENABLED=true`, set HTTPS `STAGING_SMOKE_BASE_URL` and `STAGING_SMOKE_API_BASE_URL` to the same non-production origin, and provide `STAGING_SMOKE_LOGIN_EMAIL`, `STAGING_SMOKE_LOGIN_PASSWORD`, and optional `STAGING_SMOKE_VERIFY_CODE` in the `staging` environment. The target health response must report `environment=staging` before live authentication smoke is allowed.

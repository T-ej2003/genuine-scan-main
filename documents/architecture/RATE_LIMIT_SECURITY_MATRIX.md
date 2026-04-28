# MSCQR Rate-Limit Security Matrix

This matrix is the abuse-control contract for MSCQR backend routes. Each route family must declare:

- its auth model
- its direct pre-auth route-family limiter, when the route is protected or customer-cookie aware
- its post-auth actor/IP limiter family
- whether CSRF is required

Route families below are grouped by security model so abuse budgets can be tuned without guessing.

| Route family | Auth model | Pre-auth limiter | Post-auth limiter | CSRF |
| --- | --- | --- | --- | --- |
| `auth.login` | Public mutation | n/a | `auth.login:ip`, `auth.login:actor` | No |
| `auth.invite` | Public mutation | n/a | `auth.invite:ip`, `auth.invite:actor` | No |
| `auth.verify-email` | Public mutation | n/a | `auth.verify-email:ip`, `auth.verify-email:actor` | No |
| `auth.password-reset` | Public mutation | n/a | `auth.password-reset:ip`, `auth.password-reset:actor` | No |
| `auth.session-read` | Protected read | `auth.session-read:pre-auth` | `auth.session-read` | No |
| `account.security` | Cookie/bearer mutation | n/a | `account.security`, `account.security:ip`, `account.security:actor` | Yes |
| `admin.mfa` | Privileged mutation | n/a | `admin.mfa`, `admin.mfa:ip`, `admin.mfa:actor` | Yes |
| `admin.invite` | Privileged mutation | `admin.invite:pre-auth` | `admin.invite`, `admin.invite:ip`, `admin.invite:actor` | Yes |
| `verify.lookup` | Cookie read | n/a | `verify.lookup`, `verify.code:ip`, `verify.code:actor` | No |
| `verify.providers` | Public read | n/a | `verify.providers`, `verify.code:ip`, `verify.code:actor` | No |
| `verify.otp-request` | Public mutation | n/a | `verify.otp-request`, `verify.otp-request:ip`, `verify.otp-request:actor` | No |
| `verify.customer-session` | Cookie read | `verify.customer-session:pre-auth` | `verify.customer-session`, `verify.customer-session:ip`, `verify.customer-session:actor` | No |
| `verify.customer-auth` | Public mutation | `verify.customer-auth:pre-auth` | `verify.customer-auth`, `verify.customer-auth:ip`, `verify.customer-auth:actor` | No |
| `verify.customer-cookie` | Cookie mutation | `verify.customer-cookie:pre-auth` | `verify.customer-cookie`, `verify.customer-cookie:ip`, `verify.customer-cookie:actor` | Yes |
| `verify.claim` | Cookie mutation | `verify.claim:pre-auth` | `verify.claim`, `verify.claim:ip`, `verify.claim:actor` | Yes |
| `telemetry.mutation` | Optional-auth cookie mutation | `telemetry.mutation:pre-auth` | `telemetry.mutation`, `telemetry.route-transition:ip`, `telemetry.route-transition:actor` | No |
| `telemetry.csp` | Optional-auth public mutation | `telemetry.csp:pre-auth` | `telemetry.csp`, `telemetry.csp-report:ip`, `telemetry.csp-report:actor` | No |
| `public.status` | Public read | n/a | `public.status:ip`, `public.status:actor` | No |
| `licensees.read` | Protected read | `licensees.read:pre-auth` | `licensees.read`, `protected.read` | No |
| `licensees.export` | Protected read/export | `licensees.export:pre-auth` | `licensees.export`, `exports.downloads`, `exports.downloads:ip`, `exports.downloads:actor` | No |
| `licensees.mutation` | Privileged mutation | `licensees.mutation:pre-auth` | `licensees.mutation`, `protected.mutation` | Yes |
| `admin.directory.read` | Protected read | `admin.directory.read:pre-auth` | `admin.directory.read`, `protected.read` | No |
| `admin.directory.mutation` | Privileged mutation | `admin.directory.mutation:pre-auth` | `admin.directory.mutation`, `protected.mutation` | Yes |
| `qr.read` | Protected read | `qr.read:pre-auth` | `qr.read`, `protected.read` | No |
| `qr.export` | Protected read/export | `qr.export:pre-auth` | `qr.export`, `exports.downloads`, `exports.downloads:ip`, `exports.downloads:actor` | No |
| `qr.mutation` | Privileged mutation | `qr.mutation:pre-auth` | `qr.mutation`, `protected.mutation` | Yes |
| `qr.requests.read` | Protected read | `qr.requests.read:pre-auth` | `qr.requests.read`, `protected.read` | No |
| `qr.requests.mutation` | Privileged mutation | `qr.requests.mutation:pre-auth` | `qr.requests.mutation`, `protected.mutation` | Yes |
| `policy.read` | Protected read | `policy.read:pre-auth` | `policy.read`, `protected.read` | No |
| `policy.mutation` | Privileged mutation | `policy.mutation:pre-auth` | `policy.mutation`, `protected.mutation` | Yes |
| `support.read` | Protected read | `support.read:pre-auth` | `support.read`, `protected.read` | No |
| `support.mutation` | Privileged mutation | `support.mutation:pre-auth` | `support.mutation`, `protected.mutation` | Yes |
| `incidents.read` | Protected read | `incidents.read:pre-auth` | `incidents.read`, `protected.read` | No |
| `incidents.mutation` | Privileged mutation | `incidents.mutation:pre-auth` | `incidents.mutation`, `protected.mutation` | Yes |
| `incidents.export` | Protected read/export | `incidents.export:pre-auth` | `incidents.export`, `exports.downloads`, `exports.downloads:ip`, `exports.downloads:actor` | No |
| `ir.read` | Protected read | `ir.read:pre-auth` | `ir.read`, `protected.read` | No |
| `ir.mutation` | Privileged mutation | `ir.mutation:pre-auth` | `ir.mutation`, `protected.mutation` | Yes |
| `account.mutation` | Protected cookie/bearer mutation | `account.mutation:pre-auth` | `account.mutation`, `protected.mutation` | Yes |
| `internal.release` | Protected read | `internal.release:pre-auth` | `internal.release`, `internal.release:ip`, `internal.release:actor` | No |
| `security-ops.read` | Protected read | `security-ops.read:pre-auth` | `security-ops.read`, `security-ops.read:ip`, `security-ops.read:actor` | No |
| `audit.package-export` | Protected read/export | `audit.package-export:pre-auth` | `audit.package-export`, `exports.downloads`, `exports.downloads:ip`, `exports.downloads:actor` | No |
| `audit.read` | Protected read | `audit.logs-read:pre-auth` | `audit.read`, `audit.read:ip`, `audit.read:actor` | No |
| `audit.export` | Protected read/export | `audit.logs-export:pre-auth` | `audit.export`, `audit.export:ip`, `audit.export:actor` | No |
| `audit.stream` | Protected stream | `audit.stream:pre-auth` | `audit.read`, `audit.stream:ip`, `audit.stream:actor` | No |
| `audit.fraud-read` | Protected read | `audit.fraud-read:pre-auth` | `audit.fraud-read`, `audit.read:ip`, `audit.read:actor` | No |
| `audit.fraud-mutation` | Privileged mutation | `audit.fraud-mutation:pre-auth` | `audit.fraud-mutation`, `audit.mutation:ip`, `audit.mutation:actor` | Yes |
| `governance.read` | Protected read | `governance.read:pre-auth` | `governance.read`, `governance.read:ip`, `governance.read:actor` | No |
| `governance.export` | Protected read/export | `governance.export:pre-auth` | `governance.export`, `governance.export:ip`, `governance.export:actor` | No |
| `governance.mutation` | Privileged mutation | `governance.mutation:pre-auth` | `governance.mutation`, `governance.mutation:ip`, `governance.mutation:actor` | Yes |
| `governance.approval-mutation` | Privileged mutation | `governance.approval-mutation:pre-auth` | `governance.approval-mutation`, `governance.approval-mutation:ip`, `governance.approval-mutation:actor` | Yes |
| `realtime.dashboard-read` | Protected read | `realtime.dashboard-read:pre-auth` | `realtime.dashboard-read`, `realtime.dashboard-read:ip`, `realtime.dashboard-read:actor` | No |
| `realtime.dashboard-stream` | Protected stream | `realtime.dashboard-stream:pre-auth` | `realtime.dashboard-stream`, `realtime.dashboard-stream:ip`, `realtime.dashboard-stream:actor` | No |
| `realtime.notifications-read` | Protected read/stream | `realtime.notifications-read:pre-auth` | `realtime.notifications-read`, `realtime.notifications-read:ip`, `realtime.notifications-read:actor` | No |
| `realtime.notifications-mutation` | Protected mutation | `realtime.notifications-mutation:pre-auth` | `realtime.notifications-mutation`, `realtime.notifications-mutation:ip`, `realtime.notifications-mutation:actor` | Yes |
| `printer-agent.status` | Protected read | `printer-agent.status:pre-auth` | `printer-agent.status`, `printer-agent.status:ip`, `printer-agent.status:actor` | No |
| `printer-agent.events` | Protected stream | `printer-agent.events:pre-auth` | `printer-agent.events`, `printer-agent.events:ip`, `printer-agent.events:actor` | No |
| `printer-agent.heartbeat` | Protected mutation | `printer-agent.heartbeat:pre-auth` | `printer-agent.heartbeat`, `printer-agent.heartbeat:ip`, `printer-agent.heartbeat:actor` | Yes |
| `gateway.heartbeat` | Machine/gateway mutation | n/a | `gateway.heartbeat`, `gateway.heartbeat:ip`, `gateway.heartbeat:actor` | No |
| `gateway.jobs` | Machine/gateway mutation | n/a | `gateway.jobs`, `gateway.jobs:ip`, `gateway.jobs:actor` | No |
| `print.read` | Protected read | n/a | `print.read`, `protected.read` | No |
| `print.export` | Protected read/export | n/a | `print.export`, `exports.downloads`, `exports.downloads:ip`, `exports.downloads:actor` | No |
| `print.mutation` | Protected mutation | n/a | `print.mutation`, `print.mutation:ip`, `print.mutation:actor` | Yes |

## Abuse-tuning notes

- Pre-auth limiters are for scanner visibility, token spray resistance, and tenant-burst protection before authorization finishes.
- Post-auth actor/IP limiters are the stronger identity-aware controls and should not be removed when pre-auth guards are added.
- Export families should always remain separate from general reads so expensive download work can be tightened independently.
- `printer-agent.*`, `gateway.*`, `support.*`, `audit.*`, `governance.*`, `licensees.*`, and `verify.claim*` are first-class telemetry families and should stay stable for dashboards and alerts.

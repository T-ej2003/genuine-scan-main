# Super-admin multi-user and high-risk login audit

## Scope and evidence

This review used protected commit `6d5a48ce7c32b12ce8671731392f92ddfa625a88` in an isolated worktree. It made no production calls or writes. The initial-super-admin bootstrap was not invoked.

## Login decision

`POST /api/auth/login` validates the request, derives `ipHash` from `req.ip`, and calls `loginWithPassword`. That function requires one existing active, non-disabled user with a password, a verified email, and a valid password. It then calculates risk from the user's recent sessions in a pre-auth transaction.

The score is the privileged-role baseline (10) plus failed attempts (up to 25), first-known-session (8), changed source IP (35), changed user agent (20), and three or more recent source-IP hashes (25). At the default block threshold (85), a `SUPER_ADMIN` or `PLATFORM_SUPER_ADMIN` is audited with `AUTH_LOGIN_BLOCKED_RISK` and receives the observed 403. No MFA challenge is offered first.

The effective fallback is `AUTH_RISK_BLOCK_THRESHOLD=85`. Before this remediation, the baseline used only `AUTH_RISK_STEPUP_THRESHOLD` (without `_` between `STEP` and `UP`) with fallback `55`.

## Established defects

`assessAuthSessionRisk` calculates `shouldStepUp`, but no production caller consumes it. Thus a score from 55 through 84 does not itself require a fresh MFA challenge. Platform admins instead follow the independent `ADMIN_LOGIN_MFA_CYCLE_DAYS` rule: a currently enabled factor used within 28 days creates an active `ADMIN_MFA` session; an older or absent factor produces an MFA-bootstrap session. This fails the intended risk-tier behaviour: score 55-84 should force step-up and score 85+ should remain a hard block.

The Express application configures `trust proxy` as `1`. For the stated CloudFront -> ALB -> Express chain this trusts only the ALB hop, so `req.ip` resolves to the CloudFront hop rather than the viewer address. Because login risk stores and compares `hashIp(req.ip)`, CloudFront edge changes can look like client-IP changes and actual viewer-IP changes can be hidden. This materially affects both the changed-IP and three-IP risk inputs. Do not change proxy configuration without a deployment-specific trusted-proxy boundary and a proxy-chain test.

## Multi-super-admin model and provisioning

The data model permits multiple `User` rows with the same role and unique emails. Refresh tokens, MFA credentials, WebAuthn credentials, MFA factors, challenges, backup codes, session capabilities, risk signals, and audit records are linked to `userId`; each new user remains a separate principal.

The canonical supported path is an authenticated platform administrator with fresh MFA calling `POST /api/auth/invite` with a platform role and no tenant selectors. `app_rls.prepare_invitation` creates a distinct `INVITED` user and one-time invitation, records `AUTH_INVITE_CREATED` with actor and target identity, and acceptance creates the password, verifies the email, activates the user, and writes `AUTH_INVITE_ACCEPTED`. The new user must complete individual MFA enrollment at first MFA-bootstrap login.

The initial bootstrap is deliberately single-use: `app_ops.bootstrap_configured_super_admin` returns `skipped_existing` when any platform administrator exists. It is not the additional-administrator path.

Both `SUPER_ADMIN` and `PLATFORM_SUPER_ADMIN` normalize to frontend `super_admin`; route metadata and backend platform-role guards authorize by role, not email or a hard-coded user ID. `administration@mscqr.com` appears only as a contact/default sender, test fixture, or screenshot fixture, not as an authorization predicate. The bootstrap's canary exception and first-existing-admin guard are singleton bootstrap controls, not runtime authorization.

## Before

Scores in the step-up range were calculated but ignored; a recent 28-day MFA use could create an active session. Express trusted one proxy hop, causing the CloudFront edge address rather than the viewer address to populate `req.ip` for a CloudFront -> ALB -> ECS path. The step-up configuration was only named `AUTH_RISK_STEPUP_THRESHOLD`.

## After

`risk.shouldStepUp` now prevents the recent-MFA-cycle fast path. Scores from the step-up threshold through one below the block threshold return only `MFA_BOOTSTRAP`; no access or refresh token is returned before a bound MFA challenge is completed. Score 85 and above remains a blocked-login transaction with the existing governed audit write.

The canonical setting is `AUTH_RISK_STEP_UP_THRESHOLD`. The legacy `AUTH_RISK_STEPUP_THRESHOLD` remains supported only when it is the sole supplied value or matches the canonical value. Invalid values, conflicting values, and `step-up >= block` fail closed. Defaults remain 55 and 85.

## Security invariants

- A block-risk platform login writes the governed `AUTH_LOGIN_BLOCKED_RISK` event before returning 403; an audit failure denies login.
- A risk-triggered MFA bootstrap has no full refresh token and uses the existing user-bound, session-bound, expiring, replay-protected MFA challenge flow.
- Two platform-admin users continue to have separate `User` identities. Every session, MFA credential/factor, challenge, refresh token, risk signal, and audit record is keyed by user ID.
- Role authorization remains role-based: `SUPER_ADMIN` and `PLATFORM_SUPER_ADMIN` normalize to the frontend super-admin surface; no email is an authorization key.

## Configuration contract

```env
AUTH_RISK_STEP_UP_THRESHOLD=55
AUTH_RISK_BLOCK_THRESHOLD=85
```

Both values must be decimal integers with `0 <= STEP_UP < BLOCK <= 100`. A legacy rollout may use `AUTH_RISK_STEPUP_THRESHOLD`, but setting both to different values is an error.

## Proxy trust contract

ASG production uses `CLIENT_IP_TRUST_MODE=cloudfront-alb-nginx`: CloudFront -> ALB -> the fixed frontend nginx address -> backend. It starts only with reviewed non-empty nginx, ALB, and CloudFront CIDR lists. The backend socket must be the configured nginx address; the terminal XFF address must be the ALB; the preceding address must be CloudFront; and the preceding address is the viewer installed as `req.ip`. Earlier forwarded entries are ignored, so a viewer-supplied prefix cannot select the client identity. The ASG manifest requires the ALB and CloudFront lists and a reviewed application-network subnet/frontend address; bootstrap requires the nginx CIDR to match that frontend address exactly. Direct, shortened, malformed, or untrusted chains receive a generic 400. Loopback-only `/health/live` is the sole direct exception, so the backend container health check can run without a proxy header.

Read-only AWS inspection found that the current CloudFront distribution does not forward `CloudFront-Viewer-Address` or configure an edge-attestation origin header. This implementation intentionally uses the documented XFF append positions and deployment must supply/review all proxy CIDRs and verify the live chain before activation. No infrastructure was changed here.

## Test evidence

`npm run build` passed in `backend`. The focused suite passed: `sessionRiskThresholds`, `authAdminLoginMfaCycle`, `clientIpTrust`, and `authMfaChallengeStateMachine`.

The risk suite proves fallback/config rejection, low/new-IP/new-agent/new-device scoring, normal new-device step-up without hard block, three-IP and combined block scoring. The login suite proves 55, 70, and 84 force MFA bootstrap despite recent MFA and that 85 and 86 preserve hard block. The proxy suite proves CloudFront -> ALB resolution, spoofed prefixes, direct/short/untrusted paths, and IPv4/IPv6 chain handling.

The PostgreSQL invitation application-path test was run against a new loopback-only, disposable PostgreSQL 18 container. It stopped before the invitation cases because the fixture does not provision the authenticated-session capability required by current authenticated routes; the route returns 401 rather than bypassing that boundary. The fixture's runtime role names were aligned with the current runtime-role validator, but the missing capability setup remains a separate test-harness defect. No security requirement was bypassed. Consequently, full two-principal invitation/MFA/session/risk end-to-end proof remains incomplete.

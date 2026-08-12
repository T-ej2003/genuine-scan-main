# MSCQR production onboarding contract

This contract separates an onboarding-safe overlap deployment from a closed signing-material rotation.

## Onboarding-safe overlap

`READY_FOR_ONBOARDING` may be proven while the service runs with `CURRENT=B` and `PREVIOUS=A`.
The final protected-main source SHA, signed image digest, stable target deployment, health release SHA,
prepared JWT and QR fixtures, cookie continuity, independent artifact signing, authentication, bootstrap,
tenant/RBAC/security smokes, dependencies, and Stage-A networking must all pass.

The overlap proof is runtime evidence from the exact ECS task selected by the ECS Exec verifier. It must not
be converted into final rotation freshness evidence, and it must not claim that old material has been retired.

## Rotation closed

`ROTATION_CLOSED` is separate. It requires the persisted grace deadline, previous and pending retirement,
cleanup deployment after retirement, cleanup runtime proof, old JWT/QR rejection, and fresh final evidence.
If cleanup deployment fails after retirement, retry cleanup forward; do not restore retired secrets automatically.

## Artifact signing and ECS Exec

Compliance and immutable-audit artifacts use independent Ed25519 signing with an explicit `keyVersion` and
bounded historical public-key registry. JWT, QR signing, and QR HMAC material are never artifact fallbacks;
production startup fails closed when the artifact configuration is missing or inconsistent.

The canonical deployment wrapper receives `ENABLE_EXECUTE_COMMAND=true` for the overlap and cleanup service
update. It performs the task-definition switch and ECS Exec enablement in one reviewed `UpdateService` mutation,
waits for stability, and verifies the service flag before the verifier is invoked. The verifier then selects the
exact cluster/service/task definition/image/release, transfers the 0600 fixture through
PTY stdin, runs inside `/app`, deletes fixture and proof files, and prints only redacted proof metadata. The
historical-artifact proof input must be an approved existing artifact envelope; it is never generated from a
deployed secret and its payload/signature is never printed.

## Onboarding smoke

Use the reviewed production-green canary tenant/account and approved secret-store credentials. Run login, MFA,
`/api/auth/me`, refresh, dashboard stats, QR stats, and public `/api/verify/:code` with a tagged synthetic run identifier.
Customer credentials and customer QR payloads are prohibited; provisioning is operational and not performed here.

## Deterministic security probes

The strict production probe manifest is generated from the mounted route contract. `tenantIsolation` logs in with
the existing production-green canary `LICENSEE_ADMIN` principal and reads the deterministic isolation-control
licensee `GET /api/licensees/4e5d6a2d-42cd-4b87-ac85-793e2e72b95c`; the target is deliberately outside that
principal's tenant and `403` or `404` is required. A platform-admin session, a fabricated target, and a successful
empty response are not valid tenant-isolation evidence. `rbac` reads `GET /api/manufacturer/printer-agent/status`,
while the audit, printer-trust, and artifact-signing probes use their reviewed read endpoints.

`antiCloning` and `publicQrVerification` intentionally share `GET /api/verify/:code`. After rotation preparation,
the coordinator's 0600 rotation fixture supplies the identifier-only synthetic signed token in memory. The public
and anti-cloning probes send it through the dedicated `X-MSCQR-Verification-Token` header, never the query string;
the public probe verifies it, and the anti-cloning probe changes one signature byte and requires the route's rejection
status. The backend records only the route template, so the token is never placed in the onboarding manifest, URL,
nginx/application request logs, command line, or onboarding evidence.

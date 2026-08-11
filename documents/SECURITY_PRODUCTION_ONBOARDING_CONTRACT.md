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

The verifier selects the exact cluster/service/task definition/image/release, transfers the 0600 fixture through
PTY stdin, runs inside `/app`, deletes fixture and proof files, and prints only redacted proof metadata. The
historical-artifact proof input must be an approved existing artifact envelope; it is never generated from a
deployed secret and its payload/signature is never printed.

## Onboarding smoke

Use a dedicated synthetic tenant/account and approved secret-store credentials. Run login, MFA, `/api/auth/me`,
refresh, dashboard stats, QR stats, and public `/api/verify/:code` with a tagged synthetic run identifier.
Customer credentials and customer QR payloads are prohibited; provisioning is operational and not performed here.

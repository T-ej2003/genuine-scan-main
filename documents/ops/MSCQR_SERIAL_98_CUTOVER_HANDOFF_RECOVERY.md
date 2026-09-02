# Serial-98 cutover handoff recovery

The serial-98 continuation uses three explicit, identifier-only boundaries:

- `SUPERSEDE_STALE_PENDING`: the stale dual-slot rotation is accepted only when every reviewed secret slot still carries the exact stale source and rotation ID. The transition writes a new source/rotation identity with deterministic request tokens and records version IDs; it never logs secret values or silently rebinds the old identity.
- `POST_APPLY_STAGE_A_PLAN_RECOVERY`: when the historical binary Stage-A plan is unavailable, this is evidence of converged Stage-A state, hash-bound handoff provenance, serial-98 Stage-B state, and a fresh read-only ingress postcondition. At cutover, the release profile rereads the canonical Stage-A and Stage-B state objects and the ingress rule before accepting the evidence. It is not a reconstructed Terraform plan and cannot authorize an apply.
- Root-drop evidence: `produce-production-root-drop-evidence.mjs` requires an explicitly selected root operator profile, verifies the exact root caller with STS, and signs the canonical root payload with the dedicated root-only KMS key. The schema-v2 signed bytes bind the exact source, rotation, image authorization, successor-recovery authorization, administrator evidence, and administrator signature as well as caller/account/region/freshness/nonce. The release bootstrap independently verifies every binding; a self-hashed JSON object or a prior weak schema cannot authorize continuation. Provisioning the new Stage-A root-drop key is a separate reviewed infrastructure prerequisite; this PR does not apply it.

The cutover runtime accepts exactly one Stage-A input: a preserved saved plan or
the explicit post-apply recovery evidence. Existing saved-plan behavior remains
unchanged. All artifacts are written outside the repository with the Stage-B
private artifact contract (directory `0700`, file `0600`, atomic publication).

Recommended operator sequence after reviewed merge: obtain fresh protected-main
identity, run stale-rotation supersession only after its expected-state check,
produce root-drop evidence from an authenticated root boundary, generate
post-apply Stage-A recovery evidence from serial-98 read-only observations, and
then run the existing cutover wrapper. Never reuse stale rotation records or
run Terraform again for this continuation.

## Fail-closed handoff invariants

- Rotation supersession classifies every slot as `OLD_AUTHENTICATED`, `NEW_AUTHENTICATED`, `UNKNOWN`, or `INVALID`. Only an authenticated old-only state writes; an authenticated old/new prefix resumes missing slots; all-new is a zero-write replay. Every write uses a deterministic source/rotation/slot request token.
- Supersession evidence uses exact create-or-verify publication: an exact existing result is reused with zero secret writes, while malformed, stale, substituted, or mismatched evidence fails closed and is never overwritten.
- Replacement QR/JWT material is generated with OS CSPRNG entropy and retained only in an owner-readable atomic `.material` journal beside the private binding output until the seven-slot transition is durably verified; the journal is never published as evidence and is removed on success.
- Secrets Manager and AWS CLI reads/writes use an explicit credential profile/provider and independently verify the production account and release-deployer principal. Ambient static credential variables cannot override a selected profile.
- Post-apply Stage-A recovery reuses the existing Stage-A state contract. Metadata-only state is rejected; the state must contain the reviewed outputs, indexed networking resources, exact security-group identities, runtime roles, approval resources, and checker role-chain policy. The ingress proof is state-derived and must be TCP/443 endpoint-to-runtime ingress.
- Root evidence verification requires the existing KMS trust root, exact account/region/root ARN, protected source, freshness, canonical payload hash, and valid signature. No secret, credential, or MFA value is stored in the artifact.

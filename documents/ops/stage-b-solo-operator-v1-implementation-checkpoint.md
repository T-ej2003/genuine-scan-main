# Stage B solo-operator disabled implementation and activation boundary

Source baseline: `24b5504d1077099e3175ba8d4529e847f603e27c`.
Decision package SHA-256: `4672d9162b8336cbf01acfbc9aa035fb54650007929d0f9adec27ad1a93b3033`.
Historical broker release: `475dc456ecda56e7f3386adeffa8c2e3dc632777`.

The conditional production lane remains source-disabled. This change does not authorize solo production operation or issue any production evidence.

## Verified source boundaries

- `production-cutover-conditional-issuance.mjs` issues root, adoption and successor KMS evidence. It has a confirmed immutable issuance claim and one native Sign attempt. Its `approvedRequestSha256` argument checks bytes, but does **not** authenticate the human who approved those bytes.
- `production-cutover-conditional-workflow.mjs` issues the prepare-overlap artifact through the existing protected Stage B workflow. The producer and consumer authenticate GitHub run, artifact and approval data. Their independent-human mode must compare actual stable user IDs even when GitHub allows self-review.
- `production-cutover-conditional-authorization.mjs` authenticates the four phase envelopes and a sealed derivation. A new solo grant requires a distinct signed schema and actual operator-approval provenance; old envelopes retain their historical meaning.
- `production-cutover-consumption-journal.mjs` holds the global rotation/predecessor claim and phase/native claims. These keys must remain policy-independent. An ambiguous native outcome remains `OUTCOME_UNKNOWN`; a write-once receipt is not proof of exactly-once execution.
- `production-cutover-registration-reconciliation.mjs` binds CloudTrail audit to the release-deployer that dispatched ECS registration. There is no authenticated equivalent read principal in the current source. The proposed, unapplied permission statement is:

```json
{"Sid":"ReadOnlyConditionalEcsRegistrationAuditEuWest2","Effect":"Allow","Action":"cloudtrail:LookupEvents","Resource":"*","Condition":{"StringEquals":{"aws:RequestedRegion":"eu-west-2"}}}
```

The `Resource: "*"` is limited to this read action because LookupEvents does not support resource-level IAM scoping. This is a separate production IAM authorization and must not be applied by the source PR.

## Source implementation and deliberate fail-closed interfaces

The checker signer cannot call `kms:GetKeyPolicy`; its Stage A permission contract intentionally excludes it. The existing release-deployer can read the exact key policy. The source correction uses that fixed role only for policy metadata, verifies the key and policy before dispatch and again before Sign, and leaves the checker as the sole signer. Focused tests verify wrong metadata reader and policy drift fail before Sign.

The V2 adoption and successor consumers now require a separate signed phase-approval envelope. Verification binds the designated issuer key, policy hash, phase, derivation, exact issuance request, operator identity and session, MFA attestation digest, issue/expiry times and unique authorization ID. The production issuer is deliberately **not designated**: `issueSoloPhaseApproval` rejects every call. A caller-provided request hash or signer callback cannot assert human consent. The local positive tests sign synthetic fixtures; they are not production approval evidence. Root-drop cannot use V2 solo authorization.

The issuer's configured policy hash alone is not proof of a current KMS policy. Before either signed human approval or ACTIVE/SUSPENDED/REVOKED state is accepted, `authenticateSoloIssuerTrust` must read that exact key's public key and current policy through the fixed release-deployer metadata role. It compares the live policy with the pinned hash and returns a process-local verified trust object valid for at most 15 minutes; unverified trust objects fail closed. Future production activation must wire that fixed-role live read into both issuance and continuation and designate the pinned issuer policies. No such live issuer trust is present in the disabled production path.

The current checker credential runner inherits an assumed-role session. `sts:GetCallerIdentity` proves that role session, and the Stage A IAM trust contract proves the first-hop role requires MFA from the checker IAM user. Neither result by itself proves which human held the specific inherited session. Any solo approval producer must establish that session-to-human link with authenticated evidence; a caller-supplied `operatorAwsUserArn` or session name is insufficient.

The authority-state verifier supports signed ACTIVE, SUSPENDED and REVOKED records bound to the exact policy, operator, source and rotation. It requires a confirmed conditional claim and readback in the existing encrypted release coordinator; missing ACTIVE, read failure, bad issuer, suspension and revocation fail closed. The conditional journal rechecks authority at execution claim, phase claim and native dispatch. The production suspension issuer and live source remain **undesignated** (`null`), so production cannot activate solo mode. Suspension is monotonic for a policy/rotation key: an ACTIVE record cannot clear a SUSPENDED or REVOKED record.

The protected prepare-overlap producer and its independent artifact consumer both verify actual GitHub actor/reviewer IDs and explicit V2 policy identity. Under V1 they reject same-human review even if GitHub environment configuration permits it. V2 is source-disabled and cannot reinterpret V1 receipts. The global rotation/predecessor claim is policy-independent, and native dispatch is reachable only through the canonical guarded signer/operator capabilities.

## Governance choices needed before activation

1. Designate a human/MFA approval issuer and its exact KMS key/policy. It must authenticate the actual human and MFA event before issuing distinct adoption and successor approvals. The checker signing key and root key cannot serve as this human issuer. The production issuance interface stays blocked until this is specified and independently tested.
2. Designate an emergency suspension issuer and authenticated live state source. The existing encrypted S3 release coordinator in account `368992683803`, region `eu-west-2`, bucket `mscqr-production-terraform-state-368992683803-eu-west-2`, using the existing release-deployer role, is the minimal candidate for durable records. Governance must still name the signing principal/key for ACTIVE/SUSPENDED/REVOKED records, approve the issuer's ability to write them, and define how emergency suspension is immediately observed. A separate designated authority must control clearing; the current implementation permits no clearing. No existing production issuer was authenticated as suitable in this source review.
3. Verify external obligations per phase; decide whether self-authorization of adoption, successor and prepare-overlap is acceptable. Root-drop remains separately authorized. Approve the narrow CloudTrail IAM statement above through its own governed plan/apply process. Verify live journal permissions, key policy, MFA attribution and timed rehearsal before any activation.

Even with the final live-state read immediately before a native call, a suspension arriving in the brief interval between that read and AWS accepting the call cannot retroactively cancel the call. Emergency procedure must also revoke sessions and stop the protected workflow. Unknown KMS/ECS outcomes remain terminal or read-only reconciled; S3 claims do not imply exactly-once AWS execution.

## Hostile source review

The initial mock approval issuer accepted arbitrary caller-supplied human and MFA fields. That was a high-severity future-activation flaw: a valid issuer signature would have authenticated bytes, not the actual consent event. The issuer interface now rejects all calls until governance designates a trusted human/MFA issuer and an implementation proves that event before Sign. Tests use synthetic signed fixtures only to exercise the verifier. The broad release suite also exposed a circular module import introduced by the policy module; fixed identities now remain local and a regression test compares them with the canonical environment contract.

Native effects remain behind the source-disabled gate and an unexported canonical dispatch capability. The V2 bundle requires distinct signed phase approval evidence for adoption and successor, a protected workflow receipt for prepare-overlap, and a V1 root authority. The production composition passes its fixed policy and suspension trust into the journal; it cannot accept those from caller adapters. The consumer checks policy, exact derivation and source, current suspension state, global rotation claim, phase claim and native dispatch claim. A lost KMS result remains `OUTCOME_UNKNOWN`; a lost ECS registration is read-only reconciled against the exact operation and CloudTrail context. No local test establishes live AWS permissions, operational emergency delivery or a completed production rehearsal.

## Security stop

Do not enable the conditional lane, alter TTLs, issue production KMS signatures, or apply IAM based on this source change. A merged disabled implementation would still require the governance decisions, designated issuer implementation, production permission verification and timed rehearsal above.

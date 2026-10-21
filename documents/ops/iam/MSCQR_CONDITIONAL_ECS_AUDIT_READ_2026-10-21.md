# Conditional ECS registration audit read

Baseline protected main: `808468b54599414870b2b694311d62b37f55df64`. This source change proposes one read-only permission for the existing `mscqr-production-release-deployer` role. It does not apply IAM or enable the conditional lane.

The canonical ambiguous `ecs:RegisterTaskDefinition` reconciler runs under the same release-deployer session that dispatched registration. It must find one matching regional CloudTrail event and compare its request, principal, task definition and operation identity. A live `cloudtrail:LookupEvents` call under that role returned `AccessDenied`; missing audit evidence remains `OUTCOME_UNKNOWN`, never permission to retry registration.

The role already has `MSCQRProductionGreenStageBReferenceAuditReadOnly` attached. Its live default policy version was `v10`, with canonical SHA-256 `c47d653427eaae883d502f920283b27f84281b08593fa4f1990e221588b63eac` and no LookupEvents statement at inspection. The proposed source policy retains all existing statements and adds only:

```json
{"Sid":"ReadOnlyConditionalEcsRegistrationAuditEuWest2","Effect":"Allow","Action":"cloudtrail:LookupEvents","Resource":"*","Condition":{"StringEquals":{"aws:RequestedRegion":"eu-west-2"}}}
```

`LookupEvents` has no resource-level IAM scope. The regional condition is enforced by IAM; the reconciler still requires exact event/principal/request correlation. The source policy preserves the exact statement order of the saved `CLOUDTRAIL_IAM_PROPOSED.json` proposal. Its canonical policy SHA-256 is `e04893453a106b6c465d4995cab66df9c496a3bf7c3b380c4b16d3e1dbb1d877`. The permission manifest and generated capability graph bind this one action to the same policy and SID. The Stage B identity validator continues to reject `iam:SimulatePrincipalPolicy` and every other release-deployer CloudTrail capability.

This is a coordinated source/IAM transition: after merge, the source preflight expects the new policy hash and will fail closed until the separately approved IAM update is applied. Do not merge into an active release window without an approved, ready-to-execute IAM plan. Reauthenticate the new source SHA and current live policy attachment/default version. Check version capacity and full before/after document before mutation. Apply only through the existing governed IAM mechanism. Verify the new default document hash, sole intended attachment, absence of extra actions and an actual bounded `LookupEvents` read under the release-deployer. Then re-run the Stage B permission preflight against the new source. This PR itself grants no live access.

Production activation remains blocked on designated solo human/MFA approval and suspension issuers, authenticated live suspension state, a separately approved isolated coordinator claim/readback probe, and a production-like timed rehearsal. Do not begin QR/root evidence until those are closed. A source merge changes protected-main identity, so current-source authorizations must be regenerated; immutable published images may only be reused under the actual image-impact and consumer contracts.

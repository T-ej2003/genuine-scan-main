# Production Release Gate OIDC identity

Release Gate assumes
`arn:aws:iam::368992683803:role/mscqr-production-release-deployer` only for the
deployment capabilities assigned to that role. Image publication remains in the
separate `production-stage-b-image-publish` environment under
`mscqr-production-stage-b-image-publisher`; approval publication remains under
the MFA-backed independent checker; only the broker reads the approval secret;
and ECS Exec remains under the dedicated verifier. The Release Gate job consumes
the signed four-image authorization and broker validation instead of inheriting
producer credentials. It does not accept a role ARN from
dispatch inputs, repository variables, environment variables, or secrets, and
it has no static AWS credential fallback.

Normal activation preserves `mscqr-frontend:20`; the Stage-B publisher contract
does not authorize frontend publication. Release Gate contains no ECR login,
repository-control, image-push, or approval-secret read step. Backend recovery
retains only its narrowly scoped ECR reads. Rotation overlap explicitly consumes
the GitHub OIDC release-deployer session and rechecks its STS caller before ECS
mutation; local operator cutover continues to use the named MFA profile.

## Capability routing

| Capability | Authoritative principal | Release Gate boundary |
| --- | --- | --- |
| Publish/scan/sign backend, worker, executor, and canary images | `mscqr-production-stage-b-image-publisher` | Separate protected image workflow; Release Gate accepts only the signed four-image authorization. |
| Verify ECR image/repository evidence and sign the report | governed administrator | Completed before dispatch; Release Gate re-verifies the KMS-backed authorization. |
| Publish Stage-B approval | `mscqr-production-rls-independent-checker` | Separate MFA-backed command; no checker credentials enter Release Gate. |
| Read Stage-B approval | `mscqr-production-rls-approval-broker` | Release-deployer sends only the exact derived approval ID to the reviewed broker alias. |
| Stage-B broker invocation and exact backend candidate activation | `mscqr-production-release-deployer` | Exact environment-bound OIDC role, caller-checked by runtime contracts. No production worker ECS service currently exists. |
| Legacy backend health recovery | `mscqr-production-release-deployer` | Same OIDC role, limited recovery mode and narrowly scoped ECR reads. |
| Rotation overlap/cleanup deployment | `mscqr-production-release-deployer` | Same OIDC role; explicit GitHub OIDC credential source and STS caller readback. |
| ECS Exec post-deploy verification | `mscqr-production-ecs-exec-verifier` | Separate MFA-backed verifier; never inherited by Release Gate. |
| Release-deployer OIDC trust convergence | governed root administrator | Existing bootstrap path, exact IAM write/readback, then protected source activation. |

Normal Stage-B activation is a consumer phase, not an image or approval
producer. Any future frontend publication requires its own reviewed publisher
contract; it must not be inferred from the backend/worker publisher.

The source trust policy is
[`MSCQR_PRODUCTION_RELEASE_DEPLOYER_TRUST_POLICY.json`](./MSCQR_PRODUCTION_RELEASE_DEPLOYER_TRUST_POLICY.json).
It preserves the MFA-gated bootstrap-operator handoff and adds one GitHub OIDC
statement restricted by exact equality to:

- provider `arn:aws:iam::368992683803:oidc-provider/token.actions.githubusercontent.com`;
- audience `sts.amazonaws.com`;
- subject `repo:T-ej2003/genuine-scan-main:environment:production`.

The subject is GitHub's default subject for a job bound to the `production`
environment. It intentionally does not combine the environment subject with a
branch subject. Protected deployment-branch rules and required environment
review remain GitHub-owned gates.

## Bootstrap-safe rollout

The tracked rollout manifest starts as `PENDING_ADMINISTRATOR_CONVERGENCE`. In that
state every Release Gate mode exits before `configure-aws-credentials`; merging
the convergence tooling cannot strand the existing administrator path or make
an unready OIDC attempt.

From a fresh, clean protected-main checkout, the root administrator runs:

```sh
npm run production:release-oidc-trust -- \
  --mode converge \
  --admin-profile <authenticated-root-administrator-profile> \
  --source-sha <protected-main-sha>
```

The command accepts only the exact MFA-only current trust or the exact target
trust. It performs at most one `iam:UpdateAssumeRolePolicy`, preserves the MFA
statement, and calls `iam:GetRole` again. Only after the authenticated live
readback is semantically identical to the reviewed source
does it change the tracked source phase to `OIDC_ATTEMPT_ENABLED`. Running it
against the exact target is a zero-write IAM no-op. Any other principal, role,
trust, partial write, or failed readback leaves the source phase pending.

The resulting one-file source-phase change requires protected review and merge.
It is rollout intent, not authentication evidence: it contains no caller claim,
`readbackVerified` flag, timestamp, or self-authenticating digest. At runtime,
AWS STS evaluates the GitHub token against the role's current live trust and is
the final authentication authority. If trust changes after administrator
readback, `AssumeRoleWithWebIdentity` fails closed. This small residual TOCTOU
window cannot produce AWS credentials from stale source metadata.

The legacy `github-actions-mscqr-deploy` role is not a valid Release Gate
principal and is not changed or deleted by this contract.

## Normal Stage-B backend activation

Normal release does not clone or register `mscqr-backend:*`. Terraform registers
the reviewed `mscqr-production-rls-green-backend-candidate` revision, and the
activation path derives its exact ARN, image digest, source SHA, lineage, and
serial from the authenticated Stage-B state object. Worker images and candidate
definitions remain governed, but no worker service update is attempted while
production has no worker ECS service.

After the current-source Stage-B apply and before dispatching normal Release
Gate, the governed root administrator runs:

```sh
npm run production:normal-backend-activation -- \
  --mode converge-policy \
  --source-sha "$(git rev-parse HEAD)" \
  --admin-profile mscqr-production-root
```

This command changes only the exact candidate-revision condition in
`MSCQRProductionGreenStageBFinalApplyWrite`, reads the operative policy back,
and simulates the selected revision as allowed while adjacent revisions remain
denied. Each simulation uses AWS CLI `ContextEntry` structures for the exact
region, cluster ARN, and task-definition ARN; shorthand key/value strings are
not accepted. It is idempotent. Release Gate then repeats authenticated state, IAM,
task-definition, and service reads before database mutation and immediately
before the single `ecs:UpdateService`. The private local binding hash provides
content identity only; live AWS readback and AWS authorization are authoritative.

Policy publication is followed by an authenticated operative-policy readback
before simulation. A failed write with an exact readback is reconciled and the
simulations continue. A write attempt whose final policy cannot be authenticated
reports `PARTIAL_CONVERGENCE_LIVE_STATE_UNAUTHENTICATED`, performs no automatic
rollback, and requires the operator to rerun the same governed convergence with
the administrator profile. A post-readback simulation failure reports
`CONVERGENCE_MUTATION_READBACK_VERIFIED_VALIDATION_FAILED`; it never claims that
IAM was unchanged.

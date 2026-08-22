# Production Release Gate OIDC identity

Release Gate uses only
`arn:aws:iam::368992683803:role/mscqr-production-release-deployer` for its
environment-bound production job. The workflow does not accept a role ARN from
dispatch inputs, repository variables, environment variables, or secrets, and
it has no static AWS credential fallback.

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
